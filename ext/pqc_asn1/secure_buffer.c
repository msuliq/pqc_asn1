/*
 * secure_buffer.c — PqcAsn1::SecureBuffer TypedData wrapper around libpqcsb.
 *
 * ARCHITECTURE OVERVIEW
 * =====================
 * This module provides the Ruby-facing SecureBuffer class as a thin wrapper around
 * libpqcsb (https://github.com/msuliq/libpqcsb), a standalone C library for secure
 * memory management with mmap-backed allocation, mprotect-based access control,
 * mlock-based swap prevention, and cryptographic canaries for tamper detection.
 *
 * DESIGN DECISIONS
 * ================
 * 1. OPAQUE STRUCT APPROACH
 *    libpqcsb uses an opaque pqcsb_buf_t struct (definition hidden in internal.h).
 *    This prevents accidental field access and enables safe API evolution.
 *    See LIBPQCSB_INTEGRATION.md for detailed migration notes.
 *
 * 2. GUARD PATTERN FOR ACCESS CONTROL
 *    libpqcsb uses guard structures (pqcsb_read_guard_t) returned by value.
 *    Guards contain both data/len AND a status code, making errors explicit.
 *    This enforces proper pairing of begin_read/end_read at compile time.
 *    See guard lifetime documentation in pqcsb_use() below.
 *
 * 3. TYPEDDATA PATTERN
 *    TypedData_Wrap_Struct(klass, &pqcsb_buf_type, buf_ptr) wraps the opaque pointer.
 *    This differs from the old TypedData_Make_Struct which embedded the struct.
 *    Since pqcsb_buf_t is opaque, we can only use the pointer wrapper approach.
 *
 * 4. RUBY WRAPPER NAMING
 *    Ruby wrapper functions use pqcsb_rb_* prefix to avoid conflicts with
 *    libpqcsb's public functions (which use pqcsb_* prefix).
 *    Example: pqcsb_rb_create() vs libpqcsb's pqcsb_create()
 *
 * CRITICAL GUARD PATTERN USAGE
 * =============================
 * Guards are critical to understanding this code. They have several important properties:
 *
 * 1. RETURNED BY VALUE (not pointer):
 *    pqcsb_read_guard_t guard = pqcsb_begin_read(buf);
 *    The guard struct itself is small (24 bytes) and includes:
 *      - const uint8_t *data (pointer to readable region)
 *      - size_t len (readable length)
 *      - pqcsb_status_t status (success/failure code)
 *      - pqcsb_buf_t *_priv (internal reference, not user-facing)
 *
 * 2. LIFETIME-CRITICAL:
 *    Guard must remain alive from begin_read to end_read.
 *    In rb_ensure blocks, store guard in the context struct:
 *      typedef struct {
 *          pqcsb_read_guard_t *guard;  // Note: POINTER to guard
 *          ...
 *      } ctx_t;
 *    Then call pqcsb_end_read(&ctx->guard) in the ensure function.
 *
 * 3. EXCEPTION SAFETY:
 *    Guards work with rb_ensure() to guarantee cleanup even on exceptions.
 *    The ensure function MUST call pqcsb_end_read(&guard) to re-protect.
 *    This prevents leaking unprotected mmap pages on exception paths.
 *
 * 4. STATUS CHECKED UPFRONT:
 *    Always check guard.status immediately after begin_read:
 *      if (guard.status != PQCSB_OK) {
 *          rb_raise(rb_eRuntimeError, "pqcsb_begin_read failed: %s",
 *                   pqcsb_error_message(guard.status));
 *      }
 *    Do NOT assume guard.data is non-NULL on failure.
 */

#include "secure_buffer.h"
#include <stdatomic.h>

/* File-static handles. */
static VALUE s_cSecureBuffer;

VALUE pqcsb_class(void) { return s_cSecureBuffer; }

/* Per-process salt XOR'd into hash output for extra isolation. */
static st_index_t s_hash_salt = 0;

/* ------------------------------------------------------------------ */
/* TypedData bookkeeping                                               */
/* ------------------------------------------------------------------ */

static void
pqcsb_dfree(void *ptr)
{
    pqcsb_buf_t *buf = (pqcsb_buf_t *)ptr;
    pqcsb_destroy(&buf);
}

static size_t
pqcsb_dsize(const void *ptr)
{
    const pqcsb_buf_t *buf = (const pqcsb_buf_t *)ptr;
    /* Return the total allocation size reported by libpqcsb.
     * We can't use sizeof(*buf) since pqcsb_buf_t is opaque. */
    return pqcsb_get_allocation_size(buf);
}

const rb_data_type_t pqcsb_buf_type = {
    .wrap_struct_name = "PqcAsn1::SecureBuffer",
    .function = {
        .dmark = NULL,
        .dfree = pqcsb_dfree,
        .dsize = pqcsb_dsize,
    },
    .flags = RUBY_TYPED_FREE_IMMEDIATELY,
};

/* ------------------------------------------------------------------ */
/* Wiped-state check                                                   */
/* ------------------------------------------------------------------ */

static void
pqcsb_check_wiped(const pqcsb_buf_t *buf)
{
    if (pqcsb_is_wiped(buf))
        rb_raise(rb_eRuntimeError, "SecureBuffer has been wiped");
}

/* ------------------------------------------------------------------ */
/* Ruby-level factory helpers                                          */
/* ------------------------------------------------------------------ */

VALUE
pqcsb_rb_create(VALUE klass, const uint8_t *data, size_t len)
{
    pqcsb_buf_t *buf = NULL;
    pqcsb_status_t rc = pqcsb_create(data, len, &buf);
    if (rc != PQCSB_OK)
        rb_raise(rb_eNoMemError, "pqcsb_create failed: %s", pqcsb_error_message(rc));

    VALUE obj = TypedData_Wrap_Struct(klass, &pqcsb_buf_type, buf);
    rb_obj_freeze(obj);
    return obj;
}

VALUE
pqcsb_rb_create_inplace(VALUE klass, size_t len,
                        pqcsb_status_t (*fill)(uint8_t *data, size_t len, void *ctx),
                        void *ctx)
{
    pqcsb_buf_t *buf = NULL;
    pqcsb_status_t rc = pqcsb_create_inplace(len, fill, ctx, &buf);
    if (rc != PQCSB_OK)
        rb_raise(rb_eNoMemError, "pqcsb_create_inplace failed: %s", pqcsb_error_message(rc));

    VALUE obj = TypedData_Wrap_Struct(klass, &pqcsb_buf_type, buf);
    rb_obj_freeze(obj);
    return obj;
}

void
pqcsb_rb_wipe(VALUE obj)
{
    pqcsb_buf_t *buf = (pqcsb_buf_t *)RTYPEDDATA_DATA(obj);
    pqcsb_wipe(buf);
}

/* ------------------------------------------------------------------ */
/* Ruby methods                                                        */
/* ------------------------------------------------------------------ */

static VALUE
pqcsb_bytesize(VALUE self)
{
    const pqcsb_buf_t *buf = (const pqcsb_buf_t *)RTYPEDDATA_DATA(self);
    return SIZET2NUM(pqcsb_len(buf));
}

static VALUE
pqcsb_to_s(VALUE self)
{
    (void)self;
    rb_raise(rb_eNotImpError,
             "SecureBuffer#to_s is disabled to prevent accidental key leakage; "
             "use #use { |bytes| ... } instead");
    return Qnil;
}

/* Context for rb_ensure in #use. */
typedef struct {
    VALUE                rb_bytes;
    pqcsb_buf_t         *buf;
    pqcsb_read_guard_t  *guard;
} pqcsb_use_ctx_t;

static VALUE
pqcsb_use_ensure(VALUE arg)
{
    pqcsb_use_ctx_t *ctx = (pqcsb_use_ctx_t *)arg;

    /* Unlock the temporary string if not frozen by user code. */
    if (!OBJ_FROZEN(ctx->rb_bytes))
        rb_str_unlocktmp(ctx->rb_bytes);

    /* Securely zero the backing memory regardless of frozen state. */
    if (RSTRING_LEN(ctx->rb_bytes) > 0)
        pqcsb_secure_zero((uint8_t *)RSTRING_PTR(ctx->rb_bytes),
                           (size_t)RSTRING_LEN(ctx->rb_bytes));

    /* Truncate and freeze. */
    if (!OBJ_FROZEN(ctx->rb_bytes)) {
        rb_str_resize(ctx->rb_bytes, 0);
        rb_str_freeze(ctx->rb_bytes);
    }

    /* Re-protect the mmap region by closing the guard. */
    pqcsb_end_read(ctx->guard);

    return Qnil;
}

/*
 * SecureBuffer#use { |bytes| ... } — yield temporary heap copy for block.
 *
 * SECURITY MODEL
 * ==============
 * This method provides secure access to encrypted key material by:
 *
 * 1. GUARD-BASED UNLOCKING
 *    - Calls pqcsb_begin_read() which returns a guard struct containing a pointer
 *      to the protected mmap region (temporarily unprotected to PROT_READ)
 *    - Guard tracks access via atomic refcount (multiple #use calls can nest)
 *
 * 2. TEMPORARY HEAP COPY
 *    - Creates a new Ruby String on the heap containing a copy of the key material
 *    - This allows Ruby code to work with the bytes (Ruby APIs need mutable Strings)
 *    - Trade-off: temporary copy exists on heap during block execution
 *      (unavoidable limitation of Ruby String semantics)
 *
 * 3. GUARANTEED CLEANUP via rb_ensure
 *    - Even if the block raises an exception, pqcsb_use_ensure() guarantees:
 *      a) Heap copy is securely zeroed
 *      b) Heap copy is frozen (escaped references become useless)
 *      c) mmap region is re-protected to PROT_NONE (via pqcsb_end_read)
 *
 * 4. NESTED CALL SAFETY
 *    - Multiple #use calls can nest (read_refs tracks depth)
 *    - Re-entry only re-protects on the outermost exit
 *    - Prevents premature re-protection while outer caller still needs access
 *
 * WHY GUARD IN CONTEXT?
 * =====================
 * The guard MUST be stored as a pointer in the context struct so it remains
 * valid through the rb_ensure lifecycle:
 *
 *     pqcsb_read_guard_t guard = pqcsb_begin_read(...);  // Guard on stack
 *     ctx = { .guard = &guard };                          // Store POINTER
 *     rb_ensure(..., pqcsb_use_ensure, (VALUE)&ctx);     // Ensure sees &guard
 *
 * If we passed guard by value, it might go out of scope before ensure runs.
 * Storing &guard ensures the original stack-allocated guard is accessible.
 *
 * RETURN VALUE
 * ============
 * Returns the block's return value (not the bytes), allowing:
 *     SecureBuffer#use { |b| b.bytesize }  # => integer
 *     SecureBuffer#use { |b| b.reverse }   # => reversed bytes
 */
static VALUE
pqcsb_use(VALUE self)
{
    if (!rb_block_given_p())
        rb_raise(rb_eArgError, "SecureBuffer#use requires a block");

    pqcsb_buf_t *buf = (pqcsb_buf_t *)RTYPEDDATA_DATA(self);
    pqcsb_check_wiped(buf);

    /* Begin read: temporarily unprotect mmap region and get access guard.
     * Guard contains both data pointer and status code. */
    pqcsb_read_guard_t guard = pqcsb_begin_read(buf);
    if (guard.status != PQCSB_OK)
        rb_raise(rb_eRuntimeError, "pqcsb_begin_read failed: %s",
                 pqcsb_error_message(guard.status));

    /* Create temporary heap copy for Ruby to work with.
     * This must be on the heap because Ruby's String semantics require it. */
    VALUE rb_bytes = rb_str_new((const char *)guard.data, (long)guard.len);
    rb_enc_associate(rb_bytes, rb_ascii8bit_encoding());
    rb_str_locktmp(rb_bytes);

    /* Store guard pointer (not value!) in context for ensure cleanup.
     * The guard remains on this function's stack and is valid for rb_ensure. */
    pqcsb_use_ctx_t ctx = { .rb_bytes = rb_bytes, .buf = buf, .guard = &guard };

    /* rb_ensure guarantees pqcsb_use_ensure runs even if block raises.
     * This ensures proper cleanup of both heap and mmap protections. */
    VALUE block_result = rb_ensure(rb_yield, rb_bytes, pqcsb_use_ensure, (VALUE)&ctx);

    return block_result;
}

static VALUE
pqcsb_eq(VALUE self, VALUE other)
{
    pqcsb_buf_t *buf = (pqcsb_buf_t *)RTYPEDDATA_DATA(self);
    pqcsb_check_wiped(buf);

    if (rb_obj_is_kind_of(other, s_cSecureBuffer)) {
        pqcsb_buf_t *other_buf = (pqcsb_buf_t *)RTYPEDDATA_DATA(other);
        pqcsb_check_wiped(other_buf);
        return pqcsb_ct_equal_bufs(buf, other_buf) ? Qtrue : Qfalse;
    }

    if (RB_TYPE_P(other, T_STRING)) {
        const uint8_t *other_ptr = (const uint8_t *)RSTRING_PTR(other);
        size_t other_len = (size_t)RSTRING_LEN(other);
        return pqcsb_ct_equal(buf, other_ptr, other_len) ? Qtrue : Qfalse;
    }

    return Qfalse;
}

static VALUE
pqcsb_eql(VALUE self, VALUE other)
{
    return pqcsb_eq(self, other);
}

static VALUE
pqcsb_inspect(VALUE self)
{
    const pqcsb_buf_t *buf = (const pqcsb_buf_t *)RTYPEDDATA_DATA(self);
    if (pqcsb_is_wiped(buf))
        return rb_sprintf("#<PqcAsn1::SecureBuffer [WIPED]>");
    return rb_sprintf("#<PqcAsn1::SecureBuffer %zu bytes [REDACTED]>", pqcsb_len(buf));
}

static VALUE
pqcsb_marshal_dump(VALUE self)
{
    (void)self;
    rb_raise(rb_eTypeError,
             "can't dump PqcAsn1::SecureBuffer (contains secret key material)");
    return Qnil;
}

static VALUE
pqcsb_hash(VALUE self)
{
    pqcsb_buf_t *buf = (pqcsb_buf_t *)RTYPEDDATA_DATA(self);
    pqcsb_check_wiped(buf);

    pqcsb_read_guard_t guard = pqcsb_begin_read(buf);
    if (guard.status != PQCSB_OK)
        rb_raise(rb_eRuntimeError, "pqcsb_begin_read failed: %s",
                 pqcsb_error_message(guard.status));

    st_index_t h = rb_memhash(guard.data, (long)guard.len);
    pqcsb_end_read(&guard);

    h ^= s_hash_salt;
    return ST2FIX(h);
}

static VALUE
pqcsb_wipe_rb(VALUE self)
{
    pqcsb_rb_wipe(self);
    return self;
}

static VALUE
pqcsb_wiped_p(VALUE self)
{
    const pqcsb_buf_t *buf = (const pqcsb_buf_t *)RTYPEDDATA_DATA(self);
    return pqcsb_is_wiped(buf) ? Qtrue : Qfalse;
}

static VALUE
pqcsb_canary_ok(VALUE self)
{
    pqcsb_buf_t *buf = (pqcsb_buf_t *)RTYPEDDATA_DATA(self);
    if (pqcsb_is_wiped(buf))
        return Qfalse;
    return pqcsb_check_canary(buf) == PQCSB_OK ? Qtrue : Qfalse;
}

static VALUE
pqcsb_random(VALUE klass, VALUE rb_n)
{
    long n_signed = NUM2LONG(rb_n);
    if (n_signed <= 0)
        rb_raise(rb_eArgError, "size must be > 0");
    size_t n = (size_t)n_signed;

    pqcsb_buf_t *buf = NULL;
    pqcsb_status_t rc = pqcsb_create_random(n, &buf);
    if (rc != PQCSB_OK)
        rb_raise(rb_eRuntimeError, "pqcsb_create_random failed: %s",
                 pqcsb_error_message(rc));

    VALUE obj = TypedData_Wrap_Struct(klass, &pqcsb_buf_type, buf);
    rb_obj_freeze(obj);
    return obj;
}

typedef struct {
    pqcsb_buf_t *buf;
    size_t       offset;
    size_t       length;
    VALUE        result;
} pqcsb_slice_ctx_t;

static VALUE
pqcsb_slice_body(VALUE arg)
{
    pqcsb_slice_ctx_t *ctx = (pqcsb_slice_ctx_t *)arg;

    pqcsb_buf_t *out = NULL;
    pqcsb_status_t rc = pqcsb_slice(ctx->buf, ctx->offset, ctx->length, &out);
    if (rc != PQCSB_OK) {
        pqcsb_destroy(&out);
        rb_raise(rb_eRangeError, "pqcsb_slice failed: %s", pqcsb_error_message(rc));
    }

    ctx->result = TypedData_Wrap_Struct(s_cSecureBuffer, &pqcsb_buf_type, out);
    rb_obj_freeze(ctx->result);
    return ctx->result;
}

static VALUE
pqcsb_ensure_end_read(VALUE arg)
{
    pqcsb_read_guard_t *guard = (pqcsb_read_guard_t *)arg;
    pqcsb_end_read(guard);
    return Qnil;
}

static VALUE
ruby_pqcsb_slice(VALUE self, VALUE rb_offset, VALUE rb_length)
{
    pqcsb_buf_t *buf = (pqcsb_buf_t *)RTYPEDDATA_DATA(self);
    pqcsb_check_wiped(buf);

    long offset_signed = NUM2LONG(rb_offset);
    long length_signed = NUM2LONG(rb_length);
    if (offset_signed < 0)
        rb_raise(rb_eArgError, "offset must be >= 0");
    if (length_signed <= 0)
        rb_raise(rb_eArgError, "length must be > 0");

    size_t offset = (size_t)offset_signed;
    size_t length = (size_t)length_signed;
    size_t buf_len = pqcsb_len(buf);

    if (offset >= buf_len)
        rb_raise(rb_eRangeError, "offset out of bounds");
    if (length > buf_len - offset)
        rb_raise(rb_eRangeError, "offset + length exceeds buffer size");

    pqcsb_read_guard_t guard = pqcsb_begin_read(buf);
    if (guard.status != PQCSB_OK)
        rb_raise(rb_eRuntimeError, "pqcsb_begin_read failed");

    pqcsb_slice_ctx_t ctx = { buf, offset, length, Qnil };
    rb_ensure(pqcsb_slice_body, (VALUE)&ctx,
              pqcsb_ensure_end_read, (VALUE)&guard);
    return ctx.result;
}

static VALUE
pqcsb_from_string(VALUE klass, VALUE rb_str)
{
    StringValue(rb_str);
    const uint8_t *ptr = (const uint8_t *)RSTRING_PTR(rb_str);
    size_t len = (size_t)RSTRING_LEN(rb_str);
    if (len == 0)
        rb_raise(rb_eArgError, "string must not be empty");
    return pqcsb_rb_create(klass, ptr, len);
}

/* ------------------------------------------------------------------ */
/* Init                                                                */
/* ------------------------------------------------------------------ */

void
init_secure_buffer(VALUE mPqcAsn1)
{
    /* Check libpqcsb ABI compatibility. */
    if (pqcsb_check_abi_version(PQCSB_ABI_VERSION_MAJOR, PQCSB_ABI_VERSION_MINOR) != PQCSB_OK)
        rb_raise(rb_eLoadError, "libpqcsb ABI version mismatch");

    /* Generate per-process hash salt. */
    {
        uint8_t salt_bytes[sizeof(s_hash_salt)];
        pqcsb_status_t rc = pqcsb_fill_random(salt_bytes, sizeof(salt_bytes));
        if (rc != PQCSB_OK)
            rb_raise(rb_eRuntimeError, "pqcsb_fill_random failed for hash salt");
        memcpy(&s_hash_salt, salt_bytes, sizeof(s_hash_salt));
        pqcsb_secure_zero(salt_bytes, sizeof(salt_bytes));
    }

    s_cSecureBuffer = rb_define_class_under(mPqcAsn1, "SecureBuffer", rb_cObject);
    rb_gc_register_address(&s_cSecureBuffer);
    rb_undef_alloc_func(s_cSecureBuffer);
    rb_undef_method(s_cSecureBuffer, "dup");
    rb_undef_method(s_cSecureBuffer, "clone");

    rb_define_method(s_cSecureBuffer, "bytesize",     pqcsb_bytesize,     0);
    rb_define_method(s_cSecureBuffer, "size",         pqcsb_bytesize,     0);
    rb_define_method(s_cSecureBuffer, "to_s",         pqcsb_to_s,         0);
    rb_define_method(s_cSecureBuffer, "use",          pqcsb_use,          0);
    rb_define_method(s_cSecureBuffer, "==",           pqcsb_eq,           1);
    rb_define_method(s_cSecureBuffer, "eql?",         pqcsb_eql,          1);
    rb_define_method(s_cSecureBuffer, "hash",         pqcsb_hash,         0);
    rb_define_method(s_cSecureBuffer, "inspect",      pqcsb_inspect,      0);
    rb_define_method(s_cSecureBuffer, "marshal_dump", pqcsb_marshal_dump, 0);
    rb_define_method(s_cSecureBuffer, "slice",        ruby_pqcsb_slice,        2);
    rb_define_method(s_cSecureBuffer, "wipe!",        pqcsb_wipe_rb,      0);
    rb_define_method(s_cSecureBuffer, "wiped?",       pqcsb_wiped_p,      0);
    rb_define_method(s_cSecureBuffer, "canary_ok?",   pqcsb_canary_ok,    0);

    rb_define_singleton_method(s_cSecureBuffer, "random",      pqcsb_random,      1);
    rb_define_singleton_method(s_cSecureBuffer, "from_string", pqcsb_from_string, 1);
}
