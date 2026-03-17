/*
 * secure_buffer.c — PqcAsn1::SecureBuffer TypedData implementation.
 *
 * SecureBuffer holds secret key material with comprehensive protections:
 *
 *   - mmap-backed allocation with PROT_NONE guard pages before and after
 *     the data region, catching overflows/underflows with an immediate
 *     segfault.
 *   - mlock on the data region to prevent the OS from swapping key
 *     material to disk.  A process-wide atomic counter tracks locked
 *     bytes against RLIMIT_MEMLOCK.
 *   - mprotect toggles the data pages between PROT_NONE (idle) and
 *     PROT_READ (during #use / equality / hash), so even an in-process
 *     memory-read vulnerability cannot see keys outside access windows.
 *   - 8-byte canary sentinels before and after user data, verified in
 *     the destructor to detect buffer corruption.
 *   - Secure zeroing via memset_s / explicit_bzero / volatile loop.
 *   - Constant-time equality to prevent timing side-channels.
 *   - Explicit #wipe! for deterministic destruction without waiting
 *     for GC.
 *   - SecureBuffer.random(n) fills a buffer directly from arc4random_buf
 *     or /dev/urandom, avoiding a Ruby String intermediate.
 *   - The #use block yields a temporary String that is zeroed, truncated,
 *     and frozen after the block exits, rendering any escaped reference
 *     useless.
 *   - dup, clone, Marshal.dump, and to_s are blocked.
 *
 * On Windows, VirtualAlloc/VirtualProtect/VirtualLock provide equivalent
 *   protections to the Unix mmap/mprotect/mlock path.
 * Platforms without mmap or VirtualAlloc fall back to malloc-based allocation.
 */

#include "secure_buffer.h"
#include <stdatomic.h>
#include <fcntl.h>
#include <errno.h>

#ifdef HAVE_ARC4RANDOM_BUF
#include <stdlib.h>
#endif

#ifdef HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif

#ifdef _WIN32
#include <windows.h>
#include <ntsecapi.h>  /* RtlGenRandom */
#endif

/* MAP_ANONYMOUS may be spelled MAP_ANON on some BSDs. */
#if defined(HAVE_MMAP) && !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

/* Unified platform detection: prefer mmap on Unix, VirtualAlloc on Windows. */
#if defined(HAVE_MMAP) && defined(MAP_ANONYMOUS)
#  define PQCSB_USE_MMAP 1
#elif defined(_WIN32)
#  define PQCSB_USE_VIRTUALALLOC 1
#endif

/* ------------------------------------------------------------------ */
/* Platform abstraction macros                                         */
/*                                                                     */
/* These collapse the 3-way #if/#elif/#else duplication for memory     */
/* protection operations into single-call macros.                      */
/* ------------------------------------------------------------------ */

#if defined(PQCSB_USE_MMAP) && defined(HAVE_MPROTECT)
#  define PQCSB_SET_PROT(base, ps, dp, prot) \
       mprotect((base) + (ps), (dp), (prot))
#  define PQCSB_PROT_NONE   PROT_NONE
#  define PQCSB_PROT_READ   PROT_READ
#  define PQCSB_PROT_RW     (PROT_READ | PROT_WRITE)
#  define PQCSB_HAS_PROTECT 1
#elif defined(PQCSB_USE_VIRTUALALLOC)
#  define PQCSB_SET_PROT(base, ps, dp, prot) do { \
       DWORD _old; \
       VirtualProtect((base) + (ps), (dp), (prot), &_old); \
   } while (0)
#  define PQCSB_PROT_NONE   PAGE_NOACCESS
#  define PQCSB_PROT_READ   PAGE_READONLY
#  define PQCSB_PROT_RW     PAGE_READWRITE
#  define PQCSB_HAS_PROTECT 1
#else
#  define PQCSB_HAS_PROTECT 0
#endif

/* ------------------------------------------------------------------ */
/* File-static state                                                   */
/* ------------------------------------------------------------------ */

static VALUE s_cSecureBuffer;

VALUE pqcsb_class(void) { return s_cSecureBuffer; }

/* Process-wide counter of mlock'd bytes for RLIMIT_MEMLOCK budgeting. */
static _Atomic size_t s_locked_bytes = 0;

/* Per-process salt XOR'd into hash output for extra isolation. */
static st_index_t s_hash_salt = 0;

/* Forward declaration — defined later in this file. */
static void pqcsb_fill_random(uint8_t *dst, size_t len);

/* ------------------------------------------------------------------ */
/* Secure zeroing (platform-specific best available)                  */
/* ------------------------------------------------------------------ */

void
pqcsb_secure_zero(uint8_t *ptr, size_t len)
{
    if (!ptr || len == 0) return;
#if defined(HAVE_MEMSET_S)
    memset_s(ptr, len, 0, len);
#elif defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(ptr, len);
#elif defined(_WIN32)
    SecureZeroMemory(ptr, len);
#else
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    size_t i;
    for (i = 0; i < len; i++) p[i] = 0;
#endif
}

/* ------------------------------------------------------------------ */
/* Page-size helpers                                                    */
/* ------------------------------------------------------------------ */

static _Atomic size_t s_page_size = 0;

static size_t
pqcsb_page_size(void)
{
    size_t ps = atomic_load(&s_page_size);
    if (ps == 0) {
#ifdef _WIN32
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        ps = (size_t)si.dwPageSize;
        if (ps == 0) ps = 4096;
#else
        long v = sysconf(_SC_PAGESIZE);
        ps = (v > 0) ? (size_t)v : 4096;
#endif
        atomic_store(&s_page_size, ps);
    }
    return ps;
}

static size_t
pqcsb_round_up_page(size_t n)
{
    size_t ps = pqcsb_page_size();
    return (n + ps - 1) & ~(ps - 1);
}

/* ------------------------------------------------------------------ */
/* mlock budget tracking                                               */
/* ------------------------------------------------------------------ */

static int
pqcsb_try_mlock(uint8_t *ptr, size_t len)
{
#if defined(HAVE_MLOCK) && defined(HAVE_GETRLIMIT)
    struct rlimit rl;
    if (getrlimit(RLIMIT_MEMLOCK, &rl) != 0) return 0;

    /* Atomically claim the mlock budget before calling mlock to avoid a
     * TOCTOU race where two threads both pass the budget check and then
     * both call mlock, potentially exceeding RLIMIT_MEMLOCK. */
    size_t current = atomic_load(&s_locked_bytes);
    for (;;) {
        size_t needed = current + len;
        if (rl.rlim_cur != RLIM_INFINITY && needed > rl.rlim_cur) return 0;
        if (atomic_compare_exchange_weak(&s_locked_bytes, &current, needed))
            break;
        /* current is updated by CAS on failure — retry with fresh value. */
    }

    if (mlock(ptr, len) == 0) {
        return 1;
    }

    /* mlock failed — release the budget we claimed. */
    atomic_fetch_sub(&s_locked_bytes, len);
#elif defined(_WIN32)
    if (VirtualLock(ptr, len)) {
        atomic_fetch_add(&s_locked_bytes, len);
        return 1;
    }
#else
    (void)ptr; (void)len;
#endif
    return 0;
}

static void
pqcsb_do_munlock(uint8_t *ptr, size_t len)
{
#if defined(HAVE_MUNLOCK)
    munlock(ptr, len);
    atomic_fetch_sub(&s_locked_bytes, len);
#elif defined(_WIN32)
    VirtualUnlock(ptr, len);
    atomic_fetch_sub(&s_locked_bytes, len);
#else
    (void)ptr; (void)len;
#endif
}

/* ------------------------------------------------------------------ */
/* mprotect helpers                                                    */
/* ------------------------------------------------------------------ */

static void
pqcsb_protect(pqcsb_buf_t *buf)
{
#if PQCSB_HAS_PROTECT
    if (buf->mmap_base && !buf->wiped) {
        size_t ps = pqcsb_page_size();
        PQCSB_SET_PROT(buf->mmap_base, ps, buf->data_pages, PQCSB_PROT_NONE);
    }
#else
    (void)buf;
#endif
}

static void
pqcsb_unprotect(pqcsb_buf_t *buf)
{
#if PQCSB_HAS_PROTECT
    if (buf->mmap_base && !buf->wiped) {
        size_t ps = pqcsb_page_size();
        PQCSB_SET_PROT(buf->mmap_base, ps, buf->data_pages, PQCSB_PROT_READ);
    }
#else
    (void)buf;
#endif
}

static void
pqcsb_unprotect_rw(pqcsb_buf_t *buf)
{
#if PQCSB_HAS_PROTECT
    if (buf->mmap_base) {
        size_t ps = pqcsb_page_size();
        PQCSB_SET_PROT(buf->mmap_base, ps, buf->data_pages, PQCSB_PROT_RW);
    }
#else
    (void)buf;
#endif
}

/* ------------------------------------------------------------------ */
/* Public C-level read-access helpers (for der.c and pem.c)           */
/* ------------------------------------------------------------------ */

void
pqcsb_begin_read(pqcsb_buf_t *buf)
{
    /* Only mprotect(PROT_READ) on the first reader; subsequent nested
     * calls just bump the counter.  This prevents an inner end_read
     * from prematurely re-protecting while an outer caller still needs
     * access. */
    if (atomic_fetch_add(&buf->read_refs, 1) == 0)
        pqcsb_unprotect(buf);
}

void
pqcsb_end_read(pqcsb_buf_t *buf)
{
    /* Only re-protect when the last reader exits. */
    if (atomic_fetch_sub(&buf->read_refs, 1) == 1)
        pqcsb_protect(buf);
}

/* ------------------------------------------------------------------ */
/* Canary helpers                                                      */
/* ------------------------------------------------------------------ */

static void
pqcsb_write_canaries(pqcsb_buf_t *buf)
{
    memcpy(buf->data - PQCSB_CANARY_SIZE, buf->canary, PQCSB_CANARY_SIZE);
    memcpy(buf->data + buf->len, buf->canary, PQCSB_CANARY_SIZE);
}

static int
pqcsb_check_canaries(const pqcsb_buf_t *buf)
{
    if (memcmp(buf->data - PQCSB_CANARY_SIZE, buf->canary, PQCSB_CANARY_SIZE) != 0)
        return 0;
    if (memcmp(buf->data + buf->len, buf->canary, PQCSB_CANARY_SIZE) != 0)
        return 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Buffer allocation / deallocation                                    */
/* ------------------------------------------------------------------ */

static void
pqcsb_alloc_buffer(pqcsb_buf_t *buf, size_t len)
{
    buf->len        = len;
    buf->wiped      = 0;
    buf->locked     = 0;
    atomic_init(&buf->read_refs, 0);
    buf->mmap_base  = NULL;
    buf->mmap_len   = 0;
    buf->data_pages = 0;

    /* Generate a unique random canary for this buffer so values are
     * unpredictable per-allocation (not a fixed compile-time constant). */
    pqcsb_fill_random(buf->canary, PQCSB_CANARY_SIZE);

#if defined(PQCSB_USE_MMAP)
    size_t ps = pqcsb_page_size();
    size_t needed = PQCSB_CANARY_SIZE + len + PQCSB_CANARY_SIZE;
    size_t data_pages = pqcsb_round_up_page(needed);
    size_t total = ps + data_pages + ps;

    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
#ifdef HAVE_CONST_MAP_NOCORE
    flags |= MAP_NOCORE;
#endif

    uint8_t *base = (uint8_t *)mmap(NULL, total, PROT_READ | PROT_WRITE,
                                     flags, -1, 0);
    if (base == MAP_FAILED)
        rb_raise(rb_eNoMemError, "mmap failed for SecureBuffer (%zu bytes)", len);

    mprotect(base, ps, PROT_NONE);
    mprotect(base + ps + data_pages, ps, PROT_NONE);

#ifdef HAVE_MADVISE
#ifdef HAVE_CONST_MADV_DONTDUMP
    madvise(base + ps, data_pages, MADV_DONTDUMP);
#endif
#ifdef HAVE_CONST_MADV_WIPEONFORK
    /* Zero data pages in forked child processes so key material does not
     * survive across fork().  Available on Linux 4.14+. */
    madvise(base + ps, data_pages, MADV_WIPEONFORK);
#endif
#endif

    buf->mmap_base  = base;
    buf->mmap_len   = total;
    buf->data_pages = data_pages;

    /* Right-align so overflows immediately hit the rear guard page. */
    buf->data = base + ps + data_pages - PQCSB_CANARY_SIZE - len;
    buf->locked = pqcsb_try_mlock(base + ps, data_pages);

#elif defined(PQCSB_USE_VIRTUALALLOC)
    size_t ps = pqcsb_page_size();
    size_t needed = PQCSB_CANARY_SIZE + len + PQCSB_CANARY_SIZE;
    size_t data_pages = pqcsb_round_up_page(needed);
    size_t total = ps + data_pages + ps;

    uint8_t *base = (uint8_t *)VirtualAlloc(NULL, total,
                                             MEM_COMMIT | MEM_RESERVE,
                                             PAGE_READWRITE);
    if (!base)
        rb_raise(rb_eNoMemError, "VirtualAlloc failed for SecureBuffer (%zu bytes)", len);

    /* Set guard pages to PAGE_NOACCESS. */
    DWORD old;
    VirtualProtect(base, ps, PAGE_NOACCESS, &old);
    VirtualProtect(base + ps + data_pages, ps, PAGE_NOACCESS, &old);

    buf->mmap_base  = base;
    buf->mmap_len   = total;
    buf->data_pages = data_pages;

    /* Right-align so overflows immediately hit the rear guard page. */
    buf->data = base + ps + data_pages - PQCSB_CANARY_SIZE - len;
    buf->locked = pqcsb_try_mlock(base + ps, data_pages);

#else
    size_t alloc_size = PQCSB_CANARY_SIZE + len + PQCSB_CANARY_SIZE;
    uint8_t *raw = (uint8_t *)ruby_xmalloc(alloc_size);
    buf->data = raw + PQCSB_CANARY_SIZE;
#endif
}

static void
pqcsb_free_buffer(pqcsb_buf_t *buf)
{
    if (!buf->data) return;

    pqcsb_unprotect_rw(buf);

    if (!buf->wiped && !pqcsb_check_canaries(buf)) {
        fprintf(stderr, "pqc_asn1: CANARY CORRUPTION DETECTED! "
                "SecureBuffer at %p (%zu bytes) may have been tampered with.\n",
                (void *)buf->data, buf->len);
    }

    pqcsb_secure_zero(buf->data - PQCSB_CANARY_SIZE,
                       PQCSB_CANARY_SIZE + buf->len + PQCSB_CANARY_SIZE);

#if defined(PQCSB_USE_MMAP)
    if (buf->mmap_base) {
        if (buf->locked) {
            size_t ps = pqcsb_page_size();
            pqcsb_do_munlock(buf->mmap_base + ps, buf->data_pages);
        }
        munmap(buf->mmap_base, buf->mmap_len);
        buf->mmap_base = NULL;
    } else {
        ruby_xfree(buf->data - PQCSB_CANARY_SIZE);
    }
#elif defined(PQCSB_USE_VIRTUALALLOC)
    if (buf->mmap_base) {
        if (buf->locked) {
            size_t ps = pqcsb_page_size();
            pqcsb_do_munlock(buf->mmap_base + ps, buf->data_pages);
        }
        VirtualFree(buf->mmap_base, 0, MEM_RELEASE);
        buf->mmap_base = NULL;
    } else {
        ruby_xfree(buf->data - PQCSB_CANARY_SIZE);
    }
#else
    ruby_xfree(buf->data - PQCSB_CANARY_SIZE);
#endif

    buf->data = NULL;
}

/* ------------------------------------------------------------------ */
/* Wiped-state check                                                   */
/* ------------------------------------------------------------------ */

static void
pqcsb_check_wiped(const pqcsb_buf_t *buf)
{
    if (buf->wiped)
        rb_raise(rb_eRuntimeError, "SecureBuffer has been wiped");
}

/* ------------------------------------------------------------------ */
/* Exception-safe end_read for rb_ensure                               */
/* ------------------------------------------------------------------ */

static VALUE
pqcsb_ensure_end_read(VALUE arg)
{
    pqcsb_end_read((pqcsb_buf_t *)arg);
    return Qnil;
}

/* ------------------------------------------------------------------ */
/* TypedData bookkeeping                                               */
/* ------------------------------------------------------------------ */

static void
pqcsb_dfree(void *ptr)
{
    pqcsb_buf_t *buf = (pqcsb_buf_t *)ptr;
    pqcsb_free_buffer(buf);
    ruby_xfree(buf);
}

static size_t
pqcsb_dsize(const void *ptr)
{
    const pqcsb_buf_t *buf = (const pqcsb_buf_t *)ptr;
    if (buf->mmap_base)
        return sizeof(*buf) + buf->mmap_len;
    return sizeof(*buf) + PQCSB_CANARY_SIZE + buf->len + PQCSB_CANARY_SIZE;
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
/* Cryptographic random helpers                                        */
/* ------------------------------------------------------------------ */

/* Cached /dev/urandom fd for the fallback path (opened once, never closed). */
#if !defined(HAVE_ARC4RANDOM_BUF) && !defined(HAVE_GETRANDOM) && \
    !defined(HAVE_GETENTROPY) && !defined(_WIN32)
static int s_urandom_fd = -1;
#endif

static void
pqcsb_fill_random(uint8_t *dst, size_t len)
{
#if defined(HAVE_ARC4RANDOM_BUF)
    arc4random_buf(dst, len);
#elif defined(_WIN32)
    /* RtlGenRandom (SystemFunction036) is the recommended CSPRNG on Windows.
     * It is available on Windows XP+ and does not require CryptoAPI. */
    if (!RtlGenRandom(dst, (ULONG)len))
        rb_raise(rb_eRuntimeError, "RtlGenRandom failed for SecureBuffer");
#elif defined(HAVE_GETRANDOM)
    /* getrandom(2) — available on Linux 3.17+.  No fd needed, blocks until
     * the CSPRNG is seeded (without GRND_NONBLOCK). */
    size_t off = 0;
    while (off < len) {
        ssize_t r = getrandom(dst + off, len - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            rb_sys_fail("getrandom");
        }
        off += (size_t)r;
    }
#elif defined(HAVE_GETENTROPY)
    /* getentropy(3) — available on OpenBSD, glibc 2.25+, macOS 10.12+.
     * Limited to 256 bytes per call. */
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 256) chunk = 256;
        if (getentropy(dst + off, chunk) != 0)
            rb_sys_fail("getentropy");
        off += chunk;
    }
#else
    /* Fallback: cached /dev/urandom fd (opened once, never closed). */
    if (s_urandom_fd < 0) {
        s_urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (s_urandom_fd < 0) rb_sys_fail("open(/dev/urandom)");
    }
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(s_urandom_fd, dst + off, len - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            rb_sys_fail("read(/dev/urandom)");
        }
        if (r == 0)
            rb_raise(rb_eIOError, "/dev/urandom returned EOF");
        off += (size_t)r;
    }
#endif
}

/* ------------------------------------------------------------------ */
/* Public C-level factory (used by der.c)                             */
/* ------------------------------------------------------------------ */

VALUE
pqcsb_create(VALUE klass, const uint8_t *data, size_t len)
{
    pqcsb_buf_t *buf;
    VALUE obj = TypedData_Make_Struct(klass, pqcsb_buf_t, &pqcsb_buf_type, buf);
    pqcsb_alloc_buffer(buf, len);

    pqcsb_unprotect_rw(buf);
    memcpy(buf->data, data, len);
    pqcsb_write_canaries(buf);
    pqcsb_protect(buf);

    rb_obj_freeze(obj);
    return obj;
}

/* In-place factory: allocate, call fill callback, write canaries, protect.
 * Avoids a temporary heap buffer + copy for callers like build_pkcs8. */
VALUE
pqcsb_create_inplace(VALUE klass, size_t len,
                     void (*fill)(uint8_t *data, size_t len, void *ctx),
                     void *ctx)
{
    pqcsb_buf_t *buf;
    VALUE obj = TypedData_Make_Struct(klass, pqcsb_buf_t, &pqcsb_buf_type, buf);
    pqcsb_alloc_buffer(buf, len);

    pqcsb_unprotect_rw(buf);
    fill(buf->data, len, ctx);
    pqcsb_write_canaries(buf);
    pqcsb_protect(buf);

    rb_obj_freeze(obj);
    return obj;
}

/* ------------------------------------------------------------------ */
/* Ruby methods                                                        */
/* ------------------------------------------------------------------ */

static VALUE
pqcsb_bytesize(VALUE self)
{
    pqcsb_buf_t *buf;
    TypedData_Get_Struct(self, pqcsb_buf_t, &pqcsb_buf_type, buf);
    return SIZET2NUM(buf->len);
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
    VALUE        rb_bytes;
    pqcsb_buf_t *buf;
} pqcsb_use_ctx_t;

static VALUE
pqcsb_use_ensure(VALUE arg)
{
    pqcsb_use_ctx_t *ctx = (pqcsb_use_ctx_t *)arg;

    /* Unlock the temporary string first so we can modify it.
     * If the block froze the string, rb_str_unlocktmp would raise —
     * check OBJ_FROZEN and work around it. */
    if (!OBJ_FROZEN(ctx->rb_bytes))
        rb_str_unlocktmp(ctx->rb_bytes);

    /* Securely zero the backing memory regardless of frozen state. */
    if (RSTRING_LEN(ctx->rb_bytes) > 0)
        pqcsb_secure_zero((uint8_t *)RSTRING_PTR(ctx->rb_bytes),
                           (size_t)RSTRING_LEN(ctx->rb_bytes));

    /* Truncate and freeze.  If already frozen (by user code), we cannot
     * rb_str_resize — but we already zeroed the memory above. */
    if (!OBJ_FROZEN(ctx->rb_bytes)) {
        rb_str_resize(ctx->rb_bytes, 0);
        rb_str_freeze(ctx->rb_bytes);
    }

    /* The mmap region was already re-protected to PROT_NONE immediately
     * after the copy (before rb_yield), so no additional protect is needed.
     * No code path in the user's block can unprotect it: nested #use calls
     * pair their own unprotect/protect, and #hash/#== use begin_read/end_read
     * which manage read_refs independently. */
    return Qnil;
}

/*
 * SecureBuffer#use { |bytes| ... }
 *
 * Yields a *temporary copy* of the key material as a mutable Ruby String.
 * The copy lives on the Ruby heap for the duration of the block, then is
 * securely zeroed, truncated to zero length, and frozen — rendering any
 * escaped reference useless.
 *
 * Design note: rb_str_new_static was considered to eliminate the heap copy
 * entirely (the String would point directly at the mmap region).  This was
 * rejected because after re-protecting the mmap to PROT_NONE, any access
 * to an escaped String reference would cause a segfault rather than a clean
 * Ruby exception.  The heap-copy approach is safer for Ruby consumers.
 *
 * Security caveat: during the block, the secret bytes exist in two places
 * (the mmap-protected region and the Ruby heap copy).  Ruby's GC compactor
 * may relocate the heap copy, leaving a stale image in the old location
 * until that page is reused.  This is an inherent limitation of yielding
 * a Ruby String — callers who need tighter guarantees should use the C-level
 * pqcsb_begin_read / pqcsb_end_read API instead (no heap copy).
 */
static VALUE
pqcsb_use(VALUE self)
{
    if (!rb_block_given_p())
        rb_raise(rb_eArgError, "SecureBuffer#use requires a block");

    pqcsb_buf_t *buf;
    TypedData_Get_Struct(self, pqcsb_buf_t, &pqcsb_buf_type, buf);
    pqcsb_check_wiped(buf);

    /* Use begin_read/end_read so the read_refs counter participates in
     * the same re-entrancy tracking as #hash, #==, and nested #use calls.
     * If #use is called from inside another #use (or #hash inside a block),
     * read_refs ensures mprotect is toggled only once for the outermost
     * caller, preventing a nested end_read from prematurely re-protecting
     * while an outer caller is still accessing the buffer. */
    pqcsb_begin_read(buf);

    VALUE rb_bytes = rb_str_new((const char *)buf->data, (long)buf->len);
    rb_enc_associate(rb_bytes, rb_ascii8bit_encoding());

    /* Re-protect immediately after the copy so the mmap region is guarded
     * for the entire duration of the user's block. */
    pqcsb_end_read(buf);

    rb_str_locktmp(rb_bytes);

    pqcsb_use_ctx_t ctx = { .rb_bytes = rb_bytes, .buf = buf };
    return rb_ensure(rb_yield, rb_bytes, pqcsb_use_ensure, (VALUE)&ctx);
}

/*
 * SecureBuffer#==(other) — constant-time equality.
 *
 * Comparison asymmetry: `sb == string` works (this method handles
 * String on the right-hand side), but `string == sb` always returns
 * false because String#== does not know how to unwrap SecureBuffer.
 * This is intentional — the alternative (implementing to_str) would
 * allow implicit coercion, which risks leaking key material into
 * contexts that expect a plain String.
 */
static VALUE
pqcsb_eq(VALUE self, VALUE other)
{
    pqcsb_buf_t *buf;
    TypedData_Get_Struct(self, pqcsb_buf_t, &pqcsb_buf_type, buf);
    pqcsb_check_wiped(buf);

    const uint8_t *other_ptr;
    size_t other_len;
    pqcsb_buf_t *other_buf = NULL;

    if (rb_obj_is_kind_of(other, s_cSecureBuffer)) {
        TypedData_Get_Struct(other, pqcsb_buf_t, &pqcsb_buf_type, other_buf);
        pqcsb_check_wiped(other_buf);
        pqcsb_begin_read(other_buf);
        other_ptr = other_buf->data;
        other_len = other_buf->len;
    } else if (RB_TYPE_P(other, T_STRING)) {
        other_ptr = (const uint8_t *)RSTRING_PTR(other);
        other_len = (size_t)RSTRING_LEN(other);
    } else {
        return Qfalse;
    }

    pqcsb_begin_read(buf);

    /* Constant-time comparison.  The length is compared in variable time
     * because bytesize is already publicly exposed via #bytesize — only
     * the content must be compared in constant time. */
    VALUE result;
    if (buf->len != other_len) {
        result = Qfalse;
    } else {
        volatile uint8_t diff = 0;
        size_t i;
        for (i = 0; i < buf->len; i++)
            diff |= buf->data[i] ^ other_ptr[i];
        result = (diff == 0) ? Qtrue : Qfalse;
    }

    pqcsb_end_read(buf);
    if (other_buf) pqcsb_end_read(other_buf);
    return result;
}

static VALUE
pqcsb_eql(VALUE self, VALUE other)
{
    return pqcsb_eq(self, other);
}

static VALUE
pqcsb_inspect(VALUE self)
{
    pqcsb_buf_t *buf;
    TypedData_Get_Struct(self, pqcsb_buf_t, &pqcsb_buf_type, buf);

    if (buf->wiped)
        return rb_sprintf("#<PqcAsn1::SecureBuffer [WIPED]>");
    return rb_sprintf("#<PqcAsn1::SecureBuffer %zu bytes [REDACTED]>", buf->len);
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
    pqcsb_buf_t *buf;
    TypedData_Get_Struct(self, pqcsb_buf_t, &pqcsb_buf_type, buf);
    pqcsb_check_wiped(buf);

    pqcsb_begin_read(buf);
    st_index_t h = rb_memhash(buf->data, (long)buf->len);
    pqcsb_end_read(buf);

    h ^= s_hash_salt;
    return ST2FIX(h);
}

/* Internal wipe logic shared by Ruby wipe! and C-level pqcsb_wipe. */
static void
pqcsb_wipe_internal(pqcsb_buf_t *buf)
{
    if (buf->wiped) return;

    pqcsb_unprotect_rw(buf);
    pqcsb_secure_zero(buf->data - PQCSB_CANARY_SIZE,
                       PQCSB_CANARY_SIZE + buf->len + PQCSB_CANARY_SIZE);
    pqcsb_protect(buf);

    if (buf->locked) {
#if defined(PQCSB_USE_MMAP) || defined(PQCSB_USE_VIRTUALALLOC)
        size_t ps = pqcsb_page_size();
        pqcsb_do_munlock(buf->mmap_base + ps, buf->data_pages);
#endif
        buf->locked = 0;
    }

    buf->wiped = 1;
}

/* C-level wipe callable from other translation units (e.g. der.c). */
void
pqcsb_wipe(VALUE obj)
{
    pqcsb_buf_t *buf;
    TypedData_Get_Struct(obj, pqcsb_buf_t, &pqcsb_buf_type, buf);
    pqcsb_wipe_internal(buf);
}

static VALUE
pqcsb_wipe_rb(VALUE self)
{
    pqcsb_buf_t *buf;
    TypedData_Get_Struct(self, pqcsb_buf_t, &pqcsb_buf_type, buf);
    pqcsb_wipe_internal(buf);
    return self;
}

static VALUE
pqcsb_wiped_p(VALUE self)
{
    pqcsb_buf_t *buf;
    TypedData_Get_Struct(self, pqcsb_buf_t, &pqcsb_buf_type, buf);
    return buf->wiped ? Qtrue : Qfalse;
}

static VALUE
pqcsb_canary_ok(VALUE self)
{
    pqcsb_buf_t *buf;
    TypedData_Get_Struct(self, pqcsb_buf_t, &pqcsb_buf_type, buf);

    if (buf->wiped) return Qfalse;

    pqcsb_begin_read(buf);
    int ok = pqcsb_check_canaries(buf);
    pqcsb_end_read(buf);

    return ok ? Qtrue : Qfalse;
}

/* SecureBuffer.random(n) -> SecureBuffer */
static VALUE
pqcsb_random(VALUE klass, VALUE rb_n)
{
    /* Validate before NUM2SIZET: negative Fixnums would wrap to huge
     * size_t values, causing mmap to allocate gigabytes or fail. */
    long n_signed = NUM2LONG(rb_n);
    if (n_signed <= 0)
        rb_raise(rb_eArgError, "size must be > 0");
    size_t n = (size_t)n_signed;

    pqcsb_buf_t *buf;
    VALUE obj = TypedData_Make_Struct(klass, pqcsb_buf_t, &pqcsb_buf_type, buf);
    pqcsb_alloc_buffer(buf, n);

    pqcsb_unprotect_rw(buf);
    pqcsb_fill_random(buf->data, n);
    pqcsb_write_canaries(buf);
    pqcsb_protect(buf);

    rb_obj_freeze(obj);
    return obj;
}

/* SecureBuffer#slice(offset, length) -> SecureBuffer
 * Returns a new SecureBuffer containing a copy of the specified byte range.
 * Avoids exposing the full buffer on the Ruby heap for partial extraction.
 *
 * Uses rb_ensure to guarantee pqcsb_end_read is called even if
 * pqcsb_create raises (e.g. NoMemError from mmap, or rb_sys_fail
 * from pqcsb_fill_random), preventing read_refs from leaking. */

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
    ctx->result = pqcsb_create(s_cSecureBuffer,
                               ctx->buf->data + ctx->offset,
                               ctx->length);
    return ctx->result;
}

static VALUE
pqcsb_slice(VALUE self, VALUE rb_offset, VALUE rb_length)
{
    pqcsb_buf_t *buf;
    TypedData_Get_Struct(self, pqcsb_buf_t, &pqcsb_buf_type, buf);
    pqcsb_check_wiped(buf);

    /* Validate before NUM2SIZET: negative values would wrap to huge
     * size_t, causing out-of-bounds reads from the mmap region. */
    long offset_signed = NUM2LONG(rb_offset);
    long length_signed = NUM2LONG(rb_length);
    if (offset_signed < 0)
        rb_raise(rb_eArgError, "offset must be >= 0");
    if (length_signed < 0)
        rb_raise(rb_eArgError, "length must be >= 0");
    size_t offset = (size_t)offset_signed;
    size_t length = (size_t)length_signed;

    if (length == 0)
        rb_raise(rb_eArgError, "length must be > 0");
    if (offset >= buf->len)
        rb_raise(rb_eRangeError,
                 "offset (%zu) out of bounds for SecureBuffer of size %zu",
                 offset, buf->len);
    /* Use subtraction to avoid size_t overflow: since offset < buf->len
     * is guaranteed above, (buf->len - offset) cannot underflow. */
    if (length > buf->len - offset)
        rb_raise(rb_eRangeError,
                 "offset + length exceeds SecureBuffer size %zu",
                 buf->len);

    pqcsb_begin_read(buf);
    pqcsb_slice_ctx_t ctx = { buf, offset, length, Qnil };
    rb_ensure(pqcsb_slice_body, (VALUE)&ctx,
              pqcsb_ensure_end_read, (VALUE)buf);
    return ctx.result;
}

/* SecureBuffer.from_string(str) -> SecureBuffer
 * Copies the String contents into a SecureBuffer. */
static VALUE
pqcsb_from_string(VALUE klass, VALUE rb_str)
{
    StringValue(rb_str);
    const uint8_t *ptr = (const uint8_t *)RSTRING_PTR(rb_str);
    size_t len = (size_t)RSTRING_LEN(rb_str);
    if (len == 0)
        rb_raise(rb_eArgError, "string must not be empty");
    return pqcsb_create(klass, ptr, len);
}

/* ------------------------------------------------------------------ */
/* Init                                                                */
/* ------------------------------------------------------------------ */

void
init_secure_buffer(VALUE mPqcAsn1)
{
    {
        uint8_t salt_bytes[sizeof(s_hash_salt)];
        pqcsb_fill_random(salt_bytes, sizeof(salt_bytes));
        memcpy(&s_hash_salt, salt_bytes, sizeof(s_hash_salt));
        pqcsb_secure_zero(salt_bytes, sizeof(salt_bytes));
    }

    s_cSecureBuffer = rb_define_class_under(mPqcAsn1, "SecureBuffer", rb_cObject);
    rb_gc_register_address(&s_cSecureBuffer);
    rb_undef_alloc_func(s_cSecureBuffer);
    rb_undef_method(s_cSecureBuffer, "dup");
    rb_undef_method(s_cSecureBuffer, "clone");

    rb_define_method(s_cSecureBuffer, "bytesize",    pqcsb_bytesize,    0);
    rb_define_method(s_cSecureBuffer, "size",        pqcsb_bytesize,    0);
    rb_define_method(s_cSecureBuffer, "to_s",        pqcsb_to_s,        0);
    rb_define_method(s_cSecureBuffer, "use",         pqcsb_use,         0);
    rb_define_method(s_cSecureBuffer, "==",          pqcsb_eq,          1);
    rb_define_method(s_cSecureBuffer, "eql?",        pqcsb_eql,         1);
    rb_define_method(s_cSecureBuffer, "hash",        pqcsb_hash,        0);
    rb_define_method(s_cSecureBuffer, "inspect",     pqcsb_inspect,     0);
    rb_define_method(s_cSecureBuffer, "marshal_dump",pqcsb_marshal_dump,0);
    rb_define_method(s_cSecureBuffer, "slice",       pqcsb_slice,       2);
    rb_define_method(s_cSecureBuffer, "wipe!",       pqcsb_wipe_rb,     0);
    rb_define_method(s_cSecureBuffer, "wiped?",      pqcsb_wiped_p,     0);
    rb_define_method(s_cSecureBuffer, "canary_ok?",  pqcsb_canary_ok,   0);

    rb_define_singleton_method(s_cSecureBuffer, "random",      pqcsb_random,      1);
    rb_define_singleton_method(s_cSecureBuffer, "from_string", pqcsb_from_string, 1);
}
