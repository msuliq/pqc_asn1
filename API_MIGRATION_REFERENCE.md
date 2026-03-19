# libpqcsb API Migration Reference

## Quick Reference: Old → New API Mapping

### Memory Management

| Old API | New API | Notes |
|---------|---------|-------|
| `pqcsb_alloc_buffer(buf, len)` | `pqcsb_create(data, len, &buf)` | Now returns status, uses output param |
| `pqcsb_free_buffer(buf)` | `pqcsb_destroy(&buf)` | Zeros, unmaps, and frees |
| `pqcsb_fill_random(buf->data, len)` | `pqcsb_create_random(len, &buf)` | Allocates, fills, returns new buffer |

### Access Control

| Old API | New API | Impact |
|---------|---------|--------|
| `void pqcsb_begin_read(buf)` | `guard = pqcsb_begin_read(buf)` | Returns guard struct, must check status |
| `void pqcsb_end_read(buf)` | `pqcsb_end_read(&guard)` | Takes guard pointer, enforces pairing |
| `buf->mmap_base, ->data_pages` | Not accessible | Use public API: `pqcsb_get_allocation_size()` |

### Status Queries

| Old API | New API | Notes |
|---------|---------|-------|
| `if (buf->wiped)` | `if (pqcsb_is_wiped(buf))` | Direct field access → API call |
| `buf->len` | `pqcsb_len(buf)` | Direct field access → API call |
| `buf->locked` | `pqcsb_is_locked(buf)` | Direct field access → API call |
| `buf->read_refs` | `pqcsb_get_read_refcount(buf)` | Internal state → public query |

### Guard Access

| Old Pattern | New Pattern | Notes |
|-------------|-------------|-------|
| `buf->data` | `guard.data` | Access data via guard, not buffer |
| `buf->len` | `guard.len` | Length available in guard struct |
| Check `buf` state | Check `guard.status` | Errors reported in guard.status |

### Comparison & Equality

| Old API | New API | Notes |
|---------|---------|-------|
| volatile byte loop | `pqcsb_ct_equal(buf, ptr, len)` | Constant-time comparison with raw bytes |
| volatile byte loop | `pqcsb_ct_equal_bufs(a, b)` | Constant-time comparison between buffers |

### Operations

| Old API | New API | Notes |
|---------|---------|-------|
| `pqcsb_slice(buf, offset, len)` | `pqcsb_slice(buf, offset, len, &out)` | Now returns status, uses output param |
| `pqcsb_wipe(buf)` | `pqcsb_wipe(buf)` | Same signature, now returns status |
| `pqcsb_check_canaries(buf)` | `pqcsb_check_canary(buf)` | Returns status, name changed |

## Affected Code Locations

### secure_buffer.c

#### TypedData Changes
```c
// OLD: Embedded struct
VALUE obj = TypedData_Make_Struct(klass, pqcsb_buf_t, &pqcsb_buf_type, buf);
// buf is directly accessible: buf->data, buf->len, sizeof(*buf), etc.

// NEW: Opaque pointer
pqcsb_buf_t *buf = NULL;
pqcsb_status_t rc = pqcsb_create(data, len, &buf);
VALUE obj = TypedData_Wrap_Struct(klass, &pqcsb_buf_type, buf);
// buf is opaque: can't access fields, use pqcsb_len(buf), pqcsb_is_wiped(buf), etc.
```

**Affected Methods:**
- `pqcsb_rb_create()` - Now calls `pqcsb_create()` + `TypedData_Wrap_Struct()`
- `pqcsb_dsize()` - Can't use `sizeof(*buf)`, must use `pqcsb_get_allocation_size(buf)`
- `pqcsb_use()` - Guard handling via context pointer
- `pqcsb_hash()` - Guard-based temporary read access
- `ruby_pqcsb_slice()` - Guard with rb_ensure for exception safety
- `pqcsb_random()` - `pqcsb_create_random()` instead of inline allocation

#### Guard Pattern Changes
```c
// OLD: Simple void functions
pqcsb_begin_read(buf);
// ... use buf->data and buf->len ...
pqcsb_end_read(buf);

// NEW: Guard-based (multiple places)
// 1. In pqcsb_use():
pqcsb_read_guard_t guard = pqcsb_begin_read(buf);
if (guard.status != PQCSB_OK) rb_raise(...);
VALUE rb_bytes = rb_str_new((const char *)guard.data, (long)guard.len);
// ... yield to block ...
pqcsb_end_read(&guard);  // In ensure function

// 2. In pqcsb_hash():
pqcsb_read_guard_t guard = pqcsb_begin_read(buf);
st_index_t h = rb_memhash(guard.data, (long)guard.len);
pqcsb_end_read(&guard);

// 3. In ruby_pqcsb_slice():
pqcsb_read_guard_t guard = pqcsb_begin_read(buf);
// ... use guard in rb_ensure block ...
pqcsb_end_read(&guard);  // In ensure function
```

**Key Pattern: Guard in Context for Exception Safety**
```c
typedef struct {
    VALUE rb_bytes;
    pqcsb_buf_t *buf;
    pqcsb_read_guard_t *guard;  // POINTER to guard
} pqcsb_use_ctx_t;

static VALUE pqcsb_use_ensure(VALUE arg) {
    pqcsb_use_ctx_t *ctx = (pqcsb_use_ctx_t *)arg;
    // ... cleanup ...
    pqcsb_end_read(ctx->guard);  // Access via pointer
    return Qnil;
}
```

### der.c

#### Struct Field Access Changes
```c
// OLD: Direct field access
if (sk_buf->wiped)
    rb_raise(rb_eRuntimeError, "SecureBuffer has been wiped");
// ...
size_t total;
pqc_asn1_pkcs8_size_ex(..., ctx->sk_buf->len, ...);
// ...
ctx->result = pqcsb_create_inplace(...);  // Ruby wrapper

// NEW: API calls + guard-based access
if (pqcsb_is_wiped(sk_buf))
    rb_raise(rb_eRuntimeError, "SecureBuffer has been wiped");
// ...
size_t total;
pqc_asn1_pkcs8_size_ex(..., ctx->guard.len, ...);  // From guard
// ...
ctx->result = pqcsb_rb_create_inplace(...);  // Renamed wrapper
```

**Location: `rb_der_build_pkcs8()` SecureBuffer input path**
- Line ~390: TypedData_Get_Struct → RTYPEDDATA_DATA + guard init
- Line ~316: sk_buf->len → guard.len
- Line ~324: pqcsb_create_inplace → pqcsb_rb_create_inplace
- Line ~402: pqcsb_wipe → pqcsb_rb_wipe

#### Callback Signature Changes
```c
// OLD: Void return
static void pkcs8_build_fill(uint8_t *data, size_t len, void *ctx_ptr) {
    pkcs8_build_ctx_t *ctx = (pkcs8_build_ctx_t *)ctx_ptr;
    ctx->rc = pqc_asn1_pkcs8_build_write_ex(...);
    // Error stored in context
}

// NEW: Status return
static pqcsb_status_t pkcs8_build_fill(uint8_t *data, size_t len, void *ctx_ptr) {
    pkcs8_build_ctx_t *ctx = (pkcs8_build_ctx_t *)ctx_ptr;
    ctx->rc = pqc_asn1_pkcs8_build_write_ex(...);
    return ctx->rc == PQC_ASN1_OK ? PQCSB_OK : PQCSB_ERR_ALLOC;
    // Error returned directly
}
```

**Location: `pkcs8_build_fill()` callback**
- Line ~268: Change return type from `void` to `pqcsb_status_t`
- Line ~279: Add return statement at end

#### Factory Call Changes
```c
// THREE locations in der.c need this pattern:

// OLD:
VALUE result = pqcsb_create_inplace(pqcsb_class(), total,
                                    pkcs8_build_fill, &build_ctx);
// NEW:
VALUE result = pqcsb_rb_create_inplace(pqcsb_class(), total,
                                       pkcs8_build_fill, &build_ctx);

// OLD:
ctx->rb_key = pqcsb_create(pqcsb_class(), sk_bytes, sk_len);
// NEW:
ctx->rb_key = pqcsb_rb_create(pqcsb_class(), sk_bytes, sk_len);

// OLD:
pqcsb_wipe(sb_ctx.result);
// NEW:
pqcsb_rb_wipe(sb_ctx.result);
```

**Locations:**
- Line ~324: `pqcsb_create_inplace` in `pkcs8_sb_build_body()`
- Line ~431: `pqcsb_create_inplace` in `rb_der_build_pkcs8()` String path
- Line ~530: `pqcsb_create` in `pkcs8_parse_use_cb()`
- Line ~585: `pqcsb_create` in `rb_der_parse_pkcs8()` String path
- Line ~402: `pqcsb_wipe` in `rb_der_build_pkcs8()` SecureBuffer path
- Line ~436: `pqcsb_wipe` in `rb_der_build_pkcs8()` String path

### pem.c

#### Context Structure Changes
```c
// OLD: Store buffer pointer
typedef struct {
    pqcsb_buf_t *sb;
    // ...
} pem_encode_sb_ctx_t;

// NEW: Store guard pointer
typedef struct {
    pqcsb_read_guard_t guard;  // Guard (not pointer) in struct
    // ...
} pem_encode_sb_ctx_t;
```

**Location: `pem_encode_sb_ctx_t` struct definition (~line 85)**

#### Guard-Based Access Changes
```c
// OLD: Use buffer directly
ctx->rc = pqc_asn1_pem_encode(
    ctx->sb->data, ctx->sb->len,
    ctx->label, ctx->label_len,
    &ctx->pem_buf, &ctx->pem_len);

// NEW: Use guard data/len
ctx->rc = pqc_asn1_pem_encode(
    ctx->guard.data, ctx->guard.len,
    ctx->label, ctx->label_len,
    &ctx->pem_buf, &ctx->pem_len);
```

**Location: `pem_encode_sb_body()` function (~line 94)**

#### Ensure Cleanup Changes
```c
// OLD:
pqcsb_end_read(ctx->sb);

// NEW:
pqcsb_end_read(&ctx->guard);
```

**Location: `pem_encode_sb_cleanup()` function (~line 110)**

#### SecureBuffer Input Path Changes
```c
// OLD:
pqcsb_buf_t *sb;
TypedData_Get_Struct(rb_der, pqcsb_buf_t, &pqcsb_buf_type, sb);
if (sb->wiped)
    rb_raise(rb_eRuntimeError, "SecureBuffer has been wiped");
pem_encode_sb_ctx_t ctx = {sb, label, label_len, NULL, 0, PQC_ASN1_OK};
pqcsb_begin_read(sb);
rb_ensure(pem_encode_sb_body, (VALUE)&ctx,
          pem_encode_sb_cleanup, (VALUE)&ctx);

// NEW:
pqcsb_buf_t *sb = (pqcsb_buf_t *)RTYPEDDATA_DATA(rb_der);
if (pqcsb_is_wiped(sb))
    rb_raise(rb_eRuntimeError, "SecureBuffer has been wiped");
pqcsb_read_guard_t guard = pqcsb_begin_read(sb);
if (guard.status != PQCSB_OK)
    rb_raise(rb_eRuntimeError, "pqcsb_begin_read failed");
pem_encode_sb_ctx_t ctx = {guard, label, label_len, NULL, 0, PQC_ASN1_OK};
rb_ensure(pem_encode_sb_body, (VALUE)&ctx,
          pem_encode_sb_cleanup, (VALUE)&ctx);
```

**Location: SecureBuffer input branch in encoding function (~line 263)**
- TypedData_Get_Struct → RTYPEDDATA_DATA
- Direct field check → API call
- Initialize guard before creating context
- Pass context to rb_ensure (not just buffer)

## Testing Checklist

After applying these changes:

- [ ] `rake compile` succeeds without errors
- [ ] `rake test` passes all 338 tests
- [ ] Guard lifetime issues caught by tests
- [ ] No memory leaks (guard cleanup verified)
- [ ] Exception safety verified (block exceptions don't leak protection)
- [ ] Nested #use calls work correctly
- [ ] Round-trip encode/decode works (SecureBuffer → DER → SecureBuffer)
- [ ] All SecureBuffer methods work (bytesize, ==, hash, wipe, slice, etc.)

## When to Update libpqcsb

```bash
# Check for new releases
curl -s https://api.github.com/repos/msuliq/libpqcsb/releases | jq '.[] | .tag_name'

# Update to new version (with published tarball)
rake vendor_pqcsb:update[0.1.X]

# Verify
rake test

# Lock checksums
rake vendor_pqcsb:lock
```

## Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `invalid application of 'sizeof' to an incomplete type` | Using `sizeof(*buf)` | Use `pqcsb_get_allocation_size(buf)` |
| `incomplete definition of type` | Accessing opaque struct fields | Use public API (pqcsb_len, pqcsb_is_wiped, etc.) |
| `function name 'pqcsb_slice' in conflict` | Ruby method name conflicts with libpqcsb | Rename to `ruby_pqcsb_slice` |
| Guard goes out of scope | Storing guard by value in context | Store `pqcsb_read_guard_t *guard` (pointer) |
| Missing re-protection on exception | Not calling pqcsb_end_read in ensure | Always use rb_ensure with cleanup function |
