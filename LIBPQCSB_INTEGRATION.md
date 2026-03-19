# libpqcsb Integration Guide

## Overview

This document describes the architecture and design decisions for integrating libpqcsb into the pqc_asn1 gem, replacing the previous 997-line inline implementation of secure buffers.

## Why libpqcsb?

- **Single Responsibility**: Dedicated library for secure memory buffers
- **Tested & Audited**: Standalone library with comprehensive test coverage
- **Reusable**: Can be used by other projects (Ruby, Python, Rust bindings)
- **Better Maintainability**: Bug fixes and improvements in one place

## Architecture Changes

### 1. TypedData Pattern

#### Old Approach (Pre-libpqcsb)
```c
// Concrete struct embedded in TypedData
typedef struct {
    uint8_t *data;
    size_t len;
    int wiped;
    // ... 20+ other fields
} pqcsb_buf_t;

VALUE obj = TypedData_Make_Struct(klass, pqcsb_buf_t, &type, buf);
// buf is directly accessible as a concrete struct
sizeof(*buf)  // ✓ Works
buf->data     // ✓ Works
```

#### New Approach (With libpqcsb)
```c
// Opaque struct (definition hidden in internal.h)
typedef struct pqcsb_buf pqcsb_buf_t;

VALUE obj = TypedData_Wrap_Struct(klass, &type, buf_ptr);
// buf_ptr is an opaque pointer
sizeof(*buf)  // ✗ Compile error - struct definition not visible
buf->data     // ✗ Compile error - struct is opaque
```

**Implications:**
- `TypedData_Get_Struct()` doesn't work (can't determine struct size)
- Use `RTYPEDDATA_DATA()` macro instead to extract raw pointer
- `dsize()` callback can't use `sizeof()`, must use `pqcsb_get_allocation_size()`
- All direct field access must be replaced with public API calls

**Affected Files:**
- `secure_buffer.c` (TypedData wrapper implementation)
- `der.c` (SecureBuffer input handling)
- `pem.c` (SecureBuffer encoding)

### 2. Guard Pattern (The Most Important Change)

#### Old Approach (Pre-libpqcsb)
```c
// Simple void functions that modify buffer in-place
void pqcsb_begin_read(pqcsb_buf_t *buf);
// Changes buf->mprotect to PROT_READ, increments read_refs

void pqcsb_end_read(pqcsb_buf_t *buf);
// Changes buf->mprotect back to PROT_NONE, decrements read_refs

// Usage:
pqcsb_begin_read(buf);
// ... use buf->data ...
pqcsb_end_read(buf);  // Easy to forget or misplace
```

**Problems with old approach:**
- No compile-time enforcement of pairing
- Easy to call `end_read` on wrong buffer
- Guard lifetime not explicit
- Exception paths could leak unprotected access

#### New Approach (With libpqcsb)
```c
// Guard returned by value
typedef struct {
    const uint8_t *data;
    size_t len;
    pqcsb_status_t status;
    pqcsb_buf_t *_priv;  // For internal tracking
} pqcsb_read_guard_t;

// Usage requires explicit guard handling:
pqcsb_read_guard_t guard = pqcsb_begin_read(buf);
if (guard.status != PQCSB_OK) {
    // Error handling
}

// Access data via guard, not buffer
const uint8_t *data = guard.data;
size_t len = guard.len;

// End read requires guard pointer (enforces pairing)
pqcsb_end_read(&guard);
```

**Benefits:**
- ✅ Compile-time enforcement of pairing (guard must be passed)
- ✅ Explicit lifetime (guard lives through its scope)
- ✅ Status checked upfront (no silent failures)
- ✅ Prevents buffer/guard mix-ups (different types)
- ✅ Works with `rb_ensure` for exception safety

**Critical Pattern in Ruby Methods:**
```c
// Store guard in context for ensure block
typedef struct {
    VALUE rb_bytes;
    pqcsb_buf_t *buf;
    pqcsb_read_guard_t *guard;  // Store pointer for cleanup
} pqcsb_use_ctx_t;

// Ensure function handles cleanup
static VALUE pqcsb_use_ensure(VALUE arg) {
    pqcsb_use_ctx_t *ctx = (pqcsb_use_ctx_t *)arg;
    // ... zero and freeze rb_bytes ...
    pqcsb_end_read(ctx->guard);  // Guaranteed to run
    return Qnil;
}

// Main function
pqcsb_read_guard_t guard = pqcsb_begin_read(buf);
pqcsb_use_ctx_t ctx = {..., .guard = &guard};
VALUE result = rb_ensure(rb_yield, rb_bytes, pqcsb_use_ensure, (VALUE)&ctx);
return result;
```

**Affected Files:**
- `secure_buffer.c` (`pqcsb_use` method - guard lifetime management)
- `secure_buffer.c` (`pqcsb_hash` method - temporary guard in calculations)
- `secure_buffer.c` (`ruby_pqcsb_slice` - guard with rb_ensure)
- `der.c` (SecureBuffer input path for `build_pkcs8`)
- `pem.c` (SecureBuffer input path for `to_pem`)

### 3. Opaque Struct - Field Access Changes

#### What Changed
```c
// OLD: Direct field access
if (buf->wiped) { ... }
size_t len = buf->len;
uint8_t *data = buf->data;
int locked = buf->locked;

// NEW: Public API calls
if (pqcsb_is_wiped(buf)) { ... }
size_t len = pqcsb_len(buf);
const uint8_t *data = guard.data;  // From guard
int locked = pqcsb_is_locked(buf);
```

#### Mapping of Replaced Field Access
| Old | New | Notes |
|-----|-----|-------|
| `buf->wiped` | `pqcsb_is_wiped(buf)` | Called on buf |
| `buf->len` | `pqcsb_len(buf)` | Called on buf |
| `buf->data` | `guard.data` | From guard, not buf |
| `buf->locked` | `pqcsb_is_locked(buf)` | Called on buf |
| `sizeof(*buf)` | `pqcsb_get_allocation_size(buf)` | For dsize() |

**Affected Files:**
- `der.c` (6+ locations)
- `pem.c` (2+ locations)
- `secure_buffer.c` (dsize callback)

### 4. Callback Signature Changes

#### Old Approach
```c
// Fill callbacks returned void
typedef void (*pqcsb_fill_fn)(uint8_t *data, size_t len, void *ctx);

static void pkcs8_build_fill(uint8_t *data, size_t len, void *ctx_ptr) {
    pkcs8_build_ctx_t *ctx = (pkcs8_build_ctx_t *)ctx_ptr;
    ctx->rc = pqc_asn1_pkcs8_build_write_ex(...);
    // Error stored in ctx->rc, not returned
}

// Called with Ruby wrapper
VALUE pqcsb_create_inplace(VALUE klass, size_t len,
                           void (*fill)(uint8_t*, size_t, void*),
                           void *ctx);
```

#### New Approach
```c
// Fill callbacks return status
typedef pqcsb_status_t (*pqcsb_fill_fn)(uint8_t *data, size_t len, void *ctx);

static pqcsb_status_t pkcs8_build_fill(uint8_t *data, size_t len, void *ctx_ptr) {
    pkcs8_build_ctx_t *ctx = (pkcs8_build_ctx_t *)ctx_ptr;
    ctx->rc = pqc_asn1_pkcs8_build_write_ex(...);
    return ctx->rc == PQC_ASN1_OK ? PQCSB_OK : PQCSB_ERR_ALLOC;
    // Error returned directly
}

// Called with libpqcsb wrapper
pqcsb_status_t pqcsb_create_inplace(size_t len,
                                     pqcsb_status_t (*fill)(uint8_t*, size_t, void*),
                                     void *ctx,
                                     pqcsb_buf_t **out);
```

**Key Difference:** Error handling is now in the return value, not context struct.

**Affected Files:**
- `der.c` (`pkcs8_build_fill` callback signature and caller)

### 5. Function Name Conflicts

#### Old Ruby Method Names
```c
static VALUE pqcsb_slice(VALUE self, VALUE offset, VALUE length)
static VALUE pqcsb_create(VALUE klass, const uint8_t *data, size_t len)
static VALUE pqcsb_wipe(VALUE obj)
```

#### New libpqcsb Public API
```c
// These names already exist in libpqcsb!
PQCSB_API pqcsb_status_t pqcsb_slice(pqcsb_buf_t *buf, size_t offset, size_t length, pqcsb_buf_t **out);
PQCSB_API pqcsb_status_t pqcsb_create(const uint8_t *data, size_t len, pqcsb_buf_t **out);
// etc.
```

#### Solution: Rename Ruby Implementation
```c
// Ruby wrapper functions (different signatures)
static VALUE ruby_pqcsb_slice(VALUE self, VALUE offset, VALUE length)
static VALUE pqcsb_rb_create(VALUE klass, const uint8_t *data, size_t len)
static void pqcsb_rb_wipe(VALUE obj)

// Register with clear names
rb_define_method(s_cSecureBuffer, "slice", ruby_pqcsb_slice, 2);
```

**Better Approach for Future:** Use consistent naming convention from the start
```c
// Pattern: pqcsb_rb_<name> for Ruby wrappers
static VALUE pqcsb_rb_create(...)
static VALUE pqcsb_rb_slice(...)
static void pqcsb_rb_wipe(...)

// libpqcsb functions use pqcsb_<name>
pqcsb_create(...)
pqcsb_slice(...)
```

## Implementation Checklist

### Phase 1: Planning & Documentation
- [x] Identify all files that touch secure buffers (secure_buffer.c, der.c, pem.c)
- [x] Document all API changes
- [x] Create migration guide (this file)
- [x] Map old → new patterns

### Phase 2: Core Integration
- [x] Vendor libpqcsb files (pqcsb.h, pqcsb.c, internal.h)
- [x] Create pqcsb_config.h stub
- [x] Update extconf.rb with pkg-config + vendored sources

### Phase 3: Secure Buffer Wrapper
- [x] Rewrite secure_buffer.h (slim header)
- [x] Rewrite secure_buffer.c (wrapper implementation)
  - [x] TypedData pattern (Wrap_Struct instead of Make_Struct)
  - [x] Guard-based API usage
  - [x] Callback implementations
  - [x] pqcsb_use with guard lifetime management

### Phase 4: DER & PEM Updates
- [x] Update der.c (SecureBuffer input path, struct field access)
- [x] Update pem.c (SecureBuffer encoding path)
- [x] Update callback signatures

### Phase 5: Build & Test
- [x] Update extconf.rb
- [x] Compile without errors
- [x] All tests pass

## Design Lessons

### ✅ What Worked Well
1. **Guard pattern is superior** - Enforces safety at compile time
2. **Opaque structs prevent misuse** - Can't accidentally depend on internals
3. **Public API is complete** - No need to access private struct fields
4. **Callback return values** - Cleaner error handling than context state

### 🔄 What Would Be Different Next Time
1. **Audit all API changes upfront** - Prevents last-minute surprises
2. **Identify all affected files early** - Avoid discovering pem.c needs updates during compilation
3. **Test incrementally** - Catch guard lifetime issues immediately
4. **Use consistent naming** - Prefix all Ruby wrappers with `pqcsb_rb_` from start
5. **Document thoroughly** - This guide for future maintainers

### 📚 Code Comments Strategy
- Guard pattern usage includes examples
- TypedData changes explained in secure_buffer.c
- Each changed callback documented
- Critical lifetime issues marked with comments

## Maintainability Notes

### When to Update libpqcsb
```bash
# Check for new version
rake vendor_pqcsb:update[VERSION]

# Test thoroughly
rake test

# Record checksums
rake vendor_pqcsb:lock
```

### Compatibility Guarantees
- libpqcsb API version checked at init time
- ABI version compatibility enforced
- Guard struct is versioned (incompatible changes unlikely)

### Future Extensions
If adding Ruby bindings for new libpqcsb features:
1. Study the guard pattern thoroughly
2. Use `pqcsb_rb_` prefix for Ruby wrappers
3. Document guard lifetime explicitly
4. Test guard cleanup with ensure blocks
5. Add inline comments explaining why pattern is needed

## References

- libpqcsb documentation: https://github.com/msuliq/libpqcsb
- libpqcsb API: `include/pqcsb.h` in vendored copy
- Original secure_buffer design: Git history before libpqcsb integration
