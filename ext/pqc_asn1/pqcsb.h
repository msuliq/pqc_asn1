/*
 * pqcsb.h — Secure memory buffer for cryptographic key material.
 *
 * Standalone C library — no external dependencies beyond the C standard library.
 *
 * Provides mmap/mprotect/mlock-backed memory containers with:
 *   - Guard pages (PROT_NONE) before and after data region
 *   - mlock to prevent swapping to disk
 *   - mprotect-based access control (PROT_NONE when idle)
 *   - Canary values for tamper/overflow detection
 *   - Secure zeroing via best available platform primitive
 *   - Constant-time equality comparison
 *   - Platform CSPRNG for random buffer generation
 *
 * Allocation strategy
 * ===================
 * The pqcsb_buf_t struct itself is allocated via PQCSB_MALLOC / PQCSB_FREE.
 * By default these resolve to malloc / free.  Language bindings can override
 * them before including this header:
 *
 *   #define PQCSB_MALLOC ruby_xmalloc
 *   #define PQCSB_FREE   ruby_xfree
 *   #include "pqcsb.h"
 *
 * The secure data region always uses mmap (Unix) or VirtualAlloc (Windows),
 * falling back to malloc only when neither is available.
 *
 * Thread safety
 * =============
 * pqcsb_begin_read / pqcsb_end_read use atomic reference counting, so
 * concurrent readers from multiple threads are safe.  All other operations
 * require external synchronisation if called concurrently on the same buffer.
 */

#ifndef PQCSB_H
#define PQCSB_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Visibility                                                          */
/* ------------------------------------------------------------------ */

#if defined(PQCSB_BUILDING_SHARED) && defined(__GNUC__)
#  define PQCSB_API __attribute__((visibility("default")))
#elif defined(PQCSB_BUILDING_SHARED) && defined(_MSC_VER)
#  define PQCSB_API __declspec(dllexport)
#elif defined(_MSC_VER) && !defined(PQCSB_STATIC)
#  define PQCSB_API __declspec(dllimport)
#else
#  define PQCSB_API
#endif

/* ------------------------------------------------------------------ */
/* Version                                                             */
/* ------------------------------------------------------------------ */

#define PQCSB_VERSION_MAJOR 0
#define PQCSB_VERSION_MINOR 1
#define PQCSB_VERSION_PATCH 0

#define PQCSB_VERSION_STRING "0.1.0"

/* ------------------------------------------------------------------ */
/* Status codes                                                        */
/* ------------------------------------------------------------------ */

typedef enum {
    PQCSB_OK              =  0,
    PQCSB_ERR_ALLOC       = -1,   /* mmap/VirtualAlloc/malloc failed */
    PQCSB_ERR_MLOCK       = -2,   /* mlock failed (non-fatal, buffer still usable) */
    PQCSB_ERR_MPROTECT    = -3,   /* mprotect/VirtualProtect failed */
    PQCSB_ERR_WIPED       = -4,   /* operation on already-wiped buffer */
    PQCSB_ERR_CANARY      = -5,   /* canary corruption detected */
    PQCSB_ERR_RANDOM      = -6,   /* CSPRNG failure */
    PQCSB_ERR_RANGE       = -7,   /* offset/length out of bounds */
    PQCSB_ERR_NULL_PARAM  = -8,   /* NULL pointer argument */
    PQCSB_ERR_BUSY        = -9,   /* operation not allowed (e.g., wipe while readers active) */
} pqcsb_status_t;

/* Runtime version query (returns PQCSB_VERSION_STRING). */
PQCSB_API const char *pqcsb_version(void);

/* ------------------------------------------------------------------ */
/* ABI Version — incremented on breaking changes                      */
/* ------------------------------------------------------------------ */

#define PQCSB_ABI_VERSION_MAJOR 1
#define PQCSB_ABI_VERSION_MINOR 0

/*
 * Check runtime ABI compatibility.
 * Returns PQCSB_OK if compatible (major matches AND minor >= expected).
 * Language bindings should call this at initialization.
 */
PQCSB_API pqcsb_status_t pqcsb_check_abi_version(int expected_major,
                                                   int expected_minor);

/* Human-readable error message for a status code. */
PQCSB_API const char *pqcsb_error_message(pqcsb_status_t code);

/* Error categorization (for bindings to decide error handling strategy). */
typedef struct {
    pqcsb_status_t code;
    int is_fatal;        /* 1 = buffer permanently unusable after this error */
    int is_recoverable;  /* 1 = operation may be retried */
} pqcsb_error_info_t;

/* Get detailed error information for a status code. */
PQCSB_API pqcsb_error_info_t pqcsb_get_error_info(pqcsb_status_t code);

/* ------------------------------------------------------------------ */
/* Configurable allocator                                              */
/* ------------------------------------------------------------------ */

/* Used only for the pqcsb_buf_t struct itself, NOT for the secure data
 * region (which always uses mmap/VirtualAlloc/malloc with canaries). */
#if !defined(PQCSB_MALLOC) || !defined(PQCSB_FREE)
#include <stdlib.h>
#endif

#ifndef PQCSB_MALLOC
#define PQCSB_MALLOC malloc
#endif
#ifndef PQCSB_FREE
#define PQCSB_FREE free
#endif

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

/* Canary size in bytes, placed before and after user data.
 * Override before including this header: #define PQCSB_CANARY_SIZE 32
 * Larger canaries reduce collision probability; 16 bytes provides strong protection.
 */
#ifndef PQCSB_CANARY_SIZE
#define PQCSB_CANARY_SIZE 16
#endif

/* ------------------------------------------------------------------ */
/* Runtime configuration                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    int    use_mlock;              /* 1 = try mlock (default), 0 = skip */
    int    check_canaries_on_read; /* 1 = verify canaries in begin_read (default 0) */
    size_t mlock_budget_override;  /* 0 = use RLIMIT_MEMLOCK, >0 = custom byte limit */
} pqcsb_config_t;

#define PQCSB_CONFIG_DEFAULT { 1, 0, 0 }

/* ------------------------------------------------------------------ */
/* Opaque handle                                                       */
/* ------------------------------------------------------------------ */

/*
 * Language bindings never see the struct internals.
 * Ruby/Python/Rust receive a pqcsb_buf_t* as an opaque pointer.
 */
typedef struct pqcsb_buf pqcsb_buf_t;

/* ------------------------------------------------------------------ */
/* Guard types for read/write access                                  */
/* ------------------------------------------------------------------ */

/*
 * Guard structures returned by pqcsb_begin_read/begin_write.
 * These enforce proper pairing with end_read/end_write and prevent
 * common mistakes like double-close or mixing buffers.
 *
 * The _priv field is for internal use only. Do not read or write it.
 */

typedef struct {
    const uint8_t *data;   /* NULL on failure */
    size_t         len;    /* 0 on failure; actual user data length on success */
    pqcsb_status_t status; /* PQCSB_OK on success, error code on failure */
    pqcsb_buf_t   *_priv;  /* internal only — do not access */
} pqcsb_read_guard_t;

typedef struct {
    uint8_t       *data;   /* NULL on failure */
    size_t         len;    /* 0 on failure; actual user data length on success */
    pqcsb_status_t status; /* PQCSB_OK on success, error code on failure */
    pqcsb_buf_t   *_priv;  /* internal only — do not access */
} pqcsb_write_guard_t;

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

/*
 * Allocate a buffer of `len` bytes, copy `data` into it, apply protections.
 * On success: *out != NULL, returns PQCSB_OK.
 * On failure: *out == NULL, returns error code.
 * `len` must be > 0 and `data` must not be NULL.
 */
PQCSB_API pqcsb_status_t pqcsb_create(const uint8_t *data, size_t len,
                                       pqcsb_buf_t **out);

/*
 * Allocate `len` bytes and call fill() to populate in-place, then protect.
 * fill() is called with the region in PROT_READ|PROT_WRITE state.
 * fill() must return PQCSB_OK to proceed, or error to abort allocation.
 */
PQCSB_API pqcsb_status_t pqcsb_create_inplace(
    size_t len,
    pqcsb_status_t (*fill)(uint8_t *data, size_t len, void *ctx),
    void *ctx,
    pqcsb_buf_t **out);

/*
 * Allocate a buffer with custom configuration options.
 * config may be NULL to use defaults (equivalent to PQCSB_CONFIG_DEFAULT).
 */
PQCSB_API pqcsb_status_t pqcsb_create_ex(
    const uint8_t *data, size_t len,
    const pqcsb_config_t *config,
    pqcsb_buf_t **out);

/*
 * Allocate and fill from platform CSPRNG.
 * Returns PQCSB_ERR_RANDOM if the CSPRNG fails.
 */
PQCSB_API pqcsb_status_t pqcsb_create_random(size_t len, pqcsb_buf_t **out);

/*
 * Securely zero and deallocate.  Safe to call on NULL.
 * After this call, *buf is set to NULL.
 */
PQCSB_API void pqcsb_destroy(pqcsb_buf_t **buf);

/* ------------------------------------------------------------------ */
/* Access control                                                      */
/* ------------------------------------------------------------------ */

/*
 * Begin a read-only access session.
 * Returns a read guard structure with data pointer and status.
 * MUST be paired with pqcsb_end_read(guard).  Thread-safe (atomic refcount).
 * The guard's status field indicates success or failure.
 */
PQCSB_API pqcsb_read_guard_t pqcsb_begin_read(pqcsb_buf_t *buf);

/*
 * End a read-only access session.
 * Takes the guard pointer (not the buffer) to enforce proper pairing.
 * Safe to call multiple times on the same guard (idempotent).
 */
PQCSB_API void pqcsb_end_read(pqcsb_read_guard_t *guard);

/*
 * Begin a read-write access session.
 * Returns a write guard structure with data pointer and status.
 * MUST be paired with pqcsb_end_write(guard).
 * The guard's status field indicates success or failure.
 */
PQCSB_API pqcsb_write_guard_t pqcsb_begin_write(pqcsb_buf_t *buf);

/*
 * End a read-write access session.
 * Takes the guard pointer (not the buffer) to enforce proper pairing.
 * Rewrites canaries before re-protecting.
 */
PQCSB_API void pqcsb_end_write(pqcsb_write_guard_t *guard);

/* ------------------------------------------------------------------ */
/* Queries                                                             */
/* ------------------------------------------------------------------ */

/* Returns the user data length in bytes (0 if buf is NULL). */
PQCSB_API size_t pqcsb_len(const pqcsb_buf_t *buf);

/* Returns 1 if wipe() has been called, 0 otherwise. */
PQCSB_API int pqcsb_is_wiped(const pqcsb_buf_t *buf);

/* Returns 1 if mlock succeeded on the data region, 0 otherwise. */
PQCSB_API int pqcsb_is_locked(const pqcsb_buf_t *buf);

/* Returns 1 if buffer is currently held open by begin_read (read_refs > 0), 0 otherwise. */
PQCSB_API int pqcsb_is_readable(const pqcsb_buf_t *buf);

/* Returns the current read reference count (number of active begin_read holders). */
PQCSB_API int pqcsb_get_read_refcount(const pqcsb_buf_t *buf);

/* Returns total mmap'd/allocated bytes including guard pages and canaries (0 if malloc fallback). */
PQCSB_API size_t pqcsb_get_allocation_size(const pqcsb_buf_t *buf);

/* ------------------------------------------------------------------ */
/* Operations                                                          */
/* ------------------------------------------------------------------ */

/*
 * Securely zero contents + canaries, munlock.  Buffer remains allocated
 * but all operations except destroy/is_wiped return PQCSB_ERR_WIPED.
 * Safe to call multiple times (no-op after first).
 */
PQCSB_API pqcsb_status_t pqcsb_wipe(pqcsb_buf_t *buf);

/*
 * Check canary integrity.
 * Returns PQCSB_OK if intact, PQCSB_ERR_CANARY if corrupted,
 * or PQCSB_ERR_WIPED if the buffer has been wiped.
 */
PQCSB_API pqcsb_status_t pqcsb_check_canary(pqcsb_buf_t *buf);

/*
 * Deep copy the entire buffer into a new independent buffer.
 * The source buffer is temporarily unlocked for the copy.
 */
PQCSB_API pqcsb_status_t pqcsb_clone(pqcsb_buf_t *src, pqcsb_buf_t **out);

/*
 * Copy a sub-range [offset, offset+length) into a new buffer.
 * The source buffer is temporarily unlocked for the copy.
 */
PQCSB_API pqcsb_status_t pqcsb_slice(pqcsb_buf_t *buf,
                                      size_t offset, size_t length,
                                      pqcsb_buf_t **out);

/*
 * Constant-time equality: SecureBuffer vs raw bytes.
 * Temporarily unlocks buf for comparison.
 * Returns 1 if equal, 0 if not or on error.
 */
PQCSB_API int pqcsb_ct_equal(pqcsb_buf_t *a,
                              const uint8_t *b, size_t b_len);

/*
 * Constant-time equality: two SecureBuffers.
 * Temporarily unlocks both for comparison.
 * Returns 1 if equal, 0 if not or on error.
 */
PQCSB_API int pqcsb_ct_equal_bufs(pqcsb_buf_t *a, pqcsb_buf_t *b);

/* ------------------------------------------------------------------ */
/* Utilities                                                           */
/* ------------------------------------------------------------------ */

/* Secure zero `len` bytes at `ptr` using best available primitive.
 * Safe to call with NULL ptr or zero len (no-op). */
PQCSB_API void pqcsb_secure_zero(void *ptr, size_t len);

/* Fill `dst` with `len` bytes from the platform CSPRNG.
 * Returns PQCSB_OK on success, PQCSB_ERR_RANDOM on failure. */
PQCSB_API pqcsb_status_t pqcsb_fill_random(uint8_t *dst, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PQCSB_H */
