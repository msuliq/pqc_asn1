/*
 * secure_buffer.h — PqcAsn1::SecureBuffer TypedData declarations.
 *
 * Provides a secure memory container for cryptographic key material with:
 *   - mmap-backed allocation with guard pages
 *   - mlock to prevent swapping to disk
 *   - mprotect-based access control (PROT_NONE when idle)
 *   - Canary values for tamper detection
 *   - Secure zeroing on GC and explicit wipe
 */

#ifndef PQC_ASN1_SECURE_BUFFER_H
#define PQC_ASN1_SECURE_BUFFER_H

/* Enable memset_s() on Apple/BSD via C11 Annex K.
 * Must appear before any system header that may transitively include string.h.
 * Guard against redefinition: Ruby's config.h on Windows already defines this. */
#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include "shared.h"
#include <stdatomic.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

/* Canary size in bytes, placed before and after user data. */
#define PQCSB_CANARY_SIZE 8

typedef struct {
    uint8_t *data;        /* pointer to user data (inside mmap region or malloc'd) */
    size_t   len;         /* user-requested byte length */
    uint8_t *mmap_base;   /* base of entire mmap region (NULL if malloc fallback) */
    size_t   mmap_len;    /* total mmap size including guard pages */
    size_t   data_pages;  /* size of the data region (between guard pages) */
    int      wiped;       /* 1 if wipe! was called */
    int      locked;      /* 1 if mlock succeeded on the data pages */
    _Atomic int read_refs; /* reference count for nested begin_read/end_read */
    uint8_t  canary[PQCSB_CANARY_SIZE]; /* per-buffer random canary */
} pqcsb_buf_t;

/* rb_data_type_t for TypedData_Get_Struct in der.c and pem.c. */
extern const rb_data_type_t pqcsb_buf_type;

/* Securely zero len bytes at ptr using the best available primitive. */
void pqcsb_secure_zero(uint8_t *ptr, size_t len);

/*
 * Temporarily allow reading data pages (PROT_READ).
 * MUST be followed by pqcsb_end_read() before any Ruby allocation or call
 * that could raise an exception.  Only call between pure-C operations.
 */
void pqcsb_begin_read(pqcsb_buf_t *buf);

/* Re-protect data pages (PROT_NONE) after a pqcsb_begin_read() call. */
void pqcsb_end_read(pqcsb_buf_t *buf);

/* Create a frozen SecureBuffer containing a copy of data[0..len-1].
 * klass must be the PqcAsn1::SecureBuffer class VALUE. */
VALUE pqcsb_create(VALUE klass, const uint8_t *data, size_t len);

/* Allocate a SecureBuffer of `len` bytes and call `fill(data_ptr, len, ctx)`
 * to populate it in-place (with mmap region already PROT_READ|PROT_WRITE).
 * Returns a frozen SecureBuffer.  The fill function must not raise. */
VALUE pqcsb_create_inplace(VALUE klass, size_t len,
                           void (*fill)(uint8_t *data, size_t len, void *ctx),
                           void *ctx);

/* Programmatically wipe a SecureBuffer from C.  Equivalent to calling
 * wipe! from Ruby.  Safe to call multiple times (no-op if already wiped). */
void pqcsb_wipe(VALUE obj);

/* Return the PqcAsn1::SecureBuffer class VALUE.
 * Only valid after init_secure_buffer() has been called. */
VALUE pqcsb_class(void);

/* Register PqcAsn1::SecureBuffer under mPqcAsn1. */
void init_secure_buffer(VALUE mPqcAsn1);

#endif /* PQC_ASN1_SECURE_BUFFER_H */
