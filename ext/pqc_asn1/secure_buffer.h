/*
 * secure_buffer.h — PqcAsn1::SecureBuffer TypedData declarations.
 *
 * Thin wrapper around libpqcsb providing mmap/mprotect/mlock-backed
 * secure memory containers for cryptographic key material.
 *
 * Redirects struct allocation to Ruby's allocator for seamless GC integration.
 */

#ifndef PQC_ASN1_SECURE_BUFFER_H
#define PQC_ASN1_SECURE_BUFFER_H

/* Redirect libpqcsb struct allocation to Ruby's allocator. */
#define PQCSB_MALLOC ruby_xmalloc
#define PQCSB_FREE   ruby_xfree

#include "pqcsb.h"
#include "shared.h"

/* rb_data_type_t for TypedData_Wrap_Struct in der.c. */
extern const rb_data_type_t pqcsb_buf_type;

/*
 * Ruby-level factory helpers.
 * Named pqcsb_rb_* to avoid conflicts with libpqcsb's public API
 * (which uses the same base names with different signatures).
 */

/* Create a frozen SecureBuffer containing a copy of data[0..len-1]. */
VALUE pqcsb_rb_create(VALUE klass, const uint8_t *data, size_t len);

/* Allocate a SecureBuffer of `len` bytes and call `fill` to populate in-place.
 * The fill function is called with the mmap region unlocked (PROT_READ|PROT_WRITE).
 * The fill callback must return PQCSB_OK on success or an error code on failure. */
VALUE pqcsb_rb_create_inplace(VALUE klass, size_t len,
                               pqcsb_status_t (*fill)(uint8_t *data, size_t len, void *ctx),
                               void *ctx);

/* Securely wipe a SecureBuffer wrapped in a Ruby object. */
void pqcsb_rb_wipe(VALUE obj);

/* Return the PqcAsn1::SecureBuffer class VALUE.
 * Only valid after init_secure_buffer() has been called. */
VALUE pqcsb_class(void);

/* Register PqcAsn1::SecureBuffer under mPqcAsn1. */
void init_secure_buffer(VALUE mPqcAsn1);

#endif /* PQC_ASN1_SECURE_BUFFER_H */
