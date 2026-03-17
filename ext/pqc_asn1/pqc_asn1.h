/*
 * pqc_asn1.h — DER/PEM/Base64 utilities for post-quantum key serialization.
 *
 *
 * Standalone C library — no external dependencies beyond the C standard library.
 *
 * This module is intentionally algorithm-agnostic: the same DER/PEM
 * primitives apply to ML-DSA, ML-KEM, SLH-DSA, and any future PQC
 * scheme that uses standard SPKI / PKCS#8 / PEM wrapping.
 *
 * Allocation strategy
 * ===================
 * Functions that allocate memory use PQC_ASN1_MALLOC / PQC_ASN1_FREE /
 * PQC_ASN1_REALLOC macros.  By default these resolve to malloc / free /
 * realloc.  Language bindings can override them before including this
 * header:
 *
 *   #define PQC_ASN1_MALLOC  ruby_xmalloc
 *   #define PQC_ASN1_FREE    ruby_xfree
 *   #define PQC_ASN1_REALLOC ruby_xrealloc
 *   #include "pqc_asn1.h"
 */

#ifndef PQC_ASN1_H
#define PQC_ASN1_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Version                                                             */
/* ------------------------------------------------------------------ */

#define PQC_ASN1_VERSION_MAJOR 0
#define PQC_ASN1_VERSION_MINOR 1
#define PQC_ASN1_VERSION_PATCH 3

#define PQC_ASN1_VERSION_STRING "0.1.3"

/* Runtime version query (returns PQC_ASN1_VERSION_STRING). */
const char *pqc_asn1_version(void);

/* ------------------------------------------------------------------ */
/* Configurable allocator                                              */
/* ------------------------------------------------------------------ */

/* The allocator macros allow language bindings to route allocations
 * through their runtime's memory manager (e.g. ruby_xmalloc/ruby_xfree).
 * When all three are user-defined, <stdlib.h> is not included — keeping
 * the header dependency-free for embedded consumers. */
#if !defined(PQC_ASN1_MALLOC) || !defined(PQC_ASN1_FREE) || !defined(PQC_ASN1_REALLOC)
#include <stdlib.h>
#endif

#ifndef PQC_ASN1_MALLOC
#define PQC_ASN1_MALLOC malloc
#endif

#ifndef PQC_ASN1_FREE
#define PQC_ASN1_FREE free
#endif

/* Optional realloc override for the buffer-trim path in base64_decode.
 * Defaults to realloc.  Consumers who override MALLOC/FREE with a
 * custom allocator should also override this if their allocator does
 * not provide a realloc-compatible function. */
#ifndef PQC_ASN1_REALLOC
#define PQC_ASN1_REALLOC realloc
#endif

/* ------------------------------------------------------------------ */
/* Limits                                                              */
/* ------------------------------------------------------------------ */

/* Maximum PEM label length (e.g. "PUBLIC KEY", "PRIVATE KEY"). */
#define PQC_ASN1_MAX_PEM_LABEL_LEN 64

/* ------------------------------------------------------------------ */
/* Error / status codes                                                */
/* ------------------------------------------------------------------ */

/* Every public function returns a status code.  PQC_ASN1_OK (0) means
 * success; all errors are negative, making "if (rc) handle_error()"
 * safe.  Error codes are specific enough for callers to distinguish
 * structural DER issues, PEM format problems, and resource failures. */
typedef enum {
    PQC_ASN1_OK                   =   0,
    PQC_ASN1_ERR_OUTER_SEQUENCE   =  -1,   /* bad outer SEQUENCE */
    PQC_ASN1_ERR_VERSION          =  -2,   /* bad version INTEGER (PKCS#8) */
    PQC_ASN1_ERR_ALGORITHM        =  -3,   /* bad AlgorithmIdentifier */
    PQC_ASN1_ERR_KEY              =  -4,   /* bad key element */
    PQC_ASN1_ERR_UNUSED_BITS      =  -5,   /* bad unused-bits in BIT STRING */
    PQC_ASN1_ERR_TRAILING_DATA    =  -6,   /* unexpected data after outer SEQUENCE */
    PQC_ASN1_ERR_PEM_NO_MARKERS   =  -7,   /* no PEM BEGIN marker found */
    PQC_ASN1_ERR_PEM_LABEL        =  -8,   /* PEM label mismatch */
    PQC_ASN1_ERR_BASE64           =  -9,   /* invalid base64 data */
    PQC_ASN1_ERR_INVALID_OID      = -10,   /* oid_der is not a valid OID TLV */
    PQC_ASN1_ERR_EXTRA_FIELDS     = -11,   /* unexpected extra fields inside structure */
    PQC_ASN1_ERR_OVERFLOW         = -12,   /* size overflow in computation */
    PQC_ASN1_ERR_ALLOC            = -13,   /* memory allocation failed */
    PQC_ASN1_ERR_BUFFER_TOO_SMALL = -14,   /* caller-provided buffer is too small */
    PQC_ASN1_ERR_LABEL_TOO_LONG   = -15,   /* PEM label exceeds MAX_PEM_LABEL_LEN */
    PQC_ASN1_ERR_DER_PARSE        = -16,   /* generic DER parse error */
    PQC_ASN1_ERR_NULL_PARAM       = -17,   /* required pointer parameter is NULL */
    PQC_ASN1_ERR_PEM_MALFORMED    = -18    /* PEM boundary line has trailing junk */
} pqc_asn1_status_t;

/* ------------------------------------------------------------------ */
/* Secure zeroing                                                      */
/* ------------------------------------------------------------------ */

/* Securely zero a buffer, preventing the compiler from optimizing
 * away the write.  Uses platform-specific primitives where available
 * (memset_s on Apple/BSD, explicit_bzero on glibc), with a volatile-
 * pointer fallback elsewhere.
 *
 * ptr may be NULL, in which case the call is a no-op regardless of len. */
void pqc_asn1_secure_zero(void *ptr, size_t len);

/* ------------------------------------------------------------------ */
/* DER helpers                                                         */
/* ------------------------------------------------------------------ */

/* Low-level DER primitives.  These operate on raw byte buffers and
 * follow a "local cursor" pattern: read functions take a *pos that is
 * only advanced on success, so partial parse failures never leave the
 * caller's position in an inconsistent state.
 *
 * Every function comes in two flavors:
 *   _write / _into : write into a caller-provided buffer (zero-copy)
 *   (no suffix)    : allocate and return a new buffer (caller frees)
 * This dual API lets callers choose between control and convenience. */

/* Compute the number of bytes needed for a DER length field.
 * On success, writes to *out and returns PQC_ASN1_OK.
 * Returns PQC_ASN1_ERR_OVERFLOW if len exceeds the maximum encodable
 * DER length, or PQC_ASN1_ERR_NULL_PARAM if out is NULL. */
pqc_asn1_status_t pqc_asn1_der_length_size(size_t len, size_t *out);

/* Write a complete TLV (tag + length + content) into a caller-provided buffer.
 * buf_len must be >= 1 (tag) + DER length field size + content_len.
 * On success, *out_written is set to the total bytes written.
 * Returns PQC_ASN1_OK, PQC_ASN1_ERR_OVERFLOW, PQC_ASN1_ERR_BUFFER_TOO_SMALL,
 * or PQC_ASN1_ERR_NULL_PARAM. */
pqc_asn1_status_t pqc_asn1_der_write_tlv_write(
    uint8_t tag, const uint8_t *content, size_t content_len,
    uint8_t *buf, size_t buf_len, size_t *out_written);

/* Write a complete TLV (tag + length + content).
 * On success, *out_buf receives a newly allocated buffer (caller must
 * free with PQC_ASN1_FREE) and *out_total is set to the total length.
 * On failure, *out_buf is set to NULL and *out_total to 0.
 * Returns PQC_ASN1_OK, PQC_ASN1_ERR_OVERFLOW, PQC_ASN1_ERR_ALLOC,
 * or PQC_ASN1_ERR_NULL_PARAM. */
pqc_asn1_status_t pqc_asn1_der_write_tlv(
    uint8_t tag, const uint8_t *content, size_t content_len,
    uint8_t **out_buf, size_t *out_total);

/* Read a DER length field.  Returns PQC_ASN1_OK on success.
 * Advances *pos past the length bytes and writes to *out_len. */
pqc_asn1_status_t pqc_asn1_der_read_length(
    const uint8_t *buf, size_t buf_len,
    size_t *pos, size_t *out_len);

/* Read a TLV: verify expected tag, parse length, return pointer
 * to content and content length.  Advances *pos past the entire TLV.
 * Returns PQC_ASN1_OK on success, PQC_ASN1_ERR_DER_PARSE on error. */
pqc_asn1_status_t pqc_asn1_der_read_tlv(
    const uint8_t *buf, size_t buf_len, size_t *pos,
    uint8_t expected_tag,
    const uint8_t **content, size_t *content_len);

/* ------------------------------------------------------------------ */
/* DER structure builders                                              */
/* ------------------------------------------------------------------ */

/* High-level functions to build SPKI (public key) and PKCS#8 (private
 * key) DER structures.  Internally these use "layout structs" that
 * pre-compute every DER field size, then serialize in a single pass.
 * This design ensures the _size function and the _write function always
 * agree on buffer requirements.
 *
 * PKCS#8 _write variants securely zero the buffer on error because
 * partial output may contain secret key material. */

/* Compute SPKI DER total size.
 * Returns PQC_ASN1_OK on success, PQC_ASN1_ERR_INVALID_OID or
 * PQC_ASN1_ERR_OVERFLOW on failure. */
pqc_asn1_status_t pqc_asn1_spki_size(const uint8_t *oid_der, size_t oid_der_len,
                                       size_t pk_len, size_t *out_size);

/* Compute SPKI DER total size with optional AlgorithmIdentifier parameters.
 * params/params_len: raw DER bytes appended after the OID inside AlgorithmIdentifier
 *   (pass NULL/0 for OID-only AlgorithmIdentifier, equivalent to pqc_asn1_spki_size).
 * Returns PQC_ASN1_OK on success, or a negative error code. */
pqc_asn1_status_t pqc_asn1_spki_size_ex(
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *params, size_t params_len,
    size_t pk_len, size_t *out_size);

/* Write SPKI DER into a caller-provided buffer.
 * buf_len must be >= pqc_asn1_spki_size().
 * On success, *out_written is set to the total bytes written.
 * Returns PQC_ASN1_OK on success, or a negative error code. */
pqc_asn1_status_t pqc_asn1_spki_build_write(
    uint8_t *buf, size_t buf_len,
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *pk_bytes, size_t pk_len,
    size_t *out_written);

/* Write SPKI DER with optional AlgorithmIdentifier parameters.
 * params/params_len: raw DER bytes appended after the OID (NULL/0 if absent).
 * buf_len must be >= pqc_asn1_spki_size_ex().
 * On success, *out_written is set to the total bytes written.
 * Returns PQC_ASN1_OK on success, or a negative error code. */
pqc_asn1_status_t pqc_asn1_spki_build_write_ex(
    uint8_t *buf, size_t buf_len,
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *params, size_t params_len,
    const uint8_t *pk_bytes, size_t pk_len,
    size_t *out_written);

/* Build SubjectPublicKeyInfo DER (allocating).
 * On success, *out_buf receives a newly allocated buffer (caller must
 * free with PQC_ASN1_FREE) and *out_total is set.
 * On failure, *out_buf is set to NULL and *out_total to 0.
 * Returns PQC_ASN1_OK, PQC_ASN1_ERR_INVALID_OID, PQC_ASN1_ERR_OVERFLOW,
 * PQC_ASN1_ERR_ALLOC, or PQC_ASN1_ERR_NULL_PARAM.
 *   SEQUENCE {
 *     SEQUENCE { OID }
 *     BIT STRING { 0x00, key_bytes }
 *   }
 */
pqc_asn1_status_t pqc_asn1_spki_build(
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *pk_bytes, size_t pk_len,
    uint8_t **out_buf, size_t *out_total);

/* Compute PKCS#8 DER total size.
 * Returns PQC_ASN1_OK on success, PQC_ASN1_ERR_INVALID_OID or
 * PQC_ASN1_ERR_OVERFLOW on failure. */
pqc_asn1_status_t pqc_asn1_pkcs8_size(const uint8_t *oid_der, size_t oid_der_len,
                                        size_t sk_len, size_t *out_size);

/* Compute PKCS#8 DER total size with optional parameters and publicKey field.
 * params/params_len: AlgorithmIdentifier parameter bytes (NULL/0 if absent).
 * pub_len: size of optional OneAsymmetricKey publicKey [1] field (0 if absent).
 * Returns PQC_ASN1_OK on success, or a negative error code. */
pqc_asn1_status_t pqc_asn1_pkcs8_size_ex(
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *params, size_t params_len,
    size_t sk_len, size_t pub_len, size_t *out_size);

/* Write PKCS#8 DER into a caller-provided buffer.
 * buf_len must be >= pqc_asn1_pkcs8_size().
 * On success, *out_written is set to the total bytes written.
 * Returns PQC_ASN1_OK on success, or a negative error code. */
pqc_asn1_status_t pqc_asn1_pkcs8_build_write(
    uint8_t *buf, size_t buf_len,
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *sk_bytes, size_t sk_len,
    size_t *out_written);

/* Write PKCS#8 DER with optional AlgorithmIdentifier parameters and
 * OneAsymmetricKey publicKey [1] IMPLICIT field.
 * params/params_len: AlgorithmIdentifier parameter bytes (NULL/0 if absent).
 * pub_bytes/pub_len: publicKey [1] IMPLICIT content bytes (NULL/0 if absent).
 * buf_len must be >= pqc_asn1_pkcs8_size_ex().
 * Error paths securely zero the buffer (may contain partial secret key material).
 * Returns PQC_ASN1_OK on success, or a negative error code. */
pqc_asn1_status_t pqc_asn1_pkcs8_build_write_ex(
    uint8_t *buf, size_t buf_len,
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *params, size_t params_len,
    const uint8_t *sk_bytes, size_t sk_len,
    const uint8_t *pub_bytes, size_t pub_len,
    size_t *out_written);

/* Build PKCS#8 OneAsymmetricKey DER (allocating).
 * On success, *out_buf receives a newly allocated buffer (caller must
 * secure-zero and free with PQC_ASN1_FREE) and *out_total is set.
 * On failure, *out_buf is set to NULL and *out_total to 0.
 * Returns PQC_ASN1_OK, PQC_ASN1_ERR_INVALID_OID, PQC_ASN1_ERR_OVERFLOW,
 * PQC_ASN1_ERR_ALLOC, or PQC_ASN1_ERR_NULL_PARAM.
 *   SEQUENCE {
 *     INTEGER 0
 *     SEQUENCE { OID }
 *     OCTET STRING { key_bytes }
 *   }
 */
pqc_asn1_status_t pqc_asn1_pkcs8_build(
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *sk_bytes, size_t sk_len,
    uint8_t **out_buf, size_t *out_total);

/* ------------------------------------------------------------------ */
/* Parse flags                                                         */
/* ------------------------------------------------------------------ */

/* Flags controlling the strictness of pqc_asn1_spki_parse and
 * pqc_asn1_pkcs8_parse.  Pass 0 for default (permissive) behaviour.
 * Combine with bitwise OR for multiple constraints. */

/* Reject any trailing bytes inside the AlgorithmIdentifier SEQUENCE
 * (i.e. reject algorithm parameters).  RFC 9629 mandates absent params
 * for ML-DSA, ML-KEM, and SLH-DSA; use this flag to enforce that rule.
 * Without this flag the parser accepts and optionally captures params. */
#define PQC_PARSE_STRICT_ALG_ID  0x01u

/* ------------------------------------------------------------------ */
/* DER structure parsers                                               */
/* ------------------------------------------------------------------ */

/* Parse SPKI / PKCS#8 DER structures.  Output pointers reference into
 * the input buffer (zero-copy, no allocation).  Parsers enforce:
 *   - No trailing data after the outer SEQUENCE
 *   - No extra fields inside the outer SEQUENCE
 *   - BIT STRING unused-bits byte must be 0x00
 *   - PKCS#8 version must be INTEGER 0
 *
 * flags: bitwise OR of PQC_PARSE_* constants, or 0 for defaults.
 *   PQC_PARSE_STRICT_ALG_ID — reject AlgorithmIdentifier parameters.
 *   Without this flag, parameters are accepted and optionally captured.
 *
 * alg_params/alg_params_len: AlgorithmIdentifier params bytes (0 len if
 *   absent).  Pass NULL/NULL to discard.  Ignored when STRICT_ALG_ID set.
 *
 * PKCS#8: the optional OneAsymmetricKey publicKey [1] field is returned
 * via pub_key/pub_key_len when present; pass NULL/NULL to ignore it. */

/* Parse SubjectPublicKeyInfo DER.
 * Returns PQC_ASN1_OK on success, or a negative PQC_ASN1_ERR_* code.
 * Output pointers reference into the input buffer (no allocation).
 * oid_der/oid_der_len: the OID TLV from within AlgorithmIdentifier.
 * alg_params/alg_params_len: AlgorithmIdentifier params bytes (0 len if absent).
 *   Pass NULL/NULL to discard.  Not written when PQC_PARSE_STRICT_ALG_ID set.
 * pk_bytes/pk_len: public key bytes (after BIT STRING unused-bits byte).
 * flags: 0 or bitwise OR of PQC_PARSE_* constants. */
pqc_asn1_status_t pqc_asn1_spki_parse(
    const uint8_t *der, size_t der_len,
    const uint8_t **oid_der, size_t *oid_der_len,
    const uint8_t **alg_params, size_t *alg_params_len,
    const uint8_t **pk_bytes, size_t *pk_len,
    uint32_t flags);

/* Parse PKCS#8 OneAsymmetricKey DER.
 * Returns PQC_ASN1_OK on success, or a negative PQC_ASN1_ERR_* code.
 * Output pointers reference into the input buffer (no allocation).
 * oid_der/oid_der_len: the OID TLV from within AlgorithmIdentifier.
 * alg_params/alg_params_len: AlgorithmIdentifier params bytes (0 len if absent).
 *   Pass NULL/NULL to discard.  Not written when PQC_PARSE_STRICT_ALG_ID set.
 * sk_bytes/sk_len: secret key bytes (OCTET STRING content).
 * pub_key/pub_key_len: optional publicKey [1] BIT STRING bytes (0 len if absent).
 *   Pass NULL/NULL to discard.
 * flags: 0 or bitwise OR of PQC_PARSE_* constants. */
pqc_asn1_status_t pqc_asn1_pkcs8_parse(
    const uint8_t *der, size_t der_len,
    const uint8_t **oid_der, size_t *oid_der_len,
    const uint8_t **alg_params, size_t *alg_params_len,
    const uint8_t **sk_bytes, size_t *sk_len,
    const uint8_t **pub_key, size_t *pub_key_len,
    uint32_t flags);

/* ------------------------------------------------------------------ */
/* Base64 codec                                                        */
/* ------------------------------------------------------------------ */

/* Standard RFC 4648 base64 encoding/decoding.  Two variants:
 *   - "raw" functions: no line wrapping (for transport, URLs, etc.)
 *   - non-"raw" functions: 64-char line wrapping (for PEM bodies)
 *
 * Decoding is strict per RFC 4648 section 3.5:
 *   - Only standard alphabet (no URL-safe variant)
 *   - Whitespace (\\n, \\r, space, tab) is silently skipped
 *   - Non-zero bits in padding positions are rejected
 *   - Data after padding characters is rejected
 *   - Partial output is securely zeroed on error (key material safety) */

/* Compute the output size for raw base64 encoding (no line wrapping).
 * Returns PQC_ASN1_OK on success, PQC_ASN1_ERR_OVERFLOW on overflow. */
pqc_asn1_status_t pqc_asn1_base64_encode_size_raw(size_t data_len, size_t *out_size);

/* Encode binary data to raw base64 (no line wrapping).
 * Writes into caller-provided buffer of at least
 * pqc_asn1_base64_encode_size_raw() bytes.
 * Returns PQC_ASN1_OK on success, sets *out_written to bytes written. */
pqc_asn1_status_t pqc_asn1_base64_encode_raw(
    const uint8_t *data, size_t data_len,
    char *out, size_t out_len, size_t *out_written);

/* Encode binary data to raw base64 (allocating, no line wrapping).
 * On success, *out_buf receives a NUL-terminated buffer (caller must
 * free with PQC_ASN1_FREE) and *out_len is the length excluding NUL.
 * On failure, *out_buf is set to NULL and *out_len to 0.
 * Returns PQC_ASN1_OK, PQC_ASN1_ERR_OVERFLOW, PQC_ASN1_ERR_ALLOC,
 * or PQC_ASN1_ERR_NULL_PARAM. */
pqc_asn1_status_t pqc_asn1_base64_encode_raw_alloc(
    const uint8_t *data, size_t data_len,
    char **out_buf, size_t *out_len);

/* Compute the output size for base64 encoding with PEM-style line wrapping.
 * Returns PQC_ASN1_OK on success, PQC_ASN1_ERR_OVERFLOW on overflow. */
pqc_asn1_status_t pqc_asn1_base64_encode_size(size_t data_len, size_t *out_size);

/* Encode binary data to base64 with PEM-style 64-char line wrapping.
 * Writes into caller-provided buffer of at least
 * pqc_asn1_base64_encode_size() bytes.
 * Returns PQC_ASN1_OK on success, sets *out_written to bytes written. */
pqc_asn1_status_t pqc_asn1_base64_encode_write(
    const uint8_t *data, size_t data_len,
    char *out, size_t out_len, size_t *out_written);

/* Encode binary data to base64 with PEM-style 64-char line wrapping (allocating).
 * On success, *out_buf receives a NUL-terminated buffer (caller must
 * free with PQC_ASN1_FREE) and *out_len is the length excluding NUL.
 * On failure, *out_buf is set to NULL and *out_len to 0.
 * Returns PQC_ASN1_OK, PQC_ASN1_ERR_OVERFLOW, PQC_ASN1_ERR_ALLOC,
 * or PQC_ASN1_ERR_NULL_PARAM. */
pqc_asn1_status_t pqc_asn1_base64_encode(
    const uint8_t *data, size_t data_len,
    char **out_buf, size_t *out_len);

/* Compute the maximum output size for base64 decoding.
 * Returns PQC_ASN1_OK on success, PQC_ASN1_ERR_OVERFLOW on overflow. */
pqc_asn1_status_t pqc_asn1_base64_decode_maxsize(size_t b64_len, size_t *out_size);

/* Decode base64 to binary into caller-provided buffer, skipping whitespace.
 * out_max is the size of the output buffer (must be >= decode_maxsize).
 * Returns PQC_ASN1_OK on success, sets *out_written to decoded length. */
pqc_asn1_status_t pqc_asn1_base64_decode_into(
    const char *b64, size_t b64_len,
    uint8_t *out, size_t out_max, size_t *out_written);

/* Decode base64 to binary (allocating), skipping whitespace.
 * On success, *out_buf receives a newly allocated buffer (caller must
 * free with PQC_ASN1_FREE) and *out_len is set.
 * On failure, *out_buf is set to NULL and *out_len to 0.
 * Returns PQC_ASN1_OK, PQC_ASN1_ERR_BASE64, PQC_ASN1_ERR_ALLOC,
 * or PQC_ASN1_ERR_NULL_PARAM. */
pqc_asn1_status_t pqc_asn1_base64_decode(
    const char *b64, size_t b64_len,
    uint8_t **out_buf, size_t *out_len);

/* ------------------------------------------------------------------ */
/* PEM codec                                                           */
/* ------------------------------------------------------------------ */

/* RFC 7468 PEM encoding/decoding.  Boundary lines must appear at line
 * start.  Only whitespace is tolerated after closing dashes on both
 * BEGIN and END lines.  Labels are validated: non-empty, printable
 * ASCII (0x20-0x7E), at most PQC_ASN1_MAX_PEM_LABEL_LEN bytes.
 *
 * Four decode variants provide flexibility:
 *   - pem_decode / pem_decode_into: require expected_label to match
 *   - pem_decode_auto / pem_decode_auto_into: accept any label
 *
 * All decode functions optionally report the discovered label via
 * found_label/found_label_max (pass NULL/0 to skip). */

/* Compute an upper bound for PEM decoded output size, subtracting the
 * minimum header/footer overhead before applying the base64 3/4 ratio.
 * Useful for sizing the output buffer passed to pqc_asn1_pem_decode_into().
 * Returns PQC_ASN1_OK on success, PQC_ASN1_ERR_OVERFLOW on overflow,
 * or PQC_ASN1_ERR_NULL_PARAM if out_size is NULL. */
pqc_asn1_status_t pqc_asn1_pem_decode_maxsize(size_t pem_len, size_t *out_size);

/* Validate a PEM label: must be non-empty, at most PQC_ASN1_MAX_PEM_LABEL_LEN
 * bytes, and contain only printable ASCII (0x20-0x7E) per RFC 7468.
 * Returns PQC_ASN1_OK on success, PQC_ASN1_ERR_PEM_LABEL if empty or
 * contains non-printable chars, PQC_ASN1_ERR_LABEL_TOO_LONG if too long. */
pqc_asn1_status_t pqc_asn1_validate_pem_label(const char *label, size_t label_len);

/* Compute the output size for PEM encoding (header + base64 + footer).
 * Validates the label (non-empty, printable ASCII, within length limit).
 * Returns PQC_ASN1_OK on success, PQC_ASN1_ERR_PEM_LABEL,
 * PQC_ASN1_ERR_LABEL_TOO_LONG, or PQC_ASN1_ERR_OVERFLOW on failure. */
pqc_asn1_status_t pqc_asn1_pem_encode_size(size_t der_len,
                                              const char *label, size_t label_len,
                                              size_t *out_size);

/* Encode DER to PEM into a caller-provided buffer of at least
 * pqc_asn1_pem_encode_size() bytes.
 * Returns PQC_ASN1_OK on success, sets *out_written to bytes written. */
pqc_asn1_status_t pqc_asn1_pem_encode_write(
    const uint8_t *der, size_t der_len,
    const char *label, size_t label_len,
    char *out, size_t out_len, size_t *out_written);

/* Encode DER to PEM (allocating).
 * On success, *out_buf receives a NUL-terminated buffer (caller must
 * free with PQC_ASN1_FREE) and *out_len is the length excluding NUL.
 * On failure, *out_buf is set to NULL and *out_len to 0.
 * Returns PQC_ASN1_OK or a negative error code. */
pqc_asn1_status_t pqc_asn1_pem_encode(
    const uint8_t *der, size_t der_len,
    const char *label, size_t label_len,
    char **out_buf, size_t *out_len);

/* Decode PEM into a caller-provided buffer, checking the label.
 * out_max is the size of the output buffer.
 * Returns PQC_ASN1_OK on success, sets *out_written to decoded length.
 * found_label/found_label_max: optional (may be NULL/0) — when non-NULL,
 * receives the label found between BEGIN/END markers. */
pqc_asn1_status_t pqc_asn1_pem_decode_into(
    const char *pem, size_t pem_len,
    const char *expected_label, size_t expected_label_len,
    uint8_t *out, size_t out_max, size_t *out_written,
    char *found_label, size_t found_label_max);

/* Decode PEM into a caller-provided buffer without checking the label.
 * out_max is the size of the output buffer.
 * Returns PQC_ASN1_OK on success, sets *out_written to decoded length.
 * found_label/found_label_max: optional (may be NULL/0) — when non-NULL,
 * receives the discovered label. */
pqc_asn1_status_t pqc_asn1_pem_decode_auto_into(
    const char *pem, size_t pem_len,
    uint8_t *out, size_t out_max, size_t *out_written,
    char *found_label, size_t found_label_max);

/* Decode PEM, checking the label matches expected_label.
 * Returns PQC_ASN1_OK on success, or a negative PQC_ASN1_ERR_* code.
 * On success, *out_buf is a newly allocated decoded buffer (caller must
 * secure-zero and free with PQC_ASN1_FREE) and *out_len is set.
 * On failure, *out_buf is set to NULL and *out_len to 0.
 * found_label/found_label_max: optional (may be NULL/0) — when non-NULL,
 * receives the label found between BEGIN/END markers. */
pqc_asn1_status_t pqc_asn1_pem_decode(
    const char *pem, size_t pem_len,
    const char *expected_label, size_t expected_label_len,
    uint8_t **out_buf, size_t *out_len,
    char *found_label, size_t found_label_max);

/* Decode PEM without checking the label.  Extracts whatever label is
 * present in the BEGIN marker and finds the matching END marker.
 * found_label/found_label_max: optional (may be NULL/0) — when non-NULL,
 * receives the discovered label.
 * Returns PQC_ASN1_OK on success, or a negative PQC_ASN1_ERR_* code.
 * On success, *out_buf is a newly allocated decoded buffer.
 * On failure, *out_buf is set to NULL and *out_len to 0. */
pqc_asn1_status_t pqc_asn1_pem_decode_auto(
    const char *pem, size_t pem_len,
    uint8_t **out_buf, size_t *out_len,
    char *found_label, size_t found_label_max);

/* ------------------------------------------------------------------ */
/* Error description                                                   */
/* ------------------------------------------------------------------ */

/* Return a human-readable string for a pqc_asn1_status_t code.
 * The returned pointer is to a static string (do not free). */
const char *pqc_asn1_error_message(pqc_asn1_status_t code);

#ifdef __cplusplus
}
#endif

#endif /* PQC_ASN1_H */
