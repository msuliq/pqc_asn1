/*
 * pqc_asn1.c — DER/PEM/Base64 utilities for post-quantum key serialization.
 *
 * VENDORED FILE — do not edit directly.
 * Origin: libpqcasn1 (https://github.com/msuliq/libpqcasn1)
 * To update: run `bundle exec rake vendor:concat` (local checkout) or
 *            run `bundle exec rake vendor:update[VERSION]` (release tarball).
 *
 * Standalone C library — no external dependencies beyond the C standard library.
 *
 * Algorithm-agnostic codec for ASN.1/DER/PEM/Base64 encoding.
 * All allocating functions use PQC_ASN1_MALLOC / PQC_ASN1_FREE macros
 * (default: malloc/free), configurable by the consumer before including
 * the header.
 *
 * This module is intentionally algorithm-agnostic: the same DER/PEM
 * primitives apply to ML-DSA, ML-KEM, SLH-DSA, and any future PQC
 * scheme that uses standard SPKI / PKCS#8 / PEM wrapping.
 */

/* Feature-test macros — must precede all system includes.
 * _GNU_SOURCE:             enables memmem() and explicit_bzero() on glibc.
 * __STDC_WANT_LIB_EXT1__: enables memset_s() on Apple/BSD via Annex K. */
#if defined(__linux__)
#define _GNU_SOURCE
#endif
#if defined(__APPLE__) || defined(__FreeBSD__)
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include "pqc_asn1.h"
#include <string.h>
#if defined(_MSC_VER)
#include <windows.h>    /* SecureZeroMemory */
#endif

#define PQC_SIZE_OVERFLOW ((size_t)-1)

/* Overflow-checked addition.  Returns PQC_SIZE_OVERFLOW on wraparound.
 * Composable: safe_add(safe_add(a, b), c) propagates overflow because
 * any addition involving PQC_SIZE_OVERFLOW will itself overflow. */
static inline size_t safe_add(size_t a, size_t b)
{
    size_t result = a + b;
    if (result < a)
        return PQC_SIZE_OVERFLOW;
    return result;
}

/* Compute total TLV size for a given content length: 1 (tag) + length field + content.
 * Returns PQC_SIZE_OVERFLOW on overflow or if length is too large to encode. */
static inline size_t der_tlv_total_size(size_t inner_len)
{
    size_t len_size;
    if (pqc_asn1_der_length_size(inner_len, &len_size) != PQC_ASN1_OK)
        return PQC_SIZE_OVERFLOW;
    size_t total = safe_add(safe_add(1, len_size), inner_len);
    return total;  /* PQC_SIZE_OVERFLOW if safe_add overflowed */
}

/* Write DER length field into out.  Returns number of bytes written,
 * or 0 on overflow.  Caller must ensure out has at least 5 bytes. */
static inline size_t der_write_length(uint8_t *out, size_t len)
{
    size_t n;
    if (pqc_asn1_der_length_size(len, &n) != PQC_ASN1_OK)
        return 0;  /* too large to encode */
    if (n == 1) {
        out[0] = (uint8_t)len;
    } else {
        size_t num_bytes = n - 1;
        size_t i;
        out[0] = (uint8_t)(0x80 | num_bytes);
        for (i = 1; i <= num_bytes; i++)
            out[i] = (uint8_t)(len >> (8 * (num_bytes - i)));
    }
    return n;
}

/* Write DER length, returning status.  Advances *p by bytes written.
 * Used by _write functions to guard against der_write_length returning 0. */
static inline pqc_asn1_status_t der_write_length_safe(uint8_t **p, size_t len)
{
    size_t n = der_write_length(*p, len);
    if (n == 0) return PQC_ASN1_ERR_OVERFLOW;
    *p += n;
    return PQC_ASN1_OK;
}



/* ================================================================== */
/* Concatenated from: src/tlv.c */
/* ================================================================== */



/* ------------------------------------------------------------------ */
/* Version                                                             */
/* ------------------------------------------------------------------ */

const char *pqc_asn1_version(void)
{
    return PQC_ASN1_VERSION_STRING;
}

/* ------------------------------------------------------------------ */
/* Secure zeroing                                                      */
/* ------------------------------------------------------------------ */

/* Securely zero a memory region, preventing the compiler from
 * optimizing away the write.  This is critical for clearing secret key
 * material from stack and heap buffers.
 *
 * Platform selection rationale:
 *   - MSVC:        SecureZeroMemory is an intrinsic — always emitted.
 *   - Apple/BSD:   memset_s (C11 Annex K) is guaranteed not optimized away.
 *   - glibc/BSD:   explicit_bzero is purpose-built for this use case.
 *   - Fallback:    volatile pointer write loop — the volatile qualifier
 *                  forces the compiler to emit every store. */
void pqc_asn1_secure_zero(void *ptr, size_t len)
{
    if (!ptr || len == 0) return;
#if defined(_MSC_VER)
    SecureZeroMemory(ptr, len);
#elif defined(__APPLE__) || defined(__FreeBSD__)
    memset_s(ptr, len, 0, len);
#elif defined(__GLIBC__) || defined(__OpenBSD__) || defined(__NetBSD__) || \
      defined(__DragonFly__)
    explicit_bzero(ptr, len);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
#endif
}

/* ------------------------------------------------------------------ */
/* DER length helpers                                                  */
/* ------------------------------------------------------------------ */

/* Maximum DER length we support encoding: 4 bytes (0xFFFFFFFF).
 * On 64-bit platforms, size_t can exceed this; we reject such values.
 * Uses static const rather than enum because the value exceeds INT_MAX
 * on 32-bit platforms and cannot be portably represented as an enum. */
static const size_t PQC_DER_MAX_LENGTH = 0xFFFFFFFFUL;

pqc_asn1_status_t pqc_asn1_der_length_size(size_t len, size_t *out)
{
    if (!out) return PQC_ASN1_ERR_NULL_PARAM;
    if (len < 128) { *out = 1; return PQC_ASN1_OK; }
    if (len <= 0xFF) { *out = 2; return PQC_ASN1_OK; }
    if (len <= 0xFFFF) { *out = 3; return PQC_ASN1_OK; }
    if (len <= 0xFFFFFF) { *out = 4; return PQC_ASN1_OK; }
    if (len <= PQC_DER_MAX_LENGTH) { *out = 5; return PQC_ASN1_OK; }
    *out = 0;
    return PQC_ASN1_ERR_OVERFLOW;
}

/* Note: der_tlv_total_size, der_write_length, der_write_length_safe, safe_add,
 * and PQC_SIZE_OVERFLOW are defined as static inline in pqc_asn1_internal.h
 * so they are available to all translation units. */

pqc_asn1_status_t pqc_asn1_der_write_tlv_write(
    uint8_t tag, const uint8_t *content, size_t content_len,
    uint8_t *buf, size_t buf_len, size_t *out_written)
{
    if (!buf || !out_written) return PQC_ASN1_ERR_NULL_PARAM;
    *out_written = 0;

    if (!content && content_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t len_size;
    if (pqc_asn1_der_length_size(content_len, &len_size) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_OVERFLOW;

    size_t total = safe_add(safe_add(1, len_size), content_len);
    if (total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    if (buf_len < total) return PQC_ASN1_ERR_BUFFER_TOO_SMALL;

    uint8_t *p = buf;
    *p++ = tag;
    p += der_write_length(p, content_len);
    if (content_len > 0)
        memcpy(p, content, content_len);

    *out_written = total;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_der_write_tlv(
    uint8_t tag, const uint8_t *content, size_t content_len,
    uint8_t **out_buf, size_t *out_total)
{
    if (!out_buf || !out_total) return PQC_ASN1_ERR_NULL_PARAM;
    *out_buf = NULL;
    *out_total = 0;

    if (!content && content_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t len_size;
    if (pqc_asn1_der_length_size(content_len, &len_size) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_OVERFLOW;

    size_t total = safe_add(safe_add(1, len_size), content_len);
    if (total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    uint8_t *buf = (uint8_t *)PQC_ASN1_MALLOC(total);
    if (!buf) return PQC_ASN1_ERR_ALLOC;

    size_t written;
    pqc_asn1_status_t rc = pqc_asn1_der_write_tlv_write(
        tag, content, content_len, buf, total, &written);
    if (rc != PQC_ASN1_OK) { PQC_ASN1_FREE(buf); return rc; }

    *out_buf = buf;
    *out_total = written;
    return PQC_ASN1_OK;
}

/* ------------------------------------------------------------------ */
/* DER reading helpers                                                 */
/* ------------------------------------------------------------------ */

pqc_asn1_status_t pqc_asn1_der_read_length(
    const uint8_t *buf, size_t buf_len,
    size_t *pos, size_t *out_len)
{
    if (!buf || !pos || !out_len) return PQC_ASN1_ERR_NULL_PARAM;

    size_t p = *pos;  /* local cursor — only committed on success */

    if (p >= buf_len) return PQC_ASN1_ERR_DER_PARSE;
    uint8_t b0 = buf[p++];
    if (b0 < 128) {
        *out_len = b0;
        *pos = p;
        return PQC_ASN1_OK;
    }
    if (b0 == 0x80) return PQC_ASN1_ERR_DER_PARSE;  /* indefinite length — not DER */
    size_t num_bytes = b0 & 0x7f;
    if (num_bytes > 4 || num_bytes > buf_len - p) return PQC_ASN1_ERR_DER_PARSE;

    /* Reject non-canonical: leading zero byte means a shorter encoding exists. */
    if (num_bytes > 0 && buf[p] == 0x00) return PQC_ASN1_ERR_DER_PARSE;

    size_t len = 0;
    size_t j;
    for (j = 0; j < num_bytes; j++)
        len = (len << 8) | buf[p++];

    /* Reject non-canonical: value < 128 must use short form,
     * and value must require all num_bytes to encode. */
    if (len < 128) return PQC_ASN1_ERR_DER_PARSE;
    if (num_bytes > 1 && len < ((size_t)1 << (8 * (num_bytes - 1))))
        return PQC_ASN1_ERR_DER_PARSE;

    if (len > buf_len - p) return PQC_ASN1_ERR_DER_PARSE;  /* content exceeds buffer */
    *out_len = len;
    *pos = p;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_der_read_tlv(
    const uint8_t *buf, size_t buf_len, size_t *pos,
    uint8_t expected_tag,
    const uint8_t **content, size_t *content_len)
{
    if (!buf || !pos || !content || !content_len) return PQC_ASN1_ERR_NULL_PARAM;
    size_t p = *pos;  /* local cursor — only committed on success */
    if (p >= buf_len || buf[p] != expected_tag) return PQC_ASN1_ERR_DER_PARSE;
    p++;
    if (pqc_asn1_der_read_length(buf, buf_len, &p, content_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_DER_PARSE;
    /* der_read_length already validates content fits within buf_len. */
    *content = buf + p;
    p += *content_len;
    *pos = p;  /* commit only on success */
    return PQC_ASN1_OK;
}


/* ------------------------------------------------------------------ */
/* Error description                                                   */
/* ------------------------------------------------------------------ */

const char *pqc_asn1_error_message(pqc_asn1_status_t code)
{
    switch (code) {
    case PQC_ASN1_OK:                   return "success";
    case PQC_ASN1_ERR_OUTER_SEQUENCE:   return "invalid or missing outer SEQUENCE";
    case PQC_ASN1_ERR_VERSION:          return "invalid or missing version (expected INTEGER 0)";
    case PQC_ASN1_ERR_ALGORITHM:        return "invalid or missing AlgorithmIdentifier";
    case PQC_ASN1_ERR_KEY:              return "invalid or missing key element";
    case PQC_ASN1_ERR_UNUSED_BITS:      return "BIT STRING has non-zero unused-bits byte";
    case PQC_ASN1_ERR_TRAILING_DATA:    return "unexpected trailing data after outer SEQUENCE";
    case PQC_ASN1_ERR_PEM_NO_MARKERS:   return "no valid PEM markers found";
    case PQC_ASN1_ERR_PEM_LABEL:        return "PEM label invalid or mismatched";
    case PQC_ASN1_ERR_BASE64:           return "invalid Base64 data";
    case PQC_ASN1_ERR_INVALID_OID:      return "oid_der is not a valid OID TLV";
    case PQC_ASN1_ERR_EXTRA_FIELDS:     return "unexpected extra fields inside structure";
    case PQC_ASN1_ERR_OVERFLOW:         return "size overflow in computation";
    case PQC_ASN1_ERR_ALLOC:            return "memory allocation failed";
    case PQC_ASN1_ERR_BUFFER_TOO_SMALL: return "caller-provided buffer is too small";
    case PQC_ASN1_ERR_LABEL_TOO_LONG:   return "PEM label exceeds maximum length";
    case PQC_ASN1_ERR_DER_PARSE:        return "DER parse error";
    case PQC_ASN1_ERR_NULL_PARAM:       return "required pointer parameter is NULL";
    case PQC_ASN1_ERR_PEM_MALFORMED:   return "PEM boundary line has trailing non-whitespace";
    }
    return "unknown error";
}

/* ================================================================== */
/* Concatenated from: src/builder.c */
/* ================================================================== */


/* ------------------------------------------------------------------ */
/* Internal: SPKI layout (shared between _size and _write)             */
/* ------------------------------------------------------------------ */

/* Pre-computed DER sizes for SubjectPublicKeyInfo.  Computing the layout
 * once and passing it to both the _size and _write functions ensures the
 * size calculation and serialization always agree — a mismatch would
 * cause buffer overflows or truncated output.
 *
 *   SEQUENCE (total) {
 *     SEQUENCE (alg_total) { OID (alg_inner) }
 *     BIT STRING (bs_total) { 0x00 unused-bits, pk_bytes (bs_inner) }
 *   }
 */
typedef struct {
    size_t alg_inner;   /* AlgorithmIdentifier content (= OID TLV) */
    size_t alg_total;   /* AlgorithmIdentifier SEQUENCE TLV */
    size_t bs_inner;    /* BIT STRING content (1 + pk_len) */
    size_t bs_total;    /* BIT STRING TLV */
    size_t seq_inner;   /* outer SEQUENCE content */
    size_t total;       /* outer SEQUENCE TLV (final DER size) */
} spki_layout_t;

/* Validate that oid_der is a well-formed OID TLV by delegating to the
 * existing DER TLV reader.  This ensures consistent length parsing
 * (including long-form lengths) and avoids duplicating DER validation
 * logic.  The TLV must consume the entire buffer exactly. */
static pqc_asn1_status_t validate_oid_tlv(const uint8_t *oid_der, size_t oid_der_len)
{
    if (!oid_der || oid_der_len < 3) return PQC_ASN1_ERR_INVALID_OID;
    size_t pos = 0;
    const uint8_t *content;
    size_t content_len;
    if (pqc_asn1_der_read_tlv(oid_der, oid_der_len, &pos, 0x06,
                                &content, &content_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_INVALID_OID;
    /* OID content must be non-empty and TLV must span the entire buffer. */
    if (content_len == 0 || pos != oid_der_len)
        return PQC_ASN1_ERR_INVALID_OID;
    return PQC_ASN1_OK;
}

/* Compute AlgorithmIdentifier SEQUENCE { OID [params] } total size.
 * params_len == 0 means no parameters (OID-only AlgorithmIdentifier).
 * Shared between SPKI and PKCS#8 layout computation. */
static pqc_asn1_status_t alg_id_compute_size(const uint8_t *oid_der, size_t oid_der_len,
                                               size_t params_len,
                                               size_t *alg_inner_out, size_t *alg_total_out)
{
    pqc_asn1_status_t rc = validate_oid_tlv(oid_der, oid_der_len);
    if (rc != PQC_ASN1_OK) return rc;

    *alg_inner_out = safe_add(oid_der_len, params_len);
    if (*alg_inner_out == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    *alg_total_out = der_tlv_total_size(*alg_inner_out);
    if (*alg_total_out == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    return PQC_ASN1_OK;
}

static pqc_asn1_status_t spki_compute_layout_ex(spki_layout_t *l,
                                                  const uint8_t *oid_der, size_t oid_der_len,
                                                  size_t params_len, size_t pk_len)
{
    pqc_asn1_status_t rc = alg_id_compute_size(oid_der, oid_der_len,
                                                params_len,
                                                &l->alg_inner, &l->alg_total);
    if (rc != PQC_ASN1_OK) return rc;

    l->bs_inner = safe_add(1, pk_len);
    if (l->bs_inner == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;

    l->bs_total = der_tlv_total_size(l->bs_inner);
    if (l->bs_total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;

    l->seq_inner = safe_add(l->alg_total, l->bs_total);
    if (l->seq_inner == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;

    l->total = der_tlv_total_size(l->seq_inner);
    if (l->total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;

    return PQC_ASN1_OK;
}

static pqc_asn1_status_t spki_compute_layout(spki_layout_t *l,
                                               const uint8_t *oid_der, size_t oid_der_len,
                                               size_t pk_len)
{
    return spki_compute_layout_ex(l, oid_der, oid_der_len, 0, pk_len);
}

/* ------------------------------------------------------------------ */
/* Internal: PKCS#8 layout (shared between _size and _write)           */
/* ------------------------------------------------------------------ */

/* Version field for PKCS#8 OneAsymmetricKey — always INTEGER 0 (v1).
 * Stored as a pre-encoded DER TLV to avoid runtime encoding. */
static const uint8_t PKCS8_VERSION_TLV[] = {0x02, 0x01, 0x00};

/* Pre-computed DER sizes for PKCS#8 OneAsymmetricKey.
 *
 *   SEQUENCE (total) {
 *     INTEGER 0 (version)
 *     SEQUENCE (alg_total) { OID [params] (alg_inner) }
 *     OCTET STRING (os_total) { sk_bytes (os_inner) }
 *     [1] IMPLICIT (pub_total) { pub_bytes }   -- optional publicKey field
 *   }
 */
typedef struct {
    size_t alg_inner;   /* AlgorithmIdentifier content (= OID TLV [+ params]) */
    size_t alg_total;   /* AlgorithmIdentifier SEQUENCE TLV */
    size_t os_inner;    /* OCTET STRING content (= sk_len) */
    size_t os_total;    /* OCTET STRING TLV */
    size_t pub_total;   /* publicKey [1] TLV size (0 if absent) */
    size_t seq_inner;   /* outer SEQUENCE content */
    size_t total;       /* outer SEQUENCE TLV (final DER size) */
} pkcs8_layout_t;

static pqc_asn1_status_t pkcs8_compute_layout_ex(pkcs8_layout_t *l,
                                                   const uint8_t *oid_der, size_t oid_der_len,
                                                   size_t params_len, size_t sk_len,
                                                   size_t pub_len)
{
    pqc_asn1_status_t rc = alg_id_compute_size(oid_der, oid_der_len,
                                                params_len,
                                                &l->alg_inner, &l->alg_total);
    if (rc != PQC_ASN1_OK) return rc;

    l->os_inner = sk_len;
    l->os_total = der_tlv_total_size(l->os_inner);
    if (l->os_total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;

    if (pub_len > 0) {
        l->pub_total = der_tlv_total_size(pub_len);
        if (l->pub_total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    } else {
        l->pub_total = 0;
    }

    l->seq_inner = safe_add(
        safe_add(safe_add(sizeof(PKCS8_VERSION_TLV), l->alg_total), l->os_total),
        l->pub_total);
    if (l->seq_inner == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;

    l->total = der_tlv_total_size(l->seq_inner);
    if (l->total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;

    return PQC_ASN1_OK;
}

static pqc_asn1_status_t pkcs8_compute_layout(pkcs8_layout_t *l,
                                                const uint8_t *oid_der, size_t oid_der_len,
                                                size_t sk_len)
{
    return pkcs8_compute_layout_ex(l, oid_der, oid_der_len, 0, sk_len, 0);
}

/* ------------------------------------------------------------------ */
/* DER structure builders                                              */
/* ------------------------------------------------------------------ */

pqc_asn1_status_t pqc_asn1_spki_size_ex(
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *params, size_t params_len,
    size_t pk_len, size_t *out_size)
{
    if (!out_size) return PQC_ASN1_ERR_NULL_PARAM;
    *out_size = 0;
    if (!oid_der) return PQC_ASN1_ERR_NULL_PARAM;
    if (params_len > 0 && !params) return PQC_ASN1_ERR_NULL_PARAM;
    spki_layout_t l;
    pqc_asn1_status_t rc = spki_compute_layout_ex(&l, oid_der, oid_der_len, params_len, pk_len);
    if (rc != PQC_ASN1_OK) return rc;
    *out_size = l.total;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_spki_size(const uint8_t *oid_der, size_t oid_der_len,
                                       size_t pk_len, size_t *out_size)
{
    return pqc_asn1_spki_size_ex(oid_der, oid_der_len, NULL, 0, pk_len, out_size);
}

pqc_asn1_status_t pqc_asn1_spki_build_write_ex(
    uint8_t *buf, size_t buf_len,
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *params, size_t params_len,
    const uint8_t *pk_bytes, size_t pk_len,
    size_t *out_written)
{
    if (!buf || !oid_der || !pk_bytes || !out_written) return PQC_ASN1_ERR_NULL_PARAM;
    if (params_len > 0 && !params) return PQC_ASN1_ERR_NULL_PARAM;
    *out_written = 0;

    spki_layout_t l;
    pqc_asn1_status_t rc = spki_compute_layout_ex(&l, oid_der, oid_der_len, params_len, pk_len);
    if (rc != PQC_ASN1_OK) return rc;
    if (buf_len < l.total)
        return PQC_ASN1_ERR_BUFFER_TOO_SMALL;

    uint8_t *p = buf;

    /* Outer SEQUENCE */
    *p++ = 0x30;
    rc = der_write_length_safe(&p, l.seq_inner);
    if (rc != PQC_ASN1_OK) return rc;

    /* AlgorithmIdentifier SEQUENCE { OID [params] } */
    *p++ = 0x30;
    rc = der_write_length_safe(&p, l.alg_inner);
    if (rc != PQC_ASN1_OK) return rc;
    memcpy(p, oid_der, oid_der_len);
    p += oid_der_len;
    if (params_len > 0) {
        memcpy(p, params, params_len);
        p += params_len;
    }

    /* BIT STRING { 0x00 unused-bits, key bytes } */
    *p++ = 0x03;
    rc = der_write_length_safe(&p, l.bs_inner);
    if (rc != PQC_ASN1_OK) return rc;
    *p++ = 0x00;
    memcpy(p, pk_bytes, pk_len);

    *out_written = l.total;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_spki_build_write(
    uint8_t *buf, size_t buf_len,
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *pk_bytes, size_t pk_len,
    size_t *out_written)
{
    return pqc_asn1_spki_build_write_ex(
        buf, buf_len, oid_der, oid_der_len, NULL, 0, pk_bytes, pk_len, out_written);
}

pqc_asn1_status_t pqc_asn1_spki_build(
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *pk_bytes, size_t pk_len,
    uint8_t **out_buf, size_t *out_total)
{
    if (!out_buf || !out_total) return PQC_ASN1_ERR_NULL_PARAM;
    *out_buf = NULL;
    *out_total = 0;

    if (!oid_der || !pk_bytes) return PQC_ASN1_ERR_NULL_PARAM;

    spki_layout_t l;
    pqc_asn1_status_t rc = spki_compute_layout(&l, oid_der, oid_der_len, pk_len);
    if (rc != PQC_ASN1_OK) return rc;
    uint8_t *buf = (uint8_t *)PQC_ASN1_MALLOC(l.total);
    if (!buf) return PQC_ASN1_ERR_ALLOC;
    size_t written;
    rc = pqc_asn1_spki_build_write(
        buf, l.total, oid_der, oid_der_len, pk_bytes, pk_len, &written);
    if (rc != PQC_ASN1_OK) { PQC_ASN1_FREE(buf); return rc; }
    *out_buf = buf;
    *out_total = written;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_pkcs8_size_ex(
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *params, size_t params_len,
    size_t sk_len, size_t pub_len, size_t *out_size)
{
    if (!out_size) return PQC_ASN1_ERR_NULL_PARAM;
    *out_size = 0;
    if (!oid_der) return PQC_ASN1_ERR_NULL_PARAM;
    if (params_len > 0 && !params) return PQC_ASN1_ERR_NULL_PARAM;
    pkcs8_layout_t l;
    pqc_asn1_status_t rc = pkcs8_compute_layout_ex(&l, oid_der, oid_der_len,
                                                    params_len, sk_len, pub_len);
    if (rc != PQC_ASN1_OK) return rc;
    *out_size = l.total;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_pkcs8_size(const uint8_t *oid_der, size_t oid_der_len,
                                        size_t sk_len, size_t *out_size)
{
    return pqc_asn1_pkcs8_size_ex(oid_der, oid_der_len, NULL, 0, sk_len, 0, out_size);
}

/* Write PKCS#8 DER with optional AlgorithmIdentifier parameters and
 * OneAsymmetricKey publicKey [1] field into a caller-provided buffer.
 * Error paths securely zero the buffer because it may contain partial
 * secret key material — callers should not need to handle this. */
pqc_asn1_status_t pqc_asn1_pkcs8_build_write_ex(
    uint8_t *buf, size_t buf_len,
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *params, size_t params_len,
    const uint8_t *sk_bytes, size_t sk_len,
    const uint8_t *pub_bytes, size_t pub_len,
    size_t *out_written)
{
    if (!buf || !oid_der || !sk_bytes || !out_written) return PQC_ASN1_ERR_NULL_PARAM;
    if (params_len > 0 && !params) return PQC_ASN1_ERR_NULL_PARAM;
    if (pub_len > 0 && !pub_bytes) return PQC_ASN1_ERR_NULL_PARAM;
    *out_written = 0;

    pkcs8_layout_t l;
    pqc_asn1_status_t rc = pkcs8_compute_layout_ex(&l, oid_der, oid_der_len,
                                                    params_len, sk_len, pub_len);
    if (rc != PQC_ASN1_OK) return rc;
    if (buf_len < l.total)
        return PQC_ASN1_ERR_BUFFER_TOO_SMALL;

    uint8_t *p = buf;

    /* Outer SEQUENCE */
    *p++ = 0x30;
    rc = der_write_length_safe(&p, l.seq_inner);
    if (rc != PQC_ASN1_OK) { pqc_asn1_secure_zero(buf, buf_len); return rc; }

    /* INTEGER 0 (version) */
    memcpy(p, PKCS8_VERSION_TLV, sizeof(PKCS8_VERSION_TLV));
    p += sizeof(PKCS8_VERSION_TLV);

    /* AlgorithmIdentifier SEQUENCE { OID [params] } */
    *p++ = 0x30;
    rc = der_write_length_safe(&p, l.alg_inner);
    if (rc != PQC_ASN1_OK) { pqc_asn1_secure_zero(buf, buf_len); return rc; }
    memcpy(p, oid_der, oid_der_len);
    p += oid_der_len;
    if (params_len > 0) {
        memcpy(p, params, params_len);
        p += params_len;
    }

    /* OCTET STRING { key bytes } */
    *p++ = 0x04;
    rc = der_write_length_safe(&p, l.os_inner);
    if (rc != PQC_ASN1_OK) { pqc_asn1_secure_zero(buf, buf_len); return rc; }
    memcpy(p, sk_bytes, sk_len);
    p += sk_len;

    /* Optional publicKey [1] IMPLICIT (tag 0x81) */
    if (pub_len > 0) {
        *p++ = 0x81;
        rc = der_write_length_safe(&p, pub_len);
        if (rc != PQC_ASN1_OK) { pqc_asn1_secure_zero(buf, buf_len); return rc; }
        memcpy(p, pub_bytes, pub_len);
    }

    *out_written = l.total;
    return PQC_ASN1_OK;
}

/* Write PKCS#8 DER into a caller-provided buffer (no params, no publicKey).
 * Error paths securely zero the buffer because it may contain partial
 * secret key material — callers should not need to handle this. */
pqc_asn1_status_t pqc_asn1_pkcs8_build_write(
    uint8_t *buf, size_t buf_len,
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *sk_bytes, size_t sk_len,
    size_t *out_written)
{
    return pqc_asn1_pkcs8_build_write_ex(
        buf, buf_len, oid_der, oid_der_len, NULL, 0, sk_bytes, sk_len, NULL, 0, out_written);
}

pqc_asn1_status_t pqc_asn1_pkcs8_build(
    const uint8_t *oid_der, size_t oid_der_len,
    const uint8_t *sk_bytes, size_t sk_len,
    uint8_t **out_buf, size_t *out_total)
{
    if (!out_buf || !out_total) return PQC_ASN1_ERR_NULL_PARAM;
    *out_buf = NULL;
    *out_total = 0;

    if (!oid_der || !sk_bytes) return PQC_ASN1_ERR_NULL_PARAM;

    pkcs8_layout_t l;
    pqc_asn1_status_t rc = pkcs8_compute_layout(&l, oid_der, oid_der_len, sk_len);
    if (rc != PQC_ASN1_OK) return rc;
    uint8_t *buf = (uint8_t *)PQC_ASN1_MALLOC(l.total);
    if (!buf) return PQC_ASN1_ERR_ALLOC;
    size_t written;
    rc = pqc_asn1_pkcs8_build_write(
        buf, l.total, oid_der, oid_der_len, sk_bytes, sk_len, &written);
    if (rc != PQC_ASN1_OK) { PQC_ASN1_FREE(buf); return rc; }
    *out_buf = buf;
    *out_total = written;
    return PQC_ASN1_OK;
}


/* ================================================================== */
/* Concatenated from: src/parser.c */
/* ================================================================== */


/* ------------------------------------------------------------------ */
/* Internal: shared AlgorithmIdentifier parser                         */
/* ------------------------------------------------------------------ */

/* Parse AlgorithmIdentifier SEQUENCE from within an outer SEQUENCE.
 * Reads the OID TLV and captures any trailing bytes as parameters.
 * On success, *oid_out points to the OID TLV and *params_out to the
 * optional parameters (NULL/0 if absent).  Advances *pos past the
 * AlgorithmIdentifier SEQUENCE.
 * Pass NULL for params_out/params_len_out to discard parameters.
 * When (flags & PQC_PARSE_STRICT_ALG_ID), any trailing bytes in the
 * AlgorithmIdentifier are rejected as PQC_ASN1_ERR_EXTRA_FIELDS. */
static pqc_asn1_status_t parse_algorithm_identifier(
    const uint8_t *seq, size_t seq_len, size_t *pos,
    const uint8_t **oid_out, size_t *oid_len_out,
    const uint8_t **params_out, size_t *params_len_out,
    uint32_t flags)
{
    const uint8_t *alg_content;
    size_t alg_len;
    if (pqc_asn1_der_read_tlv(seq, seq_len, pos, 0x30,
                                &alg_content, &alg_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_ALGORITHM;

    size_t alg_pos = 0;
    const uint8_t *oid_content;
    size_t oid_content_len;
    if (pqc_asn1_der_read_tlv(alg_content, alg_len, &alg_pos, 0x06,
                                &oid_content, &oid_content_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_ALGORITHM;

    /* alg_pos now equals the full OID TLV size (tag + length + content). */
    size_t oid_tlv_len = alg_pos;
    *oid_out = alg_content;
    *oid_len_out = oid_tlv_len;

    /* Capture optional AlgorithmIdentifier parameters (bytes after OID).
     * PQC_PARSE_STRICT_ALG_ID: reject any trailing bytes (RFC 9629 strict).
     * Without that flag: capture if out-pointers are non-NULL, otherwise discard. */
    if (alg_pos < alg_len) {
        if (flags & PQC_PARSE_STRICT_ALG_ID) {
            return PQC_ASN1_ERR_EXTRA_FIELDS;
        }
        if (params_out && params_len_out) {
            *params_out = alg_content + alg_pos;
            *params_len_out = alg_len - alg_pos;
        }
    } else {
        if (params_out) *params_out = NULL;
        if (params_len_out) *params_len_out = 0;
    }

    return PQC_ASN1_OK;
}

/* ------------------------------------------------------------------ */
/* DER structure parsers                                               */
/* ------------------------------------------------------------------ */

pqc_asn1_status_t pqc_asn1_spki_parse(
    const uint8_t *der, size_t der_len,
    const uint8_t **oid_der, size_t *oid_der_len,
    const uint8_t **alg_params, size_t *alg_params_len,
    const uint8_t **pk_bytes, size_t *pk_len,
    uint32_t flags)
{
    if (!der || !oid_der || !oid_der_len || !pk_bytes || !pk_len)
        return PQC_ASN1_ERR_NULL_PARAM;

    size_t pos = 0;
    const uint8_t *seq_content;
    size_t seq_len;

    /* Outer SEQUENCE */
    if (pqc_asn1_der_read_tlv(der, der_len, &pos, 0x30,
                                &seq_content, &seq_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_OUTER_SEQUENCE;
    if (pos != der_len)
        return PQC_ASN1_ERR_TRAILING_DATA;

    size_t inner_pos = 0;

    /* AlgorithmIdentifier SEQUENCE { OID [params] } */
    pqc_asn1_status_t alg_rc = parse_algorithm_identifier(
        seq_content, seq_len, &inner_pos, oid_der, oid_der_len,
        alg_params, alg_params_len, flags);
    if (alg_rc != PQC_ASN1_OK) return alg_rc;

    /* BIT STRING */
    const uint8_t *bs_content;
    size_t bs_len;
    if (pqc_asn1_der_read_tlv(seq_content, seq_len, &inner_pos, 0x03,
                                &bs_content, &bs_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_KEY;

    if (bs_len < 1 || bs_content[0] != 0x00)
        return PQC_ASN1_ERR_UNUSED_BITS;

    /* Reject extra fields inside outer SEQUENCE */
    if (inner_pos != seq_len)
        return PQC_ASN1_ERR_EXTRA_FIELDS;

    *pk_bytes = bs_content + 1;
    *pk_len = bs_len - 1;

    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_pkcs8_parse(
    const uint8_t *der, size_t der_len,
    const uint8_t **oid_der, size_t *oid_der_len,
    const uint8_t **alg_params, size_t *alg_params_len,
    const uint8_t **sk_bytes, size_t *sk_len,
    const uint8_t **pub_key, size_t *pub_key_len,
    uint32_t flags)
{
    if (!der || !oid_der || !oid_der_len || !sk_bytes || !sk_len)
        return PQC_ASN1_ERR_NULL_PARAM;

    size_t pos = 0;
    const uint8_t *seq_content;
    size_t seq_len;

    /* Outer SEQUENCE */
    if (pqc_asn1_der_read_tlv(der, der_len, &pos, 0x30,
                                &seq_content, &seq_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_OUTER_SEQUENCE;
    if (pos != der_len)
        return PQC_ASN1_ERR_TRAILING_DATA;

    size_t inner_pos = 0;

    /* INTEGER (version — must be 0) */
    const uint8_t *int_content;
    size_t int_len;
    if (pqc_asn1_der_read_tlv(seq_content, seq_len, &inner_pos, 0x02,
                                &int_content, &int_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_VERSION;
    if (int_len != 1 || int_content[0] != 0x00)
        return PQC_ASN1_ERR_VERSION;

    /* AlgorithmIdentifier SEQUENCE { OID [params] } */
    pqc_asn1_status_t alg_rc = parse_algorithm_identifier(
        seq_content, seq_len, &inner_pos, oid_der, oid_der_len,
        alg_params, alg_params_len, flags);
    if (alg_rc != PQC_ASN1_OK) return alg_rc;

    /* OCTET STRING (secret key) */
    const uint8_t *os_content;
    size_t os_len;
    if (pqc_asn1_der_read_tlv(seq_content, seq_len, &inner_pos, 0x04,
                                &os_content, &os_len) != PQC_ASN1_OK)
        return PQC_ASN1_ERR_KEY;

    *sk_bytes = os_content;
    *sk_len = os_len;

    /* Optional publicKey [1] IMPLICIT BIT STRING (RFC 9629 / RFC 5958 §3).
     * Tag 0x81 = CONTEXT-SPECIFIC[1] PRIMITIVE.  Only accepted if no other
     * unrecognised fields follow; silently skip if caller passes NULL. */
    if (pub_key) *pub_key = NULL;
    if (pub_key_len) *pub_key_len = 0;

    if (inner_pos < seq_len) {
        /* Accept [1] IMPLICIT BIT STRING — store if caller wants it. */
        if (seq_content[inner_pos] == 0x81) {
            const uint8_t *pk_content;
            size_t pk_len_val;
            if (pqc_asn1_der_read_tlv(seq_content, seq_len, &inner_pos, 0x81,
                                       &pk_content, &pk_len_val) != PQC_ASN1_OK)
                return PQC_ASN1_ERR_KEY;
            if (pub_key) *pub_key = pk_content;
            if (pub_key_len) *pub_key_len = pk_len_val;
        }
    }

    /* Reject any remaining unrecognised fields. */
    if (inner_pos != seq_len)
        return PQC_ASN1_ERR_EXTRA_FIELDS;

    return PQC_ASN1_OK;
}

/* ------------------------------------------------------------------ */

/* ================================================================== */
/* Concatenated from: src/base64.c */
/* ================================================================== */


/* Base64 codec                                                        */
/* ------------------------------------------------------------------ */

/* Standard RFC 4648 alphabet.  Used by both raw (no line-wrap) and
 * PEM-style (64-char line-wrap) encoding paths. */
static const char b64_encode_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Compile-time 256-entry decode table — maps every byte value to either
 * its 6-bit decoded value (0–63) or PQC_B64_INV (255) for invalid bytes.
 * Built at compile time to avoid the cost of a runtime init function. */
enum { PQC_B64_INV = 255 };
static const uint8_t b64_decode_table[256] = {
    /* 0x00-0x0F */ PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    /* 0x10-0x1F */ PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    /* 0x20-0x2F */ PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,         62,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,         63,
    /* 0x30-0x3F */         52,         53,         54,         55,
                            56,         57,         58,         59,
                            60,         61, PQC_B64_INV, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    /* 0x40-0x4F */ PQC_B64_INV,          0,          1,          2,
                             3,          4,          5,          6,
                             7,          8,          9,         10,
                            11,         12,         13,         14,
    /* 0x50-0x5F */         15,         16,         17,         18,
                            19,         20,         21,         22,
                            23,         24,         25, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    /* 0x60-0x6F */ PQC_B64_INV,         26,         27,         28,
                            29,         30,         31,         32,
                            33,         34,         35,         36,
                            37,         38,         39,         40,
    /* 0x70-0x7F */         41,         42,         43,         44,
                            45,         46,         47,         48,
                            49,         50,         51, PQC_B64_INV,
                    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    /* 0x80-0xFF: all invalid */
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
    PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV, PQC_B64_INV,
};

/* Internal: raw base64 encode.  Callers must validate size and buffer
 * before calling — this function does not perform size checks. */
static void base64_encode_core(
    const uint8_t *data, size_t data_len,
    char *out, size_t *out_written,
    int wrap_lines)
{
    size_t si = 0, di = 0, col = 0;

    while (si + 2 < data_len) {
        uint32_t n = ((uint32_t)data[si] << 16) |
                     ((uint32_t)data[si+1] << 8) |
                      (uint32_t)data[si+2];
        si += 3;
        out[di++] = b64_encode_table[(n >> 18) & 0x3f];
        out[di++] = b64_encode_table[(n >> 12) & 0x3f];
        out[di++] = b64_encode_table[(n >>  6) & 0x3f];
        out[di++] = b64_encode_table[ n        & 0x3f];
        col += 4;
        if (wrap_lines && col == 64 && si < data_len) {
            out[di++] = '\n';
            col = 0;
        }
    }
    if (si < data_len) {
        /* If the main loop filled a line exactly (col == 64), insert a
         * newline before the trailing-bytes group to avoid a >64-char line. */
        if (wrap_lines && col == 64) {
            out[di++] = '\n';
        }
        int has_second = (si + 1 < data_len);
        uint32_t n = (uint32_t)data[si] << 16;
        if (has_second) n |= (uint32_t)data[si+1] << 8;
        out[di++] = b64_encode_table[(n >> 18) & 0x3f];
        out[di++] = b64_encode_table[(n >> 12) & 0x3f];
        out[di++] = has_second ? b64_encode_table[(n >> 6) & 0x3f] : '=';
        out[di++] = '=';
    }

    *out_written = di;
}

pqc_asn1_status_t pqc_asn1_base64_encode_size_raw(size_t data_len, size_t *out_size)
{
    if (!out_size) return PQC_ASN1_ERR_NULL_PARAM;
    *out_size = 0;
    if (data_len > (SIZE_MAX / 4) * 3)
        return PQC_ASN1_ERR_OVERFLOW;
    *out_size = ((data_len + 2) / 3) * 4;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_base64_encode_raw(
    const uint8_t *data, size_t data_len,
    char *out, size_t out_len, size_t *out_written)
{
    if (!out || !out_written) return PQC_ASN1_ERR_NULL_PARAM;
    *out_written = 0;
    if (!data && data_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t needed;
    pqc_asn1_status_t rc = pqc_asn1_base64_encode_size_raw(data_len, &needed);
    if (rc != PQC_ASN1_OK) return rc;
    if (out_len < needed) return PQC_ASN1_ERR_BUFFER_TOO_SMALL;

    base64_encode_core(data, data_len, out, out_written, 0);
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_base64_encode_raw_alloc(
    const uint8_t *data, size_t data_len,
    char **out_buf, size_t *out_len)
{
    if (!out_buf || !out_len) return PQC_ASN1_ERR_NULL_PARAM;
    *out_buf = NULL;
    *out_len = 0;

    if (!data && data_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t total;
    pqc_asn1_status_t rc = pqc_asn1_base64_encode_size_raw(data_len, &total);
    if (rc != PQC_ASN1_OK) return rc;
    char *out = (char *)PQC_ASN1_MALLOC(total + 1);
    if (!out) return PQC_ASN1_ERR_ALLOC;
    size_t written;
    rc = pqc_asn1_base64_encode_raw(data, data_len, out, total, &written);
    if (rc != PQC_ASN1_OK) { PQC_ASN1_FREE(out); return rc; }
    out[written] = '\0';
    *out_buf = out;
    *out_len = written;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_base64_encode_size(size_t data_len, size_t *out_size)
{
    if (!out_size) return PQC_ASN1_ERR_NULL_PARAM;
    *out_size = 0;
    size_t b64_len;
    pqc_asn1_status_t rc = pqc_asn1_base64_encode_size_raw(data_len, &b64_len);
    if (rc != PQC_ASN1_OK) return rc;
    size_t newlines = (b64_len > 0) ? ((b64_len - 1) / 64) : 0;
    size_t total = safe_add(b64_len, newlines);
    if (total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    *out_size = total;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_base64_encode_write(
    const uint8_t *data, size_t data_len,
    char *out, size_t out_len, size_t *out_written)
{
    if (!out || !out_written) return PQC_ASN1_ERR_NULL_PARAM;
    *out_written = 0;
    if (!data && data_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t needed;
    pqc_asn1_status_t rc = pqc_asn1_base64_encode_size(data_len, &needed);
    if (rc != PQC_ASN1_OK) return rc;
    if (out_len < needed)
        return PQC_ASN1_ERR_BUFFER_TOO_SMALL;

    base64_encode_core(data, data_len, out, out_written, 1);
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_base64_encode(
    const uint8_t *data, size_t data_len,
    char **out_buf, size_t *out_len)
{
    if (!out_buf || !out_len) return PQC_ASN1_ERR_NULL_PARAM;
    *out_buf = NULL;
    *out_len = 0;

    if (!data && data_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t total;
    pqc_asn1_status_t rc = pqc_asn1_base64_encode_size(data_len, &total);
    if (rc != PQC_ASN1_OK) return rc;
    char *out = (char *)PQC_ASN1_MALLOC(total + 1);
    if (!out) return PQC_ASN1_ERR_ALLOC;
    size_t written;
    rc = pqc_asn1_base64_encode_write(data, data_len,
        out, total, &written);
    if (rc != PQC_ASN1_OK) { PQC_ASN1_FREE(out); return rc; }
    out[written] = '\0';
    *out_buf = out;
    *out_len = written;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_base64_decode_maxsize(size_t b64_len, size_t *out_size)
{
    if (!out_size) return PQC_ASN1_ERR_NULL_PARAM;
    *out_size = 0;
    if (b64_len == 0) return PQC_ASN1_OK;
    /* Guard against overflow: (b64_len / 4 + 1) * 3 */
    size_t groups = b64_len / 4;
    if (groups > (SIZE_MAX / 3) - 1)
        return PQC_ASN1_ERR_OVERFLOW;
    *out_size = (groups + 1) * 3;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_base64_decode_into(
    const char *b64, size_t b64_len,
    uint8_t *out, size_t out_max, size_t *out_written)
{
    if (!out || !out_written) return PQC_ASN1_ERR_NULL_PARAM;
    *out_written = 0;
    if (!b64 && b64_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t si = 0, di = 0;
    uint8_t buf4[4];
    int buf4_count = 0;
    int pad = 0;
    int seen_pad = 0;
    pqc_asn1_status_t err = PQC_ASN1_ERR_BASE64;

    for (si = 0; si < b64_len; si++) {
        unsigned char c = (unsigned char)b64[si];
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        if (c == '=') {
            pad++;
            if (pad > 2) goto fail;
            seen_pad = 1;
            buf4[buf4_count++] = 0;
        }
        else if (seen_pad) { goto fail; }
        else if (b64_decode_table[c] == PQC_B64_INV) { goto fail; }
        else { buf4[buf4_count++] = b64_decode_table[c]; }

        if (buf4_count == 4) {
            uint32_t n = ((uint32_t)buf4[0] << 18) | ((uint32_t)buf4[1] << 12) |
                         ((uint32_t)buf4[2] << 6)  |  (uint32_t)buf4[3];
            /* RFC 4648 §3.5: non-significant bits in padding must be zero. */
            if (pad == 2 && (n & 0x0FFFF)) goto fail;
            if (pad == 1 && (n & 0x000FF)) goto fail;
            if (di >= out_max) { err = PQC_ASN1_ERR_BUFFER_TOO_SMALL; goto fail; }
            out[di++] = (uint8_t)(n >> 16);
            if (pad < 2) {
                if (di >= out_max) { err = PQC_ASN1_ERR_BUFFER_TOO_SMALL; goto fail; }
                out[di++] = (uint8_t)(n >> 8);
            }
            if (pad < 1) {
                if (di >= out_max) { err = PQC_ASN1_ERR_BUFFER_TOO_SMALL; goto fail; }
                out[di++] = (uint8_t)n;
            }
            buf4_count = 0;
            pad = 0;
        }
    }
    if (buf4_count != 0) goto fail;

    *out_written = di;
    return PQC_ASN1_OK;

fail:
    /* Zero any partially-decoded output to prevent key material leakage. */
    if (di > 0) pqc_asn1_secure_zero(out, di);
    return err;
}

pqc_asn1_status_t pqc_asn1_base64_decode(
    const char *b64, size_t b64_len,
    uint8_t **out_buf, size_t *out_len)
{
    if (!out_buf || !out_len) return PQC_ASN1_ERR_NULL_PARAM;
    *out_buf = NULL;
    *out_len = 0;

    if (!b64 && b64_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    /* Empty input decodes to empty output — avoid unnecessary allocation.
     * out_buf and out_len are already zeroed above. */
    if (b64_len == 0)
        return PQC_ASN1_OK;

    size_t max_out;
    pqc_asn1_status_t rc = pqc_asn1_base64_decode_maxsize(b64_len, &max_out);
    if (rc != PQC_ASN1_OK) return rc;
    uint8_t *out = (uint8_t *)PQC_ASN1_MALLOC(max_out);
    if (!out) return PQC_ASN1_ERR_ALLOC;
    size_t decoded;
    rc = pqc_asn1_base64_decode_into(b64, b64_len,
                                       out, max_out, &decoded);
    if (rc != PQC_ASN1_OK) { PQC_ASN1_FREE(out); return rc; }

    /* Trim to exact decoded size to avoid returning an over-allocated buffer.
     * Skip the trim when waste is trivial (<=32 bytes) — the extra
     * reallocation is not worth it for such small savings.
     * Securely zero the unused tail before realloc so that key material
     * does not persist in freed heap memory regardless of whether realloc
     * moves the buffer or shrinks it in place. */
    if (decoded > 0 && max_out - decoded > 32) {
        pqc_asn1_secure_zero(out + decoded, max_out - decoded);
        uint8_t *trimmed = (uint8_t *)PQC_ASN1_REALLOC(out, decoded);
        if (trimmed)
            out = trimmed;
        /* If realloc fails, keep the over-sized buffer — still correct. */
    }

    *out_buf = out;
    *out_len = decoded;
    return PQC_ASN1_OK;
}

/* ------------------------------------------------------------------ */

/* ================================================================== */
/* Concatenated from: src/pem.c */
/* ================================================================== */


/* PEM — internal helpers                                              */
/* ------------------------------------------------------------------ */

/* PEM boundary string constants per RFC 7468.  Stored as static arrays
 * so sizeof() yields the length at compile time.  Shared between the
 * encode and decode paths. */
static const char pem_begin_prefix[] = "-----BEGIN ";
static const char pem_end_prefix[]   = "-----END ";
static const char pem_dashes[]       = "-----";
static const char pem_suffix[]       = "-----\n";

enum {
    PEM_BEGIN_PREFIX_LEN = sizeof(pem_begin_prefix) - 1,
    PEM_END_PREFIX_LEN   = sizeof(pem_end_prefix) - 1,
    PEM_DASHES_LEN       = sizeof(pem_dashes) - 1,
    PEM_SUFFIX_LEN       = sizeof(pem_suffix) - 1
};

/* Length-bounded substring search.  Uses the platform's memmem() where
 * available (glibc, BSD) for performance; falls back to a simple O(n*m)
 * scan elsewhere.  The fallback is adequate because PEM inputs are
 * bounded and needles are short (< 100 bytes). */
static const char *bounded_find(const char *hay, size_t hay_len,
                                 const char *needle, size_t needle_len)
{
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__) || defined(_GNU_SOURCE)
    return (const char *)memmem(hay, hay_len, needle, needle_len);
#else
    if (needle_len == 0) return hay;
    if (needle_len > hay_len) return NULL;
    size_t limit = hay_len - needle_len;
    size_t i;
    for (i = 0; i <= limit; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0)
            return hay + i;
    }
    return NULL;
#endif
}

/* Find needle in haystack, but only match if the candidate is at the very
 * start of the input (pem_start) or immediately preceded by a newline.
 * Returns pointer to match, or NULL. */
static const char *find_at_line_start(const char *hay, size_t hay_len,
                                       const char *needle, size_t needle_len,
                                       const char *pem_start)
{
    const char *search = hay;
    size_t search_len = hay_len;
    while (search_len > 0) {
        const char *candidate = bounded_find(search, search_len, needle, needle_len);
        if (!candidate) return NULL;
        /* Safe: when candidate != pem_start, candidate > start of search
         * range (hay >= pem_start), so candidate[-1] is always in bounds. */
        if (candidate == pem_start || candidate[-1] == '\n' || candidate[-1] == '\r')
            return candidate;
        size_t skip = (size_t)(candidate - search) + 1;
        search += skip;
        search_len -= skip;
    }
    return NULL;
}

pqc_asn1_status_t pqc_asn1_pem_decode_maxsize(size_t pem_len, size_t *out_size)
{
    if (!out_size) return PQC_ASN1_ERR_NULL_PARAM;
    *out_size = 0;
    /* Subtract the minimum possible header + footer overhead before
     * applying the base64 3/4 ratio.  The shortest valid PEM has
     * "-----BEGIN X-----\n" (19) + "-----END X-----\n" (17) = 36 bytes
     * of framing.  When pem_len is smaller than the minimum framing, we
     * fall back to pem_len as a safe (if generous) upper bound — such
     * input can never be valid PEM, but the caller may still want a
     * buffer size before attempting decode. */
    enum { PEM_MIN_FRAMING = 36 };
    size_t body_upper = (pem_len > PEM_MIN_FRAMING) ? (pem_len - PEM_MIN_FRAMING) : pem_len;
    return pqc_asn1_base64_decode_maxsize(body_upper, out_size);
}

/* Validate a PEM label: non-empty, within length limit, printable ASCII only.
 * Used by both encode and decode paths. */
pqc_asn1_status_t pqc_asn1_validate_pem_label(const char *label, size_t label_len)
{
    if (!label || label_len == 0) return PQC_ASN1_ERR_PEM_LABEL;
    if (label_len > PQC_ASN1_MAX_PEM_LABEL_LEN) return PQC_ASN1_ERR_LABEL_TOO_LONG;
    /* RFC 7468: labels must contain only printable ASCII (0x20-0x7E). */
    size_t li;
    for (li = 0; li < label_len; li++) {
        unsigned char ch = (unsigned char)label[li];
        if (ch < 0x20 || ch > 0x7E)
            return PQC_ASN1_ERR_PEM_LABEL;
    }
    return PQC_ASN1_OK;
}

/* Find PEM markers and extract the base64 body region.
 * label_out must be a non-NULL buffer of at least label_out_max bytes.
 * On success, writes the NUL-terminated label into label_out.
 * Returns PQC_ASN1_OK on success, or a specific error code. */
static pqc_asn1_status_t pem_find_body(const char *pem, size_t pem_len,
                                         char *label_out, size_t label_out_max,
                                         const char **body_start_out,
                                         size_t *body_len_out)
{
    /* RFC 7468: the pre-encapsulation boundary must be at the start of a line. */
    const char *begin = find_at_line_start(pem, pem_len,
                                            pem_begin_prefix, PEM_BEGIN_PREFIX_LEN, pem);
    if (!begin) return PQC_ASN1_ERR_PEM_NO_MARKERS;
    const char *label_start = begin + PEM_BEGIN_PREFIX_LEN;
    size_t remaining = pem_len - (size_t)(label_start - pem);
    const char *label_end = bounded_find(label_start, remaining, pem_dashes, PEM_DASHES_LEN);
    if (!label_end) return PQC_ASN1_ERR_PEM_NO_MARKERS;
    size_t label_len = (size_t)(label_end - label_start);
    if (label_len == 0) return PQC_ASN1_ERR_PEM_NO_MARKERS;
    if (label_len >= label_out_max)
        return PQC_ASN1_ERR_BUFFER_TOO_SMALL;
    {
        pqc_asn1_status_t lrc = pqc_asn1_validate_pem_label(label_start, label_len);
        if (lrc != PQC_ASN1_OK) return lrc;
    }
    /* Write directly into the caller's buffer. */
    memcpy(label_out, label_start, label_len);
    label_out[label_len] = '\0';

    /* Verify nothing but whitespace follows the closing dashes on the BEGIN line.
     * RFC 7468: the line should end after "-----". */
    const char *after_dashes = label_end + PEM_DASHES_LEN;
    const char *body_start = after_dashes;
    while (body_start < pem + pem_len && *body_start != '\n' && *body_start != '\r') {
        if (*body_start != ' ' && *body_start != '\t')
            return PQC_ASN1_ERR_PEM_MALFORMED;
        body_start++;
    }
    while (body_start < pem + pem_len && (*body_start == '\n' || *body_start == '\r'))
        body_start++;

    /* Build END marker with memcpy — avoids <stdio.h> dependency.
     * Safe because label_len <= MAX_PEM_LABEL_LEN. */
    char end_marker[PEM_END_PREFIX_LEN + PQC_ASN1_MAX_PEM_LABEL_LEN + PEM_DASHES_LEN];
    char *ep = end_marker;
    memcpy(ep, pem_end_prefix, PEM_END_PREFIX_LEN); ep += PEM_END_PREFIX_LEN;
    memcpy(ep, label_out, label_len); ep += label_len;
    memcpy(ep, pem_dashes, PEM_DASHES_LEN); ep += PEM_DASHES_LEN;
    size_t em_len = (size_t)(ep - end_marker);

    /* RFC 7468: the post-encapsulation boundary must be at the start of a line. */
    remaining = pem_len - (size_t)(body_start - pem);
    const char *body_end = find_at_line_start(body_start, remaining,
                                               end_marker, em_len, pem);
    if (!body_end) return PQC_ASN1_ERR_PEM_NO_MARKERS;

    /* Verify nothing but whitespace follows the closing dashes on the END line. */
    const char *after_end = body_end + em_len;
    const char *pem_end_ptr = pem + pem_len;
    while (after_end < pem_end_ptr && *after_end != '\n' && *after_end != '\r') {
        if (*after_end != ' ' && *after_end != '\t')
            return PQC_ASN1_ERR_PEM_MALFORMED;
        after_end++;
    }

    *body_start_out = body_start;
    *body_len_out = (size_t)(body_end - body_start);
    return PQC_ASN1_OK;
}

/* ------------------------------------------------------------------ */
/* PEM codec                                                           */
/* ------------------------------------------------------------------ */

pqc_asn1_status_t pqc_asn1_pem_encode_size(size_t der_len,
                                              const char *label, size_t label_len,
                                              size_t *out_size)
{
    if (!out_size) return PQC_ASN1_ERR_NULL_PARAM;
    *out_size = 0;
    {
        pqc_asn1_status_t lrc = pqc_asn1_validate_pem_label(label, label_len);
        if (lrc != PQC_ASN1_OK) return lrc;
    }
    size_t header_len = safe_add(safe_add(PEM_BEGIN_PREFIX_LEN, label_len), PEM_SUFFIX_LEN);
    if (header_len == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    /* base64 body + trailing newline */
    size_t b64_body;
    pqc_asn1_status_t rc = pqc_asn1_base64_encode_size(der_len, &b64_body);
    if (rc != PQC_ASN1_OK) return rc;
    size_t b64_len = safe_add(b64_body, 1);
    if (b64_len == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    size_t footer_len = safe_add(safe_add(PEM_END_PREFIX_LEN, label_len), PEM_SUFFIX_LEN);
    if (footer_len == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    size_t total = safe_add(safe_add(header_len, b64_len), footer_len);
    if (total == PQC_SIZE_OVERFLOW) return PQC_ASN1_ERR_OVERFLOW;
    *out_size = total;
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_pem_encode_write(
    const uint8_t *der, size_t der_len,
    const char *label, size_t label_len,
    char *out, size_t out_len, size_t *out_written)
{
    if (!out || !label || !out_written) return PQC_ASN1_ERR_NULL_PARAM;
    *out_written = 0;
    if (!der && der_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t needed;
    pqc_asn1_status_t rc = pqc_asn1_pem_encode_size(der_len, label, label_len, &needed);
    if (rc != PQC_ASN1_OK) return rc;
    if (out_len < needed)
        return PQC_ASN1_ERR_BUFFER_TOO_SMALL;

    char *p = out;

    /* Header: -----BEGIN <label>-----\n */
    memcpy(p, pem_begin_prefix, PEM_BEGIN_PREFIX_LEN); p += PEM_BEGIN_PREFIX_LEN;
    memcpy(p, label, label_len); p += label_len;
    memcpy(p, pem_suffix, PEM_SUFFIX_LEN); p += PEM_SUFFIX_LEN;

    /* Base64 body */
    size_t b64_written;
    size_t b64_space = out_len - (size_t)(p - out);
    rc = pqc_asn1_base64_encode_write(der, der_len,
        p, b64_space, &b64_written);
    if (rc != PQC_ASN1_OK) return rc;
    p += b64_written;
    *p++ = '\n';

    /* Footer: -----END <label>-----\n */
    memcpy(p, pem_end_prefix, PEM_END_PREFIX_LEN); p += PEM_END_PREFIX_LEN;
    memcpy(p, label, label_len); p += label_len;
    memcpy(p, pem_suffix, PEM_SUFFIX_LEN); p += PEM_SUFFIX_LEN;

    *out_written = (size_t)(p - out);
    return PQC_ASN1_OK;
}

pqc_asn1_status_t pqc_asn1_pem_encode(
    const uint8_t *der, size_t der_len,
    const char *label, size_t label_len,
    char **out_buf, size_t *out_len)
{
    if (!out_buf || !out_len) return PQC_ASN1_ERR_NULL_PARAM;
    *out_buf = NULL;
    *out_len = 0;

    if (!label) return PQC_ASN1_ERR_NULL_PARAM;
    if (!der && der_len > 0) return PQC_ASN1_ERR_NULL_PARAM;

    size_t total;
    pqc_asn1_status_t rc = pqc_asn1_pem_encode_size(der_len, label, label_len, &total);
    if (rc != PQC_ASN1_OK) return rc;

    char *buf = (char *)PQC_ASN1_MALLOC(total + 1);  /* +1 for NUL */
    if (!buf) return PQC_ASN1_ERR_ALLOC;

    size_t written;
    rc = pqc_asn1_pem_encode_write(der, der_len,
        label, label_len, buf, total, &written);
    if (rc != PQC_ASN1_OK) { PQC_ASN1_FREE(buf); return rc; }
    buf[written] = '\0';
    *out_buf = buf;
    *out_len = written;
    return PQC_ASN1_OK;
}

/* Internal: shared PEM decode prefix — find body, handle label copy and
 * expected-label comparison.  On success, *body_start_out and *body_len_out
 * point to the base64 body region ready for decoding. */
static pqc_asn1_status_t pem_decode_prefix(
    const char *pem, size_t pem_len,
    const char *expected_label, size_t expected_label_len,
    char *found_label, size_t found_label_max,
    const char **body_start_out, size_t *body_len_out)
{
    if (!pem) return PQC_ASN1_ERR_NULL_PARAM;
    if (found_label && found_label_max > 0) found_label[0] = '\0';

    /* Always extract into a local buffer so we have the label for
     * comparison even when the caller passes found_label == NULL. */
    char local_label[PQC_ASN1_MAX_PEM_LABEL_LEN + 1];
    local_label[0] = '\0';

    pqc_asn1_status_t rc = pem_find_body(pem, pem_len, local_label,
                                          sizeof(local_label),
                                          body_start_out, body_len_out);
    if (rc != PQC_ASN1_OK)
        return rc;

    size_t lbl_len = strlen(local_label);

    /* Copy to caller's buffer if provided. */
    if (found_label) {
        if (lbl_len >= found_label_max)
            return PQC_ASN1_ERR_BUFFER_TOO_SMALL;
        memcpy(found_label, local_label, lbl_len + 1);
    }

    if (expected_label) {
        if (lbl_len != expected_label_len ||
            memcmp(local_label, expected_label, expected_label_len) != 0)
            return PQC_ASN1_ERR_PEM_LABEL;
    }

    return PQC_ASN1_OK;
}

/* Internal: shared PEM decode logic (allocating variant). */
static pqc_asn1_status_t pem_decode_common(
    const char *pem, size_t pem_len,
    const char *expected_label, size_t expected_label_len,
    uint8_t **out_buf, size_t *out_len,
    char *found_label, size_t found_label_max)
{
    if (!out_buf || !out_len) return PQC_ASN1_ERR_NULL_PARAM;
    *out_buf = NULL;
    *out_len = 0;

    const char *body_start;
    size_t body_len;
    pqc_asn1_status_t rc = pem_decode_prefix(pem, pem_len,
                                              expected_label, expected_label_len,
                                              found_label, found_label_max,
                                              &body_start, &body_len);
    if (rc != PQC_ASN1_OK) return rc;

    return pqc_asn1_base64_decode(body_start, body_len, out_buf, out_len);
}

/* Internal: shared PEM decode-into-buffer logic. */
static pqc_asn1_status_t pem_decode_common_into(
    const char *pem, size_t pem_len,
    const char *expected_label, size_t expected_label_len,
    uint8_t *out, size_t out_max, size_t *out_written,
    char *found_label, size_t found_label_max)
{
    if (!out || !out_written) return PQC_ASN1_ERR_NULL_PARAM;
    *out_written = 0;

    const char *body_start;
    size_t body_len;
    pqc_asn1_status_t rc = pem_decode_prefix(pem, pem_len,
                                              expected_label, expected_label_len,
                                              found_label, found_label_max,
                                              &body_start, &body_len);
    if (rc != PQC_ASN1_OK) return rc;

    return pqc_asn1_base64_decode_into(body_start, body_len,
                                        out, out_max, out_written);
}

pqc_asn1_status_t pqc_asn1_pem_decode_into(
    const char *pem, size_t pem_len,
    const char *expected_label, size_t expected_label_len,
    uint8_t *out, size_t out_max, size_t *out_written,
    char *found_label, size_t found_label_max)
{
    if (!expected_label) return PQC_ASN1_ERR_NULL_PARAM;
    return pem_decode_common_into(pem, pem_len,
                                   expected_label, expected_label_len,
                                   out, out_max, out_written,
                                   found_label, found_label_max);
}

pqc_asn1_status_t pqc_asn1_pem_decode_auto_into(
    const char *pem, size_t pem_len,
    uint8_t *out, size_t out_max, size_t *out_written,
    char *found_label, size_t found_label_max)
{
    return pem_decode_common_into(pem, pem_len, NULL, 0,
                                   out, out_max, out_written,
                                   found_label, found_label_max);
}

pqc_asn1_status_t pqc_asn1_pem_decode(
    const char *pem, size_t pem_len,
    const char *expected_label, size_t expected_label_len,
    uint8_t **out_buf, size_t *out_len,
    char *found_label, size_t found_label_max)
{
    if (!expected_label) return PQC_ASN1_ERR_NULL_PARAM;
    return pem_decode_common(pem, pem_len,
                              expected_label, expected_label_len,
                              out_buf, out_len, found_label, found_label_max);
}

pqc_asn1_status_t pqc_asn1_pem_decode_auto(
    const char *pem, size_t pem_len,
    uint8_t **out_buf, size_t *out_len,
    char *found_label, size_t found_label_max)
{
    return pem_decode_common(pem, pem_len, NULL, 0,
                              out_buf, out_len, found_label, found_label_max);
}

/* ------------------------------------------------------------------ */
