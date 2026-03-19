/*
 * der.c — PqcAsn1::DER module method implementations.
 *
 * Provides the SPKI/PKCS#8 build/parse API and lower-level TLV helpers.
 *
 * Public:   build_spki, build_pkcs8, parse_spki, parse_pkcs8,
 *           read_tlv, write_tlv
 * Private:  write_length  (implementation detail, tested via send)
 *
 * OID representation
 * ==================
 * build_spki / build_pkcs8 accept OIDs as either a PqcAsn1::OID instance
 * or a dotted-decimal String ("2.16.840.1.101.3.4.3.17").
 *
 * parse_spki / parse_pkcs8 return the OID as a PqcAsn1::OID value object.
 *
 * SecureBuffer interaction
 * ========================
 * SecureBuffer is defined in the same extension (secure_buffer.c), so
 * TypedData_Get_Struct and pqcsb_create are safe.  build_pkcs8 and
 * parse_pkcs8 use pqcsb_create(pqcsb_class(), data, len) to wrap
 * secret-key bytes directly — no intermediate Ruby String needed.
 * parse_pkcs8 (SecureBuffer input path) still uses #use to iterate
 * over the DER bytes exception-safely via rb_block_call.
 */

#include "shared.h"
#include "error.h"
#include "oid.h"
#include "secure_buffer.h"

/* ------------------------------------------------------------------ */
/* File-static handles                                                 */
/* ------------------------------------------------------------------ */

static VALUE s_cKeyInfo;

/* ------------------------------------------------------------------ */
/* Human-readable error messages for parse errors                     */
/* ------------------------------------------------------------------ */

static const char *
spki_error_message(pqc_asn1_status_t code)
{
    switch (code) {
    case PQC_ASN1_ERR_OUTER_SEQUENCE:
        return "SPKI parse error: invalid or missing outer SEQUENCE";
    case PQC_ASN1_ERR_ALGORITHM:
        return "SPKI parse error: invalid or missing AlgorithmIdentifier SEQUENCE";
    case PQC_ASN1_ERR_KEY:
        return "SPKI parse error: invalid or missing BIT STRING for public key";
    case PQC_ASN1_ERR_UNUSED_BITS:
        return "SPKI parse error: BIT STRING has non-zero unused-bits byte";
    case PQC_ASN1_ERR_TRAILING_DATA:
        return "SPKI parse error: unexpected trailing data after outer SEQUENCE";
    case PQC_ASN1_ERR_EXTRA_FIELDS:
        return "SPKI parse error: unexpected extra fields inside SEQUENCE";
    default:
        return "SPKI parse error: unknown error";
    }
}

static const char *
pkcs8_error_message(pqc_asn1_status_t code)
{
    switch (code) {
    case PQC_ASN1_ERR_OUTER_SEQUENCE:
        return "PKCS#8 parse error: invalid or missing outer SEQUENCE";
    case PQC_ASN1_ERR_VERSION:
        return "PKCS#8 parse error: invalid or missing version (expected INTEGER 0)";
    case PQC_ASN1_ERR_ALGORITHM:
        return "PKCS#8 parse error: invalid or missing AlgorithmIdentifier SEQUENCE";
    case PQC_ASN1_ERR_KEY:
        return "PKCS#8 parse error: invalid or missing OCTET STRING for secret key";
    case PQC_ASN1_ERR_TRAILING_DATA:
        return "PKCS#8 parse error: unexpected trailing data after outer SEQUENCE";
    case PQC_ASN1_ERR_EXTRA_FIELDS:
        return "PKCS#8 parse error: unexpected extra fields inside SEQUENCE";
    default:
        return "PKCS#8 parse error: unknown error";
    }
}

/* ------------------------------------------------------------------ */
/* Local DER length encoder (bypasses C library for the write path)   */
/* ------------------------------------------------------------------ */

static size_t
der_write_length_local(uint8_t *buf, size_t len)
{
    if (len < 128) {
        buf[0] = (uint8_t)len;
        return 1;
    }
    if (len <= 0xFF) {
        buf[0] = 0x81; buf[1] = (uint8_t)len;
        return 2;
    }
    if (len <= 0xFFFF) {
        buf[0] = 0x82; buf[1] = (uint8_t)(len >> 8); buf[2] = (uint8_t)len;
        return 3;
    }
    if (len <= 0xFFFFFF) {
        buf[0] = 0x83; buf[1] = (uint8_t)(len >> 16);
        buf[2] = (uint8_t)(len >> 8); buf[3] = (uint8_t)len;
        return 4;
    }
    buf[0] = 0x84; buf[1] = (uint8_t)(len >> 24); buf[2] = (uint8_t)(len >> 16);
    buf[3] = (uint8_t)(len >> 8); buf[4] = (uint8_t)len;
    return 5;
}

/* ------------------------------------------------------------------ */
/* Private helper: write_length                                       */
/* ------------------------------------------------------------------ */

static VALUE
rb_der_write_length(UNUSED VALUE _self, VALUE rb_len)
{
    size_t len = NUM2SIZET(rb_len);
    uint8_t buf[5];
    size_t written = der_write_length_local(buf, len);
    return frozen_bin_str((const char *)buf, (long)written);
}

/* ------------------------------------------------------------------ */
/* Public TLV helpers                                                  */
/* ------------------------------------------------------------------ */

static VALUE
rb_der_read_tlv(UNUSED VALUE _self, VALUE rb_der, VALUE rb_offset, VALUE rb_tag)
{
    StringValue(rb_der);
    const uint8_t *buf = (const uint8_t *)RSTRING_PTR(rb_der);
    size_t buf_len = (size_t)RSTRING_LEN(rb_der);
    long offset_signed = NUM2LONG(rb_offset);
    if (offset_signed < 0)
        rb_raise(rb_eArgError, "offset must be >= 0");
    size_t pos = (size_t)offset_signed;
    uint8_t tag = (uint8_t)NUM2INT(rb_tag);
    const uint8_t *content;
    size_t content_len;

    pqc_asn1_status_t rc = pqc_asn1_der_read_tlv(
        buf, buf_len, &pos, tag, &content, &content_len);
    if (rc != PQC_ASN1_OK)
        raise_with_code(pqc_der_error_class(),
                 rb_sprintf("DER parse error: expected tag 0x%02x at offset %lu",
                             tag, (unsigned long)NUM2SIZET(rb_offset)),
                 rc);

    VALUE result = rb_ary_new2(2);
    rb_ary_store(result, 0, frozen_bin_str((const char *)content, (long)content_len));
    rb_ary_store(result, 1, SIZET2NUM(pos));
    return result;
}

static VALUE
rb_der_write_tlv(UNUSED VALUE _self, VALUE rb_tag, VALUE rb_content)
{
    uint8_t tag = (uint8_t)NUM2INT(rb_tag);
    StringValue(rb_content);
    const uint8_t *content = (const uint8_t *)RSTRING_PTR(rb_content);
    size_t content_len = (size_t)RSTRING_LEN(rb_content);

    size_t len_size;
    pqc_asn1_status_t rc = pqc_asn1_der_length_size(content_len, &len_size);
    if (rc != PQC_ASN1_OK)
        raise_status(rc, "DER write TLV");

    size_t total = 1 + len_size + content_len;
    VALUE result = rb_str_buf_new((long)total);
    rb_str_set_len(result, (long)total);

    size_t written;
    rc = pqc_asn1_der_write_tlv_write(
        tag, content, content_len,
        (uint8_t *)RSTRING_PTR(result), total, &written);
    if (rc != PQC_ASN1_OK)
        raise_status(rc, "DER write TLV");

    rb_str_set_len(result, (long)written);
    rb_enc_associate(result, rb_ascii8bit_encoding());
    rb_obj_freeze(result);
    return result;
}

/* ------------------------------------------------------------------ */
/* Public builders                                                     */
/* ------------------------------------------------------------------ */

/*
 * DER.build_spki(oid, public_key, parameters: nil) -> String
 *
 * When parameters: is provided (a raw DER-encoded AlgorithmIdentifier
 * parameter, e.g. "\x05\x00" for NULL), it is appended after the OID
 * inside the AlgorithmIdentifier SEQUENCE.  Without it, the fast C
 * library path is used (OID-only AlgorithmIdentifier).
 */
static VALUE
rb_der_build_spki(int argc, VALUE *argv, VALUE _self)
{
    VALUE rb_oid, rb_pk, rb_opts;
    rb_scan_args(argc, argv, "2:", &rb_oid, &rb_pk, &rb_opts);

    VALUE rb_oid_der = oid_from_dotted_rb(rb_oid);
    StringValue(rb_oid_der);
    StringValue(rb_pk);

    const uint8_t *oid_ptr = (const uint8_t *)RSTRING_PTR(rb_oid_der);
    size_t oid_len = (size_t)RSTRING_LEN(rb_oid_der);
    const uint8_t *pk_ptr = (const uint8_t *)RSTRING_PTR(rb_pk);
    size_t pk_len = (size_t)RSTRING_LEN(rb_pk);

    /* Extract parameters: keyword (nil = absent). */
    VALUE rb_params = Qnil;
    if (!NIL_P(rb_opts)) {
        static ID kw_params = 0;
        if (!kw_params) kw_params = rb_intern("parameters");
        rb_get_kwargs(rb_opts, &kw_params, 0, 1, &rb_params);
        if (rb_params == Qundef) rb_params = Qnil;
    }

    const uint8_t *params_ptr = NULL;
    size_t params_len = 0;
    if (!NIL_P(rb_params)) {
        StringValue(rb_params);
        params_ptr = (const uint8_t *)RSTRING_PTR(rb_params);
        params_len = (size_t)RSTRING_LEN(rb_params);
    }

    /* Unified path: C library _ex variant handles both with and without params. */
    size_t total;
    pqc_asn1_status_t rc = pqc_asn1_spki_size_ex(
        oid_ptr, oid_len, params_ptr, params_len, pk_len, &total);
    if (rc != PQC_ASN1_OK)
        raise_status(rc, NULL);
    VALUE result = rb_str_buf_new((long)total);
    rb_str_set_len(result, (long)total);
    size_t written;
    rc = pqc_asn1_spki_build_write_ex(
        (uint8_t *)RSTRING_PTR(result), total,
        oid_ptr, oid_len, params_ptr, params_len, pk_ptr, pk_len, &written);
    if (rc != PQC_ASN1_OK)
        raise_status(rc, NULL);
    rb_str_set_len(result, (long)written);
    rb_enc_associate(result, rb_ascii8bit_encoding());
    rb_obj_freeze(result);
    return result;
}

/* Context for pqcsb_create_inplace callback in build_pkcs8.
 * Unified struct covers both the simple path (no params/publicKey) and
 * the extended path — the _ex C library function handles both cases. */
typedef struct {
    const uint8_t *oid_ptr;
    size_t oid_len;
    const uint8_t *params_ptr;
    size_t params_len;
    const uint8_t *sk_ptr;
    size_t sk_len;
    const uint8_t *pk_ptr;
    size_t pk_len;
    pqc_asn1_status_t rc;
    size_t written;
} pkcs8_build_ctx_t;

static pqcsb_status_t
pkcs8_build_fill(uint8_t *data, size_t len, void *ctx_ptr)
{
    pkcs8_build_ctx_t *ctx = (pkcs8_build_ctx_t *)ctx_ptr;
    ctx->rc = pqc_asn1_pkcs8_build_write_ex(
        data, len,
        ctx->oid_ptr, ctx->oid_len,
        ctx->params_ptr, ctx->params_len,
        ctx->sk_ptr, ctx->sk_len,
        ctx->pk_ptr, ctx->pk_len,
        &ctx->written);
    return ctx->rc == PQC_ASN1_OK ? PQCSB_OK : PQCSB_ERR_ALLOC;
}

/* ------------------------------------------------------------------ */
/* SecureBuffer input path for build_pkcs8                             */
/*                                                                     */
/* Reads directly from the source SecureBuffer's mmap region via       */
/* begin_read/end_read, avoiding any heap copy of the secret key.      */
/* rb_ensure guarantees end_read even if pqcsb_create_inplace raises.  */
/* ------------------------------------------------------------------ */

typedef struct {
    VALUE          rb_oid_der;
    pqcsb_buf_t   *sk_buf;
    pqcsb_read_guard_t guard;  /* Read access guard to sk_buf */
    VALUE          result;
    pqc_asn1_status_t rc;
    /* Extended fields (NULL/0 when not using keywords). */
    const uint8_t *params_ptr;
    size_t         params_len;
    const uint8_t *pk_ptr;
    size_t         pk_len;
} pkcs8_sb_ctx_t;

static VALUE
pkcs8_sb_build_body(VALUE arg)
{
    pkcs8_sb_ctx_t *ctx = (pkcs8_sb_ctx_t *)arg;
    const uint8_t *oid_ptr = (const uint8_t *)RSTRING_PTR(ctx->rb_oid_der);
    size_t oid_len = (size_t)RSTRING_LEN(ctx->rb_oid_der);

    /* Unified path — _ex handles with or without params/publicKey. */
    size_t total;
    pqc_asn1_status_t rc = pqc_asn1_pkcs8_size_ex(
        oid_ptr, oid_len,
        ctx->params_ptr, ctx->params_len,
        ctx->guard.len, ctx->pk_len, &total);
    if (rc != PQC_ASN1_OK)
        raise_status(rc, NULL);

    pkcs8_build_ctx_t build_ctx = {
        oid_ptr, oid_len,
        ctx->params_ptr, ctx->params_len,
        ctx->guard.data, ctx->guard.len,
        ctx->pk_ptr, ctx->pk_len,
        PQC_ASN1_OK, 0
    };
    ctx->result = pqcsb_rb_create_inplace(pqcsb_class(), total,
                                          pkcs8_build_fill, &build_ctx);
    ctx->rc = build_ctx.rc;
    return Qnil;
}

static VALUE
pkcs8_sb_ensure_end_read(VALUE arg)
{
    pkcs8_sb_ctx_t *ctx = (pkcs8_sb_ctx_t *)arg;
    pqcsb_end_read(&ctx->guard);
    return Qnil;
}

/*
 * DER.build_pkcs8(oid, secret_key, parameters: nil, public_key: nil) -> SecureBuffer
 *
 * parameters: — raw DER-encoded AlgorithmIdentifier parameter bytes
 *   (e.g. "\x05\x00" for NULL), appended after the OID inside the
 *   AlgorithmIdentifier SEQUENCE.
 *
 * public_key: — raw public key bytes for the OneAsymmetricKey v1
 *   publicKey [1] IMPLICIT BIT STRING field (RFC 5958).
 */
static VALUE
rb_der_build_pkcs8(int argc, VALUE *argv, VALUE _self)
{
    VALUE rb_oid, rb_sk, rb_opts;
    rb_scan_args(argc, argv, "2:", &rb_oid, &rb_sk, &rb_opts);

    VALUE rb_oid_der = oid_from_dotted_rb(rb_oid);
    StringValue(rb_oid_der);

    /* Extract optional keyword arguments. */
    VALUE rb_params = Qnil, rb_pubkey = Qnil;
    if (!NIL_P(rb_opts)) {
        static ID kw_params = 0, kw_pubkey = 0;
        if (!kw_params) kw_params = rb_intern("parameters");
        if (!kw_pubkey) kw_pubkey = rb_intern("public_key");
        ID kws[2] = {kw_params, kw_pubkey};
        VALUE vals[2];
        rb_get_kwargs(rb_opts, kws, 0, 2, vals);
        rb_params = (vals[0] == Qundef) ? Qnil : vals[0];
        rb_pubkey = (vals[1] == Qundef) ? Qnil : vals[1];
    }

    const uint8_t *params_ptr = NULL;
    size_t params_len = 0;
    if (!NIL_P(rb_params)) {
        StringValue(rb_params);
        params_ptr = (const uint8_t *)RSTRING_PTR(rb_params);
        params_len = (size_t)RSTRING_LEN(rb_params);
    }

    const uint8_t *pk_ptr = NULL;
    size_t pk_len = 0;
    if (!NIL_P(rb_pubkey)) {
        StringValue(rb_pubkey);
        pk_ptr = (const uint8_t *)RSTRING_PTR(rb_pubkey);
        pk_len = (size_t)RSTRING_LEN(rb_pubkey);
    }

    /* Accept SecureBuffer input: read directly from its mmap region
     * without ever placing secret key material on the Ruby heap. */
    if (rb_obj_is_kind_of(rb_sk, pqcsb_class())) {
        pqcsb_buf_t *sk_buf = (pqcsb_buf_t *)RTYPEDDATA_DATA(rb_sk);
        if (pqcsb_is_wiped(sk_buf))
            rb_raise(rb_eRuntimeError, "SecureBuffer has been wiped");

        pkcs8_sb_ctx_t sb_ctx = {
            rb_oid_der, sk_buf, {NULL, 0, PQCSB_OK, NULL}, Qnil, PQC_ASN1_OK,
            params_ptr, params_len, pk_ptr, pk_len
        };
        sb_ctx.guard = pqcsb_begin_read(sk_buf);
        if (sb_ctx.guard.status != PQCSB_OK)
            rb_raise(rb_eRuntimeError, "pqcsb_begin_read failed");

        rb_ensure(pkcs8_sb_build_body, (VALUE)&sb_ctx,
                  pkcs8_sb_ensure_end_read, (VALUE)&sb_ctx);

        if (sb_ctx.rc != PQC_ASN1_OK) {
            pqcsb_rb_wipe(sb_ctx.result);
            raise_status(sb_ctx.rc, NULL);
        }
        return sb_ctx.result;
    }

    /* String input path — unified via _ex (handles with/without params/publicKey). */
    StringValue(rb_sk);
    const uint8_t *oid_ptr = (const uint8_t *)RSTRING_PTR(rb_oid_der);
    size_t oid_len = (size_t)RSTRING_LEN(rb_oid_der);
    const uint8_t *sk_ptr = (const uint8_t *)RSTRING_PTR(rb_sk);
    size_t sk_len = (size_t)RSTRING_LEN(rb_sk);

    size_t total;
    pqc_asn1_status_t rc = pqc_asn1_pkcs8_size_ex(
        oid_ptr, oid_len, params_ptr, params_len, sk_len, pk_len, &total);
    if (rc != PQC_ASN1_OK)
        raise_status(rc, NULL);

    /* Build PKCS#8 DER directly into the SecureBuffer's mmap-protected
     * region, avoiding a temporary heap buffer that would need separate
     * zeroing.  The fill callback runs with PROT_READ|PROT_WRITE. */
    pkcs8_build_ctx_t build_ctx = {
        oid_ptr, oid_len,
        params_ptr, params_len,
        sk_ptr, sk_len,
        pk_ptr, pk_len,
        PQC_ASN1_OK, 0
    };
    VALUE result = pqcsb_rb_create_inplace(pqcsb_class(), total,
                                           pkcs8_build_fill, &build_ctx);
    if (build_ctx.rc != PQC_ASN1_OK) {
        /* Wipe the SecureBuffer so garbage content doesn't escape if
         * the caller rescues the exception. */
        pqcsb_rb_wipe(result);
        raise_status(build_ctx.rc, NULL);
    }
    return result;
}

/* ------------------------------------------------------------------ */
/* Public parsers                                                      */
/* ------------------------------------------------------------------ */

static VALUE
rb_der_parse_spki(UNUSED VALUE _self, VALUE rb_der)
{
    StringValue(rb_der);
    if (!RB_OBJ_FROZEN_RAW(rb_der) ||
            rb_enc_get(rb_der) != rb_ascii8bit_encoding()) {
        rb_der = rb_str_dup(rb_der);
        rb_enc_associate(rb_der, rb_ascii8bit_encoding());
        rb_obj_freeze(rb_der);
    }
    const uint8_t *oid_der, *alg_params, *pk_bytes;
    size_t oid_len, alg_params_len, pk_len;

    pqc_asn1_status_t rc = pqc_asn1_spki_parse(
        (const uint8_t *)RSTRING_PTR(rb_der), (size_t)RSTRING_LEN(rb_der),
        &oid_der, &oid_len,
        &alg_params, &alg_params_len,
        &pk_bytes, &pk_len,
        0);
    if (rc != PQC_ASN1_OK)
        raise_with_code(pqc_der_error_class(),
                        rb_str_new_cstr(spki_error_message(rc)), rc);

    VALUE oid_tlv = frozen_bin_str((const char *)oid_der, (long)oid_len);
    VALUE oid_val = oid_wrap_rb(oid_to_dotted_rb(oid_tlv));

    VALUE params_val = alg_params && alg_params_len > 0
                         ? frozen_bin_str((const char *)alg_params, (long)alg_params_len)
                         : Qnil;
    VALUE key_val = frozen_bin_str((const char *)pk_bytes, (long)pk_len);

    VALUE args[5] = {oid_val, params_val, key_val, Qnil, ID2SYM(rb_intern("spki"))};
    return rb_class_new_instance(5, args, s_cKeyInfo);
}

/* Context struct for the parse_pkcs8 SecureBuffer use block. */
struct pkcs8_parse_ctx {
    pqc_asn1_status_t  rc;
    VALUE rb_oid_val;
    VALUE rb_params;
    VALUE rb_key;
    VALUE rb_pub;
};

/* rb_block_call callback for SecureBuffer#use in rb_der_parse_pkcs8.
 * Called with rb_bytes = the plaintext DER bytes (temporary mutable String).
 * Parses and copies all data out before returning so #use can zero rb_bytes.
 *
 * GC interaction: this callback allocates Ruby objects (frozen Strings via
 * frozen_bin_str, and a new SecureBuffer via pqcsb_create).  Any of these
 * allocations can trigger GC.  The local VALUE variables (oid_tlv, etc.)
 * are on the C stack and therefore visible to the conservative GC marker,
 * so they are safe.  The ctx struct fields (rb_oid_val, rb_key, etc.) are
 * also on the stack (the struct lives in rb_der_parse_pkcs8's frame) and
 * are visible to GC.  No additional rb_gc_mark or rb_gc_register_address
 * is needed here. */
static VALUE
pkcs8_parse_use_cb(VALUE rb_bytes, VALUE data2,
                   int UNUSED argc, const VALUE UNUSED *argv, VALUE UNUSED blockarg)
{
    struct pkcs8_parse_ctx *ctx = (struct pkcs8_parse_ctx *)data2;
    StringValue(rb_bytes);
    const uint8_t *der_ptr = (const uint8_t *)RSTRING_PTR(rb_bytes);
    size_t der_len = (size_t)RSTRING_LEN(rb_bytes);

    const uint8_t *oid_der, *alg_params, *sk_bytes, *pub_key;
    size_t oid_len, alg_params_len, sk_len, pub_key_len;

    ctx->rc = pqc_asn1_pkcs8_parse(
        der_ptr, der_len,
        &oid_der, &oid_len,
        &alg_params, &alg_params_len,
        &sk_bytes, &sk_len,
        &pub_key, &pub_key_len,
        0);
    if (ctx->rc != PQC_ASN1_OK) return Qnil;

    /* Copy all data before use zeroes rb_bytes. */
    VALUE oid_tlv = frozen_bin_str((const char *)oid_der, (long)oid_len);
    ctx->rb_oid_val = oid_wrap_rb(oid_to_dotted_rb(oid_tlv));
    ctx->rb_params  = alg_params && alg_params_len > 0
                        ? frozen_bin_str((const char *)alg_params, (long)alg_params_len)
                        : Qnil;

    ctx->rb_key = pqcsb_rb_create(pqcsb_class(), sk_bytes, sk_len);

    ctx->rb_pub = pub_key && pub_key_len > 0
                    ? frozen_bin_str((const char *)pub_key, (long)pub_key_len)
                    : Qnil;
    return Qnil;
}

static VALUE
rb_der_parse_pkcs8(UNUSED VALUE _self, VALUE rb_der)
{
    if (rb_obj_is_kind_of(rb_der, pqcsb_class())) {
        /* Access via #use — safe across DSO boundaries. */
        struct pkcs8_parse_ctx ctx = {PQC_ASN1_OK, Qnil, Qnil, Qnil, Qnil};
        rb_block_call(rb_der, rb_intern("use"), 0, NULL,
                      pkcs8_parse_use_cb, (VALUE)&ctx);
        if (ctx.rc != PQC_ASN1_OK)
            raise_with_code(pqc_der_error_class(),
                            rb_str_new_cstr(pkcs8_error_message(ctx.rc)), ctx.rc);

        VALUE args[5] = {ctx.rb_oid_val, ctx.rb_params, ctx.rb_key,
                         ctx.rb_pub, ID2SYM(rb_intern("pkcs8"))};
        return rb_class_new_instance(5, args, s_cKeyInfo);
    }

    /* Plain String input path. */
    StringValue(rb_der);
    if (!RB_OBJ_FROZEN_RAW(rb_der) ||
            rb_enc_get(rb_der) != rb_ascii8bit_encoding()) {
        rb_der = rb_str_dup(rb_der);
        rb_enc_associate(rb_der, rb_ascii8bit_encoding());
        rb_obj_freeze(rb_der);
    }

    const uint8_t *oid_der, *alg_params, *sk_bytes, *pub_key;
    size_t oid_len, alg_params_len, sk_len, pub_key_len;

    pqc_asn1_status_t rc = pqc_asn1_pkcs8_parse(
        (const uint8_t *)RSTRING_PTR(rb_der), (size_t)RSTRING_LEN(rb_der),
        &oid_der, &oid_len,
        &alg_params, &alg_params_len,
        &sk_bytes, &sk_len,
        &pub_key, &pub_key_len,
        0);
    if (rc != PQC_ASN1_OK)
        raise_with_code(pqc_der_error_class(),
                        rb_str_new_cstr(pkcs8_error_message(rc)), rc);

    VALUE oid_tlv = frozen_bin_str((const char *)oid_der, (long)oid_len);
    VALUE oid_val = oid_wrap_rb(oid_to_dotted_rb(oid_tlv));

    VALUE params_val = alg_params && alg_params_len > 0
                         ? frozen_bin_str((const char *)alg_params, (long)alg_params_len)
                         : Qnil;

    VALUE key_val = pqcsb_rb_create(pqcsb_class(), sk_bytes, sk_len);

    VALUE pub_val  = pub_key && pub_key_len > 0
                       ? frozen_bin_str((const char *)pub_key, (long)pub_key_len)
                       : Qnil;

    VALUE args[5] = {oid_val, params_val, key_val, pub_val, ID2SYM(rb_intern("pkcs8"))};
    return rb_class_new_instance(5, args, s_cKeyInfo);
}

/* ------------------------------------------------------------------ */
/* DER.detect_format(der_bytes) -> :spki, :pkcs8, or nil              */
/* ------------------------------------------------------------------ */

/*
 * Skip a DER tag + length field, returning the position just past the
 * value.  Returns 0 on any encoding error or overrun.
 */
static size_t
skip_tlv(const uint8_t *buf, size_t buf_len, size_t pos)
{
    if (pos >= buf_len)
        return 0;
    pos++; /* skip tag byte */
    if (pos >= buf_len)
        return 0;

    size_t value_len;
    if (buf[pos] < 0x80) {
        value_len = buf[pos];
        pos += 1;
    } else {
        size_t len_bytes = buf[pos] & 0x7f;
        if (len_bytes == 0 || len_bytes > 4)
            return 0;
        pos += 1;
        value_len = 0;
        for (size_t i = 0; i < len_bytes; i++) {
            if (pos >= buf_len) return 0;
            value_len = (value_len << 8) | buf[pos++];
        }
    }

    if (pos + value_len > buf_len)
        return 0;
    return pos + value_len;
}

/*
 * Lightweight format detector.  Examines the structure after the
 * outer SEQUENCE to distinguish SPKI, PKCS#8, and EncryptedPKCS#8:
 *
 *   SPKI:             SEQUENCE { SEQUENCE { OID ... } BIT STRING   ... }
 *   Encrypted PKCS#8: SEQUENCE { SEQUENCE { OID ... } OCTET STRING ... }
 *   PKCS#8:           SEQUENCE { INTEGER(v0) AlgId OCTET STRING ... }
 *
 * Returns :spki, :pkcs8, :encrypted_pkcs8, or nil (if unrecognisable).
 */
static VALUE
rb_der_detect_format(UNUSED VALUE _self, VALUE rb_der)
{
    StringValue(rb_der);
    const uint8_t *buf = (const uint8_t *)RSTRING_PTR(rb_der);
    size_t buf_len = (size_t)RSTRING_LEN(rb_der);

    /* Need at least: outer tag(1) + outer length(1+) + inner tag(1). */
    if (buf_len < 3 || buf[0] != 0x30)
        return Qnil;

    /* Skip the outer SEQUENCE's length field to find the first inner tag. */
    size_t pos = 1;
    if (buf[pos] < 0x80) {
        pos += 1; /* short-form length */
    } else {
        size_t len_bytes = buf[pos] & 0x7f;
        if (len_bytes == 0 || len_bytes > 4 || pos + 1 + len_bytes >= buf_len)
            return Qnil;
        pos += 1 + len_bytes;
    }

    if (pos >= buf_len)
        return Qnil;

    uint8_t inner_tag = buf[pos];
    if (inner_tag == 0x02)
        return ID2SYM(rb_intern("pkcs8"));

    if (inner_tag == 0x30) {
        /* Both SPKI and EncryptedPKCS#8 start with SEQUENCE { SEQUENCE ... }.
         * Skip the inner SEQUENCE and peek at the next tag:
         *   BIT STRING (0x03)   → SPKI
         *   OCTET STRING (0x04) → EncryptedPKCS#8
         *   anything else / truncated → nil (ambiguous) */
        size_t after_inner = skip_tlv(buf, buf_len, pos);
        if (after_inner > 0 && after_inner < buf_len) {
            if (buf[after_inner] == 0x03)
                return ID2SYM(rb_intern("spki"));
            if (buf[after_inner] == 0x04)
                return ID2SYM(rb_intern("encrypted_pkcs8"));
        }
        return Qnil;
    }

    return Qnil;
}

/* ------------------------------------------------------------------ */
/* Init                                                                */
/* ------------------------------------------------------------------ */

void
init_der(VALUE mPqcAsn1, VALUE mDER)
{
    s_cKeyInfo = rb_const_get(mDER, rb_intern("KeyInfo"));
    rb_gc_register_address(&s_cKeyInfo);

    rb_define_module_function(mDER, "write_length", rb_der_write_length, 1);
    rb_funcall(mDER, rb_intern("private_class_method"), 1,
               ID2SYM(rb_intern("write_length")));

    rb_define_module_function(mDER, "read_tlv",  rb_der_read_tlv,  3);
    rb_define_module_function(mDER, "write_tlv", rb_der_write_tlv, 2);

    rb_define_module_function(mDER, "build_spki",  rb_der_build_spki,  -1);
    rb_define_module_function(mDER, "build_pkcs8", rb_der_build_pkcs8, -1);
    rb_define_module_function(mDER, "parse_spki",     rb_der_parse_spki,     1);
    rb_define_module_function(mDER, "parse_pkcs8",    rb_der_parse_pkcs8,    1);
    rb_define_module_function(mDER, "detect_format",  rb_der_detect_format,  1);
}
