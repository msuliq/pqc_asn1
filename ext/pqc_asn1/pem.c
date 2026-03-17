/*
 * pem.c — PqcAsn1::PEM module method implementations.
 *
 * Wraps the C library's RFC 7468 PEM encoder/decoder.  Accepts both
 * String and SecureBuffer as input to encode, so callers can pass a
 * PKCS#8 SecureBuffer directly without first calling .to_s.
 *
 * SecureBuffer interaction
 * ========================
 * SecureBuffer is defined in the same extension (secure_buffer.c), so
 * TypedData_Get_Struct is safe.  pqcsb_begin_read / pqcsb_end_read
 * temporarily lift the mprotect read-guard around the data pages.
 *
 * pqc_asn1_pem_encode (and the decode functions) internally allocate
 * output buffers via PQC_ASN1_MALLOC = ruby_xmalloc.  Under memory
 * pressure, ruby_xmalloc raises NoMemoryError before the C function
 * returns, skipping any cleanup after the call site.  All paths that
 * hold a heap-allocated C buffer or a SecureBuffer in PROT_READ state
 * therefore use rb_ensure so those resources are released regardless
 * of whether an exception is raised.
 */

#include "shared.h"
#include "error.h"
#include "secure_buffer.h"

/* ------------------------------------------------------------------ */
/* File-static handles                                                 */
/* ------------------------------------------------------------------ */

static VALUE s_cPemDecodeResult;

/* ------------------------------------------------------------------ */
/* Ensure helpers — exception-safe cleanup for heap C buffers         */
/* ------------------------------------------------------------------ */

/*
 * pem_decoded_ctx_t — wraps a heap-allocated decoded-bytes buffer.
 *
 * pem_decoded_build_body copies the buffer into a frozen Ruby String
 * (ctx->result).  pem_decoded_cleanup always zeros and frees the buffer,
 * whether the body succeeded or raised.
 *
 * Usage:
 *   pem_decoded_ctx_t ctx = {decoded_ptr, out_len, Qnil};
 *   rb_ensure(pem_decoded_build_body, (VALUE)&ctx,
 *             pem_decoded_cleanup,    (VALUE)&ctx);
 *   VALUE data = ctx.result;   // valid only after normal return
 */
typedef struct {
    uint8_t *buf;
    size_t   len;
    VALUE    result;
} pem_decoded_ctx_t;

static VALUE
pem_decoded_build_body(VALUE arg)
{
    pem_decoded_ctx_t *ctx = (pem_decoded_ctx_t *)arg;
    ctx->result = frozen_bin_str((const char *)ctx->buf, (long)ctx->len);
    return Qnil;
}

static VALUE
pem_decoded_cleanup(VALUE arg)
{
    pem_decoded_ctx_t *ctx = (pem_decoded_ctx_t *)arg;
    if (ctx->buf) {
        pqc_asn1_secure_zero(ctx->buf, ctx->len);
        ruby_xfree(ctx->buf);
        ctx->buf = NULL;
    }
    return Qnil;
}

/*
 * pem_encode_sb_ctx_t — SecureBuffer encode context.
 *
 * pem_encode_sb_body calls pqc_asn1_pem_encode with the SecureBuffer's
 * data pointer (valid only inside begin_read/end_read).
 * pem_encode_sb_cleanup always calls pqcsb_end_read to restore guard
 * pages even when pqc_asn1_pem_encode raises via ruby_xmalloc.  On
 * exception paths it also frees any partially-allocated pem_buf.
 */
typedef struct {
    pqcsb_buf_t *sb;
    const char  *label;
    size_t       label_len;
    char        *pem_buf;
    size_t       pem_len;
    pqc_asn1_status_t rc;
} pem_encode_sb_ctx_t;

static VALUE
pem_encode_sb_body(VALUE arg)
{
    pem_encode_sb_ctx_t *ctx = (pem_encode_sb_ctx_t *)arg;
    ctx->rc = pqc_asn1_pem_encode(
        ctx->sb->data, ctx->sb->len,
        ctx->label, ctx->label_len,
        &ctx->pem_buf, &ctx->pem_len);
    return Qnil;
}

static VALUE
pem_encode_sb_cleanup(VALUE arg)
{
    pem_encode_sb_ctx_t *ctx = (pem_encode_sb_ctx_t *)arg;
    /* Always restore mprotect — this is the primary purpose of rb_ensure here. */
    pqcsb_end_read(ctx->sb);
    /* On exception paths pem_buf may have been allocated inside
     * pqc_asn1_pem_encode before ruby_xmalloc raised NoMemoryError.
     * Zero and free it here to prevent leaking PEM-encoded key material.
     *
     * Safety of rb_errinfo() check: the body function only calls
     * pqc_asn1_pem_encode, so pem_buf is non-NULL on the normal path
     * (needed by the caller after rb_ensure) and must NOT be freed.
     * On exception paths, rb_errinfo() is non-nil and we free pem_buf.
     * If this body is ever refactored to do more work, consider
     * restructuring to avoid reliance on rb_errinfo(). */
    if (rb_errinfo() != Qnil && ctx->pem_buf) {
        pqc_asn1_secure_zero(ctx->pem_buf, ctx->pem_len);
        ruby_xfree(ctx->pem_buf);
        ctx->pem_buf = NULL;
    }
    return Qnil;
}

/*
 * pem_str_ctx_t — copies a C pem_buf into a Ruby String then zeros+frees it.
 *
 * pem_str_body calls rb_str_new (which can raise NoMemoryError).
 * pem_str_cleanup always zeros and frees pem_buf so PEM-encoded key
 * material is not left dangling in the C heap if String construction fails.
 */
typedef struct {
    char  *buf;
    size_t len;
    VALUE  result;
} pem_str_ctx_t;

static VALUE
pem_str_body(VALUE arg)
{
    pem_str_ctx_t *ctx = (pem_str_ctx_t *)arg;
    ctx->result = rb_str_new(ctx->buf, (long)ctx->len);
    return Qnil;
}

static VALUE
pem_str_cleanup(VALUE arg)
{
    pem_str_ctx_t *ctx = (pem_str_ctx_t *)arg;
    if (ctx->buf) {
        pqc_asn1_secure_zero(ctx->buf, ctx->len);
        ruby_xfree(ctx->buf);
        ctx->buf = NULL;
    }
    return Qnil;
}

/* ------------------------------------------------------------------ */
/* PqcAsn1::PEM.decode(pem_string, expected_label) -> String          */
/* ------------------------------------------------------------------ */

static VALUE
rb_pem_decode(UNUSED VALUE _self, VALUE rb_pem, VALUE rb_label)
{
    StringValue(rb_pem);
    StringValue(rb_label);
    size_t   out_len;
    char     found_label[PQC_ASN1_MAX_PEM_LABEL_LEN + 1];
    uint8_t *decoded;

    pqc_asn1_status_t rc = pqc_asn1_pem_decode(
        RSTRING_PTR(rb_pem),   (size_t)RSTRING_LEN(rb_pem),
        RSTRING_PTR(rb_label), (size_t)RSTRING_LEN(rb_label),
        &decoded, &out_len, found_label, sizeof(found_label));
    if (rc != PQC_ASN1_OK) {
        if (rc == PQC_ASN1_ERR_PEM_LABEL)
            raise_with_code(pqc_pem_error_class(),
                     rb_sprintf("PEM parse error: expected label \"%s\", got \"%s\"",
                                RSTRING_PTR(rb_label), found_label),
                     rc);
        if (rc == PQC_ASN1_ERR_PEM_NO_MARKERS)
            raise_with_code(pqc_pem_error_class(),
                     rb_str_new_cstr("PEM parse error: no valid PEM markers found"), rc);
        if (rc == PQC_ASN1_ERR_BASE64 || rc == PQC_ASN1_ERR_PEM_MALFORMED)
            raise_with_code(pqc_pem_error_class(),
                     rb_str_new_cstr("PEM parse error: invalid Base64 in PEM body"), rc);
        raise_status(rc, "PEM decode");
    }

    /* Copy decoded bytes into a frozen Ruby String, then zero+free the C buffer.
     * rb_ensure guarantees cleanup even when frozen_bin_str raises NoMemoryError. */
    pem_decoded_ctx_t cleanup = {decoded, out_len, Qnil};
    rb_ensure(pem_decoded_build_body, (VALUE)&cleanup,
              pem_decoded_cleanup,    (VALUE)&cleanup);
    return cleanup.result;
}

/* ------------------------------------------------------------------ */
/* PqcAsn1::PEM.decode_auto(pem_string) -> PEM::DecodeResult          */
/* ------------------------------------------------------------------ */

static VALUE
rb_pem_decode_auto(UNUSED VALUE _self, VALUE rb_pem)
{
    StringValue(rb_pem);
    size_t   out_len;
    char     found_label[PQC_ASN1_MAX_PEM_LABEL_LEN + 1];
    uint8_t *decoded;

    pqc_asn1_status_t rc = pqc_asn1_pem_decode_auto(
        RSTRING_PTR(rb_pem), (size_t)RSTRING_LEN(rb_pem),
        &decoded, &out_len, found_label, sizeof(found_label));
    if (rc != PQC_ASN1_OK) {
        if (rc == PQC_ASN1_ERR_PEM_NO_MARKERS)
            raise_with_code(pqc_pem_error_class(),
                     rb_str_new_cstr("PEM parse error: no valid PEM markers found"), rc);
        if (rc == PQC_ASN1_ERR_BASE64 || rc == PQC_ASN1_ERR_PEM_MALFORMED)
            raise_with_code(pqc_pem_error_class(),
                     rb_str_new_cstr("PEM parse error: invalid Base64 in PEM body"), rc);
        raise_status(rc, "PEM decode");
    }

    pem_decoded_ctx_t cleanup = {decoded, out_len, Qnil};
    rb_ensure(pem_decoded_build_body, (VALUE)&cleanup,
              pem_decoded_cleanup,    (VALUE)&cleanup);
    VALUE data = cleanup.result;

    VALUE label = rb_str_new_cstr(found_label);
    rb_enc_associate(label, rb_usascii_encoding());
    rb_obj_freeze(label);

    VALUE args[2] = {data, label};
    return rb_class_new_instance(2, args, s_cPemDecodeResult);
}

/* ------------------------------------------------------------------ */
/* PqcAsn1::PEM.encode(der_bytes, label) -> String (US-ASCII)         */
/*                                                                     */
/* Security caveat: when der_bytes is a SecureBuffer (e.g. a PKCS#8   */
/* private key), the returned PEM String is an ordinary Ruby String    */
/* on the heap — NOT a SecureBuffer.  The PEM text is therefore not    */
/* mmap-protected, not mlock'd, and may be swapped to disk or copied  */
/* by the GC compactor.  Callers that require the PEM only for I/O    */
/* (e.g. writing to a file) should overwrite / discard the String as  */
/* soon as possible to limit exposure of secret key material.          */
/* ------------------------------------------------------------------ */

static VALUE
rb_pem_encode(UNUSED VALUE _self, VALUE rb_der, VALUE rb_label)
{
    StringValue(rb_label);
    const char *label     = RSTRING_PTR(rb_label);
    size_t      label_len = (size_t)RSTRING_LEN(rb_label);

    char  *pem_buf = NULL;
    size_t pem_len = 0;
    pqc_asn1_status_t rc;

    if (rb_obj_is_kind_of(rb_der, pqcsb_class())) {
        /* SecureBuffer input: use rb_ensure to restore PROT_NONE even when
         * pqc_asn1_pem_encode raises via ruby_xmalloc under memory pressure. */
        pqcsb_buf_t *sb;
        TypedData_Get_Struct(rb_der, pqcsb_buf_t, &pqcsb_buf_type, sb);
        if (sb->wiped)
            rb_raise(rb_eRuntimeError, "SecureBuffer has been wiped");

        pem_encode_sb_ctx_t ctx = {sb, label, label_len, NULL, 0, PQC_ASN1_OK};
        pqcsb_begin_read(sb);
        rb_ensure(pem_encode_sb_body, (VALUE)&ctx,
                  pem_encode_sb_cleanup, (VALUE)&ctx);
        rc      = ctx.rc;
        pem_buf = ctx.pem_buf;
        pem_len = ctx.pem_len;
    } else {
        StringValue(rb_der);
        const uint8_t *der     = (const uint8_t *)RSTRING_PTR(rb_der);
        size_t         der_len = (size_t)RSTRING_LEN(rb_der);
        rc = pqc_asn1_pem_encode(der, der_len, label, label_len,
                                  &pem_buf, &pem_len);
    }

    if (rc != PQC_ASN1_OK) {
        /* Free any partially-allocated pem_buf before raising. */
        if (pem_buf) {
            pqc_asn1_secure_zero(pem_buf, pem_len);
            ruby_xfree(pem_buf);
        }
        raise_status(rc, "PEM encode");
    }

    /* Copy pem_buf into a Ruby String, then zero+free it.  rb_ensure
     * guarantees cleanup even when rb_str_new raises NoMemoryError. */
    pem_str_ctx_t str_ctx = {pem_buf, pem_len, Qnil};
    rb_ensure(pem_str_body, (VALUE)&str_ctx, pem_str_cleanup, (VALUE)&str_ctx);

    VALUE result = str_ctx.result;

    rb_enc_associate(result, rb_usascii_encoding());
    rb_obj_freeze(result);
    return result;
}

/* ------------------------------------------------------------------ */
/* PqcAsn1::PEM.decode_each(input) { |result| } -> nil or Enumerator  */
/* ------------------------------------------------------------------ */

/*
 * pem_find — locate the first occurrence of needle in haystack using
 * memmem(3) when available (glibc / macOS / FreeBSD / POSIX.1-2024) or
 * a portable O(n*m) fallback otherwise.
 */
static const char *
pem_find(const char *haystack, size_t hlen,
         const char *needle,   size_t nlen)
{
    if (nlen == 0) return haystack;
    if (hlen < nlen) return NULL;
#ifdef HAVE_MEMMEM
    return (const char *)memmem(haystack, hlen, needle, nlen);
#else
    const char *end = haystack + hlen - nlen;
    for (const char *p = haystack; p <= end; p++) {
        if (memcmp(p, needle, nlen) == 0) return p;
    }
    return NULL;
#endif
}

/*
 * Single-pass C implementation of decode_each.  Scans for -----BEGIN ...-----
 * markers using memmem (O(n) per block instead of the previous O(n*m) nested
 * memcmp loops), extracts each PEM block, decodes via pqc_asn1_pem_decode_auto,
 * and yields a DecodeResult for each block found.
 */
static VALUE
rb_pem_decode_each(int argc, VALUE *argv, VALUE self)
{
    VALUE rb_input;
    rb_scan_args(argc, argv, "1", &rb_input);

    /* IO objects are handled incrementally by the Ruby wrapper in
     * lib/pqc_asn1.rb — by the time we reach here, rb_input is always
     * a String.  The old slurp path is kept as a fallback for any
     * IO-like object that bypasses the Ruby wrapper. */
    if (rb_respond_to(rb_input, rb_intern("read")))
        rb_input = rb_funcall(rb_input, rb_intern("read"), 0);

    StringValue(rb_input);

    if (!rb_block_given_p()) {
        /* Return an Enumerator wrapping this method + args. */
        return rb_enumeratorize(self, ID2SYM(rb_intern("decode_each")),
                                1, &rb_input);
    }

    const char *text     = RSTRING_PTR(rb_input);
    size_t      text_len = (size_t)RSTRING_LEN(rb_input);
    size_t      pos      = 0;

    static const char begin_prefix[] = "-----BEGIN ";
    static const char dashes[]       = "-----";
    enum { BEGIN_PREFIX_LEN = 11, DASHES_LEN = 5, END_PREFIX_LEN = 9 };

    while (pos < text_len) {
        /* O(n): find the next "-----BEGIN " using memmem / fallback. */
        const char *start = pem_find(text + pos, text_len - pos,
                                     begin_prefix, BEGIN_PREFIX_LEN);
        if (!start) break;

        /* Find the closing "-----" that terminates the BEGIN line. */
        const char *label_start = start + BEGIN_PREFIX_LEN;
        size_t      label_area  = text_len - (size_t)(label_start - text);
        const char *label_end   = pem_find(label_start, label_area,
                                            dashes, DASHES_LEN);
        if (!label_end) break;

        size_t label_len = (size_t)(label_end - label_start);
        if (label_len == 0 || label_len > PQC_ASN1_MAX_PEM_LABEL_LEN) {
            pos = (size_t)(label_end + DASHES_LEN - text);
            continue;
        }

        /* Build "-----END <label>-----" and find it. */
        char   end_marker[END_PREFIX_LEN + PQC_ASN1_MAX_PEM_LABEL_LEN + DASHES_LEN + 1];
        size_t end_marker_len = (size_t)snprintf(end_marker, sizeof(end_marker),
                                                  "-----END %.*s-----",
                                                  (int)label_len, label_start);

        const char *search_from = label_end + DASHES_LEN;
        size_t      search_len  = text_len - (size_t)(search_from - text);
        const char *end_found   = pem_find(search_from, search_len,
                                            end_marker, end_marker_len);
        if (!end_found) break;

        const char *block_end = end_found + end_marker_len;
        size_t      block_len = (size_t)(block_end - start);

        /* Decode this PEM block via pqc_asn1_pem_decode_auto. */
        size_t   out_len;
        char     found_label[PQC_ASN1_MAX_PEM_LABEL_LEN + 1];
        uint8_t *decoded;

        pqc_asn1_status_t rc = pqc_asn1_pem_decode_auto(
            start, block_len, &decoded, &out_len,
            found_label, sizeof(found_label));

        if (rc == PQC_ASN1_OK) {
            /* rb_ensure guarantees the decoded buffer is zeroed+freed even
             * when frozen_bin_str raises NoMemoryError. */
            pem_decoded_ctx_t dec_cleanup = {decoded, out_len, Qnil};
            rb_ensure(pem_decoded_build_body, (VALUE)&dec_cleanup,
                      pem_decoded_cleanup,    (VALUE)&dec_cleanup);
            VALUE data = dec_cleanup.result;

            VALUE lbl = rb_str_new_cstr(found_label);
            rb_enc_associate(lbl, rb_usascii_encoding());
            rb_obj_freeze(lbl);

            VALUE args[2] = {data, lbl};
            VALUE result  = rb_class_new_instance(2, args, s_cPemDecodeResult);
            rb_yield(result);
        }
        /* Malformed inner blocks are silently skipped; only valid blocks yield. */

        pos = (size_t)(block_end - text);
    }

    return Qnil;
}

/* ------------------------------------------------------------------ */
/* Init                                                                */
/* ------------------------------------------------------------------ */

void
init_pem(VALUE mPqcAsn1)
{
    /* PEM module and DecodeResult class are defined in lib/pqc_asn1.rb
     * before this extension loads — look them up rather than redefining. */
    VALUE mPEM        = rb_const_get(mPqcAsn1, rb_intern("PEM"));
    s_cPemDecodeResult = rb_const_get(mPEM, rb_intern("DecodeResult"));
    rb_gc_register_address(&s_cPemDecodeResult);

    rb_define_module_function(mPEM, "encode",      rb_pem_encode,      2);
    rb_define_module_function(mPEM, "decode",      rb_pem_decode,      2);
    rb_define_module_function(mPEM, "decode_auto", rb_pem_decode_auto, 1);
    rb_define_module_function(mPEM, "decode_each", rb_pem_decode_each, -1);
}
