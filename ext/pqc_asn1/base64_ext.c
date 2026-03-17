/*
 * base64_ext.c — PqcAsn1::Base64 module method implementations.
 *
 * Wraps the C library's RFC 4648 Base64 encoder/decoder with PEM-style
 * 64-char line wrapping.  Replaces the previous pure-Ruby implementation
 * with a single authoritative codec shared by both Base64 and PEM modules.
 */

#include "shared.h"
#include "error.h"

/* ------------------------------------------------------------------ */
/* PqcAsn1::Base64.encode(data) -> String (US-ASCII, frozen)          */
/* ------------------------------------------------------------------ */

static VALUE
rb_base64_encode(UNUSED VALUE _self, VALUE rb_data)
{
    StringValue(rb_data);
    const uint8_t *data = (const uint8_t *)RSTRING_PTR(rb_data);
    size_t data_len = (size_t)RSTRING_LEN(rb_data);

    /* Empty input → empty output. */
    if (data_len == 0) {
        VALUE empty = rb_str_new("", 0);
        rb_enc_associate(empty, rb_usascii_encoding());
        rb_obj_freeze(empty);
        return empty;
    }

    char *out_buf = NULL;
    size_t out_len = 0;
    pqc_asn1_status_t rc = pqc_asn1_base64_encode(
        data, data_len, &out_buf, &out_len);
    if (rc != PQC_ASN1_OK) {
        if (out_buf) ruby_xfree(out_buf);
        raise_status(rc, "Base64 encode");
    }

    /* Strip trailing newline if present — the Ruby API contract is
     * "no trailing newline after the final (possibly partial) line". */
    while (out_len > 0 && out_buf[out_len - 1] == '\n')
        out_len--;

    VALUE result = rb_str_new(out_buf, (long)out_len);
    ruby_xfree(out_buf);
    rb_enc_associate(result, rb_usascii_encoding());
    rb_obj_freeze(result);
    return result;
}

/* ------------------------------------------------------------------ */
/* PqcAsn1::Base64.decode(b64) -> String (ASCII-8BIT, frozen)         */
/* ------------------------------------------------------------------ */

static VALUE
rb_base64_decode(UNUSED VALUE _self, VALUE rb_b64)
{
    StringValue(rb_b64);
    const char *b64 = RSTRING_PTR(rb_b64);
    size_t b64_len = (size_t)RSTRING_LEN(rb_b64);

    /* Empty input → empty output. */
    if (b64_len == 0) {
        VALUE empty = rb_str_new("", 0);
        rb_enc_associate(empty, rb_ascii8bit_encoding());
        rb_obj_freeze(empty);
        return empty;
    }

    uint8_t *out_buf = NULL;
    size_t out_len = 0;
    pqc_asn1_status_t rc = pqc_asn1_base64_decode(
        b64, b64_len, &out_buf, &out_len);
    if (rc != PQC_ASN1_OK) {
        if (out_buf) ruby_xfree(out_buf);
        raise_with_code(pqc_pem_error_class(),
            rb_str_new_cstr("invalid Base64 input"), rc);
    }

    VALUE result = frozen_bin_str((const char *)out_buf, (long)out_len);
    ruby_xfree(out_buf);
    return result;
}

/* ------------------------------------------------------------------ */
/* Init                                                                */
/* ------------------------------------------------------------------ */

void
init_base64(VALUE mPqcAsn1)
{
    VALUE mBase64 = rb_const_get(mPqcAsn1, rb_intern("Base64"));
    rb_define_module_function(mBase64, "encode", rb_base64_encode, 1);
    rb_define_module_function(mBase64, "decode", rb_base64_decode, 1);
}
