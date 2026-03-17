/*
 * cursor.c — PqcAsn1::DER::Cursor TypedData implementation.
 *
 * Cursor is a zero-copy DER reader.  It holds a reference to the source
 * Ruby String (preventing GC) and a C pointer + length into it.  Read
 * operations advance an internal position without allocating new buffers.
 *
 * read_sequence returns a new Cursor scoped to the SEQUENCE content,
 * sharing the same source reference — still zero-copy.
 *
 * read_raw returns the full TLV bytes (tag + length + value) at the
 * current position, then advances past them.  Useful for forwarding an
 * opaque field without interpreting its contents.
 *
 * Cursor is a public API under DER:: for callers that need fine-grained
 * DER traversal beyond what parse_spki / parse_pkcs8 expose.
 */

#include "shared.h"
#include "error.h"

/* ------------------------------------------------------------------ */
/* File-static class handle                                            */
/* ------------------------------------------------------------------ */

static VALUE s_cCursor;

/* ------------------------------------------------------------------ */
/* TypedData bookkeeping                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    VALUE source;      /* keeps the source string alive during GC mark */
    const uint8_t *buf;
    size_t buf_len;
    size_t pos;
} pqc_cursor_t;

static void
cursor_dmark(void *ptr)
{
    pqc_cursor_t *c = (pqc_cursor_t *)ptr;
    rb_gc_mark(c->source);
}

static void
cursor_dfree(void *ptr)
{
    ruby_xfree(ptr);
}

static size_t
cursor_dsize(UNUSED const void *ptr)
{
    return sizeof(pqc_cursor_t);
}

static const rb_data_type_t cursor_type = {
    .wrap_struct_name = "PqcAsn1::DER::Cursor",
    .function = {
        .dmark = cursor_dmark,
        .dfree = cursor_dfree,
        .dsize = cursor_dsize,
    },
    .flags = RUBY_TYPED_FREE_IMMEDIATELY,
};

/* ------------------------------------------------------------------ */
/* Allocation helpers                                                  */
/* ------------------------------------------------------------------ */

static VALUE
cursor_alloc(VALUE klass)
{
    pqc_cursor_t *c;
    VALUE obj = TypedData_Make_Struct(klass, pqc_cursor_t, &cursor_type, c);
    c->source  = Qnil;
    c->buf     = NULL;
    c->buf_len = 0;
    c->pos     = 0;
    return obj;
}

/* Internal: create a sub-cursor scoped to a content region of an
 * existing cursor's source (used by read_sequence). */
static VALUE
cursor_from_content(const uint8_t *content, size_t content_len, VALUE source)
{
    VALUE obj = cursor_alloc(s_cCursor);
    pqc_cursor_t *c;
    TypedData_Get_Struct(obj, pqc_cursor_t, &cursor_type, c);
    c->source  = source;
    c->buf     = content;
    c->buf_len = content_len;
    c->pos     = 0;
    return obj;
}

/* ------------------------------------------------------------------ */
/* Ruby methods                                                        */
/* ------------------------------------------------------------------ */

/* Cursor.new(data, pos = 0) */
static VALUE
cursor_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE rb_data, rb_pos;
    rb_scan_args(argc, argv, "11", &rb_data, &rb_pos);
    StringValue(rb_data);

    /* Normalise to frozen ASCII-8BIT so the pointer stays stable. */
    if (rb_enc_get(rb_data) != rb_ascii8bit_encoding() || !RB_OBJ_FROZEN_RAW(rb_data)) {
        rb_data = rb_str_dup(rb_data);
        rb_enc_associate(rb_data, rb_ascii8bit_encoding());
        rb_obj_freeze(rb_data);
    }

    pqc_cursor_t *c;
    TypedData_Get_Struct(self, pqc_cursor_t, &cursor_type, c);
    c->source  = rb_data;
    c->buf     = (const uint8_t *)RSTRING_PTR(rb_data);
    c->buf_len = (size_t)RSTRING_LEN(rb_data);
    if (!NIL_P(rb_pos)) {
        long pos_signed = NUM2LONG(rb_pos);
        if (pos_signed < 0)
            rb_raise(rb_eArgError, "pos must be >= 0");
        c->pos = (size_t)pos_signed;
    } else {
        c->pos = 0;
    }
    if (c->pos > c->buf_len)
        rb_raise(rb_eArgError,
                 "pos (%zu) exceeds data length (%zu)", c->pos, c->buf_len);
    return self;
}

/* Cursor#read(expected_tag) -> String (frozen binary content bytes, no TLV wrapper) */
static VALUE
cursor_read(VALUE self, VALUE rb_tag)
{
    pqc_cursor_t *c;
    TypedData_Get_Struct(self, pqc_cursor_t, &cursor_type, c);
    uint8_t tag = (uint8_t)NUM2INT(rb_tag);
    const uint8_t *content;
    size_t content_len;

    size_t pos_before = c->pos;
    pqc_asn1_status_t rc = pqc_asn1_der_read_tlv(
        c->buf, c->buf_len, &c->pos, tag, &content, &content_len);
    if (rc != PQC_ASN1_OK)
        raise_with_code_and_offset(pqc_der_error_class(),
                 rb_sprintf("DER parse error: expected tag 0x%02x at offset %lu",
                             tag, (unsigned long)pos_before),
                 rc, pos_before);

    /* Zero-copy: return a frozen substring of the source when possible. */
    if (c->source != Qnil && RB_TYPE_P(c->source, T_STRING)) {
        const char *src_ptr = RSTRING_PTR(c->source);
        long src_len = RSTRING_LEN(c->source);
        long offset = (long)((const char *)content - src_ptr);

        if (offset >= 0 && offset + (long)content_len <= src_len) {
            VALUE sub = rb_str_substr(c->source, offset, (long)content_len);
            rb_enc_associate(sub, rb_ascii8bit_encoding());
            rb_obj_freeze(sub);
            return sub;
        }
    }

    return frozen_bin_str((const char *)content, (long)content_len);
}

/* Cursor#read_optional(expected_tag) -> String or nil
 * Returns nil if at EOF or if the next tag does not match, without
 * raising an exception.  Useful for parsing optional DER fields like
 * the OneAsymmetricKey publicKey [1] IMPLICIT. */
static VALUE
cursor_read_optional(VALUE self, VALUE rb_tag)
{
    pqc_cursor_t *c;
    TypedData_Get_Struct(self, pqc_cursor_t, &cursor_type, c);

    if (c->pos >= c->buf_len)
        return Qnil;
    uint8_t tag = (uint8_t)NUM2INT(rb_tag);
    if (c->buf[c->pos] != tag)
        return Qnil;

    return cursor_read(self, rb_tag);
}

/* Cursor#read_raw(expected_tag) -> String (frozen binary TLV: tag + length + value) */
static VALUE
cursor_read_raw(VALUE self, VALUE rb_tag)
{
    pqc_cursor_t *c;
    TypedData_Get_Struct(self, pqc_cursor_t, &cursor_type, c);
    uint8_t tag = (uint8_t)NUM2INT(rb_tag);
    size_t start = c->pos;
    const uint8_t *content;
    size_t content_len;

    pqc_asn1_status_t rc = pqc_asn1_der_read_tlv(
        c->buf, c->buf_len, &c->pos, tag, &content, &content_len);
    if (rc != PQC_ASN1_OK)
        raise_with_code_and_offset(pqc_der_error_class(),
                 rb_sprintf("DER parse error: expected tag 0x%02x at offset %lu",
                             tag, (unsigned long)start),
                 rc, start);

    /* Zero-copy: return a frozen substring of the source when possible. */
    long tlv_len = (long)(c->pos - start);
    if (c->source != Qnil && RB_TYPE_P(c->source, T_STRING)) {
        const char *src_ptr = RSTRING_PTR(c->source);
        long src_len = RSTRING_LEN(c->source);
        long offset = (long)((const char *)(c->buf + start) - src_ptr);

        if (offset >= 0 && offset + tlv_len <= src_len) {
            VALUE sub = rb_str_substr(c->source, offset, tlv_len);
            rb_enc_associate(sub, rb_ascii8bit_encoding());
            rb_obj_freeze(sub);
            return sub;
        }
    }

    return frozen_bin_str((const char *)(c->buf + start), tlv_len);
}

/* Cursor#read_sequence -> new Cursor over SEQUENCE content */
static VALUE
cursor_read_sequence(VALUE self)
{
    pqc_cursor_t *c;
    TypedData_Get_Struct(self, pqc_cursor_t, &cursor_type, c);
    const uint8_t *content;
    size_t content_len;

    size_t pos_before = c->pos;
    pqc_asn1_status_t rc = pqc_asn1_der_read_tlv(
        c->buf, c->buf_len, &c->pos, 0x30, &content, &content_len);
    if (rc != PQC_ASN1_OK)
        raise_with_code_and_offset(pqc_der_error_class(),
                 rb_sprintf("DER parse error: expected SEQUENCE (0x30) at offset %lu",
                             (unsigned long)pos_before),
                 rc, pos_before);

    return cursor_from_content(content, content_len, c->source); /* returns DER::Cursor */
}

static VALUE cursor_read_integer(VALUE self)      { return cursor_read(self, INT2FIX(0x02)); }
static VALUE cursor_read_oid(VALUE self)           { return cursor_read(self, INT2FIX(0x06)); }
static VALUE cursor_read_octet_string(VALUE self)  { return cursor_read(self, INT2FIX(0x04)); }
static VALUE cursor_read_bit_string(VALUE self)    { return cursor_read(self, INT2FIX(0x03)); }

/* Cursor#skip(expected_tag) -> self */
static VALUE
cursor_skip(VALUE self, VALUE rb_tag)
{
    pqc_cursor_t *c;
    TypedData_Get_Struct(self, pqc_cursor_t, &cursor_type, c);
    uint8_t tag = (uint8_t)NUM2INT(rb_tag);
    size_t pos_before = c->pos;
    const uint8_t *content;
    size_t content_len;

    pqc_asn1_status_t rc = pqc_asn1_der_read_tlv(
        c->buf, c->buf_len, &c->pos, tag, &content, &content_len);
    if (rc != PQC_ASN1_OK)
        raise_with_code_and_offset(pqc_der_error_class(),
                 rb_sprintf("DER parse error: expected tag 0x%02x at offset %lu",
                             tag, (unsigned long)pos_before),
                 rc, pos_before);

    return self;
}

/* Cursor#skip_optional(expected_tag) -> self or nil
 * Like skip but returns nil (without advancing) if EOF or tag mismatch. */
static VALUE
cursor_skip_optional(VALUE self, VALUE rb_tag)
{
    pqc_cursor_t *c;
    TypedData_Get_Struct(self, pqc_cursor_t, &cursor_type, c);

    if (c->pos >= c->buf_len)
        return Qnil;
    uint8_t tag = (uint8_t)NUM2INT(rb_tag);
    if (c->buf[c->pos] != tag)
        return Qnil;

    return cursor_skip(self, rb_tag);
}

/* Cursor#read_raw_optional(expected_tag) -> String or nil
 * Like read_raw but returns nil (without advancing) if EOF or tag mismatch. */
static VALUE
cursor_read_raw_optional(VALUE self, VALUE rb_tag)
{
    pqc_cursor_t *c;
    TypedData_Get_Struct(self, pqc_cursor_t, &cursor_type, c);

    if (c->pos >= c->buf_len)
        return Qnil;
    uint8_t tag = (uint8_t)NUM2INT(rb_tag);
    if (c->buf[c->pos] != tag)
        return Qnil;

    return cursor_read_raw(self, rb_tag);
}

/* Cursor#peek_tag -> Integer or nil */
static VALUE
cursor_peek_tag(VALUE self)
{
    pqc_cursor_t *c;
    TypedData_Get_Struct(self, pqc_cursor_t, &cursor_type, c);
    if (c->pos >= c->buf_len)
        return Qnil;
    return INT2FIX(c->buf[c->pos]);
}

static VALUE
cursor_eof_p(VALUE self)
{
    pqc_cursor_t *c;
    TypedData_Get_Struct(self, pqc_cursor_t, &cursor_type, c);
    return c->pos >= c->buf_len ? Qtrue : Qfalse;
}

static VALUE
cursor_remaining(VALUE self)
{
    pqc_cursor_t *c;
    TypedData_Get_Struct(self, pqc_cursor_t, &cursor_type, c);
    return SIZET2NUM(c->buf_len - c->pos);
}

static VALUE
cursor_pos(VALUE self)
{
    pqc_cursor_t *c;
    TypedData_Get_Struct(self, pqc_cursor_t, &cursor_type, c);
    return SIZET2NUM(c->pos);
}

static VALUE
cursor_data(VALUE self)
{
    pqc_cursor_t *c;
    TypedData_Get_Struct(self, pqc_cursor_t, &cursor_type, c);

    /* If the cursor's buf points into the source string at an offset
     * (e.g. a sub-cursor from read_sequence), return a frozen substring.
     * Otherwise return the source directly — true zero-copy. */
    if (c->source != Qnil && RB_TYPE_P(c->source, T_STRING)) {
        const char *src_ptr = RSTRING_PTR(c->source);
        long src_len = RSTRING_LEN(c->source);
        long offset = (long)((const char *)c->buf - src_ptr);

        if (offset >= 0 && offset + (long)c->buf_len <= src_len) {
            if (offset == 0 && (long)c->buf_len == src_len)
                return c->source; /* exact match — return source as-is */
            VALUE sub = rb_str_substr(c->source, offset, (long)c->buf_len);
            rb_enc_associate(sub, rb_ascii8bit_encoding());
            rb_obj_freeze(sub);
            return sub;
        }
    }

    /* Fallback: copy (should not normally happen). */
    return frozen_bin_str((const char *)c->buf, (long)c->buf_len);
}

/* ------------------------------------------------------------------ */
/* Init                                                                */
/* ------------------------------------------------------------------ */

void
init_cursor(VALUE mDER)
{
    s_cCursor = rb_define_class_under(mDER, "Cursor", rb_cObject);
    rb_gc_register_address(&s_cCursor);
    rb_define_alloc_func(s_cCursor, cursor_alloc);
    rb_define_method(s_cCursor, "initialize",        cursor_initialize,        -1);
    rb_define_method(s_cCursor, "read",              cursor_read,               1);
    rb_define_method(s_cCursor, "read_raw",          cursor_read_raw,           1);
    rb_define_method(s_cCursor, "read_sequence",     cursor_read_sequence,      0);
    rb_define_method(s_cCursor, "read_integer",      cursor_read_integer,       0);
    rb_define_method(s_cCursor, "read_oid",          cursor_read_oid,           0);
    rb_define_method(s_cCursor, "read_octet_string", cursor_read_octet_string,  0);
    rb_define_method(s_cCursor, "read_bit_string",   cursor_read_bit_string,    0);
    rb_define_method(s_cCursor, "read_optional",     cursor_read_optional,      1);
    rb_define_method(s_cCursor, "read_raw_optional", cursor_read_raw_optional,  1);
    rb_define_method(s_cCursor, "skip",              cursor_skip,               1);
    rb_define_method(s_cCursor, "skip_optional",     cursor_skip_optional,      1);
    rb_define_method(s_cCursor, "peek_tag",          cursor_peek_tag,           0);
    rb_define_method(s_cCursor, "eof?",              cursor_eof_p,              0);
    rb_define_method(s_cCursor, "remaining",         cursor_remaining,          0);
    rb_define_method(s_cCursor, "pos",               cursor_pos,                0);
    rb_define_method(s_cCursor, "data",              cursor_data,               0);
}
