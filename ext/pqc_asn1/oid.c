/*
 * oid.c — DER OID codec (encode / decode) in C.
 *
 * Provides oid_from_dotted_rb and oid_to_dotted_rb as both C-level helpers
 * (callable directly from der.c without Ruby dispatch overhead) and as
 * Ruby singleton methods on PqcAsn1::OID.
 *
 * oid_from_dotted_rb now accepts either a dotted-decimal String or a
 * PqcAsn1::OID instance (calls .dotted on it to get the string).
 *
 * oid_wrap_rb creates a PqcAsn1::OID instance from a dotted String — used
 * by der.c to return OID value objects from parse_spki / parse_pkcs8.
 */

#include <inttypes.h>
#include "shared.h"
#include "oid.h"

/* ------------------------------------------------------------------ */
/* File-static OID class handle                                        */
/* ------------------------------------------------------------------ */

static VALUE s_cOID;

/* ------------------------------------------------------------------ */
/* C-level key-size validation table                                   */
/*                                                                     */
/* GENERATED from data/oids.yml — run `bundle exec rake codegen:oid_c`*/
/* to regenerate this table after editing the YAML registry.          */
/*                                                                     */
/* Used by OID.validate_key_size on the hot validate path.            */
/* DER::KEY_SIZES (Ruby) is loaded from the same YAML at extension    */
/* load time; custom OIDs added via OID.register are appended there   */
/* but are not present in this C table.                               */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *dotted;    /* dotted-decimal OID string */
    size_t      pub_size;  /* expected public key size in bytes (0 = not applicable) */
    size_t      sec_size;  /* expected secret key size in bytes (0 = not applicable) */
} oid_size_entry_t;

static const oid_size_entry_t OID_KEY_SIZES[] = {
    /* ML-DSA (FIPS 204) */
    {"2.16.840.1.101.3.4.3.17", 1312, 2560},  /* ML_DSA_44 */
    {"2.16.840.1.101.3.4.3.18", 1952, 4032},  /* ML_DSA_65 */
    {"2.16.840.1.101.3.4.3.19", 2592, 4896},  /* ML_DSA_87 */
    /* ML-KEM (FIPS 203) */
    {"2.16.840.1.101.3.4.4.1",   800, 1632},  /* ML_KEM_512 */
    {"2.16.840.1.101.3.4.4.2",  1184, 2400},  /* ML_KEM_768 */
    {"2.16.840.1.101.3.4.4.3",  1568, 3168},  /* ML_KEM_1024 */
    /* SLH-DSA SHA-2 (FIPS 205) */
    {"2.16.840.1.101.3.4.3.20",   32,   64},  /* SLH_DSA_SHA2_128S */
    {"2.16.840.1.101.3.4.3.21",   32,   64},  /* SLH_DSA_SHA2_128F */
    {"2.16.840.1.101.3.4.3.22",   48,   96},  /* SLH_DSA_SHA2_192S */
    {"2.16.840.1.101.3.4.3.23",   48,   96},  /* SLH_DSA_SHA2_192F */
    {"2.16.840.1.101.3.4.3.24",   64,  128},  /* SLH_DSA_SHA2_256S */
    {"2.16.840.1.101.3.4.3.25",   64,  128},  /* SLH_DSA_SHA2_256F */
    /* SLH-DSA SHAKE (FIPS 205) */
    {"2.16.840.1.101.3.4.3.26",   32,   64},  /* SLH_DSA_SHAKE_128S */
    {"2.16.840.1.101.3.4.3.27",   32,   64},  /* SLH_DSA_SHAKE_128F */
    {"2.16.840.1.101.3.4.3.28",   48,   96},  /* SLH_DSA_SHAKE_192S */
    {"2.16.840.1.101.3.4.3.29",   48,   96},  /* SLH_DSA_SHAKE_192F */
    {"2.16.840.1.101.3.4.3.30",   64,  128},  /* SLH_DSA_SHAKE_256S */
    {"2.16.840.1.101.3.4.3.31",   64,  128},  /* SLH_DSA_SHAKE_256F */
};

#define OID_KEY_SIZES_LEN ((int)(sizeof(OID_KEY_SIZES) / sizeof(OID_KEY_SIZES[0])))

/* C-level reverse lookup hash: dotted String → constant name String.
 * Populated by init_oid_reverse(). */
static VALUE s_reverse_hash = Qnil;

/* ------------------------------------------------------------------ */
/* Internal: encode one OID arc as base-128 bytes (big-endian)        */
/* ------------------------------------------------------------------ */

/* Returns the number of bytes written.  buf must hold at least 10 bytes
 * (ceil(64/7) covers all uint64_t values). */
static size_t
encode_arc(uint64_t val, uint8_t *buf)
{
    if (val == 0) { buf[0] = 0; return 1; }

    uint8_t tmp[10];
    size_t  n = 0;
    while (val > 0) {
        tmp[n++] = (uint8_t)(val & 0x7f);
        val >>= 7;
    }
    /* tmp is little-endian; reverse into buf, setting the continuation
     * bit on every byte except the last. */
    for (size_t i = 0; i < n; i++) {
        buf[i] = tmp[n - 1 - i];
        if (i < n - 1) buf[i] |= 0x80;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* C-level API (callable from der.c without Ruby dispatch)            */
/* ------------------------------------------------------------------ */

VALUE
oid_from_dotted_rb(VALUE rb_dotted)
{
    /* Accept PqcAsn1::OID instances in addition to dotted Strings.
     * Call .dotted to extract the underlying string representation. */
    if (!RB_TYPE_P(rb_dotted, T_STRING))
        rb_dotted = rb_funcall(rb_dotted, rb_intern("dotted"), 0);

    StringValue(rb_dotted);
    const char *p   = RSTRING_PTR(rb_dotted);
    const char *end = p + RSTRING_LEN(rb_dotted);

    uint64_t comps[64];
    size_t   ncomps = 0;

    while (p < end) {
        if (ncomps >= 64)
            rb_raise(rb_eArgError, "OID has too many components");
        if (*p < '0' || *p > '9')
            rb_raise(rb_eArgError,
                     "OID component is not a non-negative integer: found '%c'", *p);

        uint64_t v = 0;
        while (p < end && *p >= '0' && *p <= '9') {
            if (v > (UINT64_MAX - (uint64_t)(*p - '0')) / 10)
                rb_raise(rb_eArgError, "OID component value overflow");
            v = v * 10 + (uint64_t)(*p++ - '0');
        }
        comps[ncomps++] = v;

        if (p < end) {
            if (*p != '.')
                rb_raise(rb_eArgError,
                         "OID contains unexpected character '%c'", *p);
            if (++p == end)
                rb_raise(rb_eArgError, "OID ends with a trailing dot");
        }
    }

    if (ncomps < 2)
        rb_raise(rb_eArgError, "OID requires at least 2 components");

    uint64_t first = comps[0], second = comps[1];
    if (first > 2)
        rb_raise(rb_eArgError, "First OID component must be 0, 1, or 2");
    if (first < 2 && second >= 40)
        rb_raise(rb_eArgError,
                 "Second OID component must be < 40 for arc 0 or 1");

    /* Encode into a value buffer.
     * 64 components × 10 bytes (ceil(64/7) for uint64_t arcs) = 640 bytes max. */
    uint8_t vbuf[640];
    uint8_t tmp[10];
    size_t  pos = 0, n;

    n = encode_arc(first * 40 + second, tmp);
    if (pos + n > sizeof(vbuf))
        rb_raise(rb_eArgError, "OID value exceeds maximum encoded length");
    memcpy(vbuf + pos, tmp, n);
    pos += n;

    for (size_t i = 2; i < ncomps; i++) {
        n = encode_arc(comps[i], tmp);
        if (pos + n > sizeof(vbuf))
            rb_raise(rb_eArgError, "OID value exceeds maximum encoded length");
        memcpy(vbuf + pos, tmp, n);
        pos += n;
    }

    /* Build TLV with DER length encoding (short-form or 1/2-byte long-form). */
    uint8_t tlv[644]; /* tag(1) + length(up to 3) + value(up to 640) */
    size_t  tlv_pos = 0;
    tlv[tlv_pos++] = 0x06;
    if (pos < 0x80) {
        tlv[tlv_pos++] = (uint8_t)pos;
    } else if (pos <= 0xFF) {
        tlv[tlv_pos++] = 0x81;
        tlv[tlv_pos++] = (uint8_t)pos;
    } else {
        tlv[tlv_pos++] = 0x82;
        tlv[tlv_pos++] = (uint8_t)(pos >> 8);
        tlv[tlv_pos++] = (uint8_t)pos;
    }
    memcpy(tlv + tlv_pos, vbuf, pos);
    return frozen_bin_str((const char *)tlv, (long)(tlv_pos + pos));
}

VALUE
oid_to_dotted_rb(VALUE rb_der)
{
    StringValue(rb_der);
    const uint8_t *der     = (const uint8_t *)RSTRING_PTR(rb_der);
    size_t         der_len = (size_t)RSTRING_LEN(rb_der);

    if (der_len < 2 || der[0] != 0x06)
        rb_raise(rb_eArgError, "OID TLV must start with tag 0x06");

    uint8_t len_byte = der[1];
    size_t  value_len;
    size_t  header_len;

    if (len_byte < 0x80) {
        value_len  = len_byte;
        header_len = 2;
    } else if (len_byte == 0x81) {
        if (der_len < 3)
            rb_raise(rb_eArgError, "OID TLV truncated in long-form length");
        value_len  = der[2];
        header_len = 3;
    } else if (len_byte == 0x82) {
        if (der_len < 4)
            rb_raise(rb_eArgError, "OID TLV truncated in long-form length");
        value_len  = ((size_t)der[2] << 8) | der[3];
        header_len = 4;
    } else {
        rb_raise(rb_eArgError,
                 "OID uses unsupported DER length form (0x%02x)", len_byte);
    }

    if (der_len != header_len + value_len)
        rb_raise(rb_eArgError, "OID TLV length mismatch");

    const uint8_t *bytes     = der + header_len;
    size_t         bytes_len = value_len;
    if (bytes_len == 0)
        rb_raise(rb_eArgError, "OID value is empty");

    /* Decode base-128 components. */
    uint64_t raw[64];
    size_t   nraw = 0, i = 0;

    while (i < bytes_len) {
        if (nraw >= 64)
            rb_raise(rb_eArgError, "OID has too many components");
        uint64_t n = 0;
        do {
            if (i >= bytes_len)
                rb_raise(rb_eArgError,
                         "Truncated OID component starting at byte %zu", i);
            uint8_t b = bytes[i++];
            if (n > (UINT64_MAX >> 7))
                rb_raise(rb_eArgError, "OID component value overflow");
            n = (n << 7) | (b & 0x7f);
            if ((b & 0x80) == 0) break;
        } while (1);
        raw[nraw++] = n;
    }

    /* Reconstruct the first two arcs from the combined first component. */
    uint64_t first_val = raw[0];
    uint64_t arc0, arc1;
    if      (first_val < 40) { arc0 = 0; arc1 = first_val; }
    else if (first_val < 80) { arc0 = 1; arc1 = first_val - 40; }
    else                     { arc0 = 2; arc1 = first_val - 80; }

    /* Build the dotted string in a fixed buffer.
     * Output arcs = nraw + 1 (arc0 and arc1 are reconstructed from raw[0]).
     * Worst case: "2." (2) + 20-digit arc1 (20) + 63 × ".NNNNN" (63×21) = 1345.
     * Buffer is sized to 1400 to leave headroom and avoid off-by-one mistakes.
     * Each snprintf return value is tracked with a size_t pos to avoid the
     * int→size_t underflow hazard when len would exceed the buffer size. */
    char   dot_buf[1400];
    size_t pos = 0;
    int    n;

    n = snprintf(dot_buf, sizeof(dot_buf), "%" PRIu64 ".%" PRIu64, arc0, arc1);
    if (n < 0 || (size_t)n >= sizeof(dot_buf))
        rb_raise(rb_eArgError, "OID dotted string too long");
    pos = (size_t)n;

    for (size_t j = 1; j < nraw; j++) {
        n = snprintf(dot_buf + pos, sizeof(dot_buf) - pos, ".%" PRIu64, raw[j]);
        if (n < 0 || n >= (int)(sizeof(dot_buf) - pos))
            rb_raise(rb_eArgError, "OID dotted string too long");
        pos += (size_t)n;
    }

    VALUE result = rb_str_new(dot_buf, (long)pos);
    rb_enc_associate(result, rb_usascii_encoding());
    rb_obj_freeze(result);
    return result;
}

VALUE
oid_wrap_rb(VALUE rb_dotted_str)
{
    return rb_funcall(s_cOID, rb_intern("new"), 1, rb_dotted_str);
}

/* ------------------------------------------------------------------ */
/* Ruby-level wrappers                                                 */
/* ------------------------------------------------------------------ */

static VALUE
rb_oid_from_dotted(UNUSED VALUE _self, VALUE rb_dotted)
{
    return oid_from_dotted_rb(rb_dotted);
}

static VALUE
rb_oid_to_dotted(UNUSED VALUE _self, VALUE rb_der)
{
    return oid_to_dotted_rb(rb_der);
}

/* ------------------------------------------------------------------ */
/* Reverse lookup                                                      */
/* ------------------------------------------------------------------ */

VALUE
oid_name_for_dotted(VALUE rb_dotted)
{
    if (s_reverse_hash == Qnil) return Qnil;
    VALUE result = rb_hash_lookup(s_reverse_hash, rb_dotted);
    return NIL_P(result) ? Qnil : result;
}

/* OID.name_for(oid) — accepts OID instance, dotted String, or DER TLV. */
static VALUE
rb_oid_name_for(VALUE _self, VALUE rb_oid)
{
    (void)_self;
    VALUE dotted;

    if (rb_obj_is_kind_of(rb_oid, s_cOID)) {
        dotted = rb_funcall(rb_oid, rb_intern("dotted"), 0);
    } else if (RB_TYPE_P(rb_oid, T_STRING)) {
        /* Check if it looks like DER TLV (starts with 0x06). */
        if (RSTRING_LEN(rb_oid) >= 2 &&
            (uint8_t)RSTRING_PTR(rb_oid)[0] == 0x06) {
            dotted = oid_to_dotted_rb(rb_oid);
        } else {
            dotted = rb_oid;
        }
    } else {
        return Qnil;
    }

    VALUE result = oid_name_for_dotted(dotted);
    if (!NIL_P(result)) return result;

    /* Fall back to the Ruby-side custom_registry for runtime-registered OIDs.
     * init_oid_reverse builds s_reverse_hash from constants present at init
     * time only; OIDs added later via OID.register are not in that hash. */
    VALUE custom_reg = rb_ivar_get(s_cOID, rb_intern("@custom_registry"));
    if (!NIL_P(custom_reg) && RB_TYPE_P(custom_reg, T_HASH))
        return rb_hash_lookup2(custom_reg, dotted, Qnil);
    return Qnil;
}

void
init_oid_reverse(VALUE cOID)
{
    /* Build reverse hash from OID constants: iterate constants,
     * filter those that are OID instances, map dotted → name. */
    VALUE consts = rb_funcall(cOID, rb_intern("constants"), 0);
    VALUE hash = rb_hash_new();
    long len = RARRAY_LEN(consts);

    for (long i = 0; i < len; i++) {
        VALUE sym = rb_ary_entry(consts, i);
        VALUE val = rb_funcall(cOID, rb_intern("const_get"), 1, sym);
        if (rb_obj_is_kind_of(val, cOID)) {
            VALUE dotted = rb_funcall(val, rb_intern("dotted"), 0);
            VALUE name = rb_funcall(sym, rb_intern("to_s"), 0);
            rb_obj_freeze(name);
            rb_hash_aset(hash, dotted, name);
        }
    }

    rb_obj_freeze(hash);
    s_reverse_hash = hash;
    rb_gc_register_address(&s_reverse_hash);

    /* Attach name_for as a singleton method on OID, replacing the Ruby version. */
    rb_define_singleton_method(cOID, "name_for", rb_oid_name_for, 1);
}

/* ------------------------------------------------------------------ */
/* OID.validate_key_size(oid_or_dotted, bytesize, is_public) -> true  */
/*                                                                     */
/* C-level key-size validation.  Replaces the Ruby KEY_SIZES hash     */
/* lookup in the hot validate path while keeping KEY_SIZES available  */
/* for user introspection.                                             */
/*                                                                     */
/* Returns true  — known OID, size matches.                           */
/* Returns nil   — OID not in the C table (unknown algorithm).        */
/* Raises ArgumentError — known OID, size mismatch.                   */
/* ------------------------------------------------------------------ */

static VALUE
rb_oid_validate_key_size(UNUSED VALUE _self, VALUE rb_oid, VALUE rb_bytesize,
                          VALUE rb_is_public)
{
    VALUE dotted;
    if (rb_obj_is_kind_of(rb_oid, s_cOID))
        dotted = rb_funcall(rb_oid, rb_intern("dotted"), 0);
    else
        dotted = rb_oid;
    StringValue(dotted);

    size_t bytesize  = NUM2SIZET(rb_bytesize);
    int    is_public = RTEST(rb_is_public);
    const char *dotted_cstr = RSTRING_PTR(dotted);

    /* Linear scan is intentional: with only 18 entries the overhead of
     * a hash table or sorted+bsearch is not justified.  Revisit if the
     * table grows significantly (e.g. composite algorithms). */
    for (int i = 0; i < OID_KEY_SIZES_LEN; i++) {
        if (strcmp(OID_KEY_SIZES[i].dotted, dotted_cstr) != 0) continue;

        size_t expected = is_public ? OID_KEY_SIZES[i].pub_size
                                    : OID_KEY_SIZES[i].sec_size;
        if (expected == 0) return Qtrue; /* no size constraint for this key type */

        if (bytesize != expected) {
            const char *type_name = is_public ? "public" : "secret";
            rb_raise(rb_eArgError,
                     "%s key size %zu does not match expected %zu for %s",
                     type_name, bytesize, expected, dotted_cstr);
        }
        return Qtrue;
    }
    return Qnil; /* OID not in C table — caller falls back to KEY_SIZES */
}

/* ------------------------------------------------------------------ */
/* Init                                                                */
/* ------------------------------------------------------------------ */

void
init_oid(VALUE mPqcAsn1, VALUE cOID)
{
    (void)mPqcAsn1;
    s_cOID = cOID;
    rb_gc_register_address(&s_cOID);
    rb_define_singleton_method(cOID, "from_dotted",        rb_oid_from_dotted,        1);
    rb_define_singleton_method(cOID, "to_dotted",          rb_oid_to_dotted,          1);
    rb_define_singleton_method(cOID, "validate_key_size",  rb_oid_validate_key_size,  3);
}
