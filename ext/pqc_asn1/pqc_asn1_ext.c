/*
 * pqc_asn1_ext.c — Ruby C extension entry point for PqcAsn1.
 *
 * The global pqc_ext_t / g_ext context struct has been eliminated.
 * Each translation unit now stores only what it needs as file-static
 * VALUEs, populated during their respective init_* call.
 *
 * init_* function signatures:
 *   init_error(mPqcAsn1)         — error.c
 *   init_oid(mPqcAsn1, cOID)     — oid.c
 *   init_der(mPqcAsn1, mDER)     — der.c
 *   init_cursor(mDER)             — cursor.c
 *   init_pem(mPqcAsn1)           — pem.c
 *
 * PqcAsn1::Base64 wraps the C library's base64 encoder/decoder
 * via init_base64(mPqcAsn1) — base64_ext.c.
 *
 * SecureBuffer (PqcAsn1::SecureBuffer) is defined in secure_buffer.c and
 * initialised by init_secure_buffer(mPqcAsn1) before the other sub-modules
 * so that der.c and pem.c can look it up at init time.
 *
 *   init_secure_buffer(mPqcAsn1) — secure_buffer.c
 */

#include "shared.h"
#include "error.h"
#include "secure_buffer.h"

/* Sub-module init functions — each defined in its own .c file. */
void init_secure_buffer(VALUE mPqcAsn1);
void init_oid(VALUE mPqcAsn1, VALUE cOID);
void init_oid_reverse(VALUE cOID);
void init_cursor(VALUE mDER);
void init_der(VALUE mPqcAsn1, VALUE mDER);
void init_pem(VALUE mPqcAsn1);
void init_base64(VALUE mPqcAsn1);

/* ------------------------------------------------------------------ */
/* Init                                                                */
/* ------------------------------------------------------------------ */

RUBY_FUNC_EXPORTED void
Init_pqc_asn1_ext(void)
{
    VALUE mPqcAsn1 = rb_define_module("PqcAsn1");

    /* Error classes are defined in lib/pqc_asn1.rb before this
     * extension loads, giving them attr_reader :code and the derived
     * category method. */
    init_error(mPqcAsn1);

    /* SecureBuffer must be initialised before DER/PEM so they can look up
     * PqcAsn1::SecureBuffer via rb_const_get at their init time. */
    init_secure_buffer(mPqcAsn1);

    /* DER and OID are pre-defined in lib/pqc_asn1.rb and lib/pqc_asn1/oid.rb.
     * Look them up rather than redefining. */
    VALUE mDER = rb_const_get(mPqcAsn1, rb_intern("DER"));
    VALUE cOID = rb_const_get(mPqcAsn1, rb_intern("OID"));

    /* Attach OID.from_dotted and OID.to_dotted as C singleton methods. */
    init_oid(mPqcAsn1, cOID);

    /* DER module methods, Cursor, Base64, PEM */
    init_der(mPqcAsn1, mDER);
    init_cursor(mDER);
    init_pem(mPqcAsn1);
    init_base64(mPqcAsn1);

    /* Build the C-level OID reverse lookup hash after all init functions
     * have run, so OID constants and from_dotted/to_dotted are available. */
    init_oid_reverse(cOID);
}
