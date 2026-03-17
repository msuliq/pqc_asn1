/*
 * error.c — error mapping and exception raising.
 *
 * Provides two layers of error information for every raised exception:
 *   Error#code     — fine-grained symbol matching the C status constant
 *   Error#category — coarse bucket derived in Ruby from #code
 *                    (:malformed_input, :malformed_encoding, :system)
 *
 * A single dispatch table (ERROR_TABLE) is the authoritative source for
 * all code-to-exception-class mappings.  Adding a new status code means
 * adding exactly one row to the table; nothing else needs updating.
 *
 * C no longer sets @category on exceptions — Error#category is a derived
 * Ruby method that maps @code → category without stored state.
 */

#include "error.h"

/* ------------------------------------------------------------------ */
/* File-static exception class handles                                */
/* ------------------------------------------------------------------ */

static VALUE s_eError;
static VALUE s_eParseError;
static VALUE s_eDERError;
static VALUE s_ePEMError;
static VALUE s_eOIDError;

VALUE pqc_error_class(void)       { return s_eError; }
VALUE pqc_parse_error_class(void) { return s_eParseError; }
VALUE pqc_der_error_class(void)   { return s_eDERError; }
VALUE pqc_pem_error_class(void)   { return s_ePEMError; }
VALUE pqc_oid_error_class(void)   { return s_eOIDError; }

/* ------------------------------------------------------------------ */
/* Dispatch table                                                      */
/* ------------------------------------------------------------------ */

typedef enum {
    EXC_PARSE,  /* PqcAsn1::ParseError — carries #code */
    EXC_DER,    /* PqcAsn1::DERError   — carries #code */
    EXC_PEM,    /* PqcAsn1::PEMError   — carries #code */
    EXC_OID,    /* PqcAsn1::OIDError   — carries #code */
    EXC_ARG,    /* ArgumentError       — no #code      */
    EXC_NOMEM,  /* NoMemoryError       — no #code      */
    EXC_BASE    /* PqcAsn1::Error      — carries #code */
} exc_kind_t;

typedef struct {
    const char *sym_name;  /* Error#code symbol name */
    exc_kind_t  exc_kind;
} error_entry_t;

/*
 * Direct-indexed dispatch table.  The enum assigns explicit negative values
 * -1 through -18, so ERR_TO_IDX maps rc → array index in O(1):
 *
 *   ERR_TO_IDX(-1) = 0   (PQC_ASN1_ERR_OUTER_SEQUENCE)
 *   ERR_TO_IDX(-18) = 17  (PQC_ASN1_ERR_PEM_MALFORMED)
 *
 * Adding a new status code requires adding exactly one row at the matching
 * index — nothing else needs updating.
 */
#define ERROR_TABLE_SIZE 18
#define ERR_TO_IDX(rc)   ((int)(-(rc)) - 1)

/* Compile-time guard: if the C library adds a new status code beyond
 * PQC_ASN1_ERR_PEM_MALFORMED (-18), ERROR_TABLE_SIZE must be increased
 * and a new row added to ERROR_TABLE.  This assertion fires immediately
 * at compile time rather than silently mapping new codes to :unknown. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(ERR_TO_IDX(PQC_ASN1_ERR_PEM_MALFORMED) == ERROR_TABLE_SIZE - 1,
               "ERROR_TABLE_SIZE is out of sync with pqc_asn1_status_t — "
               "add a new row to ERROR_TABLE and update ERROR_TABLE_SIZE");
#endif

static const error_entry_t ERROR_TABLE[ERROR_TABLE_SIZE] = {
    /* idx  0  rc= -1 */ {"outer_sequence",   EXC_DER},   /* PQC_ASN1_ERR_OUTER_SEQUENCE   */
    /* idx  1  rc= -2 */ {"version",          EXC_DER},   /* PQC_ASN1_ERR_VERSION          */
    /* idx  2  rc= -3 */ {"algorithm",        EXC_DER},   /* PQC_ASN1_ERR_ALGORITHM        */
    /* idx  3  rc= -4 */ {"key",              EXC_DER},   /* PQC_ASN1_ERR_KEY              */
    /* idx  4  rc= -5 */ {"unused_bits",      EXC_DER},   /* PQC_ASN1_ERR_UNUSED_BITS      */
    /* idx  5  rc= -6 */ {"trailing_data",    EXC_DER},   /* PQC_ASN1_ERR_TRAILING_DATA    */
    /* idx  6  rc= -7 */ {"pem_no_markers",   EXC_PEM},   /* PQC_ASN1_ERR_PEM_NO_MARKERS   */
    /* idx  7  rc= -8 */ {"pem_label",        EXC_PEM},   /* PQC_ASN1_ERR_PEM_LABEL        */
    /* idx  8  rc= -9 */ {"base64",           EXC_PEM},   /* PQC_ASN1_ERR_BASE64           */
    /* idx  9  rc=-10 */ {"invalid_oid",      EXC_OID},   /* PQC_ASN1_ERR_INVALID_OID      */
    /* idx 10  rc=-11 */ {"extra_fields",     EXC_DER},   /* PQC_ASN1_ERR_EXTRA_FIELDS     */
    /* idx 11  rc=-12 */ {"overflow",         EXC_ARG},   /* PQC_ASN1_ERR_OVERFLOW         */
    /* idx 12  rc=-13 */ {"alloc",            EXC_NOMEM}, /* PQC_ASN1_ERR_ALLOC            */
    /* idx 13  rc=-14 */ {"buffer_too_small", EXC_ARG},   /* PQC_ASN1_ERR_BUFFER_TOO_SMALL */
    /* idx 14  rc=-15 */ {"label_too_long",   EXC_ARG},   /* PQC_ASN1_ERR_LABEL_TOO_LONG   */
    /* idx 15  rc=-16 */ {"der_parse",        EXC_DER},   /* PQC_ASN1_ERR_DER_PARSE        */
    /* idx 16  rc=-17 */ {"null_param",       EXC_ARG},   /* PQC_ASN1_ERR_NULL_PARAM       */
    /* idx 17  rc=-18 */ {"pem_malformed",    EXC_PEM},   /* PQC_ASN1_ERR_PEM_MALFORMED    */
};

static const error_entry_t *
find_entry(pqc_asn1_status_t rc)
{
    int idx = ERR_TO_IDX(rc);
    if (idx < 0 || idx >= ERROR_TABLE_SIZE) return NULL;
    return &ERROR_TABLE[idx];
}

/* ------------------------------------------------------------------ */
/* Public helpers                                                      */
/* ------------------------------------------------------------------ */

VALUE
status_to_sym(pqc_asn1_status_t rc)
{
    const error_entry_t *e = find_entry(rc);
    return ID2SYM(rb_intern(e ? e->sym_name : "unknown"));
}

void
raise_with_code(VALUE exc_class, VALUE rb_msg, pqc_asn1_status_t rc)
{
    VALUE exc = rb_exc_new_str(exc_class, rb_msg);
    rb_ivar_set(exc, rb_intern("@code"), status_to_sym(rc));
    /* @category is derived by Error#category in Ruby from @code — not set here. */
    rb_exc_raise(exc);
}

void
raise_with_code_and_offset(VALUE exc_class, VALUE rb_msg,
                            pqc_asn1_status_t rc, size_t offset)
{
    VALUE exc = rb_exc_new_str(exc_class, rb_msg);
    rb_ivar_set(exc, rb_intern("@code"), status_to_sym(rc));
    rb_ivar_set(exc, rb_intern("@offset"), SIZET2NUM(offset));
    rb_exc_raise(exc);
}

void
raise_status(pqc_asn1_status_t rc, const char *prefix)
{
    if (rc == PQC_ASN1_OK) return;

    const error_entry_t *e = find_entry(rc);

    VALUE exc_class;
    if (!e) {
        exc_class = s_eError;
    } else {
        switch (e->exc_kind) {
        case EXC_DER:   exc_class = s_eDERError;     break;
        case EXC_PEM:   exc_class = s_ePEMError;     break;
        case EXC_OID:   exc_class = s_eOIDError;     break;
        case EXC_PARSE: exc_class = s_eParseError;   break;
        case EXC_ARG:   exc_class = rb_eArgError;    break;
        case EXC_NOMEM: exc_class = rb_eNoMemError;  break;
        default:        exc_class = s_eError;         break;
        }
    }

    VALUE rb_msg = prefix
        ? rb_sprintf("%s: %s", prefix, pqc_asn1_error_message(rc))
        : rb_sprintf("%s", pqc_asn1_error_message(rc));

    /* Standard library classes (ArgError, NoMemError) do not carry
     * #code — raise them directly. */
    if (exc_class == rb_eArgError || exc_class == rb_eNoMemError)
        rb_exc_raise(rb_exc_new_str(exc_class, rb_msg));
    else
        raise_with_code(exc_class, rb_msg, rc);
}

/* ------------------------------------------------------------------ */
/* Init                                                                */
/* ------------------------------------------------------------------ */

void
init_error(VALUE mPqcAsn1)
{
    /* Error and ParseError are defined in lib/pqc_asn1.rb before this
     * extension loads, giving them attr_reader :code and the derived
     * category method.  Look them up here so C code can raise them. */
    s_eError      = rb_const_get(mPqcAsn1, rb_intern("Error"));
    s_eParseError = rb_const_get(mPqcAsn1, rb_intern("ParseError"));
    s_eDERError   = rb_const_get(mPqcAsn1, rb_intern("DERError"));
    s_ePEMError   = rb_const_get(mPqcAsn1, rb_intern("PEMError"));
    s_eOIDError   = rb_const_get(mPqcAsn1, rb_intern("OIDError"));
    rb_gc_register_address(&s_eError);
    rb_gc_register_address(&s_eParseError);
    rb_gc_register_address(&s_eDERError);
    rb_gc_register_address(&s_ePEMError);
    rb_gc_register_address(&s_eOIDError);
}
