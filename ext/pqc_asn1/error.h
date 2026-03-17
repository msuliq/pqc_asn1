/*
 * error.h — error-mapping and exception-raising declarations.
 */

#ifndef PQC_ASN1_ERROR_H
#define PQC_ASN1_ERROR_H

#include "shared.h"

/* Accessors for exception classes — used by every translation unit
 * that needs to raise PqcAsn1 errors.
 * Statics are populated once by init_error; then treated as const. */
VALUE pqc_error_class(void);
VALUE pqc_parse_error_class(void);
VALUE pqc_der_error_class(void);
VALUE pqc_pem_error_class(void);
VALUE pqc_oid_error_class(void);

/* Map a pqc_asn1_status_t code to the symbol stored in Error#code. */
VALUE status_to_sym(pqc_asn1_status_t rc);

/* Raise exc_class with the given message and set Error#code.
 * @category is now derived in Ruby; C no longer sets it.
 * Declared NORETURN so the compiler knows control never returns. */
NORETURN(void raise_with_code(VALUE exc_class, VALUE rb_msg,
                               pqc_asn1_status_t rc));

/* Like raise_with_code but also sets Error#offset to the byte position
 * in the input where the error was detected.  Use in Cursor and DER
 * parse paths where position information is available. */
NORETURN(void raise_with_code_and_offset(VALUE exc_class, VALUE rb_msg,
                                          pqc_asn1_status_t rc, size_t offset));

/* Map rc to the appropriate Ruby exception class and raise it.
 * Returns normally only when rc == PQC_ASN1_OK. */
void raise_status(pqc_asn1_status_t rc, const char *prefix);

/* Look up PqcAsn1::Error and PqcAsn1::ParseError from the already-defined
 * Ruby classes and store them in file-static variables. */
void init_error(VALUE mPqcAsn1);

#endif /* PQC_ASN1_ERROR_H */
