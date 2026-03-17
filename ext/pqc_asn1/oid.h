/*
 * oid.h — OID codec declarations.
 */

#ifndef PQC_ASN1_OID_H
#define PQC_ASN1_OID_H

#include "shared.h"

/* Encode a dotted-decimal OID string or PqcAsn1::OID object to DER TLV.
 * Accepts either a Ruby String (dotted decimal) or a PqcAsn1::OID instance
 * (calls .dotted on it first).  Returns a frozen ASCII-8BIT String
 * containing the full TLV (tag 0x06 + length + value). */
VALUE oid_from_dotted_rb(VALUE rb_dotted);

/* Decode a DER TLV (tag 0x06) to a frozen US-ASCII dotted-decimal String. */
VALUE oid_to_dotted_rb(VALUE rb_der);

/* Wrap a dotted-decimal String in a PqcAsn1::OID instance. */
VALUE oid_wrap_rb(VALUE rb_dotted_str);

/* C-level reverse lookup: dotted-decimal String → constant name (frozen
 * US-ASCII String), or Qnil if unknown.  O(1) Ruby hash lookup.
 * Only valid after init_oid() + init_oid_reverse() have been called. */
VALUE oid_name_for_dotted(VALUE rb_dotted);

/* Populate the C-level reverse lookup hash from OID constants.
 * Must be called after init_oid() and the C extension is fully loaded
 * (so that OID.from_dotted is available for DER TLV inputs). */
void init_oid_reverse(VALUE cOID);

/* Attach OID.from_dotted, OID.to_dotted, and OID.validate_key_size as
 * singleton methods on cOID, and store the class handle for oid_wrap_rb. */
void init_oid(VALUE mPqcAsn1, VALUE cOID);

#endif /* PQC_ASN1_OID_H */
