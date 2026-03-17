/*
 * shared.h — common includes, macros, and utility helpers.
 *
 * Every .c file in the extension includes this header.  It defines the
 * allocator redirects (must appear before pqc_asn1.h), the UNUSED helper,
 * and the frozen_bin_str inline utility.
 *
 * The old pqc_ext_t / g_ext global context struct has been eliminated.
 * Each translation unit now stores only what it needs as file-static VALUEs
 * and exports accessor functions where other units require them (see error.h
 * for pqc_error_class / pqc_parse_error_class).
 *
 * Thread safety
 * =============
 * All VALUE statics are written exactly once during Init_pqc_asn1_ext and
 * are read-only thereafter.  All module-level functions are therefore safe
 * to call concurrently from multiple threads (or Ractors, within the limits
 * of the GVL).
 */

#ifndef PQC_ASN1_SHARED_H
#define PQC_ASN1_SHARED_H

/* Route all library allocations through Ruby's GC-aware allocator.
 * These defines must precede the inclusion of pqc_asn1.h. */
#define PQC_ASN1_MALLOC  ruby_xmalloc
#define PQC_ASN1_FREE    ruby_xfree
#define PQC_ASN1_REALLOC ruby_xrealloc

#include <ruby.h>
#include <ruby/encoding.h>
#include "pqc_asn1.h"

#ifdef __GNUC__
#  define UNUSED __attribute__((unused))
#else
#  define UNUSED
#endif

/* ------------------------------------------------------------------ */
/* String helper                                                       */
/* ------------------------------------------------------------------ */

/* Create a frozen ASCII-8BIT Ruby String from a raw byte buffer.
 * Always allocates a new Ruby String so this function is safe to call
 * from multiple threads and Ractors — there is no shared mutable state.
 *
 * The previous version cached a file-static VALUE for zero-length inputs,
 * but that lazy initialisation contradicted the "all VALUEs written once
 * during Init_pqc_asn1_ext" threading contract stated in the header. */
static inline VALUE
frozen_bin_str(const char *ptr, long len)
{
    VALUE str = rb_str_new(ptr, len);
    rb_enc_associate(str, rb_ascii8bit_encoding());
    rb_obj_freeze(str);
    return str;
}

#endif /* PQC_ASN1_SHARED_H */
