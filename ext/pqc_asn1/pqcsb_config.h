/*
 * pqcsb_config.h — bridge header for vendored libpqcsb in pqc_asn1 gem.
 *
 * All HAVE_* macros are supplied as -D compiler flags by extconf.rb
 * (via mkmf's have_func / have_header / have_const checks).
 * No additional defines are needed in this file.
 *
 * The extconf.rb feature detection queries the same platform capabilities
 * that libpqcsb's CMake setup detects, so the -D flags match the
 * #cmakedefine results exactly.
 */

#ifndef PQCSB_CONFIG_H
#define PQCSB_CONFIG_H

/* All feature detection is handled by extconf.rb via compiler flags. */

#endif /* PQCSB_CONFIG_H */
