# frozen_string_literal: true

require "mkmf"

# Try to find libpqcasn1 as a system-installed library first.
# If pkg-config finds it, the system headers and library are used and the
# vendored pqc_asn1.c is excluded from compilation.
# If not found, fall back to the vendored copy bundled in ext/pqc_asn1/.
if pkg_config("pqcasn1")
  $srcs = %w[pqc_asn1_ext.c error.c secure_buffer.c oid.c cursor.c der.c pem.c base64_ext.c]
else
  $srcs = %w[pqc_asn1_ext.c pqc_asn1.c error.c secure_buffer.c oid.c cursor.c der.c pem.c base64_ext.c]
end

# -Wpedantic generates excessive noise from Ruby's own UCRT headers on Windows
# (C23 attributes like [[nodiscard]], [[maybe_unused]], __VA_OPT__).
# Our own code is still covered by -Wall -Wextra -Wshadow.
pedantic = RUBY_PLATFORM =~ /mingw|mswin/ ? "" : " -Wpedantic"
$CFLAGS << " -O2 -Wall -Wextra -Wshadow#{pedantic} -std=c11"
$CFLAGS << " -fstack-protector-strong" if try_cflags("-fstack-protector-strong")
$CFLAGS << " -fvisibility=hidden" if try_cflags("-fvisibility=hidden")

# Feature-detect platform secure-zeroing and fast search primitives so
# pqc_asn1.c can use the best available implementation via HAVE_* defines
# rather than relying solely on platform preprocessor macros.
have_func("memset_s", %w[string.h])
have_func("explicit_bzero", %w[string.h])
have_func("memmem", %w[string.h])

# Memory mapping and protection (for SecureBuffer)
have_header("sys/mman.h")
have_func("mmap",     ["sys/mman.h"])
have_func("munmap",   ["sys/mman.h"])
have_func("mlock",    ["sys/mman.h"])
have_func("munlock",  ["sys/mman.h"])
have_func("mprotect", ["sys/mman.h"])
have_func("madvise",  ["sys/mman.h"])

# Resource limits (for mlock budget)
have_header("sys/resource.h")
have_func("getrlimit", ["sys/resource.h"])

# Page-aligned allocation fallback
have_func("posix_memalign", ["stdlib.h"])

# Cryptographic random
have_func("arc4random_buf", ["stdlib.h"])
have_header("sys/random.h")
have_func("getrandom", ["sys/random.h"])
have_func("getentropy", ["sys/random.h"])

# Platform-specific mmap/madvise flags (sys/mman.h already probed above)
have_const("MAP_NOCORE",      ["sys/mman.h"])
have_const("MADV_DONTDUMP",  ["sys/mman.h"])
have_const("MADV_WIPEONFORK", ["sys/mman.h"])

# Linux needs _GNU_SOURCE for some madvise constants
$defs.push("-D_GNU_SOURCE") if RUBY_PLATFORM =~ /linux/

# Windows: explicit feature detection for VirtualAlloc/VirtualProtect/VirtualLock
# and advapi32 for RtlGenRandom (used by pqcsb_fill_random on Windows).
if RUBY_PLATFORM =~ /mingw|mswin/
  have_library("advapi32")          # RtlGenRandom (SystemFunction036)
  have_func("VirtualAlloc",   ["windows.h"])
  have_func("VirtualProtect", ["windows.h"])
  have_func("VirtualLock",    ["windows.h"])
  have_func("VirtualFree",    ["windows.h"])
end

create_makefile("pqc_asn1/pqc_asn1_ext")
