# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `SecureBuffer#wipe!` now returns `self` instead of `nil`, enabling method
  chaining (e.g. `buf.wipe!.frozen?`).
- `SecureBuffer.random(n)` rejects negative values with a clear `ArgumentError`
  instead of silently wrapping via `NUM2SIZET`.
- `SecureBuffer#slice(offset, length)` rejects negative offset or length with
  `ArgumentError` instead of wrapping to a huge unsigned value.
- `DER.read_tlv` rejects negative offset with `ArgumentError`.
- `DER::Cursor.new(data, pos)` rejects negative pos with `ArgumentError`.
- PEM label mismatch during IO streaming now raises `PEMError` (was `ParseError`).
- Truncated PEM over IO (BEGIN without matching END) now raises `PEMError`
  with code `:pem_no_markers` instead of silently dropping the block.
- `DER.build_encrypted_pkcs8` raises `ArgumentError` when either argument is
  `nil` instead of a confusing `NoMethodError`.

### Changed

- `check_input_size!` is now a private method outside of `class << self`,
  improving readability.

## [0.1.0] — 2026-03-17

### Added

- Algorithm-agnostic DER TLV read/write (`DER.read_tlv`, `DER.write_tlv` — private).
- SPKI encode/decode (`DER.build_spki`, `DER.parse_spki`).
- PKCS#8 / OneAsymmetricKey encode/decode (`DER.build_pkcs8`, `DER.parse_pkcs8`).
- EncryptedPrivateKeyInfo encode/decode (`DER.build_encrypted_pkcs8`,
  `DER.parse_encrypted_pkcs8`) — codec only, no encryption/decryption.
- PEM encode/decode (`PEM.encode`, `PEM.decode`, `PEM.decode_auto`,
  `PEM.decode_each`).
- `PEM.decode_each` accepts IO objects (or any `#each_line` responder) in
  addition to Strings, reading line-by-line to avoid slurping the entire stream.
- `PEM::DecodeResult` — value object returned by `PEM.decode_auto` with
  `#data`, `#label`, `#to_a`, `#to_h`, `#deconstruct_keys`, and `#==`.
  Use `result.to_a` for explicit Array destructuring.
- Base64 encode/decode (RFC 4648, strict padding validation).
- Built-in OID constants for ML-DSA (FIPS 204), ML-KEM (FIPS 203), and
  SLH-DSA (FIPS 205) — all 18 NIST PQC parameter sets.
- `OID.from_dotted` / `OID.to_dotted` — convert between dotted-decimal notation
  and DER-encoded OID TLV bytes.
- `OID.name_for` — reverse lookup from OID to constant name.
- `OID.register(dotted, name, key_sizes: nil)` — register custom OIDs at
  runtime; creates a named constant under `PqcAsn1::OID` and optionally extends
  key size validation.
- `DER::KeyInfo` — immutable value object returned by `parse_spki` /
  `parse_pkcs8` with `#oid`, `#parameters`, `#key`, `#public_key`, `#format`,
  `#algorithm`, `#to_der`, `#to_pem`, and pattern-matching support.
- `DER::EncryptedKeyInfo` — value object for EncryptedPrivateKeyInfo structures.
- `DER::CompositeKeyInfo` — placeholder for future composite key support
  (raises `NotImplementedError`).
- `DER.parse_auto` — detect SPKI vs PKCS#8 vs EncryptedPrivateKeyInfo by
  structure and dispatch to the correct parser.
- `DER.parse_pem` — decode a PEM string and parse the contained DER structure;
  uses the PEM label to select the parser.
- `DER.detect_format` — lightweight format detection returning `:spki`,
  `:pkcs8`, `:encrypted_pkcs8`, or `nil`.
- `DER.build_spki` and `DER.build_pkcs8` accept `validate: true` keyword to
  check key lengths against `DER::KEY_SIZES` before encoding.
- `DER.build_spki` and `DER.build_pkcs8` accept `parameters:` keyword for
  AlgorithmIdentifier parameters and (PKCS#8 only) `public_key:` keyword for
  the RFC 5958 publicKey field.
- `DER::KEY_SIZES` — frozen Hash mapping each built-in OID to
  `{ public:, secret: }` expected byte counts.
- `DER::Cursor` — zero-copy DER reader as a first-class public API with
  `#read`, `#read_raw`, `#read_sequence`, `#read_optional`, `#read_raw_optional`,
  `#skip`, `#skip_optional`, `#peek_tag`, `#eof?`, `#remaining`, `#pos`, `#data`,
  and convenience readers (`#read_integer`, `#read_oid`, `#read_octet_string`,
  `#read_bit_string`).
- `SecureBuffer` — `mmap`-backed allocation with `mlock`, `mprotect` guard
  pages, canary integrity checking, and secure zeroing on GC.
- `SecureBuffer#use { |bytes| }` — block-scoped access to secret key
  bytes; the yielded String is securely zeroed after the block returns.
- `SecureBuffer#wipe!` — eagerly zero and mark the buffer as wiped.
- `SecureBuffer#slice(offset, length)` — extract a sub-range as a new
  SecureBuffer.
- `SecureBuffer#to_pem(label = "PRIVATE KEY")` — PEM-encode DER contents
  directly from a SecureBuffer.
- `SecureBuffer.random(n)` — fill a new buffer from the platform CSPRNG.
- `SecureBuffer.from_string(str)` — copy a String into a SecureBuffer.
- `SecureBuffer#==` — constant-time equality comparison.
- `DERError`, `PEMError`, `OIDError` — fine-grained error subclasses.
  `DERError` and `PEMError` inherit from `ParseError` (backward-compatible);
  `OIDError` inherits from `Error`.
- `Error#code` — fine-grained symbol (e.g. `:outer_sequence`, `:base64`)
  identifying the exact failure point.
- `Error#category` — coarse programmatic error category (`:malformed_input`,
  `:malformed_encoding`, `:validation`, `:system`).
- `Error#offset` — byte position in the input where a parse error was detected.
- `rake vendor:verify` — checks SHA-256 of vendored C files against pinned
  checksums; fails loudly on mismatch.
- `rake vendor:lock` — records current SHA-256 digests after a deliberate
  vendor upgrade.
- `rake vendor:concat` — re-vendor from a local libpqcasn1 checkout.
- `rake vendor:update[VERSION]` — re-vendor from a GitHub release tarball.
- `rake fixtures:generate` — regenerates test fixtures from scratch.
- No runtime dependencies; no OpenSSL.
- Vendored libpqcasn1 0.1.3.

### Known limitations

- **No Windows support.** `SecureBuffer` uses POSIX `mmap`/`mprotect`/
  `mlock`, which are unavailable on Windows.  The gem will not compile on
  Windows without a compatibility layer (e.g. Cygwin/MSYS2).
- Composite key support is not yet implemented (placeholder classes raise
  `NotImplementedError`).
