# pqc_asn1

Algorithm-agnostic ASN.1/DER/PEM/Base64 codec for post-quantum cryptography key
serialization. Implemented in C with no OpenSSL dependency.

Handles SPKI (SubjectPublicKeyInfo, RFC 5480) and PKCS#8 / OneAsymmetricKey
(RFC 5958) structures for ML-DSA, ML-KEM, SLH-DSA, and any future scheme that
uses standard key-wrapping formats.

## Installation

Add to your Gemfile:

```ruby
gem "pqc_asn1"
```

Or install directly:

```sh
gem install pqc_asn1
```

The gem builds a native C extension — a C compiler is required.

## Usage

### Public key (SPKI)

```ruby
require "pqc_asn1"

# Encode
der = PqcAsn1::DER.build_spki(PqcAsn1::OID::ML_DSA_44, public_key_bytes)
pem = PqcAsn1::PEM.encode(der, "PUBLIC KEY")

# Decode
info = PqcAsn1::DER.parse_spki(der)
info.algorithm  # => "ML_DSA_44"
info.key        # => binary String (public key bytes)
info.to_der     # => original DER bytes
info.to_pem     # => PEM string with "PUBLIC KEY" label
```

### Private key (PKCS#8)

```ruby
# build_pkcs8 returns a SecureBuffer — memory is locked and securely zeroed on GC
der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, secret_key_bytes)
pem = PqcAsn1::PEM.encode(der, "PRIVATE KEY")

# SecureBuffer convenience
der.to_pem              # => PEM string with "PRIVATE KEY" label

# Decode
info = PqcAsn1::DER.parse_pkcs8(der)
info.algorithm          # => "ML_DSA_44"

# Use block-scoped access — bytes are securely zeroed when the block exits
info.key.use { |bytes| sign(bytes) }

# Or wipe manually
info.key.wipe!
```

### Key size validation

```ruby
# Raises ArgumentError if the key length doesn't match the OID
der = PqcAsn1::DER.build_spki(PqcAsn1::OID::ML_DSA_44, pk, validate: true)
der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, sk, validate: true)
```

### Auto-detection

```ruby
# Detects SPKI vs PKCS#8 vs EncryptedPrivateKeyInfo automatically
info = PqcAsn1::DER.parse_auto(der_bytes)
info.format     # => :spki, :pkcs8, or :encrypted_pkcs8

# PEM decode with auto-detection (uses PEM label to select parser)
info = PqcAsn1::DER.parse_pem(pem_string)
```

### PEM encoding / decoding

```ruby
# Encode arbitrary bytes
pem = PqcAsn1::PEM.encode(bytes, "PUBLIC KEY")

# Decode — returns a DecodeResult
result = PqcAsn1::PEM.decode_auto(pem)
result.label    # => "PUBLIC KEY"
result.data     # => DER bytes

# Explicit destructuring via .to_a
data, label = PqcAsn1::PEM.decode_auto(pem).to_a

# Iterate multiple PEM blocks in a String or IO stream
PqcAsn1::PEM.decode_each(pem_string) { |r| process(r.data, r.label) }

# IO streaming — reads line-by-line without slurping the file
File.open("keys.pem") do |f|
  PqcAsn1::PEM.decode_each(f) { |r| process(r.data, r.label) }
end

# Without a block — returns an Enumerator
PqcAsn1::PEM.decode_each(pem_string).map(&:data)
```

### Pattern matching (Ruby 2.7+)

```ruby
case PqcAsn1::DER.parse_spki(der)
in { oid:, key: }
  store_key(oid.name, key)
end
```

### OID utilities

```ruby
# Dotted-decimal <-> DER TLV
der_tlv = PqcAsn1::OID.from_dotted("2.16.840.1.101.3.4.3.17")
PqcAsn1::OID.to_dotted(der_tlv)   # => "2.16.840.1.101.3.4.3.17"

# Name lookup
PqcAsn1::OID.name_for(der_tlv)    # => "ML_DSA_44"

# OID value objects
oid = PqcAsn1::OID.new("2.16.840.1.101.3.4.3.17")
oid.name    # => "ML_DSA_44"
oid.dotted  # => "2.16.840.1.101.3.4.3.17"
```

### Registering custom OIDs at runtime

Registration is thread-safe (protected by a Mutex).

```ruby
oid = PqcAsn1::OID.register(
  "1.3.9999.1",
  "MY_ALGO_128",
  key_sizes: { public: 1312, secret: 2528 }
)

# Look up by name or dotted string — no constant is defined automatically
PqcAsn1::OID["MY_ALGO_128"]                        # => OID value object
PqcAsn1::OID["1.3.9999.1"]                         # => same object
PqcAsn1::DER.build_spki(oid, pk, validate: true)   # key size validation works

# To define a constant, assign explicitly:
PqcAsn1::OID::MY_ALGO_128 = oid
```

### SecureBuffer

```ruby
# Build a PKCS#8 key — returns a SecureBuffer
der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, secret_key_bytes)

# Block-scoped access — bytes zeroed after the block
der.use { |bytes| sign(bytes) }

# Write DER bytes directly to an IO (minimises heap exposure)
File.open("key.der", "wb") { |f| der.write_to(f) }

# PEM-encode directly to an IO
File.open("key.pem", "w") { |f| der.to_pem_io(f) }

# Wipe returns self for chaining
der.wipe!.wiped?  # => true

# Generate random secure bytes from the platform CSPRNG
nonce = PqcAsn1::SecureBuffer.random(32)

# Extract a sub-range as a new SecureBuffer
slice = der.slice(0, 64)
```

### Input size limits

```ruby
# Default: 1 MiB — protects parse methods against oversized input
PqcAsn1::DER.max_input_size          # => 1048576

# Adjust or disable
PqcAsn1::DER.max_input_size = 4 << 20  # 4 MiB
PqcAsn1::DER.max_input_size = nil       # no limit
```

### Error handling

```ruby
begin
  PqcAsn1::DER.parse_spki(bad_bytes)
rescue PqcAsn1::DERError => e
  # DER structure is malformed
  puts e.category   # => :malformed_input
  puts e.code       # => :outer_sequence (fine-grained symbol)
  puts e.offset     # => byte position where error was detected
rescue PqcAsn1::PEMError => e
  # Base64 / PEM armor problem
rescue PqcAsn1::OIDError => e
  # Unrecognised or invalid OID
rescue PqcAsn1::ParseError => e
  # Catches both DERError and PEMError
rescue PqcAsn1::Error => e
  # Top-level catch-all
end
```

Error categories:

| Category | Meaning |
|---|---|
| `:malformed_input` | DER TLV structure is wrong |
| `:malformed_encoding` | Base64 or PEM armor is invalid |
| `:validation` | Key size or OID mismatch |
| `:system` | Memory allocation failure |

## OID constants

`PqcAsn1::OID` contains value objects for all current NIST PQC algorithms:

| Constant | Algorithm | OID |
|---|---|---|
| `ML_DSA_44` | ML-DSA (FIPS 204) | 2.16.840.1.101.3.4.3.17 |
| `ML_DSA_65` | ML-DSA (FIPS 204) | 2.16.840.1.101.3.4.3.18 |
| `ML_DSA_87` | ML-DSA (FIPS 204) | 2.16.840.1.101.3.4.3.19 |
| `ML_KEM_512` | ML-KEM (FIPS 203) | 2.16.840.1.101.3.4.4.1 |
| `ML_KEM_768` | ML-KEM (FIPS 203) | 2.16.840.1.101.3.4.4.2 |
| `ML_KEM_1024` | ML-KEM (FIPS 203) | 2.16.840.1.101.3.4.4.3 |
| `SLH_DSA_SHA2_128S` | SLH-DSA (FIPS 205) | 2.16.840.1.101.3.4.3.20 |
| `SLH_DSA_SHA2_128F` | SLH-DSA (FIPS 205) | 2.16.840.1.101.3.4.3.21 |
| `SLH_DSA_SHA2_192S` | SLH-DSA (FIPS 205) | 2.16.840.1.101.3.4.3.22 |
| `SLH_DSA_SHA2_192F` | SLH-DSA (FIPS 205) | 2.16.840.1.101.3.4.3.23 |
| `SLH_DSA_SHA2_256S` | SLH-DSA (FIPS 205) | 2.16.840.1.101.3.4.3.24 |
| `SLH_DSA_SHA2_256F` | SLH-DSA (FIPS 205) | 2.16.840.1.101.3.4.3.25 |
| `SLH_DSA_SHAKE_128S` | SLH-DSA (FIPS 205) | 2.16.840.1.101.3.4.3.26 |
| `SLH_DSA_SHAKE_128F` | SLH-DSA (FIPS 205) | 2.16.840.1.101.3.4.3.27 |
| `SLH_DSA_SHAKE_192S` | SLH-DSA (FIPS 205) | 2.16.840.1.101.3.4.3.28 |
| `SLH_DSA_SHAKE_192F` | SLH-DSA (FIPS 205) | 2.16.840.1.101.3.4.3.29 |
| `SLH_DSA_SHAKE_256S` | SLH-DSA (FIPS 205) | 2.16.840.1.101.3.4.3.30 |
| `SLH_DSA_SHAKE_256F` | SLH-DSA (FIPS 205) | 2.16.840.1.101.3.4.3.31 |

## Key size reference

`PqcAsn1::DER::KEY_SIZES` maps each OID to `{ public:, secret: }` byte counts.
Used automatically when `validate: true` is passed to `build_spki` / `build_pkcs8`.

## Implementation

The gem is implemented in C with no OpenSSL dependency:

- **libpqcasn1** (v0.1.5) — Vendored pure C ASN.1/DER codec for key serialization
- **libpqcsb** (v0.1.0) — Vendored secure memory buffer library providing `mmap`-backed
  allocation, guard pages, memory locking, and secure zeroing

Both libraries are vendored; the gem builds a single native extension with no external
C dependencies beyond POSIX APIs and the C standard library.

## Requirements

- Ruby >= 2.7.2
- A C compiler (the gem builds a native extension)
- POSIX platform (Linux, macOS). Windows is not supported — `SecureBuffer`
  requires `mmap`/`mprotect`/`mlock` which are unavailable on native Windows

## License

Licensed under either of

- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. Contributions are dual-licensed under the same terms unless
explicitly stated otherwise.
