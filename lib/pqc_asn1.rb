# frozen_string_literal: true

require_relative "pqc_asn1/version"

# Algorithm-agnostic ASN.1/DER/PEM/Base64 utilities for post-quantum
# key serialization.  Usable by ML-DSA, ML-KEM, SLH-DSA, and any
# future PQC scheme that uses standard SPKI / PKCS#8 / PEM wrapping.
#
# Submodules:
#   PqcAsn1::DER    — DER encoding/decoding, SPKI/PKCS#8 build & parse
#   PqcAsn1::PEM    — PEM armor encode/decode
#   PqcAsn1::Base64 — Base64 encode/decode
#   PqcAsn1::OID    — OID value class + constants for PQC algorithms
#
# All methods return frozen binary String buffers (ASCII-8BIT encoding)
# except where noted.
module PqcAsn1
  # Base error class for all PqcAsn1 errors.
  #
  # Two attributes enable programmatic error handling without parsing
  # the message string:
  #
  # +code+ — fine-grained symbol matching the C library status code:
  #   :outer_sequence, :version, :algorithm, :key, :unused_bits,
  #   :trailing_data, :pem_no_markers, :pem_label, :base64,
  #   :invalid_oid, :extra_fields, :overflow, :alloc,
  #   :buffer_too_small, :label_too_long, :der_parse,
  #   :null_param, :pem_malformed
  #
  # +category+ — coarse bucket derived from +code+:
  #   :malformed_input    — a DER field is structurally wrong
  #   :malformed_encoding — Base64 / PEM boundary / label problem
  #   :validation         — caller-side constraint violation (bad OID, overflow, etc.)
  #   :system             — memory allocation failed
  #
  #   rescue PqcAsn1::ParseError => e
  #     case e.category
  #     when ParseError::MALFORMED_INPUT    then retry_with_lenient_parser
  #     when ParseError::MALFORMED_ENCODING then raise "check your PEM"
  #     end
  #   end
  class Error < StandardError
    # @return [Symbol, nil] fine-grained machine-readable error code
    attr_reader :code

    # @return [Integer, nil] byte offset in the input where the error was
    #   detected, or nil when the error is not parse-position-specific.
    #   Set by the C extension for Cursor and DER parse errors.
    attr_reader :offset

    # @param msg [String, nil] human-readable description
    # @param code [Symbol, nil] fine-grained error code
    # @param offset [Integer, nil] byte offset in input where error occurred
    def initialize(msg = nil, code: nil, offset: nil)
      @code = code
      @offset = offset
      super(msg)
    end

    # @return [Symbol, nil] coarse error category derived from +code+:
    #   :malformed_input, :malformed_encoding, :validation, or :system.
    #   Returns nil when code is nil or not categorised.
    def category
      case @code
      when :outer_sequence, :version, :algorithm, :key, :unused_bits,
           :trailing_data, :extra_fields, :der_parse
        :malformed_input
      when :pem_no_markers, :pem_label, :base64, :pem_malformed
        :malformed_encoding
      when :invalid_oid, :overflow, :buffer_too_small, :label_too_long,
           :null_param
        :validation
      when :alloc
        :system
      end
    end
  end

  # Raised when DER, PEM, or Base64 input cannot be parsed.
  # Subclass of Error — rescue Error catches both.
  class ParseError < Error
    # Frozen category constants for use in +when+ branches without
    # string allocation.  Prefer these over bare symbol literals when
    # pattern-matching on e.category.
    MALFORMED_INPUT = :malformed_input
    MALFORMED_ENCODING = :malformed_encoding
    VALIDATION = :validation
    SYSTEM = :system
  end

  # Raised for DER-specific parse errors (outer SEQUENCE, version,
  # algorithm, key, unused bits, trailing data, extra fields).
  # Rescue this to handle DER problems separately from PEM/OID errors.
  class DERError < ParseError; end

  # Raised for PEM-specific parse errors (missing markers, label
  # mismatch, malformed PEM, bad Base64 body).
  class PEMError < ParseError; end

  # Raised for OID-specific errors (invalid OID format, encoding overflow).
  class OIDError < Error; end

  # Unified result returned by DER.parse_spki and DER.parse_pkcs8.
  #
  # An immutable value object carrying all parsed fields plus a +format+
  # field (:spki or :pkcs8) that identifies which structure was parsed.
  #
  # For SPKI:  +key+ is the public key bytes (frozen ASCII-8BIT String).
  # For PKCS#8: +key+ is a SecureBuffer; its backing memory is securely
  #   zeroed when the object is garbage-collected.
  #
  # Supports attribute access (+result.oid+) and +deconstruct_keys+
  # for pattern matching.
  #
  # @example SPKI
  #   parsed = PqcAsn1::DER.parse_spki(der)
  #   puts parsed.oid.name  # => "ML_DSA_44"
  #
  # @example PKCS#8 pattern matching
  #   case PqcAsn1::DER.parse_pkcs8(der)
  #   in { format: :pkcs8, oid:, key: }
  #     key.use { |bytes| sign(bytes) }
  #   end
  #
  module DER
    # Zero-copy DER reader for callers that need fine-grained traversal
    # beyond {DER.parse_spki} / {DER.parse_pkcs8}.
    #
    # *Advanced API* — most callers should use the high-level methods
    # ({DER.parse_spki}, {DER.parse_pkcs8}, {DER.parse_encrypted_pkcs8})
    # instead.  Use Cursor only when you need to navigate a custom DER
    # structure that the built-in parsers do not cover.
    #
    # A Cursor wraps a binary String and provides sequential read operations
    # that advance an internal position without copying data.
    # {#read_sequence} returns a new Cursor scoped to the SEQUENCE content,
    # sharing the same source — still zero-copy.
    #
    # All +read_*+ methods return frozen ASCII-8BIT Strings.  The Cursor
    # holds a strong reference to the source String, preventing GC while
    # any sub-cursor is alive.
    #
    # @example Parsing a custom DER structure
    #   cursor = PqcAsn1::DER::Cursor.new(der_bytes)
    #   seq    = cursor.read_sequence
    #   oid    = seq.read_oid          # tag 0x06 content bytes
    #   key    = seq.read_bit_string   # tag 0x03 content bytes
    #   assert seq.eof?
    #
    # @example Reading optional fields
    #   seq = PqcAsn1::DER::Cursor.new(der).read_sequence
    #   version = seq.read_optional(0x02)  # nil if not present
    #   algo    = seq.read_sequence
    #
    # @example Forwarding an opaque TLV
    #   raw_tlv = cursor.read_raw(0x30)  # full tag+length+value bytes
    #
    # Defined by the C extension (ext/pqc_asn1/cursor.c).
    #
    # @!method initialize(data, pos = 0)
    #   Create a new Cursor over DER-encoded data.
    #   @param data [String] binary DER bytes
    #   @param pos [Integer] starting byte offset (default 0)
    #   @return [Cursor]
    #
    # @!method read(expected_tag)
    #   Read the content bytes of the next TLV with the given tag.
    #   Advances the cursor past the entire TLV.
    #   @param expected_tag [Integer] DER tag byte (e.g. 0x02, 0x04, 0x06)
    #   @return [String] frozen binary content bytes (no tag/length)
    #   @raise [PqcAsn1::DERError] if the next tag does not match
    #
    # @!method read_raw(expected_tag)
    #   Read the full TLV bytes (tag + length + value) at the current position.
    #   Useful for forwarding an opaque field without interpreting it.
    #   @param expected_tag [Integer] DER tag byte
    #   @return [String] frozen binary TLV bytes
    #   @raise [PqcAsn1::DERError] if the next tag does not match
    #
    # @!method read_sequence
    #   Read a SEQUENCE (tag 0x30) and return a new Cursor scoped to its content.
    #   The sub-cursor shares the same source String (zero-copy).
    #   @return [Cursor] new cursor over the SEQUENCE body
    #   @raise [PqcAsn1::DERError] if the next tag is not 0x30
    #
    # @!method read_integer
    #   Shorthand for +read(0x02)+.
    #   @return [String] frozen binary INTEGER content bytes
    #
    # @!method read_oid
    #   Shorthand for +read(0x06)+.
    #   @return [String] frozen binary OID content bytes
    #
    # @!method read_octet_string
    #   Shorthand for +read(0x04)+.
    #   @return [String] frozen binary OCTET STRING content bytes
    #
    # @!method read_bit_string
    #   Shorthand for +read(0x03)+.
    #   @return [String] frozen binary BIT STRING content bytes
    #
    # @!method read_optional(expected_tag)
    #   Like {#read} but returns +nil+ (without advancing) if at EOF or
    #   the next tag does not match.
    #   @param expected_tag [Integer] DER tag byte
    #   @return [String, nil]
    #
    # @!method read_raw_optional(expected_tag)
    #   Like {#read_raw} but returns +nil+ if at EOF or tag mismatch.
    #   @param expected_tag [Integer] DER tag byte
    #   @return [String, nil]
    #
    # @!method skip(expected_tag)
    #   Skip the next TLV with the given tag.  Returns +self+ for chaining.
    #   @param expected_tag [Integer] DER tag byte
    #   @return [self]
    #   @raise [PqcAsn1::DERError] if the next tag does not match
    #
    # @!method skip_optional(expected_tag)
    #   Like {#skip} but returns +nil+ if at EOF or tag mismatch.
    #   @param expected_tag [Integer] DER tag byte
    #   @return [self, nil]
    #
    # @!method peek_tag
    #   Return the tag byte at the current position without advancing.
    #   @return [Integer, nil] nil if at EOF
    #
    # @!method eof?
    #   @return [Boolean] true if all bytes have been consumed
    #
    # @!method remaining
    #   @return [Integer] number of unconsumed bytes
    #
    # @!method pos
    #   @return [Integer] current byte offset within the source
    #
    # @!method data
    #   Return the full backing data of this cursor (or the relevant
    #   substring for a sub-cursor).  Frozen ASCII-8BIT String.
    #   @return [String]
    class Cursor; end

    # @!method self.build_spki(oid, public_key, parameters: nil)
    #   Build a SubjectPublicKeyInfo (SPKI) DER structure.
    #   @param oid [PqcAsn1::OID, String] algorithm OID
    #   @param public_key [String] raw public key bytes
    #   @param parameters [String, nil] optional AlgorithmIdentifier parameters DER
    #   @return [String] frozen DER bytes (ASCII-8BIT)

    # @!method self.build_pkcs8(oid, secret_key, parameters: nil, public_key: nil)
    #   Build a PKCS#8 / OneAsymmetricKey DER structure.
    #   @param oid [PqcAsn1::OID, String] algorithm OID
    #   @param secret_key [String] raw secret key bytes
    #   @param parameters [String, nil] optional AlgorithmIdentifier parameters DER
    #   @param public_key [String, nil] optional publicKey [1] IMPLICIT BIT STRING
    #   @return [PqcAsn1::SecureBuffer] mmap-protected DER bytes

    # @!method self.parse_spki(der)
    #   Parse a SubjectPublicKeyInfo DER structure.
    #   @param der [String] DER-encoded SPKI
    #   @return [PqcAsn1::DER::KeyInfo] with format :spki
    #   @raise [PqcAsn1::DERError] on malformed input

    # @!method self.parse_pkcs8(der)
    #   Parse a PKCS#8 / OneAsymmetricKey DER structure.
    #   @param der [String, PqcAsn1::SecureBuffer] DER-encoded PKCS#8
    #   @return [PqcAsn1::DER::KeyInfo] with format :pkcs8
    #   @raise [PqcAsn1::DERError] on malformed input

    # @!method self.detect_format(der)
    #   Detect whether DER bytes are SPKI or PKCS#8.
    #   @param der [String] DER bytes
    #   @return [Symbol] :spki or :pkcs8
    #   @raise [PqcAsn1::DERError] if unrecognised

    class KeyInfo
      # @return [PqcAsn1::OID] parsed algorithm OID
      attr_reader :oid

      # @return [String, nil] raw AlgorithmIdentifier parameter bytes
      #   (ASCII-8BIT, frozen), or nil when absent.
      attr_reader :parameters

      # @return [String, PqcAsn1::SecureBuffer] key bytes.
      #   For :spki this is the public key (frozen String).
      #   For :pkcs8 this is a SecureBuffer holding the secret key.
      attr_reader :key

      # @return [String, nil] optional public key from the PKCS#8
      #   OneAsymmetricKey publicKey [1] field, or nil if absent.
      attr_reader :public_key

      # @return [Symbol] :spki or :pkcs8
      attr_reader :format

      # @api private — constructed by DER.parse_spki / DER.parse_pkcs8 via C extension
      def initialize(oid, parameters, key, public_key, format)
        @oid = oid
        @parameters = parameters
        @key = key
        @public_key = public_key
        @format = format
        freeze
      end

      # @return [Hash{Symbol => Object}]
      def to_h
        {oid: @oid, parameters: @parameters, key: @key,
         public_key: @public_key, format: @format}
      end

      # Pattern-matching support (Ruby 2.7+).
      # When +keys+ is non-nil, only the requested keys are returned,
      # avoiding unnecessary access to fields like +key+ (a SecureBuffer
      # that requires mprotect toggling).
      # @param keys [Array<Symbol>, nil]
      # @return [Hash{Symbol => Object}]
      def deconstruct_keys(keys)
        return to_h if keys.nil?

        keys.each_with_object({}) do |k, h|
          case k
          when :oid then h[:oid] = @oid
          when :parameters then h[:parameters] = @parameters
          when :key then h[:key] = @key
          when :public_key then h[:public_key] = @public_key
          when :format then h[:format] = @format
          end
        end
      end

      # @param other [Object]
      # @return [Boolean]
      def ==(other)
        other.is_a?(KeyInfo) &&
          @oid == other.oid &&
          @parameters == other.parameters &&
          @key == other.key &&
          @public_key == other.public_key &&
          @format == other.format
      end

      alias_method :eql?, :==

      # @return [Integer]
      # For :pkcs8, the secret key is excluded from the hash to avoid
      # leaking key material into hash tables or log output.
      def hash
        if @format == :pkcs8
          [@oid, @parameters, @public_key, @format].hash
        else
          [@oid, @parameters, @key, @public_key, @format].hash
        end
      end

      # Human-readable algorithm name (e.g. "ML_DSA_44"), or the dotted
      # OID string if the algorithm is not a known constant.
      # @return [String]
      def algorithm
        @oid.name || @oid.dotted
      end

      # Re-encode this KeyInfo back to DER bytes.
      # For :spki returns a frozen binary String.
      # For :pkcs8 returns a SecureBuffer.
      # @return [String, PqcAsn1::SecureBuffer]
      def to_der
        opts = {validate: false}
        opts[:parameters] = @parameters if @parameters
        opts[:public_key] = @public_key if @public_key

        case @format
        when :spki
          PqcAsn1::DER.build_spki(@oid, @key, **opts)
        when :pkcs8
          PqcAsn1::DER.build_pkcs8(@oid, @key, **opts)
        else
          raise PqcAsn1::Error, "cannot re-encode format #{@format.inspect}"
        end
      end

      # Re-encode to PEM.  Uses "PUBLIC KEY" for :spki and
      # "PRIVATE KEY" for :pkcs8.
      #
      # Security caveat: for :pkcs8, the returned PEM String is an
      # ordinary Ruby String on the heap, NOT a SecureBuffer.  The
      # PEM text is not mmap-protected, not mlock'd, and may be
      # swapped to disk or copied by the GC compactor.  Discard the
      # result as soon as possible to limit exposure of secret key
      # material.
      #
      # @return [String] US-ASCII PEM string
      def to_pem
        der = to_der
        label =
          case @format
          when :spki then "PUBLIC KEY"
          when :pkcs8 then "PRIVATE KEY"
          else raise PqcAsn1::Error, "cannot PEM-encode format #{@format.inspect}"
          end
        PqcAsn1::PEM.encode(der, label)
      end

      # Key bytes are never shown for :pkcs8.
      # @return [String]
      def inspect
        alg = @parameters ? " params=#{@parameters.bytesize}B" : ""
        pk = @public_key ? " public_key=#{@public_key.bytesize}B" : ""
        name = algorithm
        case @format
        when :spki
          "#<PqcAsn1::DER::KeyInfo format=:spki oid=#{name}#{alg} key=#{@key.bytesize}B>"
        when :pkcs8
          "#<PqcAsn1::DER::KeyInfo format=:pkcs8 oid=#{name}#{alg} key=REDACTED#{pk}>"
        else
          "#<PqcAsn1::DER::KeyInfo format=#{@format.inspect}>"
        end
      end
    end

    # Result returned by {DER.parse_encrypted_pkcs8}.
    #
    # An immutable value object holding the two opaque fields of an
    # EncryptedPrivateKeyInfo (RFC 5958) structure.  This gem is a
    # codec — it does not perform the actual encryption or decryption.
    # Callers are responsible for:
    #   1. Encrypting a PKCS#8 DER blob (e.g. via OpenSSL or libsodium)
    #      and providing +encryption_algorithm_der+ + +encrypted_data+ to
    #      {DER.build_encrypted_pkcs8}.
    #   2. Decrypting +encrypted_data+ (using +encryption_algorithm+ as a
    #      hint for algorithm + parameters) and passing the result to
    #      {DER.parse_pkcs8}.
    #
    # @example Round-trip
    #   info = PqcAsn1::DER.parse_encrypted_pkcs8(der)
    #   info.format                          # => :encrypted_pkcs8
    #   info.encryption_algorithm.bytesize   # => AlgorithmIdentifier DER size
    #   info.encrypted_data.bytesize         # => ciphertext size
    #   info.to_pem                          # => "-----BEGIN ENCRYPTED PRIVATE KEY..."
    #
    class EncryptedKeyInfo
      # @return [String] full AlgorithmIdentifier DER TLV (frozen ASCII-8BIT).
      #   The tag, length, OID, and any algorithm parameters are all included
      #   so callers can pass this directly to their cipher implementation.
      attr_reader :encryption_algorithm

      # @return [String] raw ciphertext bytes (frozen ASCII-8BIT).
      #   These are the contents of the encryptedData OCTET STRING; the
      #   outer OCTET STRING TLV is stripped.
      attr_reader :encrypted_data

      # @return [Symbol] always +:encrypted_pkcs8+
      attr_reader :format

      # @api private — constructed by DER.parse_encrypted_pkcs8
      def initialize(encryption_algorithm, encrypted_data)
        @encryption_algorithm = encryption_algorithm
        @encrypted_data = encrypted_data
        @format = :encrypted_pkcs8
        freeze
      end

      # Re-encode to EncryptedPrivateKeyInfo DER.
      # @return [String] frozen binary DER bytes (ASCII-8BIT)
      def to_der
        PqcAsn1::DER.build_encrypted_pkcs8(@encryption_algorithm, @encrypted_data)
      end

      # Re-encode to PEM with label "ENCRYPTED PRIVATE KEY".
      # @return [String] frozen US-ASCII PEM string
      def to_pem
        PqcAsn1::PEM.encode(to_der, "ENCRYPTED PRIVATE KEY")
      end

      # @return [Hash{Symbol => Object}]
      def to_h
        {encryption_algorithm: @encryption_algorithm,
         encrypted_data: @encrypted_data,
         format: @format}
      end

      # Pattern-matching support (Ruby 2.7+).
      # @param keys [Array<Symbol>, nil]
      # @return [Hash{Symbol => Object}]
      def deconstruct_keys(keys)
        return to_h if keys.nil?

        keys.each_with_object({}) do |k, h|
          case k
          when :encryption_algorithm then h[:encryption_algorithm] = @encryption_algorithm
          when :encrypted_data then h[:encrypted_data] = @encrypted_data
          when :format then h[:format] = @format
          end
        end
      end

      # @param other [Object]
      # @return [Boolean]
      def ==(other)
        other.is_a?(EncryptedKeyInfo) &&
          @encryption_algorithm == other.encryption_algorithm &&
          @encrypted_data == other.encrypted_data
      end

      alias_method :eql?, :==

      # @return [Integer]
      def hash
        [@encryption_algorithm, @encrypted_data].hash
      end

      # @return [String]
      def inspect
        "#<PqcAsn1::DER::EncryptedKeyInfo " \
          "algo=#{@encryption_algorithm.bytesize}B " \
          "encrypted=#{@encrypted_data.bytesize}B>"
      end
    end

    # Placeholder for composite / hybrid key support (PQC + traditional).
    #
    # Composite key structures are defined in draft NIST standards and
    # IETF drafts (e.g. draft-ietf-lamps-pq-composite-sigs).  This class
    # is reserved so the API shape can be stabilised before a full
    # implementation ships.
    #
    # All methods raise {NotImplementedError}.  Track implementation progress
    # at https://github.com/msuliq/pqc_asn1/issues.
    class CompositeKeyInfo
      def initialize(*) # rubocop:disable Lint/MissingSuper
        raise NotImplementedError,
          "Composite key support is not yet implemented. " \
          "See https://github.com/msuliq/pqc_asn1/issues for status."
      end
    end
  end

  # Result returned by PEM.decode_auto.
  #
  # An immutable value object with named attributes (+data+ and +label+).
  # Use attribute access or pattern matching as the primary API:
  #
  #   result = PqcAsn1::PEM.decode_auto(pem)
  #   result.data   # => binary String
  #   result.label  # => "PUBLIC KEY"
  #
  # +to_a+ provides an explicit Array conversion when needed:
  #
  #   data, label = PqcAsn1::PEM.decode_auto(pem).to_a
  #
  # Note: +to_ary+ is intentionally absent.  Implicit array coercion
  # (e.g. via splat or Array()) is a footgun that causes DecodeResult
  # objects to be silently destructured in unexpected contexts.
  #
  # @example Pattern matching
  #   case PqcAsn1::PEM.decode_auto(pem)
  #   in { label: "PUBLIC KEY", data: }
  #     PqcAsn1::DER.parse_spki(data)
  #   end
  # PEM armor encode/decode.
  #
  # All methods are module functions defined by the C extension.
  #
  # @!method self.encode(data, label)
  #   PEM-encode binary data with the given label.
  #   @param data [String, PqcAsn1::SecureBuffer] raw DER bytes
  #   @param label [String] PEM label (e.g. "PUBLIC KEY", "PRIVATE KEY")
  #   @return [String] frozen US-ASCII PEM string
  #
  # @!method self.decode(pem, label)
  #   Decode a PEM block with the expected label.
  #   @param pem [String] PEM-encoded string
  #   @param label [String] expected PEM label
  #   @return [String] frozen binary DER bytes (ASCII-8BIT)
  #   @raise [PqcAsn1::PEMError] on missing markers, label mismatch, or bad Base64
  #
  # @!method self.decode_auto(pem)
  #   Decode a PEM block, auto-detecting the label.
  #   @param pem [String] PEM-encoded string
  #   @return [PqcAsn1::PEM::DecodeResult]
  #   @raise [PqcAsn1::PEMError] on invalid PEM
  module PEM
    class DecodeResult
      # @return [String] decoded DER bytes (ASCII-8BIT, frozen)
      attr_reader :data

      # @return [String] PEM label string (US-ASCII, frozen)
      attr_reader :label

      # @api private — constructed by PEM.decode_auto via C extension
      def initialize(data, label)
        @data = data
        @label = label
        freeze
      end

      # Explicit Array conversion: +data, label = PEM.decode_auto(pem).to_a+
      # @return [Array(String, String)]
      def to_a
        [@data, @label]
      end

      # @return [Hash{Symbol => String}]
      def to_h
        {data: @data, label: @label}
      end

      # Pattern-matching support (Ruby 2.7+).
      # When +keys+ is non-nil, only the requested keys are returned.
      # @param keys [Array<Symbol>, nil]
      # @return [Hash{Symbol => String}]
      def deconstruct_keys(keys)
        return to_h if keys.nil?

        keys.each_with_object({}) do |k, h|
          case k
          when :data then h[:data] = @data
          when :label then h[:label] = @label
          end
        end
      end

      # @param other [Object]
      # @return [Boolean]
      def ==(other)
        other.is_a?(DecodeResult) &&
          @data == other.data &&
          @label == other.label
      end

      alias_method :eql?, :==

      # @return [Integer]
      def hash
        [@data, @label].hash
      end

      # @return [String]
      def inspect
        "#<PqcAsn1::PEM::DecodeResult label=#{@label.inspect} data=#{@data.bytesize}B>"
      end
    end

    # decode_each is implemented in C (ext/pqc_asn1/pem.c) and attached
    # as a module function by init_pem() during Init_pqc_asn1_ext.
    # It iterates over all PEM blocks in a String or IO, yielding a
    # DecodeResult for each block found.
    #
    # For IO objects, a Ruby-level wrapper reads line-by-line and
    # accumulates PEM blocks incrementally, avoiding slurping the
    # entire stream into memory.
  end

  # Base64 encode/decode (RFC 4648 alphabet, no line wrapping).
  #
  # @!method self.encode(data)
  #   Base64-encode binary data.
  #   @param data [String] binary bytes
  #   @return [String] frozen US-ASCII Base64 string
  #
  # @!method self.decode(b64)
  #   Decode a Base64 string.
  #   @param b64 [String] Base64-encoded string
  #   @return [String] frozen binary bytes (ASCII-8BIT)
  #   @raise [PqcAsn1::PEMError] on invalid Base64 input
  module Base64; end

  # Secure memory buffer backed by mmap(2) with mprotect(2) and mlock(2).
  #
  # SecureBuffer holds secret key material in memory that is:
  # - mlock'd to prevent swapping to disk
  # - mprotect'd to PROT_NONE when not in use (inaccessible)
  # - securely zeroed on GC or explicit wipe!
  # - guarded by canary bytes to detect buffer overflow
  #
  # Use {#use} to temporarily unlock the memory for reading:
  #
  #   secure_buf.use { |bytes| do_something_with(bytes) }
  #
  # @!method bytesize
  #   @return [Integer] size of the protected region in bytes
  #
  # @!method size
  #   Alias for {#bytesize}.
  #   @return [Integer]
  #
  # @!method use
  #   Temporarily unlock the buffer (PROT_READ) and yield its contents.
  #   The buffer is re-locked (PROT_NONE) after the block returns.
  #   @yieldparam bytes [String] frozen binary String (valid only inside block)
  #   @return [Object] the block's return value
  #
  # @!method wipe!
  #   Securely zero the buffer contents and mark it as wiped.
  #   Subsequent {#use} calls will raise.
  #   @return [self]
  #
  # @!method wiped?
  #   @return [Boolean] true if {#wipe!} has been called
  #
  # @!method canary_ok?
  #   @return [Boolean] true if the guard canary bytes are intact
  #
  # @!method slice(offset, length)
  #   Extract a sub-range of the buffer as a new SecureBuffer.
  #   The sub-range is copied into a fresh mmap-protected region so the
  #   extracted material gets the same security guarantees as the source.
  #   @param offset [Integer] byte offset
  #   @param length [Integer] number of bytes
  #   @return [PqcAsn1::SecureBuffer] new SecureBuffer containing the requested bytes
  #
  # @!method to_s
  #   @return [String] frozen binary copy of the buffer contents
  #
  # @!method inspect
  #   @return [String] redacted representation (never reveals contents)
  class SecureBuffer; end
end

# OID class must be loaded before the C extension so that
# Init_pqc_asn1_ext can look up PqcAsn1::OID at load time.
require_relative "pqc_asn1/oid"
require "pqc_asn1/pqc_asn1_ext"
require_relative "pqc_asn1/key_sizes"

# Ruby-level extensions that depend on both OID constants and C methods.
module PqcAsn1
  module PEM
    class << self
      alias_method :_c_decode_each, :decode_each

      # Iterate over PEM blocks in a String or IO.
      #
      # For IO objects, reads line-by-line and decodes each PEM block
      # as it completes, avoiding reading the entire stream into memory.
      # For Strings, delegates directly to the C implementation.
      #
      # @param input [String, #each_line] PEM text or IO
      # @yieldparam result [PqcAsn1::PEM::DecodeResult]
      # @return [nil, Enumerator]
      def decode_each(input, &block)
        if input.respond_to?(:each_line) && !input.is_a?(String)
          return _io_decode_each_enum(input) unless block

          _io_decode_each(input, &block)
          nil
        else
          _c_decode_each(input, &block)
        end
      end

      private

      BEGIN_RE = /\A-----BEGIN (.+)-----\s*\z/
      END_RE = /\A-----END (.+)-----\s*\z/

      def _io_decode_each(io)
        label = nil
        lines = nil

        io.each_line do |line|
          line = line.chomp
          if label.nil?
            m = BEGIN_RE.match(line)
            if m
              label = m[1]
              lines = [line]
            end
          else
            lines << line
            m = END_RE.match(line)
            if m
              unless m[1] == label
                raise PqcAsn1::PEMError.new(
                  "PEM label mismatch: BEGIN #{label} / END #{m[1]}",
                  code: :pem_label
                )
              end
              block_str = lines.join("\n") << "\n"
              _c_decode_each(block_str) { |r| yield r }
              label = nil
              lines = nil
            end
          end
        end

        # If we reach EOF while inside a BEGIN block, the PEM is truncated.
        if label
          raise PqcAsn1::PEMError.new(
            "truncated PEM: found BEGIN #{label} but no matching END marker",
            code: :pem_no_markers
          )
        end
      end

      def _io_decode_each_enum(io)
        Enumerator.new do |y|
          _io_decode_each(io) { |r| y << r }
        end
      end
    end
  end

  module DER
    # Maximum input size (in bytes) accepted by parse methods.
    # Protects against denial-of-service via oversized input.
    # Set to nil to disable the limit.
    # Default: 1 MiB — more than enough for any PQC key structure.
    @max_input_size = 1 << 20 # 1 MiB

    class << self
      # @return [Integer, nil] maximum input size in bytes, or nil to disable
      attr_accessor :max_input_size
    end

    # KEY_SIZES is defined in lib/pqc_asn1/key_sizes.rb
    # (auto-generated by `rake codegen:key_sizes` from data/oids.yml).

    # Key sizes for algorithms registered at runtime via OID.register.
    # Unlike KEY_SIZES (frozen at load time from oids.yml), this hash is
    # mutable so OID.register can extend it without rebuilding KEY_SIZES.
    # Intentionally a mutable constant (standard Ruby pattern); mutated
    # only by OID.register under the GVL.
    REGISTERED_KEY_SIZES = {} # :nodoc:

    class << self
      alias_method :_c_build_spki, :build_spki
      alias_method :_c_build_pkcs8, :build_pkcs8
      alias_method :_c_parse_spki, :parse_spki
      alias_method :_c_parse_pkcs8, :parse_pkcs8

      # Build an SPKI DER structure.
      #
      # When +validate: true+, checks that the public key size matches
      # the expected size for the given OID (if known) before encoding.
      #
      # @param oid [PqcAsn1::OID, String]
      # @param public_key [String]
      # @param parameters [String, nil]
      # @param validate [Boolean] check key size against KEY_SIZES
      # @return [String] frozen DER bytes
      def build_spki(oid, public_key, parameters: nil, validate: true)
        if validate
          oid_obj = oid.is_a?(PqcAsn1::OID) ? oid : PqcAsn1::OID.new(oid)
          validate_key_size(oid_obj, public_key.bytesize, :public)
        end
        if parameters
          _c_build_spki(oid, public_key, parameters: parameters)
        else
          _c_build_spki(oid, public_key)
        end
      end

      # Build a PKCS#8 DER structure.
      #
      # When +validate: true+, checks that the secret key size matches
      # the expected size for the given OID (if known) before encoding.
      #
      # @param oid [PqcAsn1::OID, String]
      # @param secret_key [String, PqcAsn1::SecureBuffer]
      # @param parameters [String, nil]
      # @param public_key [String, nil]
      # @param validate [Boolean] check key size against KEY_SIZES
      # @return [PqcAsn1::SecureBuffer]
      def build_pkcs8(oid, secret_key, parameters: nil, public_key: nil, validate: true)
        if validate
          oid_obj = oid.is_a?(PqcAsn1::OID) ? oid : PqcAsn1::OID.new(oid)
          validate_key_size(oid_obj, secret_key.bytesize, :secret)
        end
        kwargs = {}
        kwargs[:parameters] = parameters if parameters
        kwargs[:public_key] = public_key if public_key
        if kwargs.empty?
          _c_build_pkcs8(oid, secret_key)
        else
          _c_build_pkcs8(oid, secret_key, **kwargs)
        end
      end

      # Parse an SPKI DER structure with optional input size limit.
      def parse_spki(der)
        check_input_size!(der)
        _c_parse_spki(der)
      end

      # Parse a PKCS#8 DER structure with optional input size limit.
      def parse_pkcs8(der)
        check_input_size!(der)
        _c_parse_pkcs8(der)
      end

      def check_input_size!(der)
        limit = PqcAsn1::DER.max_input_size
        return unless limit

        size = der.respond_to?(:bytesize) ? der.bytesize : 0
        return if size <= limit

        raise ArgumentError,
          "input size #{size} exceeds maximum allowed #{limit} bytes; " \
          "increase PqcAsn1::DER.max_input_size or set to nil to disable"
      end

      private :check_input_size!
    end

    # Detect the DER format and dispatch to the appropriate parser.
    #
    # Accepts a String (SPKI, PKCS#8, or EncryptedPrivateKeyInfo) or a
    # SecureBuffer (always dispatched as PKCS#8 — public keys have no
    # need for secure memory).
    #
    # @param der [String, PqcAsn1::SecureBuffer] DER-encoded key structure
    # @return [PqcAsn1::DER::KeyInfo, PqcAsn1::DER::EncryptedKeyInfo]
    # @raise [PqcAsn1::DERError] if the format cannot be detected or parsing fails
    def self.parse_auto(der)
      # SecureBuffer input is always PKCS#8 — public keys don't need
      # secure memory, so dispatch directly without format detection.
      return parse_pkcs8(der) if der.is_a?(PqcAsn1::SecureBuffer)

      case detect_format(der)
      when :spki then parse_spki(der)
      when :pkcs8 then parse_pkcs8(der)
      when :encrypted_pkcs8 then parse_encrypted_pkcs8(der)
      when nil
        raise PqcAsn1::DERError.new(
          "cannot detect DER format: input does not start with a valid DER SEQUENCE",
          code: :der_parse
        )
      else
        raise PqcAsn1::DERError.new(
          "cannot detect DER format: expected SPKI, PKCS#8, or EncryptedPrivateKeyInfo",
          code: :der_parse
        )
      end
    end

    # Decode a PEM string and parse the contained DER structure.
    #
    # Uses the PEM label to choose the parser:
    #   "PUBLIC KEY"           → {parse_spki}
    #   "PRIVATE KEY"          → {parse_pkcs8}
    #   "ENCRYPTED PRIVATE KEY" → {parse_encrypted_pkcs8}
    # Any other label raises PEMError.
    #
    # @param pem [String] PEM-encoded key
    # @return [PqcAsn1::DER::KeyInfo, PqcAsn1::DER::EncryptedKeyInfo]
    # @raise [PqcAsn1::PEMError] if PEM decoding fails
    # @raise [PqcAsn1::DERError] if DER parsing fails
    def self.parse_pem(pem)
      result = PqcAsn1::PEM.decode_auto(pem)
      case result.label
      when "PUBLIC KEY" then parse_spki(result.data)
      when "PRIVATE KEY" then parse_pkcs8(result.data)
      when "ENCRYPTED PRIVATE KEY" then parse_encrypted_pkcs8(result.data)
      else
        raise PqcAsn1::PEMError.new(
          "unsupported PEM label #{result.label.inspect}: " \
          "expected \"PUBLIC KEY\", \"PRIVATE KEY\", or \"ENCRYPTED PRIVATE KEY\"",
          code: :pem_label
        )
      end
    end

    # Parse an EncryptedPrivateKeyInfo DER structure (RFC 5958).
    #
    # This gem is a codec — it does not decrypt the key material.
    # The returned {EncryptedKeyInfo} carries the opaque +encryption_algorithm+
    # DER and raw +encrypted_data+ bytes so the caller can pass them to
    # their cipher implementation.
    #
    # @param der [String] DER-encoded EncryptedPrivateKeyInfo
    # @return [PqcAsn1::DER::EncryptedKeyInfo]
    # @raise [PqcAsn1::DERError] on malformed input
    def self.parse_encrypted_pkcs8(der)
      check_input_size!(der)
      cursor = Cursor.new(der)
      outer = cursor.read_sequence
      unless cursor.eof?
        raise PqcAsn1::DERError.new(
          "EncryptedPrivateKeyInfo parse error: trailing data after outer SEQUENCE",
          code: :trailing_data
        )
      end

      # AlgorithmIdentifier is a SEQUENCE — capture the full TLV so callers
      # can pass it directly to their cipher without re-encoding.
      algo_tlv = outer.read_raw(0x30)
      encrypted_data = outer.read_octet_string
      unless outer.eof?
        raise PqcAsn1::DERError.new(
          "EncryptedPrivateKeyInfo parse error: extra fields after encryptedData",
          code: :extra_fields
        )
      end

      EncryptedKeyInfo.new(algo_tlv, encrypted_data)
    end

    # Build an EncryptedPrivateKeyInfo DER structure (RFC 5958).
    #
    # This gem is a codec — the caller must perform the actual encryption
    # and provide the resulting ciphertext together with the
    # AlgorithmIdentifier DER that describes the encryption scheme.
    #
    # @param encryption_algorithm_der [String]
    #   Full AlgorithmIdentifier DER TLV (tag 0x30 + length + OID + params).
    # @param encrypted_data [String]
    #   Raw ciphertext bytes.  These will be wrapped in an OCTET STRING.
    # @return [String] frozen DER bytes (ASCII-8BIT)
    def self.build_encrypted_pkcs8(encryption_algorithm_der, encrypted_data)
      raise ArgumentError, "encryption_algorithm_der must not be nil" if encryption_algorithm_der.nil?
      raise ArgumentError, "encrypted_data must not be nil" if encrypted_data.nil?

      enc_data_tlv = PqcAsn1::DER.write_tlv(0x04, encrypted_data)
      content = encryption_algorithm_der.b + enc_data_tlv
      PqcAsn1::DER.write_tlv(0x30, content).freeze
    end

    # Validate that a key's byte size matches the expected size for the
    # given OID and type (:public or :secret).
    #
    # Delegates to the C-level OID.validate_key_size table for known
    # algorithms (O(1) lookup, no Ruby hash involved).  Falls back to
    # KEY_SIZES (built-in) then REGISTERED_KEY_SIZES (user-registered).
    #
    # Raises ArgumentError if the OID is unknown (not in any table) or
    # if the key size does not match the expected size.
    #
    # @param oid [PqcAsn1::OID] the algorithm OID
    # @param key_bytesize [Integer] actual key size in bytes
    # @param type [Symbol] :public or :secret
    # @return [true]
    # @raise [ArgumentError] if the size does not match or OID is unknown
    def self.validate_key_size(oid, key_bytesize, type)
      # Fast path: C-level table for built-in NIST PQC algorithms.
      c_result = PqcAsn1::OID.validate_key_size(oid, key_bytesize, type == :public)
      return true if c_result

      # Fallback: built-in KEY_SIZES, then user-registered REGISTERED_KEY_SIZES.
      sizes = KEY_SIZES[oid] || REGISTERED_KEY_SIZES[oid]
      unless sizes
        name = (oid.respond_to?(:name) && oid.name) ? oid.name : oid.to_s
        raise ArgumentError,
          "unknown OID #{name} — cannot validate key size; " \
          "register it with OID.register or pass validate: false"
      end

      expected = sizes[type]
      return true unless expected

      if key_bytesize != expected
        name = (oid.respond_to?(:name) && oid.name) ? oid.name : oid.to_s
        raise ArgumentError,
          "#{type} key size #{key_bytesize} does not match expected " \
          "#{expected} for #{name}"
      end

      true
    end

    # Build a composite SubjectPublicKeyInfo DER structure.
    #
    # Composite key structures (PQC + traditional hybrid algorithms) are
    # defined in draft NIST/IETF standards and are not yet implemented.
    # This placeholder stabilises the API surface.
    #
    # @raise [NotImplementedError] always
    def self.build_composite_spki(**)
      raise NotImplementedError,
        "Composite key support is not yet implemented. " \
        "See https://github.com/msuliq/pqc_asn1/issues for status."
    end

    # Parse a composite SubjectPublicKeyInfo DER structure.
    #
    # @raise [NotImplementedError] always
    def self.parse_composite_spki(_der)
      raise NotImplementedError,
        "Composite key support is not yet implemented. " \
        "See https://github.com/msuliq/pqc_asn1/issues for status."
    end
  end

  class SecureBuffer
    # PEM-encode the DER contents of this SecureBuffer.
    #
    # The returned PEM String is an ordinary Ruby String on the heap,
    # NOT a SecureBuffer.  Discard it as soon as possible to limit
    # exposure of secret key material.
    #
    # @param label [String] PEM label (default "PRIVATE KEY")
    # @return [String] frozen US-ASCII PEM string
    def to_pem(label = "PRIVATE KEY")
      PqcAsn1::PEM.encode(self, label)
    end

    # Write the raw DER bytes directly to an IO object.
    # The bytes pass through a temporary #use block and are written
    # immediately, minimising exposure time on the Ruby heap.
    #
    # @param io [IO] writable IO (file, socket, StringIO, etc.)
    # @return [Integer] number of bytes written
    def write_to(io)
      use { |bytes| io.write(bytes) }
    end

    # PEM-encode and write directly to an IO object.
    # The PEM string is written and then discarded immediately.
    #
    # @param io [IO] writable IO
    # @param label [String] PEM label (default "PRIVATE KEY")
    # @return [Integer] number of bytes written
    def to_pem_io(io, label = "PRIVATE KEY")
      pem = to_pem(label)
      io.write(pem)
    end
  end
end
