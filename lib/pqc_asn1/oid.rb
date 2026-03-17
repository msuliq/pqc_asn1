# frozen_string_literal: true

module PqcAsn1
  # OID value class for post-quantum algorithm identifiers standardised by NIST.
  #
  # All OID instances are frozen at construction time (initialize calls freeze).
  # Each constant wraps a dotted-decimal string.
  # Pass them directly to {PqcAsn1::DER.build_spki} or {PqcAsn1::DER.build_pkcs8};
  # dotted Strings are also accepted by the build methods.
  #
  # {PqcAsn1::DER.parse_spki} and {PqcAsn1::DER.parse_pkcs8} return the OID as
  # a PqcAsn1::OID instance that can be compared directly against these constants
  # using ==.
  #
  # @example Using an OID constant
  #   der = PqcAsn1::DER.build_spki(PqcAsn1::OID::ML_DSA_44, public_key_bytes)
  #
  # @example Checking the parsed OID
  #   parsed = PqcAsn1::DER.parse_spki(der)
  #   parsed.oid == PqcAsn1::OID::ML_DSA_44  # => true
  #   parsed.oid.name                         # => "ML_DSA_44"
  #
  # Sources (verified 2026-03-14):
  #   ML-DSA:  NIST FIPS 204, Table 2; NIST CSOR OID arc 2.16.840.1.101.3.4.3
  #   ML-KEM:  NIST FIPS 203; NIST CSOR OID arc 2.16.840.1.101.3.4.4
  #   SLH-DSA: NIST FIPS 205, Table 2; NIST CSOR OID arc 2.16.840.1.101.3.4.3
  class OID
    # @return [String] the dotted-decimal OID string (e.g. "2.16.840.1.101.3.4.3.17")
    attr_reader :dotted

    # @param dotted [String] dotted-decimal OID string
    def initialize(dotted)
      @dotted = dotted.frozen? ? dotted : dotted.dup.freeze
      # Pre-compute DER TLV if the C extension is already loaded.
      # Built-in constants (ML_DSA_44, etc.) are defined before the extension
      # loads, so from_dotted is not yet available for them — they fall back
      # to the class-level cache in #der_tlv.  OIDs constructed at runtime
      # (OID.new, OID.register) always get @der_tlv set here, skipping the
      # class-level hash entirely.
      @der_tlv = self.class.respond_to?(:from_dotted) ? self.class.from_dotted(@dotted) : nil
      freeze
    end

    # Compare against another OID or a dotted String.
    # @param other [PqcAsn1::OID, String, Object]
    # @return [Boolean]
    def ==(other)
      case other
      when OID then @dotted == other.dotted
      when String then @dotted == other
      else false
      end
    end

    # Strict equality for use in Hash / eql? contexts (OID vs OID only).
    # @param other [Object]
    # @return [Boolean]
    def eql?(other)
      other.is_a?(OID) && @dotted == other.dotted
    end

    # @return [Integer]
    def hash
      @dotted.hash
    end

    # @return [String] the dotted-decimal string representation
    def to_s
      @dotted
    end

    # @return [String]
    def inspect
      "#<PqcAsn1::OID #{@dotted}>"
    end

    # DER TLV bytes (tag 0x06 + length + value).
    # For OIDs created after the C extension loads, returns the pre-computed
    # ivar set in initialize (O(1), no hash lookup).  For the built-in
    # constants (created at load time before the extension), falls back to
    # the class-level cache on first access.
    # Requires the C extension to be loaded (called at runtime, not load time).
    # @return [String] frozen ASCII-8BIT binary string
    def der_tlv
      return @der_tlv if @der_tlv
      OID.der_tlv_cache[@dotted] ||= PqcAsn1::OID.from_dotted(@dotted)
    end

    # Human-readable constant name, e.g. "ML_DSA_44", or nil if unknown.
    # Checks both built-in OIDs and user-registered OIDs.
    # @return [String, nil]
    def name
      PqcAsn1::OID.name_for(self)
    end

    # ----------------------------------------------------------------
    # ML-DSA (FIPS 204) — Module-Lattice Digital Signature Algorithm
    # ----------------------------------------------------------------

    # OID 2.16.840.1.101.3.4.3.17 — 128-bit security (NIST level 2)
    ML_DSA_44 = new("2.16.840.1.101.3.4.3.17")

    # OID 2.16.840.1.101.3.4.3.18 — 192-bit security (NIST level 3)
    ML_DSA_65 = new("2.16.840.1.101.3.4.3.18")

    # OID 2.16.840.1.101.3.4.3.19 — 256-bit security (NIST level 5)
    ML_DSA_87 = new("2.16.840.1.101.3.4.3.19")

    # ----------------------------------------------------------------
    # ML-KEM (FIPS 203) — Module-Lattice Key Encapsulation Mechanism
    # ----------------------------------------------------------------

    # OID 2.16.840.1.101.3.4.4.1 — 128-bit security (NIST level 1)
    ML_KEM_512 = new("2.16.840.1.101.3.4.4.1")

    # OID 2.16.840.1.101.3.4.4.2 — 192-bit security (NIST level 3)
    ML_KEM_768 = new("2.16.840.1.101.3.4.4.2")

    # OID 2.16.840.1.101.3.4.4.3 — 256-bit security (NIST level 5)
    ML_KEM_1024 = new("2.16.840.1.101.3.4.4.3")

    # ----------------------------------------------------------------
    # SLH-DSA (FIPS 205) — Stateless Hash-Based Digital Signature
    # SHA-2 instantiations:
    # ----------------------------------------------------------------

    # OID 2.16.840.1.101.3.4.3.20 — SHA-2, 128-bit, small (NIST level 1)
    SLH_DSA_SHA2_128S = new("2.16.840.1.101.3.4.3.20")

    # OID 2.16.840.1.101.3.4.3.21 — SHA-2, 128-bit, fast (NIST level 1)
    SLH_DSA_SHA2_128F = new("2.16.840.1.101.3.4.3.21")

    # OID 2.16.840.1.101.3.4.3.22 — SHA-2, 192-bit, small (NIST level 3)
    SLH_DSA_SHA2_192S = new("2.16.840.1.101.3.4.3.22")

    # OID 2.16.840.1.101.3.4.3.23 — SHA-2, 192-bit, fast (NIST level 3)
    SLH_DSA_SHA2_192F = new("2.16.840.1.101.3.4.3.23")

    # OID 2.16.840.1.101.3.4.3.24 — SHA-2, 256-bit, small (NIST level 5)
    SLH_DSA_SHA2_256S = new("2.16.840.1.101.3.4.3.24")

    # OID 2.16.840.1.101.3.4.3.25 — SHA-2, 256-bit, fast (NIST level 5)
    SLH_DSA_SHA2_256F = new("2.16.840.1.101.3.4.3.25")

    # ----------------------------------------------------------------
    # SLH-DSA SHAKE instantiations:
    # ----------------------------------------------------------------

    # OID 2.16.840.1.101.3.4.3.26 — SHAKE, 128-bit, small (NIST level 1)
    SLH_DSA_SHAKE_128S = new("2.16.840.1.101.3.4.3.26")

    # OID 2.16.840.1.101.3.4.3.27 — SHAKE, 128-bit, fast (NIST level 1)
    SLH_DSA_SHAKE_128F = new("2.16.840.1.101.3.4.3.27")

    # OID 2.16.840.1.101.3.4.3.28 — SHAKE, 192-bit, small (NIST level 3)
    SLH_DSA_SHAKE_192S = new("2.16.840.1.101.3.4.3.28")

    # OID 2.16.840.1.101.3.4.3.29 — SHAKE, 192-bit, fast (NIST level 3)
    SLH_DSA_SHAKE_192F = new("2.16.840.1.101.3.4.3.29")

    # OID 2.16.840.1.101.3.4.3.30 — SHAKE, 256-bit, small (NIST level 5)
    SLH_DSA_SHAKE_256S = new("2.16.840.1.101.3.4.3.30")

    # OID 2.16.840.1.101.3.4.3.31 — SHAKE, 256-bit, fast (NIST level 5)
    SLH_DSA_SHAKE_256F = new("2.16.840.1.101.3.4.3.31")

    # Class-level cache for der_tlv so frozen OID instances can memoize
    # without writing to their own ivars.
    @der_tlv_cache = {}

    # Built-in OID reverse lookup: dotted string → OID instance (O(1)).
    # Lazily populated on first access, then frozen.
    @builtin_by_dotted = nil

    # Mutex protecting registration state (custom_oid_by_dotted,
    # custom_oid_by_name, custom_registry, and REGISTERED_KEY_SIZES).
    # Prevents TOCTOU races when two threads call OID.register concurrently.
    @register_mutex = Mutex.new

    # User-registered OIDs stored in two lookup directions.
    # dotted → OID instance  (for OID[dotted_string] lookup)
    @custom_oid_by_dotted = {}
    # name   → OID instance  (for OID[name_string] lookup)
    @custom_oid_by_name = {}
    # dotted → name (used by the #name instance method)
    @custom_registry = {}

    class << self
      # @api private
      attr_reader :der_tlv_cache

      # @api private — used by OID#name
      attr_reader :custom_registry

      # Lazily build the built-in OID reverse lookup hash on first access.
      def builtin_by_dotted
        @builtin_by_dotted ||= begin
          h = {}
          constants.each do |c|
            val = const_get(c, false)
            h[val.dotted] = val if val.is_a?(OID)
          end
          h.freeze
        end
      end

      # Look up a built-in or registered OID by name or dotted string.
      #
      # Built-in constants are found via +const_get+; registered OIDs are
      # found via the runtime registry populated by {.register}.
      #
      # @param key [String] dotted-decimal OID (contains ".") or constant name
      # @return [PqcAsn1::OID, nil] the OID instance, or nil if not found
      #
      # @example
      #   PqcAsn1::OID["ML_DSA_44"]                  # => #<PqcAsn1::OID 2.16...>
      #   PqcAsn1::OID["2.16.840.1.101.3.4.3.17"]    # => #<PqcAsn1::OID 2.16...>
      #   PqcAsn1::OID["MY_ALGO"]                     # => registered OID or nil
      def [](key)
        key = key.to_s
        if key.include?(".")
          # Dotted notation: O(1) hash lookup for built-in, then custom registry.
          builtin_by_dotted[key] || @custom_oid_by_dotted[key]
        else
          # Name: try built-in constant first, then custom registry.
          begin
            val = const_get(key, false)
            return val if val.is_a?(OID)
          rescue NameError
          end
          @custom_oid_by_name[key]
        end
      end

      # Enumerate all OIDs registered at runtime via {.register}.
      #
      # @return [Hash{String => PqcAsn1::OID}] name → OID mapping (frozen copy)
      def registered
        @custom_oid_by_name.dup.freeze
      end

      # Register a custom OID so that {.name_for} and {.[]} recognise it
      # and key-size validation works for the new algorithm.
      #
      # Unlike the previous behaviour, this method does *not* define a Ruby
      # constant on +PqcAsn1::OID+.  If you want a constant, assign the
      # return value explicitly:
      #
      #   PqcAsn1::OID::MY_ALGO = PqcAsn1::OID.register("1.3.x", "MY_ALGO")
      #
      # @param dotted [String] dotted-decimal OID (e.g. "1.3.6.1.4.1.99999.1")
      # @param name [String] symbolic name (e.g. "MY_ALGO")
      # @param key_sizes [Hash, nil] optional +{public: N, secret: M}+ for
      #   {PqcAsn1::DER.validate_key_size} support
      # @return [PqcAsn1::OID] the newly registered OID instance
      # @raise [ArgumentError] if the name or dotted OID is already registered
      #
      # @example
      #   oid = PqcAsn1::OID.register("1.3.6.1.4.1.99999.1", "BIKE_L1",
      #                                key_sizes: {public: 1541, secret: 3110})
      #   PqcAsn1::OID["BIKE_L1"].dotted  # => "1.3.6.1.4.1.99999.1"
      def register(dotted, name, key_sizes: nil)
        name = name.to_s.freeze
        dotted = dotted.to_s.freeze

        @register_mutex.synchronize do
          if @custom_oid_by_name.key?(name)
            raise ArgumentError, "OID name #{name.inspect} is already registered"
          end
          if @custom_oid_by_dotted.key?(dotted)
            raise ArgumentError,
              "OID #{dotted} is already registered as #{@custom_registry[dotted]}"
          end

          # Prevent shadowing built-in OID constants.
          begin
            existing = const_get(name, false)
            if existing.is_a?(OID)
              raise ArgumentError,
                "OID name #{name.inspect} conflicts with built-in constant #{name}"
            end
          rescue NameError
            # name is not a built-in constant — fine to register
          end

          # Prevent registering a dotted string that belongs to a built-in OID.
          if builtin_by_dotted.key?(dotted)
            builtin = builtin_by_dotted[dotted]
            builtin_name = constants.find { |c| const_get(c, false).equal?(builtin) }
            raise ArgumentError,
              "OID #{dotted} is already defined as built-in #{builtin_name}"
          end

          oid = new(dotted)
          @custom_oid_by_dotted[dotted] = oid
          @custom_oid_by_name[name] = oid
          @custom_registry[dotted] = name

          PqcAsn1::DER::REGISTERED_KEY_SIZES[oid] = key_sizes.freeze if key_sizes

          oid
        end
      end
    end

    # name_for, from_dotted, and to_dotted are implemented in C (ext/pqc_asn1/oid.c)
    # and attached to this class as singleton methods by init_oid() during
    # Init_pqc_asn1_ext.
    #
    # from_dotted(dotted_or_oid) → frozen binary String (DER TLV, tag 0x06)
    # to_dotted(der_tlv)         → frozen US-ASCII String (dotted-decimal OID)
  end
end
