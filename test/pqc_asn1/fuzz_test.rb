# frozen_string_literal: true

require "test_helper"

# Fuzz / robustness tests.
#
# These tests feed random, truncated, and mutated inputs to parsers and
# assert that they never crash, leak memory, or return success for garbage.
# The goal is to verify that all error paths in the C code are exercised
# safely.
class FuzzTest < Minitest::Test
  ITERATIONS = 200

  # --- DER parser robustness ---

  def test_parse_spki_rejects_random_bytes
    ITERATIONS.times do
      len = rand(0..512)
      garbage = Array.new(len) { rand(256) }.pack("C*")
      assert_raises(PqcAsn1::ParseError) do
        PqcAsn1::DER.parse_spki(garbage)
      end
    end
  end

  def test_parse_pkcs8_rejects_random_bytes
    ITERATIONS.times do
      len = rand(0..512)
      garbage = Array.new(len) { rand(256) }.pack("C*")
      assert_raises(PqcAsn1::ParseError) do
        PqcAsn1::DER.parse_pkcs8(garbage)
      end
    end
  end

  def test_parse_spki_rejects_truncated_valid_der
    oid = PqcAsn1::OID::ML_DSA_65
    pk = Array.new(128) { rand(256) }.pack("C*")
    valid = PqcAsn1::DER.build_spki(oid, pk, validate: false)

    # Try every possible truncation length.
    (0...valid.bytesize).each do |len|
      truncated = valid.byteslice(0, len)
      assert_raises(PqcAsn1::ParseError,
        "parse_spki should reject #{len}-byte truncation of #{valid.bytesize}-byte DER") do
        PqcAsn1::DER.parse_spki(truncated)
      end
    end
  end

  def test_parse_pkcs8_rejects_truncated_valid_der
    oid = PqcAsn1::OID::ML_KEM_768
    sk = Array.new(64) { rand(256) }.pack("C*")
    valid = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    valid_bytes = valid.use { |b| b.b }

    (0...valid_bytes.bytesize).each do |len|
      truncated = valid_bytes.byteslice(0, len)
      assert_raises(PqcAsn1::ParseError,
        "parse_pkcs8 should reject #{len}-byte truncation") do
        PqcAsn1::DER.parse_pkcs8(truncated)
      end
    end
  end

  def test_parse_spki_rejects_single_bit_flips
    oid = PqcAsn1::OID::SLH_DSA_SHA2_128S
    pk = Array.new(32) { rand(256) }.pack("C*")
    valid = PqcAsn1::DER.build_spki(oid, pk, validate: false)
    bytes = valid.bytes

    # Flip each bit in the entire DER and verify no crashes occur.
    # For structural bytes (tags and lengths), most flips should cause errors.
    crash_count = 0
    bytes.size.times do |byte_idx|
      8.times do |bit_idx|
        mutated = bytes.dup
        mutated[byte_idx] ^= (1 << bit_idx)
        mutated_str = mutated.pack("C*")
        begin
          PqcAsn1::DER.parse_spki(mutated_str)
          # Parsed successfully — acceptable for non-structural bytes.
        rescue PqcAsn1::ParseError, ArgumentError
          # Expected for most flips.
        rescue => e
          # Unexpected exception type — record as a crash.
          crash_count += 1
          flunk "Unexpected #{e.class} at byte #{byte_idx} bit #{bit_idx}: #{e.message}"
        end
      end
    end
    assert_equal 0, crash_count, "No unexpected exceptions should occur during bit-flip fuzzing"
  end

  # --- Base64 robustness ---

  def test_base64_decode_rejects_random_bytes
    ITERATIONS.times do
      len = rand(1..256)
      garbage = Array.new(len) { rand(256) }.pack("C*")
      # Random bytes are very unlikely to be valid base64.
      # Some random strings might accidentally be valid, so we just
      # verify no crash.
      begin
        PqcAsn1::Base64.decode(garbage)
      rescue PqcAsn1::ParseError
        # Expected for most random inputs.
      end
    end
  end

  def test_base64_decode_rejects_embedded_nulls
    valid = PqcAsn1::Base64.encode("hello world")
    # Insert a NUL byte in the middle of valid base64.
    corrupted = valid.dup
    mid = corrupted.bytesize / 2
    corrupted[mid] = "\x00"
    assert_raises(PqcAsn1::ParseError) do
      PqcAsn1::Base64.decode(corrupted)
    end
  end

  # --- PEM robustness ---

  def test_pem_decode_rejects_random_bytes
    ITERATIONS.times do
      len = rand(0..512)
      garbage = Array.new(len) { rand(256) }.pack("C*")
      assert_raises(PqcAsn1::ParseError) do
        PqcAsn1::PEM.decode(garbage, "PUBLIC KEY")
      end
    end
  end

  def test_pem_decode_auto_rejects_random_bytes
    ITERATIONS.times do
      len = rand(0..512)
      garbage = Array.new(len) { rand(256) }.pack("C*")
      assert_raises(PqcAsn1::ParseError) do
        PqcAsn1::PEM.decode_auto(garbage)
      end
    end
  end

  def test_pem_decode_rejects_truncated_valid_pem
    data = Array.new(64) { rand(256) }.pack("C*")
    valid = PqcAsn1::PEM.encode(data, "PUBLIC KEY")

    # Find the END marker to know where structural data ends.
    end_marker_pos = valid.index("-----END")

    # Try various truncations that cut before the END marker.
    [1, 10, 20, valid.bytesize / 2].each do |len|
      next if len >= valid.bytesize
      next if len > end_marker_pos # truncation past END marker may still parse

      truncated = valid.byteslice(0, len)
      assert_raises(PqcAsn1::ParseError,
        "PEM.decode should reject #{len}-byte truncation") do
        PqcAsn1::PEM.decode(truncated, "PUBLIC KEY")
      end
    end
  end

  def test_pem_decode_rejects_corrupted_base64_body
    data = Array.new(64) { rand(256) }.pack("C*")
    valid = PqcAsn1::PEM.encode(data, "PUBLIC KEY")
    lines = valid.split("\n")

    # Corrupt a base64 line (not header/footer).
    if lines.size > 2
      target = 1 # first base64 line
      lines[target] = "!!!INVALID!!!"
      corrupted = lines.join("\n")
      assert_raises(PqcAsn1::ParseError) do
        PqcAsn1::PEM.decode(corrupted, "PUBLIC KEY")
      end
    end
  end

  # --- Cursor robustness ---

  def test_cursor_rejects_random_bytes
    # Random bytes can occasionally form a valid SEQUENCE (tag 0x30 +
    # valid length).  When that happens read_sequence succeeds, which is
    # correct behaviour — skip those iterations rather than treating them
    # as failures.
    errors = 0
    ITERATIONS.times do
      len = rand(0..256)
      garbage = Array.new(len) { rand(256) }.pack("C*")
      cursor = PqcAsn1::DER::Cursor.new(garbage)
      begin
        cursor.read_sequence
        # Parsed successfully — the random bytes happened to form a valid
        # SEQUENCE.  This is rare but not a bug.
      rescue PqcAsn1::ParseError
        errors += 1
      end
    end
    # The vast majority of random inputs should fail to parse.
    assert errors > ITERATIONS / 2,
      "Expected most random inputs to be rejected, but only #{errors}/#{ITERATIONS} were"
  end

  def test_cursor_eof_after_full_read
    oid = PqcAsn1::OID::ML_DSA_44
    pk = Array.new(32) { rand(256) }.pack("C*")
    der = PqcAsn1::DER.build_spki(oid, pk, validate: false)

    outer = PqcAsn1::DER::Cursor.new(der)
    seq = outer.read_sequence
    alg = seq.read_sequence
    alg.read(0x06) # OID
    assert alg.eof?, "AlgorithmIdentifier cursor should be at EOF after reading OID"
    seq.read(0x03) # BIT STRING
    assert seq.eof?, "Outer SEQUENCE cursor should be at EOF"
    assert outer.eof?, "Root cursor should be at EOF"
  end

  # --- PEM.decode_each robustness ---

  def test_decode_each_with_multiple_blocks
    pk1 = Array.new(32) { rand(256) }.pack("C*")
    pk2 = Array.new(48) { rand(256) }.pack("C*")
    sk1 = Array.new(64) { rand(256) }.pack("C*")

    pem = [
      PqcAsn1::PEM.encode(pk1, "PUBLIC KEY"),
      PqcAsn1::PEM.encode(sk1, "PRIVATE KEY"),
      PqcAsn1::PEM.encode(pk2, "PUBLIC KEY")
    ].join("\n")

    results = []
    PqcAsn1::PEM.decode_each(pem) { |r| results << r }

    assert_equal 3, results.size
    assert_equal "PUBLIC KEY", results[0].label
    assert_equal pk1.b, results[0].data
    assert_equal "PRIVATE KEY", results[1].label
    assert_equal sk1.b, results[1].data
    assert_equal "PUBLIC KEY", results[2].label
    assert_equal pk2.b, results[2].data
  end

  def test_decode_each_returns_enumerator_without_block
    pem = PqcAsn1::PEM.encode("test", "TEST")
    enum = PqcAsn1::PEM.decode_each(pem)
    assert_kind_of Enumerator, enum
    assert_equal 1, enum.count
  end

  def test_decode_each_with_empty_input
    results = []
    PqcAsn1::PEM.decode_each("") { |r| results << r }
    assert_empty results
  end

  def test_decode_each_with_garbage_between_blocks
    pk1 = Array.new(16) { rand(256) }.pack("C*")
    pk2 = Array.new(16) { rand(256) }.pack("C*")

    pem = [
      PqcAsn1::PEM.encode(pk1, "PUBLIC KEY"),
      "some random garbage in between\n",
      PqcAsn1::PEM.encode(pk2, "PUBLIC KEY")
    ].join("\n")

    results = []
    PqcAsn1::PEM.decode_each(pem) { |r| results << r }
    assert_equal 2, results.size
  end

  # --- SecureBuffer canary check ---

  def test_secure_buffer_canary_ok_after_creation
    buf = PqcAsn1::SecureBuffer.random(32)
    assert buf.canary_ok?, "Canary should be OK immediately after creation"
  end

  def test_secure_buffer_canary_not_ok_after_wipe
    buf = PqcAsn1::SecureBuffer.random(32)
    buf.wipe!
    refute buf.canary_ok?, "Canary should not be OK after wipe"
  end
end
