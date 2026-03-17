# frozen_string_literal: true

require "test_helper"

# Property-based / randomized round-trip tests.
#
# Each test runs many iterations with random inputs to catch edge cases
# that example-based tests might miss.  The key property tested is:
#   parse(build(x)) == x
class PropertyTest < Minitest::Test
  ITERATIONS = 100

  def rtlv(der, offset, tag)
    PqcAsn1::DER.read_tlv(der, offset, tag)
  end

  def wtlv(tag, content)
    PqcAsn1::DER.write_tlv(tag, content)
  end

  # --- Base64 ---

  def test_base64_roundtrip_random_lengths
    ITERATIONS.times do
      len = rand(0..4096)
      data = Array.new(len) { rand(256) }.pack("C*")
      encoded = PqcAsn1::Base64.encode(data)
      decoded = PqcAsn1::Base64.decode(encoded)
      assert_equal data.b, decoded.b, "Base64 roundtrip failed for #{len}-byte input"
    end
  end

  def test_base64_encode_line_length_invariant
    ITERATIONS.times do
      len = rand(1..2000)
      data = Array.new(len) { rand(256) }.pack("C*")
      encoded = PqcAsn1::Base64.encode(data)
      lines = encoded.split("\n")
      lines.each_with_index do |line, i|
        if i < lines.size - 1
          assert_equal 64, line.length,
            "Non-final line #{i} has #{line.length} chars (expected 64) for #{len}-byte input"
        else
          assert line.length <= 64,
            "Final line has #{line.length} chars (expected <= 64) for #{len}-byte input"
        end
      end
    end
  end

  def test_base64_encode_only_valid_chars
    ITERATIONS.times do
      len = rand(0..500)
      data = Array.new(len) { rand(256) }.pack("C*")
      encoded = PqcAsn1::Base64.encode(data)
      assert_match(/\A[A-Za-z0-9+\/=\n]*\z/, encoded,
        "Base64 output contains invalid characters for #{len}-byte input")
    end
  end

  # --- DER TLV ---

  def test_write_tlv_read_tlv_roundtrip_random
    tags = [0x02, 0x03, 0x04, 0x05, 0x06, 0x30, 0x31]
    ITERATIONS.times do
      tag = tags.sample
      len = rand(0..5000)
      content = Array.new(len) { rand(256) }.pack("C*")
      tlv = wtlv(tag, content)
      parsed_content, new_offset = rtlv(tlv, 0, tag)
      assert_equal content.b, parsed_content.b,
        "TLV roundtrip failed for tag 0x#{tag.to_s(16)}, #{len}-byte content"
      assert_equal tlv.bytesize, new_offset
    end
  end

  def test_write_length_bytesize_matches_der_encoding
    ITERATIONS.times do
      len = rand(0..65535)
      buf = PqcAsn1::DER.send(:write_length, len)
      # Verify the encoded length field can round-trip via a TLV
      tlv = PqcAsn1::DER.write_tlv(0x04, "\x00" * len)
      assert_equal 1 + buf.bytesize + len, tlv.bytesize,
        "write_length for #{len} produced wrong byte count"
    end
  end

  # --- SPKI ---

  def test_spki_roundtrip_all_oids_random_keys
    oids = PqcAsn1::OID.constants
      .map { |c| PqcAsn1::OID.const_get(c) }
      .select { |v| v.is_a?(PqcAsn1::OID) }
    oids.each do |oid|
      ITERATIONS.times do
        pk_len = rand(32..2048)
        pk = Array.new(pk_len) { rand(256) }.pack("C*")
        der = PqcAsn1::DER.build_spki(oid, pk, validate: false)
        parsed = PqcAsn1::DER.parse_spki(der)
        assert_equal oid, parsed.oid,
          "SPKI OID roundtrip failed"
        assert_equal pk.b, parsed.key.b,
          "SPKI key roundtrip failed for #{pk_len}-byte key"
      end
    end
  end

  # --- PKCS#8 ---

  def test_pkcs8_roundtrip_all_oids_random_keys
    oids = PqcAsn1::OID.constants
      .map { |c| PqcAsn1::OID.const_get(c) }
      .select { |v| v.is_a?(PqcAsn1::OID) }
    oids.each do |oid|
      ITERATIONS.times do
        sk_len = rand(32..4096)
        sk = Array.new(sk_len) { rand(256) }.pack("C*")
        der = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
        parsed = PqcAsn1::DER.parse_pkcs8(der)
        assert_equal oid, parsed.oid
        parsed.key.use { |b| assert_equal sk.b, b, "PKCS#8 key roundtrip failed for #{sk_len}-byte key" }
      end
    end
  end

  # --- PEM ---

  def test_pem_roundtrip_random_data
    labels = ["PUBLIC KEY", "PRIVATE KEY", "CERTIFICATE", "TEST DATA"]
    ITERATIONS.times do
      label = labels.sample
      len = rand(0..3000)
      data = Array.new(len) { rand(256) }.pack("C*")
      pem = PqcAsn1::PEM.encode(data, label)
      decoded = PqcAsn1::PEM.decode(pem, label)
      assert_equal data.b, decoded.b,
        "PEM roundtrip failed for label '#{label}', #{len}-byte data"
    end
  end

  def test_pem_decode_auto_roundtrip_random
    labels = ["PUBLIC KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY"]
    ITERATIONS.times do
      label = labels.sample
      len = rand(1..2000)
      data = Array.new(len) { rand(256) }.pack("C*")
      pem = PqcAsn1::PEM.encode(data, label)
      result = PqcAsn1::PEM.decode_auto(pem)
      found_label = result.label
      decoded = result.data
      assert_equal label, found_label
      assert_equal data.b, decoded.b
    end
  end

  # --- Full stack: build → PEM encode → PEM decode → parse ---

  def test_full_stack_spki_roundtrip_random
    oids = [
      PqcAsn1::OID::ML_DSA_44, PqcAsn1::OID::ML_KEM_768,
      PqcAsn1::OID::SLH_DSA_SHA2_128S
    ]
    ITERATIONS.times do
      oid = oids.sample
      pk_len = rand(32..2048)
      pk = Array.new(pk_len) { rand(256) }.pack("C*")

      der = PqcAsn1::DER.build_spki(oid, pk, validate: false)
      pem = PqcAsn1::PEM.encode(der, "PUBLIC KEY")
      decoded_der = PqcAsn1::PEM.decode(pem, "PUBLIC KEY")
      parsed = PqcAsn1::DER.parse_spki(decoded_der)

      assert_equal oid, parsed.oid
      assert_equal pk.b, parsed.key.b
    end
  end

  def test_full_stack_pkcs8_roundtrip_random
    oids = [
      PqcAsn1::OID::ML_DSA_65, PqcAsn1::OID::ML_KEM_512,
      PqcAsn1::OID::SLH_DSA_SHAKE_256F
    ]
    ITERATIONS.times do
      oid = oids.sample
      sk_len = rand(32..4096)
      sk = Array.new(sk_len) { rand(256) }.pack("C*")

      der = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
      pem = PqcAsn1::PEM.encode(der, "PRIVATE KEY")
      decoded_der = PqcAsn1::PEM.decode(pem, "PRIVATE KEY")
      parsed = PqcAsn1::DER.parse_pkcs8(decoded_der)

      assert_equal oid, parsed.oid
      parsed.key.use { |b| assert_equal sk.b, b }
    end
  end

  # --- Cursor round-trip with random data ---

  def test_cursor_spki_parsing_random
    ITERATIONS.times do
      oid = PqcAsn1::OID::ML_DSA_87
      pk_len = rand(32..2048)
      pk = Array.new(pk_len) { rand(256) }.pack("C*")

      der = PqcAsn1::DER.build_spki(oid, pk, validate: false)
      outer = PqcAsn1::DER::Cursor.new(der)
      seq = outer.read_sequence
      alg = seq.read_sequence
      alg.read(0x06)
      bs = seq.read_bit_string

      assert alg.eof?
      assert seq.eof?
      assert_equal 0, bs.getbyte(0)
      assert_equal pk.b, bs[1..].b
    end
  end
end
