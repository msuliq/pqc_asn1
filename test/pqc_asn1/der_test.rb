# frozen_string_literal: true

require "test_helper"

class DerTest < Minitest::Test
  # Convenience aliases for concise fixture construction in tests.
  def rtlv(der, offset, tag)
    PqcAsn1::DER.read_tlv(der, offset, tag)
  end

  def wtlv(tag, content)
    PqcAsn1::DER.write_tlv(tag, content)
  end

  # --- write_length / length_size ---

  def test_short_form_length
    buf = PqcAsn1::DER.send(:write_length, 42)
    assert_equal [42].pack("C"), buf
    assert_equal 1, PqcAsn1::DER.send(:write_length, 42).bytesize
  end

  def test_short_form_boundary
    buf = PqcAsn1::DER.send(:write_length, 127)
    assert_equal [127].pack("C"), buf
    assert_equal 1, PqcAsn1::DER.send(:write_length, 127).bytesize
  end

  def test_one_byte_long_form
    buf = PqcAsn1::DER.send(:write_length, 128)
    assert_equal [0x81, 128].pack("CC"), buf
    assert_equal 2, PqcAsn1::DER.send(:write_length, 128).bytesize
  end

  def test_one_byte_long_form_255
    buf = PqcAsn1::DER.send(:write_length, 255)
    assert_equal [0x81, 255].pack("CC"), buf
    assert_equal 2, PqcAsn1::DER.send(:write_length, 255).bytesize
  end

  def test_two_byte_long_form
    buf = PqcAsn1::DER.send(:write_length, 256)
    assert_equal [0x82, 0x01, 0x00].pack("CCC"), buf
    assert_equal 3, PqcAsn1::DER.send(:write_length, 256).bytesize
  end

  def test_two_byte_long_form_max
    buf = PqcAsn1::DER.send(:write_length, 65535)
    assert_equal [0x82, 0xFF, 0xFF].pack("CCC"), buf
    assert_equal 3, PqcAsn1::DER.send(:write_length, 65535).bytesize
  end

  def test_zero_length
    buf = PqcAsn1::DER.send(:write_length, 0)
    assert_equal [0].pack("C"), buf
    assert_equal 1, PqcAsn1::DER.send(:write_length, 0).bytesize
  end

  def test_write_length_returns_frozen_string
    assert PqcAsn1::DER.send(:write_length, 42).frozen?
  end

  # --- read_tlv ---

  def test_read_tlv_sequence
    der = [0x30, 0x02, 0x01, 0x02].pack("C*")
    content, new_offset = rtlv(der, 0, 0x30)
    assert_equal [0x01, 0x02].pack("C*"), content
    assert_equal 4, new_offset
  end

  def test_read_tlv_wrong_tag
    der = [0x30, 0x02, 0x01, 0x02].pack("C*")
    assert_raises(PqcAsn1::ParseError) { rtlv(der, 0, 0x04) }
  end

  def test_read_tlv_at_offset
    der = [0x04, 0x02, 0xAA, 0xBB, 0x30, 0x01, 0xFF].pack("C*")
    content, new_offset = rtlv(der, 4, 0x30)
    assert_equal [0xFF].pack("C"), content
    assert_equal 7, new_offset
  end

  def test_read_tlv_empty_content
    der = [0x04, 0x00].pack("C*")
    content, new_offset = rtlv(der, 0, 0x04)
    assert_equal "", content
    assert_equal 2, new_offset
  end

  def test_read_tlv_returns_frozen_content
    der = [0x30, 0x02, 0x01, 0x02].pack("C*")
    content, = rtlv(der, 0, 0x30)
    assert content.frozen?
  end

  # --- write_tlv ---

  def test_write_tlv_builds_tlv
    content = [0x01, 0x02, 0x03].pack("C*")
    tlv = wtlv(0x04, content)
    assert_equal [0x04, 0x03, 0x01, 0x02, 0x03].pack("C*"), tlv
  end

  def test_write_tlv_empty_content
    tlv = wtlv(0x30, "")
    assert_equal [0x30, 0x00].pack("C*"), tlv
  end

  def test_write_tlv_returns_frozen_string
    assert wtlv(0x04, "test").frozen?
  end

  def test_write_tlv_roundtrips_with_read_tlv
    content = Array.new(200) { rand(256) }.pack("C*")
    tlv = wtlv(0x04, content)
    parsed_content, = rtlv(tlv, 0, 0x04)
    assert_equal content.b, parsed_content.b
  end

  # --- build_spki ---

  def test_build_spki_structure
    oid = PqcAsn1::OID::ML_DSA_44  # dotted string
    oid_tlv = PqcAsn1::OID.from_dotted(oid)
    pk_bytes = "\x00" * 32

    der = PqcAsn1::DER.build_spki(oid, pk_bytes, validate: false)
    assert_instance_of String, der
    assert der.frozen?

    content, pos = rtlv(der, 0, 0x30)
    assert_equal der.bytesize, pos

    inner_content, inner_pos = rtlv(content, 0, 0x30)
    assert_equal oid_tlv, inner_content

    bs_content, = rtlv(content, inner_pos, 0x03)
    assert_equal 0, bs_content.getbyte(0)
    assert_equal pk_bytes, bs_content[1..]
  end

  def test_build_spki_rejects_der_tlv_oid
    oid_tlv = PqcAsn1::OID.from_dotted(PqcAsn1::OID::ML_DSA_44)
    assert_raises(ArgumentError) { PqcAsn1::DER.build_spki(oid_tlv, "\x00" * 32, validate: false) }
  end

  def test_build_spki_rejects_invalid_oid
    assert_raises(ArgumentError) { PqcAsn1::DER.build_spki("\x30\x00", "\x00" * 32, validate: false) }
  end

  def test_build_spki_rejects_empty_oid
    assert_raises(ArgumentError) { PqcAsn1::DER.build_spki("", "\x00" * 32, validate: false) }
  end

  # --- build_pkcs8 ---

  def test_build_pkcs8_returns_secure_buffer
    oid = PqcAsn1::OID::ML_DSA_44
    sk_bytes = ([0xAB].pack("C") * 64).b
    der = PqcAsn1::DER.build_pkcs8(oid, sk_bytes, validate: false)
    assert_instance_of PqcAsn1::SecureBuffer, der
    assert der.frozen?
  end

  def test_build_pkcs8_structure
    oid = PqcAsn1::OID::ML_DSA_44
    oid_tlv = PqcAsn1::OID.from_dotted(oid)
    sk_bytes = ([0xAB].pack("C") * 64).b
    der = PqcAsn1::DER.build_pkcs8(oid, sk_bytes, validate: false)

    der_str = nil
    der.use { |b| der_str = b + "" }

    content, pos = rtlv(der_str, 0, 0x30)
    assert_equal der.bytesize, pos

    int_content, inner_pos = rtlv(content, 0, 0x02)
    assert_equal [0].pack("C"), int_content

    alg_content, inner_pos = rtlv(content, inner_pos, 0x30)
    assert_equal oid_tlv, alg_content

    os_content, = rtlv(content, inner_pos, 0x04)
    assert_equal sk_bytes, os_content
  end

  def test_build_pkcs8_rejects_invalid_oid
    assert_raises(ArgumentError) { PqcAsn1::DER.build_pkcs8("\x30\x00", "\x00" * 32, validate: false) }
  end

  def test_build_pkcs8_secure_buffer_works_with_pem_encode
    oid = PqcAsn1::OID::ML_DSA_44
    der = PqcAsn1::DER.build_pkcs8(oid, "\x01\x02\x03", validate: false)
    pem = PqcAsn1::PEM.encode(der, "PRIVATE KEY")
    assert_includes pem, "-----BEGIN PRIVATE KEY-----"
  end

  # --- parse_spki ---

  def test_parse_spki_roundtrip
    oid = PqcAsn1::OID::ML_DSA_65
    pk_bytes = Array.new(1952) { rand(256) }.pack("C*")

    der = PqcAsn1::DER.build_spki(oid, pk_bytes, validate: false)
    parsed = PqcAsn1::DER.parse_spki(der)

    assert_equal oid, parsed.oid
    assert_equal pk_bytes.b, parsed.key.b
    assert parsed.oid.frozen?
    assert parsed.key.frozen?
  end

  def test_parse_spki_error_on_garbage
    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_spki("garbage") }
    assert_includes err.message, "outer SEQUENCE"
  end

  def test_parse_spki_error_on_missing_bitstring
    oid_tlv = PqcAsn1::OID.from_dotted(PqcAsn1::OID::ML_DSA_44)
    alg_seq = wtlv(0x30, oid_tlv)
    outer = wtlv(0x30, alg_seq)
    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_spki(outer) }
    assert_includes err.message, "BIT STRING"
  end

  def test_parse_spki_rejects_trailing_data
    der = PqcAsn1::DER.build_spki(PqcAsn1::OID::ML_DSA_44, "\x42" * 32, validate: false)
    corrupted = der + "\xFF".b
    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_spki(corrupted) }
    assert_includes err.message, "trailing data"
  end

  def test_parse_spki_with_oid_constants
    PqcAsn1::OID.constants.select { |c| c.to_s.start_with?("ML_DSA") }.each do |name|
      oid = PqcAsn1::OID.const_get(name)
      pk = "\x42" * 32
      der = PqcAsn1::DER.build_spki(oid, pk, validate: false)
      parsed = PqcAsn1::DER.parse_spki(der)
      assert_equal oid, parsed.oid, "OID roundtrip failed for #{name}"
      assert_equal pk.b, parsed.key.b, "Key roundtrip failed for #{name}"
    end
  end

  # --- parse_pkcs8 ---

  def test_parse_pkcs8_roundtrip
    oid = PqcAsn1::OID::ML_DSA_87
    sk_bytes = Array.new(4896) { rand(256) }.pack("C*")

    der = PqcAsn1::DER.build_pkcs8(oid, sk_bytes, validate: false)
    parsed = PqcAsn1::DER.parse_pkcs8(der)

    assert_equal oid, parsed.oid
    parsed.key.use { |b| assert_equal sk_bytes.b, b.b }
    assert_instance_of PqcAsn1::SecureBuffer, parsed.key
    assert parsed.oid.frozen?
    assert parsed.key.frozen?
  end

  def test_parse_pkcs8_rejects_trailing_data
    der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, "\x01\x02\x03", validate: false)
    corrupted = nil
    der.use { |b| corrupted = b.b + "\xFF".b }
    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_pkcs8(corrupted) }
    assert_includes err.message, "trailing data"
  end

  def test_parse_pkcs8_error_on_garbage
    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_pkcs8("garbage") }
    assert_includes err.message, "outer SEQUENCE"
  end

  def test_parse_pkcs8_wrong_version
    oid = PqcAsn1::OID::ML_DSA_44
    der = PqcAsn1::DER.build_pkcs8(oid, "\x01\x02\x03", validate: false)
    corrupted = nil
    der.use { |b| corrupted = b + "" }
    len_byte = corrupted.getbyte(1)
    len_size = (len_byte < 128) ? 1 : (len_byte & 0x7f) + 1
    corrupted.setbyte(1 + len_size + 2, 0x01)
    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_pkcs8(corrupted) }
    assert_includes err.message, "version"
  end

  # --- SecureBuffer ---

  def test_secure_buffer_cannot_be_instantiated
    assert_raises(TypeError) { PqcAsn1::SecureBuffer.new }
  end

  def test_secure_buffer_bytesize
    der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, "\x01\x02\x03", validate: false)
    byte_count = der.use { |b| b.bytesize }
    assert_equal byte_count, der.bytesize
  end

  def test_secure_buffer_to_s_raises
    der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, "\x01\x02\x03", validate: false)
    err = assert_raises(NotImplementedError) { der.to_s }
    assert_includes err.message, "use"
  end

  def test_secure_buffer_equality_with_string
    sk = "\x01\x02\x03"
    der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, sk, validate: false)
    der.use { |b| assert_equal der, b }
  end

  def test_secure_buffer_equality_with_secure_buffer
    sk = "\x01\x02\x03"
    oid = PqcAsn1::OID::ML_DSA_44
    der1 = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    der2 = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    assert_equal der1, der2
  end

  def test_secure_buffer_inequality
    oid = PqcAsn1::OID::ML_DSA_44
    der1 = PqcAsn1::DER.build_pkcs8(oid, "\x01\x02\x03", validate: false)
    der2 = PqcAsn1::DER.build_pkcs8(oid, "\x04\x05\x06", validate: false)
    refute_equal der1, der2
  end

  def test_secure_buffer_inspect_redacted
    der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, "\x01\x02\x03", validate: false)
    assert_includes der.inspect, "REDACTED"
    assert_includes der.inspect, "bytes"
    refute_includes der.inspect, "\x01"
  end

  def test_secure_buffer_no_implicit_conversion
    der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, "\x01\x02\x03", validate: false)
    refute der.respond_to?(:to_str)
  end

  # --- write_length is private ---

  def test_write_length_is_private
    assert_raises(NoMethodError) { PqcAsn1::DER.write_length(42) }
  end

  # --- OID.name_for ---

  def test_oid_name_for_known_oid
    assert_equal "ML_DSA_44", PqcAsn1::OID.name_for(PqcAsn1::OID::ML_DSA_44)
    assert_equal "ML_KEM_768", PqcAsn1::OID.name_for(PqcAsn1::OID::ML_KEM_768)
    assert_equal "SLH_DSA_SHA2_128S", PqcAsn1::OID.name_for(PqcAsn1::OID::SLH_DSA_SHA2_128S)
  end

  def test_oid_name_for_accepts_der_tlv
    # name_for detects DER TLV by first byte 0x06 and converts to dotted first
    oid_tlv = PqcAsn1::OID.from_dotted(PqcAsn1::OID::ML_DSA_44)
    assert_equal "ML_DSA_44", PqcAsn1::OID.name_for(oid_tlv)
  end

  def test_oid_name_for_unknown_oid
    # DER TLV for commonName (2.5.4.3) — not a known PQC OID
    assert_nil PqcAsn1::OID.name_for("\x06\x03\x55\x04\x03")
  end

  def test_oid_name_for_all_builtin_constants
    # Skip custom-registered OIDs — name_for (C) only knows built-in OIDs;
    # the Ruby #name method handles custom OIDs via the custom_registry.
    custom = PqcAsn1::OID.custom_registry.values
    PqcAsn1::OID.constants.each do |name|
      oid = PqcAsn1::OID.const_get(name)
      next unless oid.is_a?(PqcAsn1::OID)
      next if custom.include?(name.to_s)
      assert_equal name.to_s, PqcAsn1::OID.name_for(oid),
        "name_for roundtrip failed for #{name}"
    end
  end

  # --- SecureBuffer dup/clone blocked ---

  def test_secure_buffer_dup_raises
    der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, "\x01\x02\x03", validate: false)
    assert_raises(NoMethodError) { der.dup }
  end

  def test_secure_buffer_clone_raises
    der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, "\x01\x02\x03", validate: false)
    assert_raises(NoMethodError) { der.clone }
  end

  # --- SecureBuffer hash/eql? ---

  def test_secure_buffer_hash_consistent
    sk = "\x01\x02\x03"
    oid = PqcAsn1::OID::ML_DSA_44
    der1 = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    der2 = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    assert_equal der1.hash, der2.hash
  end

  def test_secure_buffer_eql
    sk = "\x01\x02\x03"
    oid = PqcAsn1::OID::ML_DSA_44
    der1 = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    der2 = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    assert der1.eql?(der2)
  end

  def test_secure_buffer_usable_as_hash_key
    sk = "\x01\x02\x03"
    oid = PqcAsn1::OID::ML_DSA_44
    der1 = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    der2 = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    h = {der1 => :found}
    assert_equal :found, h[der2]
  end

  # --- DER::KeyInfo result type ---

  def test_parse_spki_returns_key_info
    oid = PqcAsn1::OID::ML_DSA_44
    pk = "\x42" * 32
    der = PqcAsn1::DER.build_spki(oid, pk, validate: false)
    parsed = PqcAsn1::DER.parse_spki(der)
    assert_instance_of PqcAsn1::DER::KeyInfo, parsed
    assert_equal oid, parsed.oid
    assert_nil parsed.parameters
    assert_equal pk.b, parsed.key.b
    assert_equal :spki, parsed.format
    assert parsed.frozen?
  end

  def test_parse_pkcs8_returns_key_info
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\x01\x02\x03"
    der = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    parsed = PqcAsn1::DER.parse_pkcs8(der)
    assert_instance_of PqcAsn1::DER::KeyInfo, parsed
    assert_equal oid, parsed.oid
    assert_nil parsed.parameters
    assert_instance_of PqcAsn1::SecureBuffer, parsed.key
    assert_nil parsed.public_key
    assert_equal :pkcs8, parsed.format
    assert parsed.frozen?
  end

  def test_key_info_to_h
    oid = PqcAsn1::OID::ML_DSA_44
    pk = "\x42" * 32
    parsed = PqcAsn1::DER.parse_spki(PqcAsn1::DER.build_spki(oid, pk, validate: false))
    h = parsed.to_h
    assert_equal oid, h[:oid]
    assert_equal pk.b, h[:key].b
    assert_nil h[:parameters]
    assert_equal :spki, h[:format]
  end

  def test_pkcs8_key_info_to_h
    oid = PqcAsn1::OID::ML_DSA_44
    parsed = PqcAsn1::DER.parse_pkcs8(PqcAsn1::DER.build_pkcs8(oid, "\x01", validate: false))
    h = parsed.to_h
    assert_equal oid, h[:oid]
    assert_nil h[:parameters]
    assert_nil h[:public_key]
    assert_instance_of PqcAsn1::SecureBuffer, h[:key]
    assert_equal :pkcs8, h[:format]
  end

  def test_key_info_deconstruct_keys
    oid = PqcAsn1::OID::ML_DSA_44
    pk = "\x42" * 32
    parsed = PqcAsn1::DER.parse_spki(PqcAsn1::DER.build_spki(oid, pk, validate: false))
    case parsed
    in {oid:, key:}
      assert_equal oid, PqcAsn1::OID::ML_DSA_44
      assert_equal pk.b, key.b
    end
  end

  def test_key_info_equality
    oid = PqcAsn1::OID::ML_DSA_44
    pk = "\x42" * 32
    der = PqcAsn1::DER.build_spki(oid, pk, validate: false)
    parsed1 = PqcAsn1::DER.parse_spki(der)
    parsed2 = PqcAsn1::DER.parse_spki(der)
    assert_equal parsed1, parsed2
  end

  def test_key_info_spki_inspect_shows_oid_name
    parsed = PqcAsn1::DER.parse_spki(
      PqcAsn1::DER.build_spki(PqcAsn1::OID::ML_DSA_44, "\x42" * 32, validate: false)
    )
    assert_includes parsed.inspect, "ML_DSA_44"
    assert_includes parsed.inspect, "spki"
  end

  def test_key_info_pkcs8_inspect_redacts_key
    parsed = PqcAsn1::DER.parse_pkcs8(
      PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, "\x01\x02\x03", validate: false)
    )
    assert_includes parsed.inspect, "REDACTED"
    assert_includes parsed.inspect, "pkcs8"
    refute_includes parsed.inspect, "\x01"
  end

  # --- Extended DER length forms ---

  def test_three_byte_long_form
    buf = PqcAsn1::DER.send(:write_length, 0x10000)
    assert_equal [0x83, 0x01, 0x00, 0x00].pack("C*"), buf
    assert_equal 4, PqcAsn1::DER.send(:write_length, 0x10000).bytesize
  end

  def test_four_byte_long_form
    buf = PqcAsn1::DER.send(:write_length, 0x1000000)
    assert_equal [0x84, 0x01, 0x00, 0x00, 0x00].pack("C*"), buf
    assert_equal 5, PqcAsn1::DER.send(:write_length, 0x1000000).bytesize
  end

  # --- SecureBuffer#use block API ---

  def test_secure_buffer_use_yields_key_bytes
    sk = "\x01\x02\x03\x04"
    der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, sk, validate: false)
    der.use do |bytes|
      assert_includes bytes, sk.b
      assert_equal Encoding::ASCII_8BIT, bytes.encoding
    end
  end

  def test_secure_buffer_use_zeros_temp_string_after_block
    sk = "\xAB" * 8
    der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, sk, validate: false)
    captured = nil
    der.use { |bytes| captured = bytes }
    assert_equal "\x00" * captured.bytesize, captured
  end

  def test_secure_buffer_use_returns_block_value
    der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, "\x01", validate: false)
    result = der.use { |bytes| bytes.bytesize }
    assert_equal der.bytesize, result
  end

  def test_secure_buffer_use_without_block_raises
    der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, "\x01", validate: false)
    assert_raises(ArgumentError) { der.use }
  end

  def test_secure_buffer_use_zeroes_temp_even_when_block_raises
    sk = "\xAB" * 8
    der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, sk, validate: false)
    captured = nil
    assert_raises(RuntimeError) do
      der.use do |bytes|
        captured = bytes
        raise "intentional error"
      end
    end
    # The ensure in rb_ensure must have zeroed the temporary string.
    assert_equal "\x00" * captured.bytesize, captured
  end

  # --- parse_spki / parse_pkcs8 freeze mutable input ---

  def test_parse_spki_accepts_mutable_input
    der = PqcAsn1::DER.build_spki(PqcAsn1::OID::ML_DSA_44, "\x42" * 32, validate: false)
    mutable = der.dup
    refute mutable.frozen?
    parsed = PqcAsn1::DER.parse_spki(mutable)
    assert_equal PqcAsn1::OID::ML_DSA_44, parsed.oid
  end

  def test_parse_pkcs8_accepts_mutable_input
    der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, "\x01\x02\x03", validate: false)
    mutable = nil
    der.use { |b| mutable = b + "" }
    refute mutable.frozen?
    parsed = PqcAsn1::DER.parse_pkcs8(mutable)
    assert_equal PqcAsn1::OID::ML_DSA_44, parsed.oid
  end

  # --- SecureBuffer Marshal blocked ---

  def test_secure_buffer_marshal_dump_raises
    der = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, "\x01\x02\x03", validate: false)
    assert_raises(TypeError) { Marshal.dump(der) }
  end

  # --- AlgorithmIdentifier parameters accepted ---

  def test_parse_spki_accepts_alg_params
    oid = PqcAsn1::OID::ML_DSA_44
    oid_tlv = PqcAsn1::OID.from_dotted(oid)
    null_tlv = [0x05, 0x00].pack("C*")
    alg_seq = wtlv(0x30, oid_tlv + null_tlv)
    pk = "\x42" * 32
    bs_tlv = wtlv(0x03, "\x00" + pk)
    outer = wtlv(0x30, alg_seq + bs_tlv)

    parsed = PqcAsn1::DER.parse_spki(outer)
    assert_equal oid, parsed.oid
    assert_equal null_tlv.b, parsed.parameters.b
    assert_equal pk.b, parsed.key.b
  end

  def test_parse_pkcs8_accepts_alg_params
    oid = PqcAsn1::OID::ML_DSA_44
    oid_tlv = PqcAsn1::OID.from_dotted(oid)
    null_tlv = [0x05, 0x00].pack("C*")
    alg_seq = wtlv(0x30, oid_tlv + null_tlv)
    version_tlv = [0x02, 0x01, 0x00].pack("C*")
    sk = "\xAB" * 16
    os_tlv = wtlv(0x04, sk)
    outer = wtlv(0x30, version_tlv + alg_seq + os_tlv)

    parsed = PqcAsn1::DER.parse_pkcs8(outer)
    assert_equal oid, parsed.oid
    assert_equal null_tlv.b, parsed.parameters.b
    parsed.key.use { |b| assert_equal sk.b, b.b }
  end

  # --- Extra inner fields rejected ---

  def test_parse_spki_rejects_extra_inner_fields
    oid = PqcAsn1::OID::ML_DSA_44
    der = PqcAsn1::DER.build_spki(oid, "\x42" * 32, validate: false)

    content, = rtlv(der, 0, 0x30)
    extra = wtlv(0x04, "extra")
    tampered = wtlv(0x30, content + extra)

    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_spki(tampered) }
    assert_includes err.message, "extra fields"
  end

  def test_parse_pkcs8_rejects_extra_inner_fields
    oid = PqcAsn1::OID::ML_DSA_44
    der = PqcAsn1::DER.build_pkcs8(oid, "\x01\x02\x03", validate: false)

    content = nil
    der.use { |b| content, = rtlv(b.b, 0, 0x30) }
    extra = wtlv(0x04, "extra")
    tampered = wtlv(0x30, content + extra)

    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_pkcs8(tampered) }
    assert_includes err.message, "extra fields"
  end

  # --- OID.name_for uses hash-based lookup ---

  def test_oid_reverse_hash_is_frozen
    assert PqcAsn1::OID.instance_variable_get(:@reverse).frozen?
  end

  # --- OID.from_dotted / OID.to_dotted ---

  def test_oid_from_dotted_returns_der_tlv
    tlv = PqcAsn1::OID.from_dotted("2.16.840.1.101.3.4.3.17")
    assert_equal 0x06, tlv.getbyte(0)
    assert tlv.frozen?
    assert_equal Encoding::ASCII_8BIT, tlv.encoding
  end

  def test_oid_from_dotted_roundtrips_known_constants
    PqcAsn1::OID.constants.each do |name|
      dotted = PqcAsn1::OID.const_get(name)
      tlv = PqcAsn1::OID.from_dotted(dotted)
      assert_equal dotted, PqcAsn1::OID.to_dotted(tlv),
        "from_dotted/to_dotted roundtrip failed for #{name}"
    end
  end

  def test_oid_to_dotted_known_values
    assert_equal "2.16.840.1.101.3.4.3.17",
      PqcAsn1::OID.to_dotted(PqcAsn1::OID.from_dotted("2.16.840.1.101.3.4.3.17"))
    assert_equal "2.16.840.1.101.3.4.4.2",
      PqcAsn1::OID.to_dotted(PqcAsn1::OID.from_dotted("2.16.840.1.101.3.4.4.2"))
    assert_equal "2.16.840.1.101.3.4.3.20",
      PqcAsn1::OID.to_dotted(PqcAsn1::OID.from_dotted("2.16.840.1.101.3.4.3.20"))
  end

  def test_oid_constants_are_oid_objects
    PqcAsn1::OID.constants.each do |name|
      oid = PqcAsn1::OID.const_get(name)
      assert_instance_of PqcAsn1::OID, oid,
        "#{name} should be a PqcAsn1::OID instance, got: #{oid.inspect}"
      assert_match(/\A\d+(\.\d+)+\z/, oid.dotted,
        "#{name}.dotted should be a dotted-decimal string")
    end
  end

  def test_oid_from_dotted_rejects_invalid_input
    assert_raises(ArgumentError) { PqcAsn1::OID.from_dotted("") }
    assert_raises(ArgumentError) { PqcAsn1::OID.from_dotted("1") }
    assert_raises(ArgumentError) { PqcAsn1::OID.from_dotted("9.0.1") }
    assert_raises(ArgumentError) { PqcAsn1::OID.from_dotted("0.foo") }
  end

  def test_oid_to_dotted_rejects_invalid_input
    assert_raises(ArgumentError) { PqcAsn1::OID.to_dotted("") }
    assert_raises(ArgumentError) { PqcAsn1::OID.to_dotted("\x30\x00") }
  end

  def test_build_spki_accepts_dotted_string_oid
    pk = "\x42" * 32
    der = PqcAsn1::DER.build_spki("2.16.840.1.101.3.4.3.17", pk, validate: false)
    parsed = PqcAsn1::DER.parse_spki(der)
    assert_equal PqcAsn1::OID::ML_DSA_44, parsed.oid
  end

  # --- Error#code and Error#category ---

  def test_parse_error_carries_code
    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_spki("garbage") }
    assert_equal :outer_sequence, err.code
  end

  def test_parse_error_trailing_data_code
    der = PqcAsn1::DER.build_spki(PqcAsn1::OID::ML_DSA_44, "\x42" * 32, validate: false)
    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_spki(der + "\xFF".b) }
    assert_equal :trailing_data, err.code
  end

  def test_parse_error_extra_fields_code
    oid = PqcAsn1::OID::ML_DSA_44
    der = PqcAsn1::DER.build_spki(oid, "\x42" * 32, validate: false)
    content, = rtlv(der, 0, 0x30)
    extra = wtlv(0x04, "extra")
    tampered = wtlv(0x30, content + extra)
    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_spki(tampered) }
    assert_equal :extra_fields, err.code
  end

  def test_parse_error_category_malformed_input
    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_spki("garbage") }
    assert_equal :malformed_input, err.category
  end

  def test_parse_error_category_malformed_encoding
    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::Base64.decode("!!!") }
    assert_equal :malformed_encoding, err.category
  end

  def test_parse_error_category_trailing_data
    der = PqcAsn1::DER.build_spki(PqcAsn1::OID::ML_DSA_44, "\x42" * 32, validate: false)
    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_spki(der + "\xFF".b) }
    assert_equal :malformed_input, err.category
  end

  def test_error_code_is_nil_for_standard_errors
    err = PqcAsn1::Error.new("test")
    assert_nil err.code
    assert_nil err.category
  end

  def test_error_code_keyword_arg
    err = PqcAsn1::Error.new("test", code: :algorithm)
    assert_equal :algorithm, err.code
    assert_equal :malformed_input, err.category
  end

  # --- ParseError category constants ---

  def test_parse_error_category_constants
    assert_equal :malformed_input, PqcAsn1::ParseError::MALFORMED_INPUT
    assert_equal :malformed_encoding, PqcAsn1::ParseError::MALFORMED_ENCODING
    assert_equal :system, PqcAsn1::ParseError::SYSTEM
  end

  def test_parse_error_constants_usable_in_case
    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_spki("garbage") }
    category = case err.category
    when PqcAsn1::ParseError::MALFORMED_INPUT then :input
    when PqcAsn1::ParseError::MALFORMED_ENCODING then :encoding
    when PqcAsn1::ParseError::SYSTEM then :system
    end
    assert_equal :input, category
  end

  # --- OID#der_tlv (class-level cache) ---

  def test_oid_der_tlv_returns_correct_encoding
    oid = PqcAsn1::OID::ML_DSA_44
    tlv = oid.der_tlv
    assert_equal 0x06, tlv.getbyte(0)
    assert tlv.frozen?
    assert_equal PqcAsn1::OID.from_dotted(oid), tlv
  end

  def test_oid_der_tlv_is_cached
    oid = PqcAsn1::OID::ML_KEM_768
    tlv1 = oid.der_tlv
    tlv2 = oid.der_tlv
    assert_same tlv1, tlv2
  end

  def test_oid_der_tlv_works_on_frozen_oid
    # All OID constants are frozen; der_tlv must not raise FrozenError
    assert PqcAsn1::OID::ML_DSA_87.frozen?
    tlv = PqcAsn1::OID::ML_DSA_87.der_tlv
    assert_equal 0x06, tlv.getbyte(0)
  end

  # --- DER.parse_auto ---

  def test_parse_auto_spki
    oid = PqcAsn1::OID::ML_DSA_44
    pk = "\x42" * 32
    der = PqcAsn1::DER.build_spki(oid, pk, validate: false)
    parsed = PqcAsn1::DER.parse_auto(der)
    assert_equal :spki, parsed.format
    assert_equal oid, parsed.oid
    assert_equal pk.b, parsed.key.b
  end

  def test_parse_auto_pkcs8
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 16
    der = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    der_str = nil
    der.use { |b| der_str = b + "" }
    parsed = PqcAsn1::DER.parse_auto(der_str)
    assert_equal :pkcs8, parsed.format
    assert_equal oid, parsed.oid
    parsed.key.use { |b| assert_equal sk.b, b }
  end

  def test_parse_auto_secure_buffer
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 16
    der = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    parsed = PqcAsn1::DER.parse_auto(der)
    assert_equal :pkcs8, parsed.format
    assert_equal oid, parsed.oid
    parsed.key.use { |b| assert_equal sk.b, b }
  end

  def test_parse_auto_raises_on_garbage
    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_auto("\x00\x00") }
    assert_equal :der_parse, err.code
    assert_includes err.message, "cannot detect"
  end

  # --- DER.parse_pem ---

  def test_parse_pem_public_key
    oid = PqcAsn1::OID::ML_DSA_44
    pk = "\x42" * 32
    der = PqcAsn1::DER.build_spki(oid, pk, validate: false)
    pem = PqcAsn1::PEM.encode(der, "PUBLIC KEY")
    parsed = PqcAsn1::DER.parse_pem(pem)
    assert_equal :spki, parsed.format
    assert_equal oid, parsed.oid
    assert_equal pk.b, parsed.key.b
  end

  def test_parse_pem_private_key
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 16
    der = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    pem = PqcAsn1::PEM.encode(der, "PRIVATE KEY")
    parsed = PqcAsn1::DER.parse_pem(pem)
    assert_equal :pkcs8, parsed.format
    assert_equal oid, parsed.oid
    parsed.key.use { |b| assert_equal sk.b, b }
  end

  def test_parse_pem_rejects_unknown_label
    pem = PqcAsn1::PEM.encode("data", "CERTIFICATE")
    err = assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_pem(pem) }
    assert_equal :pem_label, err.code
    assert_includes err.message, "CERTIFICATE"
  end

  def test_parse_pem_rejects_invalid_pem
    assert_raises(PqcAsn1::ParseError) { PqcAsn1::DER.parse_pem("not pem") }
  end

  # --- DER.validate_key_size ---

  def test_validate_key_size_correct
    assert PqcAsn1::DER.validate_key_size(PqcAsn1::OID::ML_DSA_44, 1312, :public)
    assert PqcAsn1::DER.validate_key_size(PqcAsn1::OID::ML_DSA_44, 2560, :secret)
    assert PqcAsn1::DER.validate_key_size(PqcAsn1::OID::ML_KEM_768, 1184, :public)
    assert PqcAsn1::DER.validate_key_size(PqcAsn1::OID::SLH_DSA_SHA2_128S, 32, :public)
    assert PqcAsn1::DER.validate_key_size(PqcAsn1::OID::SLH_DSA_SHA2_128S, 64, :secret)
  end

  def test_validate_key_size_wrong_raises
    err = assert_raises(ArgumentError) do
      PqcAsn1::DER.validate_key_size(PqcAsn1::OID::ML_DSA_44, 999, :public)
    end
    assert_includes err.message, "999"
    assert_includes err.message, "1312"
  end

  def test_validate_key_size_unknown_oid_raises
    unknown = PqcAsn1::OID.new("1.2.3.4.5")
    err = assert_raises(ArgumentError) do
      PqcAsn1::DER.validate_key_size(unknown, 42, :public)
    end
    assert_includes err.message, "unknown OID"
  end

  def test_key_sizes_covers_all_builtin_oid_constants
    custom = PqcAsn1::OID.custom_registry.values
    PqcAsn1::OID.constants.each do |name|
      oid = PqcAsn1::OID.const_get(name)
      next unless oid.is_a?(PqcAsn1::OID)
      next if custom.include?(name.to_s)
      assert PqcAsn1::DER::KEY_SIZES.key?(oid),
        "KEY_SIZES missing entry for #{name}"
    end
  end

  # --- build_pkcs8 accepts SecureBuffer input ---

  def test_build_pkcs8_accepts_secure_buffer
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 64
    sb = PqcAsn1::SecureBuffer.from_string(sk)
    der = PqcAsn1::DER.build_pkcs8(oid, sb, validate: false)
    assert_instance_of PqcAsn1::SecureBuffer, der

    parsed = PqcAsn1::DER.parse_pkcs8(der)
    assert_equal oid, parsed.oid
    parsed.key.use { |b| assert_equal sk.b, b }
  end

  def test_build_pkcs8_secure_buffer_wiped_raises
    sb = PqcAsn1::SecureBuffer.from_string("\x01\x02\x03")
    sb.wipe!
    assert_raises(RuntimeError) do
      PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, sb, validate: false)
    end
  end

  # --- OneAsymmetricKey optional publicKey [1] ---

  def test_parse_pkcs8_with_optional_public_key
    oid = PqcAsn1::OID::ML_DSA_44
    oid_tlv = PqcAsn1::OID.from_dotted(oid)
    version_tlv = [0x02, 0x01, 0x00].pack("C*")
    alg_seq = wtlv(0x30, oid_tlv)
    sk = ([0xAB].pack("C") * 16).b
    os_tlv = wtlv(0x04, sk)
    pk = ([0xCD].pack("C") * 32).b
    pub_tlv = ([0x81, pk.bytesize].pack("CC") + pk).b
    outer = wtlv(0x30, version_tlv + alg_seq + os_tlv + pub_tlv)

    parsed = PqcAsn1::DER.parse_pkcs8(outer)
    parsed.key.use { |b| assert_equal sk.b, b.b }
    assert_equal pk.b, parsed.public_key.b
  end

  def test_parse_pkcs8_without_public_key_is_nil
    oid = PqcAsn1::OID::ML_DSA_44
    der = PqcAsn1::DER.build_pkcs8(oid, "\x01\x02\x03", validate: false)
    parsed = PqcAsn1::DER.parse_pkcs8(der)
    assert_nil parsed.public_key
  end

  # --- build_spki with parameters: keyword ---

  def test_build_spki_with_parameters_roundtrip
    oid = PqcAsn1::OID::ML_DSA_44
    pk = "\x42" * 32
    null_param = [0x05, 0x00].pack("C*")
    der = PqcAsn1::DER.build_spki(oid, pk, parameters: null_param, validate: false)
    parsed = PqcAsn1::DER.parse_spki(der)
    assert_equal oid, parsed.oid
    assert_equal null_param.b, parsed.parameters.b
    assert_equal pk.b, parsed.key.b
  end

  def test_build_spki_without_parameters_keyword_still_works
    oid = PqcAsn1::OID::ML_DSA_44
    pk = "\x42" * 32
    der = PqcAsn1::DER.build_spki(oid, pk, validate: false)
    parsed = PqcAsn1::DER.parse_spki(der)
    assert_equal oid, parsed.oid
    assert_nil parsed.parameters
    assert_equal pk.b, parsed.key.b
  end

  # --- build_pkcs8 with parameters: keyword ---

  def test_build_pkcs8_with_parameters_roundtrip
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 16
    null_param = [0x05, 0x00].pack("C*")
    der = PqcAsn1::DER.build_pkcs8(oid, sk, parameters: null_param, validate: false)
    parsed = PqcAsn1::DER.parse_pkcs8(der)
    assert_equal oid, parsed.oid
    assert_equal null_param.b, parsed.parameters.b
    parsed.key.use { |b| assert_equal sk.b, b }
  end

  # --- build_pkcs8 with public_key: keyword ---

  def test_build_pkcs8_with_public_key_roundtrip
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 16
    pk = "\xCD" * 32
    der = PqcAsn1::DER.build_pkcs8(oid, sk, public_key: pk, validate: false)
    parsed = PqcAsn1::DER.parse_pkcs8(der)
    assert_equal oid, parsed.oid
    parsed.key.use { |b| assert_equal sk.b, b }
    assert_equal pk.b, parsed.public_key.b
  end

  def test_build_pkcs8_with_both_keywords
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 16
    pk = "\xCD" * 32
    null_param = [0x05, 0x00].pack("C*")
    der = PqcAsn1::DER.build_pkcs8(oid, sk, parameters: null_param, public_key: pk, validate: false)
    parsed = PqcAsn1::DER.parse_pkcs8(der)
    assert_equal oid, parsed.oid
    assert_equal null_param.b, parsed.parameters.b
    parsed.key.use { |b| assert_equal sk.b, b }
    assert_equal pk.b, parsed.public_key.b
  end

  def test_build_pkcs8_with_public_key_secure_buffer_input
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 16
    pk = "\xCD" * 32
    sb = PqcAsn1::SecureBuffer.from_string(sk)
    der = PqcAsn1::DER.build_pkcs8(oid, sb, public_key: pk, validate: false)
    parsed = PqcAsn1::DER.parse_pkcs8(der)
    assert_equal oid, parsed.oid
    parsed.key.use { |b| assert_equal sk.b, b }
    assert_equal pk.b, parsed.public_key.b
  end

  # --- Error subclasses (Item 7) ---

  def test_der_error_raised_for_spki_parse_failure
    assert_raises(PqcAsn1::DERError) { PqcAsn1::DER.parse_spki("garbage") }
  end

  def test_der_error_is_a_parse_error
    err = assert_raises(PqcAsn1::DERError) { PqcAsn1::DER.parse_spki("garbage") }
    assert_kind_of PqcAsn1::ParseError, err
  end

  def test_der_error_raised_for_pkcs8_parse_failure
    assert_raises(PqcAsn1::DERError) { PqcAsn1::DER.parse_pkcs8("garbage") }
  end

  def test_oid_error_class_hierarchy
    assert PqcAsn1::OIDError < PqcAsn1::Error
  end

  def test_oid_error_is_not_a_parse_error
    refute PqcAsn1::OIDError < PqcAsn1::ParseError
  end

  def test_invalid_oid_string_raises_argument_error
    assert_raises(ArgumentError) do
      PqcAsn1::DER.build_spki("\x30\x00", "\x00" * 32, validate: false)
    end
  end

  def test_parse_auto_raises_der_error
    err = assert_raises(PqcAsn1::DERError) { PqcAsn1::DER.parse_auto("\x00\x00") }
    assert_equal :der_parse, err.code
  end

  # --- KeyInfo convenience methods (Item 6) ---

  def test_key_info_algorithm_known_oid
    parsed = PqcAsn1::DER.parse_spki(
      PqcAsn1::DER.build_spki(PqcAsn1::OID::ML_DSA_44, "\x42" * 32, validate: false)
    )
    assert_equal "ML_DSA_44", parsed.algorithm
  end

  def test_key_info_algorithm_unknown_oid
    # Use a non-standard OID — algorithm should return dotted string
    parsed = PqcAsn1::DER.parse_spki(
      PqcAsn1::DER.build_spki("2.5.4.3", "\x42" * 32, validate: false)
    )
    assert_equal "2.5.4.3", parsed.algorithm
  end

  def test_key_info_to_der_spki_roundtrip
    oid = PqcAsn1::OID::ML_DSA_44
    pk = "\x42" * 32
    der = PqcAsn1::DER.build_spki(oid, pk, validate: false)
    parsed = PqcAsn1::DER.parse_spki(der)
    assert_equal der, parsed.to_der
  end

  def test_key_info_to_der_pkcs8_roundtrip
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 16
    der = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    parsed = PqcAsn1::DER.parse_pkcs8(der)
    re_der = parsed.to_der
    assert_instance_of PqcAsn1::SecureBuffer, re_der
    assert_equal der, re_der
  end

  def test_key_info_to_der_with_parameters
    oid = PqcAsn1::OID::ML_DSA_44
    pk = "\x42" * 32
    null_param = [0x05, 0x00].pack("C*")
    der = PqcAsn1::DER.build_spki(oid, pk, parameters: null_param, validate: false)
    parsed = PqcAsn1::DER.parse_spki(der)
    assert_equal der, parsed.to_der
  end

  def test_key_info_to_pem_spki
    oid = PqcAsn1::OID::ML_DSA_44
    pk = "\x42" * 32
    parsed = PqcAsn1::DER.parse_spki(PqcAsn1::DER.build_spki(oid, pk, validate: false))
    pem = parsed.to_pem
    assert_includes pem, "-----BEGIN PUBLIC KEY-----"
    assert_includes pem, "-----END PUBLIC KEY-----"
  end

  def test_key_info_to_pem_pkcs8
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 16
    parsed = PqcAsn1::DER.parse_pkcs8(PqcAsn1::DER.build_pkcs8(oid, sk, validate: false))
    pem = parsed.to_pem
    assert_includes pem, "-----BEGIN PRIVATE KEY-----"
    assert_includes pem, "-----END PRIVATE KEY-----"
  end

  # --- validate: keyword (Item 9) ---

  def test_build_spki_validate_correct_size
    oid = PqcAsn1::OID::ML_DSA_44
    pk = "\x42" * 1312
    der = PqcAsn1::DER.build_spki(oid, pk, validate: true)
    assert_instance_of String, der
  end

  def test_build_spki_validate_wrong_size_raises
    oid = PqcAsn1::OID::ML_DSA_44
    pk = "\x42" * 999
    assert_raises(ArgumentError) do
      PqcAsn1::DER.build_spki(oid, pk, validate: true)
    end
  end

  def test_build_spki_validate_false_skips_check
    oid = PqcAsn1::OID::ML_DSA_44
    pk = "\x42" * 999
    der = PqcAsn1::DER.build_spki(oid, pk, validate: false)
    assert_instance_of String, der
  end

  def test_build_pkcs8_validate_correct_size
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 2560
    der = PqcAsn1::DER.build_pkcs8(oid, sk, validate: true)
    assert_instance_of PqcAsn1::SecureBuffer, der
  end

  def test_build_pkcs8_validate_wrong_size_raises
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 999
    assert_raises(ArgumentError) do
      PqcAsn1::DER.build_pkcs8(oid, sk, validate: true)
    end
  end

  def test_build_pkcs8_validate_with_keywords
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 2560
    pk = "\xCD" * 32
    null_param = [0x05, 0x00].pack("C*")
    der = PqcAsn1::DER.build_pkcs8(
      oid, sk, parameters: null_param, public_key: pk, validate: true
    )
    parsed = PqcAsn1::DER.parse_pkcs8(der)
    assert_equal null_param.b, parsed.parameters.b
    assert_equal pk.b, parsed.public_key.b
  end

  # --- Dual-path verification (Item 3) ---

  def test_build_spki_fast_and_slow_paths_produce_same_output
    oid = PqcAsn1::OID::ML_DSA_44
    pk = "\x42" * 32
    null_param = [0x05, 0x00].pack("C*")

    # Fast path: no parameters
    fast = PqcAsn1::DER.build_spki(oid, pk, validate: false)

    # Slow path: with parameters (NULL added, then manually compared)
    slow = PqcAsn1::DER.build_spki(oid, pk, parameters: null_param, validate: false)

    # Both should parse correctly
    fast_parsed = PqcAsn1::DER.parse_spki(fast)
    slow_parsed = PqcAsn1::DER.parse_spki(slow)

    assert_equal oid, fast_parsed.oid
    assert_equal oid, slow_parsed.oid
    assert_equal pk.b, fast_parsed.key.b
    assert_equal pk.b, slow_parsed.key.b
    assert_nil fast_parsed.parameters
    assert_equal null_param.b, slow_parsed.parameters.b
  end

  def test_build_pkcs8_fast_and_slow_paths_produce_same_output
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 16
    null_param = [0x05, 0x00].pack("C*")
    pk = "\xCD" * 32

    # Fast path: no keywords
    fast = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)

    # Slow path: with parameters + public_key
    slow = PqcAsn1::DER.build_pkcs8(oid, sk, parameters: null_param, public_key: pk, validate: false)

    # Both should parse correctly
    fast_parsed = PqcAsn1::DER.parse_pkcs8(fast)
    slow_parsed = PqcAsn1::DER.parse_pkcs8(slow)

    assert_equal oid, fast_parsed.oid
    assert_equal oid, slow_parsed.oid
    fast_parsed.key.use { |b| assert_equal sk.b, b }
    slow_parsed.key.use { |b| assert_equal sk.b, b }
    assert_nil fast_parsed.parameters
    assert_equal null_param.b, slow_parsed.parameters.b
    assert_nil fast_parsed.public_key
    assert_equal pk.b, slow_parsed.public_key.b
  end

  def test_build_spki_fast_and_slow_paths_for_all_oids
    PqcAsn1::OID.constants.each do |name|
      oid = PqcAsn1::OID.const_get(name)
      pk = "\x42" * 32

      fast = PqcAsn1::DER.build_spki(oid, pk, validate: false)
      slow = PqcAsn1::DER.build_spki(oid, pk, parameters: [0x05, 0x00].pack("C*"), validate: false)

      fast_parsed = PqcAsn1::DER.parse_spki(fast)
      slow_parsed = PqcAsn1::DER.parse_spki(slow)

      assert_equal oid, fast_parsed.oid, "Fast path OID mismatch for #{name}"
      assert_equal oid, slow_parsed.oid, "Slow path OID mismatch for #{name}"
      assert_equal pk.b, fast_parsed.key.b, "Fast path key mismatch for #{name}"
      assert_equal pk.b, slow_parsed.key.b, "Slow path key mismatch for #{name}"
    end
  end

  # --- OID.register (Item 5) ---

  def test_oid_register_returns_oid_accessible_by_bracket
    oid = PqcAsn1::OID.register("1.3.6.1.4.1.99999.1", "TEST_ALGO_1")
    assert_instance_of PqcAsn1::OID, oid
    assert_equal "1.3.6.1.4.1.99999.1", oid.dotted
    # register does NOT auto-define a constant; use OID["name"] to look up
    assert_equal oid, PqcAsn1::OID["TEST_ALGO_1"]
    refute PqcAsn1::OID.const_defined?(:TEST_ALGO_1)
  end

  def test_oid_register_name_lookup
    oid = PqcAsn1::OID.register("1.3.6.1.4.1.99999.2", "TEST_ALGO_2")
    assert_equal "TEST_ALGO_2", oid.name
    assert_equal "TEST_ALGO_2", PqcAsn1::OID["TEST_ALGO_2"].name
  end

  def test_oid_register_with_key_sizes
    oid = PqcAsn1::OID.register(
      "1.3.6.1.4.1.99999.3", "TEST_ALGO_3",
      key_sizes: {public: 100, secret: 200}
    )
    assert PqcAsn1::DER.validate_key_size(oid, 100, :public)
    assert_raises(ArgumentError) do
      PqcAsn1::DER.validate_key_size(oid, 999, :public)
    end
  end

  def test_oid_register_duplicate_name_raises
    PqcAsn1::OID.register("1.3.6.1.4.1.99999.4", "TEST_ALGO_4")
    assert_raises(ArgumentError) do
      PqcAsn1::OID.register("1.3.6.1.4.1.99999.99", "TEST_ALGO_4")
    end
  end

  def test_oid_register_duplicate_dotted_raises
    PqcAsn1::OID.register("1.3.6.1.4.1.99999.5", "TEST_ALGO_5")
    assert_raises(ArgumentError) do
      PqcAsn1::OID.register("1.3.6.1.4.1.99999.5", "TEST_ALGO_5B")
    end
  end

  # --- SecureBuffer#to_pem (Item 2) ---

  def test_secure_buffer_to_pem
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 16
    der = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    pem = der.to_pem
    assert_includes pem, "-----BEGIN PRIVATE KEY-----"
    assert_includes pem, "-----END PRIVATE KEY-----"
  end

  def test_secure_buffer_to_pem_custom_label
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 16
    der = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    pem = der.to_pem("ENCRYPTED PRIVATE KEY")
    assert_includes pem, "-----BEGIN ENCRYPTED PRIVATE KEY-----"
  end

  def test_secure_buffer_to_pem_roundtrip
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 16
    der = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    pem = der.to_pem
    decoded = PqcAsn1::PEM.decode(pem, "PRIVATE KEY")
    der.use { |b| assert_equal b.b, decoded.b }
  end

  # --- OID.name_for with runtime-registered OIDs ---

  def test_oid_name_for_registered_oid_by_dotted
    dotted = "1.3.6.1.4.1.99999.201"
    unless PqcAsn1::OID.registered.key?("TEST_NAME_FOR_201")
      PqcAsn1::OID.register(dotted, "TEST_NAME_FOR_201")
    end
    assert_equal "TEST_NAME_FOR_201", PqcAsn1::OID.name_for(dotted)
  end

  def test_oid_name_for_registered_oid_by_instance
    dotted = "1.3.6.1.4.1.99999.202"
    unless PqcAsn1::OID.registered.key?("TEST_NAME_FOR_202")
      PqcAsn1::OID.register(dotted, "TEST_NAME_FOR_202")
    end
    oid = PqcAsn1::OID[dotted]
    assert_equal "TEST_NAME_FOR_202", PqcAsn1::OID.name_for(oid)
  end

  def test_oid_name_instance_method_matches_name_for
    dotted = "1.3.6.1.4.1.99999.203"
    unless PqcAsn1::OID.registered.key?("TEST_NAME_FOR_203")
      PqcAsn1::OID.register(dotted, "TEST_NAME_FOR_203")
    end
    oid = PqcAsn1::OID[dotted]
    assert_equal PqcAsn1::OID.name_for(dotted), oid.name
  end

  # --- EncryptedPrivateKeyInfo (parse_auto + detect_format + round-trip) ---

  def test_detect_format_returns_nil_for_truncated_spki
    # SEQUENCE { SEQUENCE { ... } } but truncated before the BIT STRING tag
    inner_seq = PqcAsn1::DER.write_tlv(0x30, "\x06\x03\x55\x04\x03")
    truncated = PqcAsn1::DER.write_tlv(0x30, inner_seq)
    # No second element after the inner SEQUENCE — ambiguous
    assert_nil PqcAsn1::DER.detect_format(truncated)
  end

  def test_detect_format_returns_nil_for_unexpected_second_tag
    # SEQUENCE { SEQUENCE { OID } INTEGER } — neither BIT STRING nor OCTET STRING
    inner_seq = PqcAsn1::DER.write_tlv(0x30, "\x06\x03\x55\x04\x03")
    integer = PqcAsn1::DER.write_tlv(0x02, "\x01")
    weird = PqcAsn1::DER.write_tlv(0x30, inner_seq + integer)
    assert_nil PqcAsn1::DER.detect_format(weird)
  end

  def test_detect_format_spki_with_bit_string
    oid = PqcAsn1::OID::ML_DSA_44
    der = PqcAsn1::DER.build_spki(oid, "\x42" * 32, validate: false)
    assert_equal :spki, PqcAsn1::DER.detect_format(der)
  end

  def test_detect_format_encrypted_pkcs8
    # Build a minimal EncryptedPrivateKeyInfo:
    # SEQUENCE { AlgorithmIdentifier(SEQUENCE) OCTET_STRING(ciphertext) }
    fake_oid_content = "\x60\x86\x48\x01\x65\x03\x04\x01\x2a".b
    algo_oid = PqcAsn1::DER.write_tlv(0x06, fake_oid_content)
    algo_seq = PqcAsn1::DER.write_tlv(0x30, algo_oid)
    enc_data = PqcAsn1::DER.write_tlv(0x04, "CIPHERTEXT".b * 4)
    der = PqcAsn1::DER.write_tlv(0x30, algo_seq + enc_data)

    assert_equal :encrypted_pkcs8, PqcAsn1::DER.detect_format(der)
  end

  def test_parse_auto_dispatches_encrypted_pkcs8
    fake_oid_content = "\x60\x86\x48\x01\x65\x03\x04\x01\x2a".b
    algo_oid = PqcAsn1::DER.write_tlv(0x06, fake_oid_content)
    algo_seq = PqcAsn1::DER.write_tlv(0x30, algo_oid)
    ciphertext = "CIPHERTEXT_PAYLOAD".b
    enc_data = PqcAsn1::DER.write_tlv(0x04, ciphertext)
    der = PqcAsn1::DER.write_tlv(0x30, algo_seq + enc_data)

    result = PqcAsn1::DER.parse_auto(der)
    assert_instance_of PqcAsn1::DER::EncryptedKeyInfo, result
    assert_equal :encrypted_pkcs8, result.format
    assert_equal algo_seq.b, result.encryption_algorithm.b
    assert_equal ciphertext.b, result.encrypted_data.b
  end

  def test_encrypted_pkcs8_roundtrip
    fake_oid_content = "\x60\x86\x48\x01\x65\x03\x04\x01\x2a".b
    algo_oid = PqcAsn1::DER.write_tlv(0x06, fake_oid_content)
    algo_seq = PqcAsn1::DER.write_tlv(0x30, algo_oid)
    ciphertext = "SOME_ENCRYPTED_BYTES".b
    der = PqcAsn1::DER.write_tlv(0x30,
      algo_seq + PqcAsn1::DER.write_tlv(0x04, ciphertext))

    info = PqcAsn1::DER.parse_encrypted_pkcs8(der)
    rebuilt = info.to_der
    assert_equal der.b, rebuilt.b
  end

  def test_encrypted_pkcs8_to_pem
    fake_oid_content = "\x60\x86\x48\x01\x65\x03\x04\x01\x2a".b
    algo_oid = PqcAsn1::DER.write_tlv(0x06, fake_oid_content)
    algo_seq = PqcAsn1::DER.write_tlv(0x30, algo_oid)
    der = PqcAsn1::DER.write_tlv(0x30,
      algo_seq + PqcAsn1::DER.write_tlv(0x04, "CT".b))

    info = PqcAsn1::DER.parse_encrypted_pkcs8(der)
    pem = info.to_pem
    assert_includes pem, "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    assert_includes pem, "-----END ENCRYPTED PRIVATE KEY-----"
  end

  def test_parse_pem_encrypted_private_key_label
    fake_oid_content = "\x60\x86\x48\x01\x65\x03\x04\x01\x2a".b
    algo_oid = PqcAsn1::DER.write_tlv(0x06, fake_oid_content)
    algo_seq = PqcAsn1::DER.write_tlv(0x30, algo_oid)
    der = PqcAsn1::DER.write_tlv(0x30,
      algo_seq + PqcAsn1::DER.write_tlv(0x04, "CIPHERTEXT".b))

    pem = PqcAsn1::PEM.encode(der, "ENCRYPTED PRIVATE KEY")
    result = PqcAsn1::DER.parse_pem(pem)
    assert_instance_of PqcAsn1::DER::EncryptedKeyInfo, result
  end

  # --- build_pkcs8 with public_key: keyword ---

  def test_pkcs8_roundtrip_with_public_key
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 32
    pk = "\xCD" * 16
    der = PqcAsn1::DER.build_pkcs8(oid, sk, public_key: pk, validate: false)
    parsed = PqcAsn1::DER.parse_pkcs8(der)
    assert_equal oid, parsed.oid
    parsed.key.use { |b| assert_equal sk.b, b }
    assert_equal pk.b, parsed.public_key.b
  end

  def test_pkcs8_without_public_key_has_nil_public_key
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 32
    der = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    parsed = PqcAsn1::DER.parse_pkcs8(der)
    assert_nil parsed.public_key
  end

  # --- KeyInfo#hash excludes secret key for :pkcs8 ---

  def test_key_info_hash_excludes_secret_key_for_pkcs8
    oid = PqcAsn1::OID::ML_DSA_44
    sk1 = "\x01" * 32
    sk2 = "\x02" * 32
    der1 = PqcAsn1::DER.build_pkcs8(oid, sk1, validate: false)
    der2 = PqcAsn1::DER.build_pkcs8(oid, sk2, validate: false)
    parsed1 = PqcAsn1::DER.parse_pkcs8(der1)
    parsed2 = PqcAsn1::DER.parse_pkcs8(der2)
    # Same OID, no parameters, no public_key, same format → same hash
    # (secret key excluded for :pkcs8)
    assert_equal parsed1.hash, parsed2.hash
  end

  def test_key_info_hash_includes_key_for_spki
    oid = PqcAsn1::OID::ML_DSA_44
    pk1 = "\x01" * 32
    pk2 = "\x02" * 32
    der1 = PqcAsn1::DER.build_spki(oid, pk1, validate: false)
    der2 = PqcAsn1::DER.build_spki(oid, pk2, validate: false)
    parsed1 = PqcAsn1::DER.parse_spki(der1)
    parsed2 = PqcAsn1::DER.parse_spki(der2)
    # Different keys → different hashes (public key is included for :spki)
    refute_equal parsed1.hash, parsed2.hash
  end

  # --- validate_key_size raises for unknown OID ---

  def test_validate_key_size_raises_for_unknown_oid
    unknown_oid = PqcAsn1::OID.new("1.2.3.4.5.6.7.8.9")
    err = assert_raises(ArgumentError) do
      PqcAsn1::DER.validate_key_size(unknown_oid, 32, :public)
    end
    assert_includes err.message, "unknown OID"
  end

  def test_build_spki_validate_true_raises_for_unknown_oid
    unknown_oid = PqcAsn1::OID.new("1.2.3.4.5.6.7.8.9")
    assert_raises(ArgumentError) do
      PqcAsn1::DER.build_spki(unknown_oid, "\x42" * 32, validate: true)
    end
  end

  def test_build_spki_validate_false_allows_unknown_oid
    unknown_oid = PqcAsn1::OID.new("1.2.3.4.5.6.7.8.9")
    der = PqcAsn1::DER.build_spki(unknown_oid, "\x42" * 32, validate: false)
    assert_instance_of String, der
  end

  # --- Input size limits ---

  def test_parse_spki_rejects_oversized_input
    original = PqcAsn1::DER.max_input_size
    begin
      PqcAsn1::DER.max_input_size = 100
      big_input = "\x30" + "\x00" * 200
      assert_raises(ArgumentError) do
        PqcAsn1::DER.parse_spki(big_input)
      end
    ensure
      PqcAsn1::DER.max_input_size = original
    end
  end

  def test_parse_pkcs8_rejects_oversized_input
    original = PqcAsn1::DER.max_input_size
    begin
      PqcAsn1::DER.max_input_size = 100
      big_input = "\x30" + "\x00" * 200
      assert_raises(ArgumentError) do
        PqcAsn1::DER.parse_pkcs8(big_input)
      end
    ensure
      PqcAsn1::DER.max_input_size = original
    end
  end

  def test_parse_spki_allows_nil_max_input_size
    original = PqcAsn1::DER.max_input_size
    begin
      PqcAsn1::DER.max_input_size = nil
      oid = PqcAsn1::OID::ML_DSA_44
      pk = "\x42" * 32
      der = PqcAsn1::DER.build_spki(oid, pk, validate: false)
      parsed = PqcAsn1::DER.parse_spki(der)
      assert_equal oid, parsed.oid
    ensure
      PqcAsn1::DER.max_input_size = original
    end
  end

  def test_parse_encrypted_pkcs8_rejects_oversized_input
    original = PqcAsn1::DER.max_input_size
    begin
      PqcAsn1::DER.max_input_size = 100
      big_input = "\x30" + "\x00" * 200
      assert_raises(ArgumentError) do
        PqcAsn1::DER.parse_encrypted_pkcs8(big_input)
      end
    ensure
      PqcAsn1::DER.max_input_size = original
    end
  end

  # --- SecureBuffer#write_to and #to_pem_io ---

  def test_secure_buffer_write_to
    sk = "\xAB" * 32
    sb = PqcAsn1::SecureBuffer.from_string(sk)
    io = StringIO.new
    sb.write_to(io)
    assert_equal sk.b, io.string.b
  end

  def test_secure_buffer_to_pem_io
    sk = "\x01\x02\x03"
    sb = PqcAsn1::SecureBuffer.from_string(sk)
    io = StringIO.new
    sb.to_pem_io(io)
    pem = io.string
    assert_includes pem, "-----BEGIN PRIVATE KEY-----"
    assert_includes pem, "-----END PRIVATE KEY-----"
    decoded = PqcAsn1::PEM.decode(pem, "PRIVATE KEY")
    assert_equal sk.b, decoded.b
  end

  def test_secure_buffer_to_pem_io_custom_label
    sk = "\x01\x02\x03"
    sb = PqcAsn1::SecureBuffer.from_string(sk)
    io = StringIO.new
    sb.to_pem_io(io, "ENCRYPTED PRIVATE KEY")
    pem = io.string
    assert_includes pem, "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    assert_includes pem, "-----END ENCRYPTED PRIVATE KEY-----"
  end

  # --- SecureBuffer#wipe! returns self ---

  def test_secure_buffer_wipe_returns_self
    buf = PqcAsn1::SecureBuffer.random(32)
    result = buf.wipe!
    assert_same buf, result
  end

  def test_secure_buffer_wipe_chaining
    buf = PqcAsn1::SecureBuffer.random(16)
    assert buf.wipe!.wiped?
  end

  # --- SecureBuffer.random / #slice input validation ---

  def test_secure_buffer_random_rejects_negative
    assert_raises(ArgumentError) do
      PqcAsn1::SecureBuffer.random(-1)
    end
  end

  def test_secure_buffer_random_rejects_zero
    assert_raises(ArgumentError) do
      PqcAsn1::SecureBuffer.random(0)
    end
  end

  def test_secure_buffer_slice_rejects_negative_offset
    buf = PqcAsn1::SecureBuffer.random(32)
    assert_raises(ArgumentError) do
      buf.slice(-1, 16)
    end
  end

  def test_secure_buffer_slice_rejects_negative_length
    buf = PqcAsn1::SecureBuffer.random(32)
    assert_raises(ArgumentError) do
      buf.slice(0, -1)
    end
  end

  # --- build_encrypted_pkcs8 nil argument validation ---

  def test_build_encrypted_pkcs8_rejects_nil_algorithm
    err = assert_raises(ArgumentError) do
      PqcAsn1::DER.build_encrypted_pkcs8(nil, "ciphertext")
    end
    assert_includes err.message, "encryption_algorithm_der"
  end

  def test_build_encrypted_pkcs8_rejects_nil_data
    algo_seq = PqcAsn1::DER.write_tlv(0x30, PqcAsn1::DER.write_tlv(0x06, "\x55\x04\x03"))
    err = assert_raises(ArgumentError) do
      PqcAsn1::DER.build_encrypted_pkcs8(algo_seq, nil)
    end
    assert_includes err.message, "encrypted_data"
  end

  # --- read_tlv / Cursor negative offset validation ---

  def test_read_tlv_rejects_negative_offset
    der = [0x30, 0x02, 0x01, 0x02].pack("C*")
    assert_raises(ArgumentError) do
      PqcAsn1::DER.read_tlv(der, -1, 0x30)
    end
  end

  def test_cursor_rejects_negative_pos
    assert_raises(ArgumentError) do
      PqcAsn1::DER::Cursor.new("\x30\x00", -1)
    end
  end
end
