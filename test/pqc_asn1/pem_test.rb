# frozen_string_literal: true

require "test_helper"

class PemTest < Minitest::Test
  def test_pem_encode_decode_roundtrip
    data = "\x30\x82\x01\x00" + ("\xAB" * 256)
    label = "PUBLIC KEY"

    pem = PqcAsn1::PEM.encode(data, label)
    assert_includes pem, "-----BEGIN PUBLIC KEY-----"
    assert_includes pem, "-----END PUBLIC KEY-----"

    decoded = PqcAsn1::PEM.decode(pem, label)
    assert_equal data.b, decoded.b
  end

  def test_pem_encode_format
    data = "Hello"
    pem = PqcAsn1::PEM.encode(data, "TEST")

    lines = pem.split("\n")
    assert_equal "-----BEGIN TEST-----", lines.first
    assert_equal "-----END TEST-----", lines.last
    body = lines[1..-2].join
    assert_equal "SGVsbG8=", body
  end

  def test_pem_encode_returns_frozen_us_ascii_string
    pem = PqcAsn1::PEM.encode("test", "TEST")
    assert pem.frozen?
    assert_equal Encoding::US_ASCII, pem.encoding
  end

  def test_pem_decode_wrong_label
    pem = "-----BEGIN PUBLIC KEY-----\nQQ==\n-----END PUBLIC KEY-----\n"
    err = assert_raises(PqcAsn1::ParseError) do
      PqcAsn1::PEM.decode(pem, "PRIVATE KEY")
    end
    assert_includes err.message, "PRIVATE KEY"
    assert_includes err.message, "PUBLIC KEY"
  end

  def test_pem_decode_no_markers
    err = assert_raises(PqcAsn1::ParseError) do
      PqcAsn1::PEM.decode("just some text", "PUBLIC KEY")
    end
    assert_includes err.message, "no valid PEM markers"
  end

  def test_pem_decode_missing_end
    pem = "-----BEGIN PUBLIC KEY-----\nQQ==\n"
    assert_raises(PqcAsn1::ParseError) do
      PqcAsn1::PEM.decode(pem, "PUBLIC KEY")
    end
  end

  def test_pem_decode_returns_frozen_binary_string
    pem = "-----BEGIN TEST-----\nQQ==\n-----END TEST-----\n"
    decoded = PqcAsn1::PEM.decode(pem, "TEST")
    assert decoded.frozen?
    assert_equal Encoding::ASCII_8BIT, decoded.encoding
  end

  def test_pem_encode_private_key_label
    data = "\x01\x02\x03"
    pem = PqcAsn1::PEM.encode(data, "PRIVATE KEY")
    assert_includes pem, "-----BEGIN PRIVATE KEY-----"
    assert_includes pem, "-----END PRIVATE KEY-----"
    decoded = PqcAsn1::PEM.decode(pem, "PRIVATE KEY")
    assert_equal data.b, decoded.b
  end

  def test_pem_roundtrip_large_data
    data = Array.new(2528) { rand(256) }.pack("C*")
    pem = PqcAsn1::PEM.encode(data, "PUBLIC KEY")

    lines = pem.split("\n")
    body_lines = lines[1..-2]
    body_lines[0..-2].each do |line|
      assert_equal 64, line.length, "Expected 64-char lines in PEM body"
    end

    decoded = PqcAsn1::PEM.decode(pem, "PUBLIC KEY")
    assert_equal data.b, decoded.b
  end

  def test_build_spki_then_pem_roundtrip
    oid_der = PqcAsn1::OID::ML_DSA_44
    pk_bytes = Array.new(1312) { rand(256) }.pack("C*")

    der = PqcAsn1::DER.build_spki(oid_der, pk_bytes, validate: false)
    pem = PqcAsn1::PEM.encode(der, "PUBLIC KEY")
    decoded_der = PqcAsn1::PEM.decode(pem, "PUBLIC KEY")
    assert_equal der.b, decoded_der.b
  end

  def test_build_pkcs8_then_pem_roundtrip
    oid_der = PqcAsn1::OID::ML_DSA_44
    sk_bytes = Array.new(2560) { rand(256) }.pack("C*")

    der = PqcAsn1::DER.build_pkcs8(oid_der, sk_bytes, validate: false)
    # PEM.encode accepts SecureBuffer directly
    pem = PqcAsn1::PEM.encode(der, "PRIVATE KEY")
    decoded_der = PqcAsn1::PEM.decode(pem, "PRIVATE KEY")
    der.use { |b| assert_equal b.b, decoded_der.b }
  end

  # --- decode_auto ---

  def test_decode_auto_public_key
    data = "\x01\x02\x03"
    pem = PqcAsn1::PEM.encode(data, "PUBLIC KEY")
    result = PqcAsn1::PEM.decode_auto(pem)
    assert_equal data.b, result.data.b
    assert_equal "PUBLIC KEY", result.label
  end

  def test_decode_auto_private_key
    data = "\xAA\xBB\xCC"
    pem = PqcAsn1::PEM.encode(data, "PRIVATE KEY")
    result = PqcAsn1::PEM.decode_auto(pem)
    assert_equal data.b, result.data.b
    assert_equal "PRIVATE KEY", result.label
  end

  def test_decode_auto_returns_frozen_strings_with_correct_encoding
    pem = PqcAsn1::PEM.encode("test", "TEST")
    result = PqcAsn1::PEM.decode_auto(pem)
    assert result.data.frozen?
    assert result.label.frozen?
    assert_equal Encoding::ASCII_8BIT, result.data.encoding
    assert_equal Encoding::US_ASCII, result.label.encoding
  end

  def test_decode_auto_invalid_pem
    assert_raises(PqcAsn1::ParseError) do
      PqcAsn1::PEM.decode_auto("not a pem")
    end
  end

  def test_pem_decode_bad_base64_body
    pem = "-----BEGIN TEST-----\n!!!invalid!!!\n-----END TEST-----\n"
    err = assert_raises(PqcAsn1::ParseError) do
      PqcAsn1::PEM.decode(pem, "TEST")
    end
    assert_includes err.message, "Base64"
  end

  def test_decode_auto_full_spki_roundtrip
    oid_der = PqcAsn1::OID::ML_KEM_768
    pk_bytes = Array.new(1184) { rand(256) }.pack("C*")

    der = PqcAsn1::DER.build_spki(oid_der, pk_bytes, validate: false)
    pem = PqcAsn1::PEM.encode(der, "PUBLIC KEY")
    result = PqcAsn1::PEM.decode_auto(pem)

    assert_equal "PUBLIC KEY", result.label
    parsed = PqcAsn1::DER.parse_spki(result.data)
    assert_equal oid_der, parsed.oid
    assert_equal pk_bytes.b, parsed.key.b
  end

  # --- PEM::DecodeResult ---

  def test_decode_auto_returns_decode_result_instance
    pem = PqcAsn1::PEM.encode("test", "TEST")
    result = PqcAsn1::PEM.decode_auto(pem)
    assert_instance_of PqcAsn1::PEM::DecodeResult, result
  end

  def test_decode_result_data_attribute
    data = "\x01\x02\x03"
    pem = PqcAsn1::PEM.encode(data, "TEST")
    result = PqcAsn1::PEM.decode_auto(pem)
    assert_equal data.b, result.data
  end

  def test_decode_result_label_attribute
    pem = PqcAsn1::PEM.encode("test", "PUBLIC KEY")
    result = PqcAsn1::PEM.decode_auto(pem)
    assert_equal "PUBLIC KEY", result.label
  end

  def test_decode_result_is_frozen
    pem = PqcAsn1::PEM.encode("test", "TEST")
    result = PqcAsn1::PEM.decode_auto(pem)
    assert result.frozen?
  end

  def test_decode_result_to_a_returns_array
    data = "\xAA\xBB"
    pem = PqcAsn1::PEM.encode(data, "PRIVATE KEY")
    arr = PqcAsn1::PEM.decode_auto(pem).to_a
    assert_equal data.b, arr[0]
    assert_equal "PRIVATE KEY", arr[1]
  end

  def test_decode_result_has_no_to_ary
    pem = PqcAsn1::PEM.encode("test", "TEST")
    result = PqcAsn1::PEM.decode_auto(pem)
    refute result.respond_to?(:to_ary),
      "DecodeResult must not implement to_ary (implicit coercion footgun)"
  end

  def test_decode_result_equality
    pem = PqcAsn1::PEM.encode("test", "TEST")
    a = PqcAsn1::PEM.decode_auto(pem)
    b = PqcAsn1::PEM.decode_auto(pem)
    assert_equal a, b
  end

  def test_decode_result_inspect_format
    pem = PqcAsn1::PEM.encode("hello", "PUBLIC KEY")
    result = PqcAsn1::PEM.decode_auto(pem)
    assert_match(/PqcAsn1::PEM::DecodeResult/, result.inspect)
    assert_match(/PUBLIC KEY/, result.inspect)
    assert_match(/\d+B/, result.inspect)
  end

  def test_decode_result_deconstruct_keys
    data = "\x01\x02"
    pem = PqcAsn1::PEM.encode(data, "TEST")
    result = PqcAsn1::PEM.decode_auto(pem)
    assert_equal({data: data.b, label: "TEST"}, result.deconstruct_keys(nil))
  end

  def test_decode_result_pattern_matching
    pem = PqcAsn1::PEM.encode("\x01\x02", "PUBLIC KEY")
    result = PqcAsn1::PEM.decode_auto(pem)
    case result
    in {label: "PUBLIC KEY", data:}
      assert_equal "\x01\x02".b, data
    else
      flunk "Pattern match failed"
    end
  end

  # --- decode_each ---

  def test_decode_each_single_block
    data = "\xAA\xBB"
    pem = PqcAsn1::PEM.encode(data, "TEST")
    results = []
    PqcAsn1::PEM.decode_each(pem) { |r| results << r }
    assert_equal 1, results.size
    assert_instance_of PqcAsn1::PEM::DecodeResult, results[0]
    assert_equal data.b, results[0].data
    assert_equal "TEST", results[0].label
  end

  def test_decode_each_multiple_blocks
    pk = "\x01\x02\x03"
    sk = "\x04\x05\x06"
    pem = [
      PqcAsn1::PEM.encode(pk, "PUBLIC KEY"),
      PqcAsn1::PEM.encode(sk, "PRIVATE KEY")
    ].join("\n")

    results = []
    PqcAsn1::PEM.decode_each(pem) { |r| results << r }
    assert_equal 2, results.size
    assert_equal "PUBLIC KEY", results[0].label
    assert_equal pk.b, results[0].data
    assert_equal "PRIVATE KEY", results[1].label
    assert_equal sk.b, results[1].data
  end

  def test_decode_each_returns_nil_with_block
    pem = PqcAsn1::PEM.encode("x", "TEST")
    result = PqcAsn1::PEM.decode_each(pem) { |_r| }
    assert_nil result
  end

  def test_decode_each_returns_enumerator_without_block
    pem = PqcAsn1::PEM.encode("x", "TEST")
    enum = PqcAsn1::PEM.decode_each(pem)
    assert_kind_of Enumerator, enum
  end

  def test_decode_each_enumerator_yields_decode_results
    pk = "\x01\x02"
    sk = "\x03\x04"
    pem = [
      PqcAsn1::PEM.encode(pk, "PUBLIC KEY"),
      PqcAsn1::PEM.encode(sk, "PRIVATE KEY")
    ].join("\n")

    enum = PqcAsn1::PEM.decode_each(pem)
    results = enum.to_a
    assert_equal 2, results.size
    assert_equal "PUBLIC KEY", results[0].label
    assert_equal "PRIVATE KEY", results[1].label
  end

  def test_decode_each_enumerator_supports_chaining
    pem = [
      PqcAsn1::PEM.encode("\x01", "PUBLIC KEY"),
      PqcAsn1::PEM.encode("\x02", "PRIVATE KEY"),
      PqcAsn1::PEM.encode("\x03", "PUBLIC KEY")
    ].join("\n")

    labels = PqcAsn1::PEM.decode_each(pem).map(&:label)
    assert_equal ["PUBLIC KEY", "PRIVATE KEY", "PUBLIC KEY"], labels
  end

  def test_decode_each_empty_input
    results = []
    PqcAsn1::PEM.decode_each("") { |r| results << r }
    assert_empty results
  end

  def test_decode_each_no_valid_blocks
    results = []
    PqcAsn1::PEM.decode_each("just plain text") { |r| results << r }
    assert_empty results
  end

  def test_decode_each_with_mixed_labels
    a = PqcAsn1::PEM.encode("\x01", "CERTIFICATE")
    b = PqcAsn1::PEM.encode("\x02", "PUBLIC KEY")
    pem = [a, b].join("\n")

    labels = []
    PqcAsn1::PEM.decode_each(pem) { |r| labels << r.label }
    assert_equal ["CERTIFICATE", "PUBLIC KEY"], labels
  end

  # --- PEMError subclass (Item 7) ---

  def test_pem_error_raised_for_decode_wrong_label
    pem = "-----BEGIN PUBLIC KEY-----\nQQ==\n-----END PUBLIC KEY-----\n"
    assert_raises(PqcAsn1::PEMError) do
      PqcAsn1::PEM.decode(pem, "PRIVATE KEY")
    end
  end

  def test_pem_error_is_a_parse_error
    err = assert_raises(PqcAsn1::PEMError) do
      PqcAsn1::PEM.decode("not pem", "TEST")
    end
    assert_kind_of PqcAsn1::ParseError, err
  end

  def test_pem_error_for_bad_base64
    pem = "-----BEGIN TEST-----\n!!!invalid!!!\\n-----END TEST-----\n"
    assert_raises(PqcAsn1::PEMError) do
      PqcAsn1::PEM.decode(pem, "TEST")
    end
  end

  def test_parse_pem_raises_pem_error_for_unknown_label
    pem = PqcAsn1::PEM.encode("data", "CERTIFICATE")
    err = assert_raises(PqcAsn1::PEMError) { PqcAsn1::DER.parse_pem(pem) }
    assert_equal :pem_label, err.code
  end

  # --- IO streaming decode_each (Item 4) ---

  def test_decode_each_with_io_object
    pk = "\x01\x02\x03"
    sk = "\x04\x05\x06"
    pem = [
      PqcAsn1::PEM.encode(pk, "PUBLIC KEY"),
      PqcAsn1::PEM.encode(sk, "PRIVATE KEY")
    ].join("\n")

    io = StringIO.new(pem)
    results = []
    PqcAsn1::PEM.decode_each(io) { |r| results << r }
    assert_equal 2, results.size
    assert_equal "PUBLIC KEY", results[0].label
    assert_equal pk.b, results[0].data
    assert_equal "PRIVATE KEY", results[1].label
    assert_equal sk.b, results[1].data
  end

  def test_decode_each_io_returns_enumerator_without_block
    pem = PqcAsn1::PEM.encode("x", "TEST")
    io = StringIO.new(pem)
    enum = PqcAsn1::PEM.decode_each(io)
    assert_kind_of Enumerator, enum
    results = enum.to_a
    assert_equal 1, results.size
    assert_equal "TEST", results[0].label
  end

  def test_decode_each_io_empty_input
    io = StringIO.new("")
    results = []
    PqcAsn1::PEM.decode_each(io) { |r| results << r }
    assert_empty results
  end

  def test_decode_each_io_no_valid_blocks
    io = StringIO.new("just plain text\nmore text\n")
    results = []
    PqcAsn1::PEM.decode_each(io) { |r| results << r }
    assert_empty results
  end

  # --- IO streaming: BEGIN/END label mismatch ---

  def test_decode_each_io_raises_on_label_mismatch
    pem = "-----BEGIN PUBLIC KEY-----\nQQ==\n-----END PRIVATE KEY-----\n"
    io = StringIO.new(pem)
    assert_raises(PqcAsn1::ParseError) do
      PqcAsn1::PEM.decode_each(io) { |_r| }
    end
  end

  def test_decode_each_io_label_mismatch_error_message
    pem = "-----BEGIN FOO-----\nQQ==\n-----END BAR-----\n"
    io = StringIO.new(pem)
    err = assert_raises(PqcAsn1::PEMError) do
      PqcAsn1::PEM.decode_each(io) { |_r| }
    end
    assert_includes err.message, "FOO"
    assert_includes err.message, "BAR"
    assert_equal :pem_label, err.code
  end

  # --- IO streaming: truncated PEM (missing END marker) ---

  def test_decode_each_io_raises_on_truncated_pem
    # BEGIN marker present but no END marker — IO stream is truncated
    truncated = "-----BEGIN PUBLIC KEY-----\nQQ==\n"
    io = StringIO.new(truncated)
    err = assert_raises(PqcAsn1::PEMError) do
      PqcAsn1::PEM.decode_each(io) { |_r| }
    end
    assert_includes err.message, "truncated"
    assert_equal :pem_no_markers, err.code
  end

  def test_decode_each_io_raises_on_truncated_pem_after_valid_block
    pk = "\x01\x02\x03"
    valid = PqcAsn1::PEM.encode(pk, "PUBLIC KEY")
    truncated = valid + "\n-----BEGIN PRIVATE KEY-----\nQQ==\n"
    io = StringIO.new(truncated)
    results = []
    err = assert_raises(PqcAsn1::PEMError) do
      PqcAsn1::PEM.decode_each(io) { |r| results << r }
    end
    # The valid block should have been yielded before the error
    assert_equal 1, results.size
    assert_equal "PUBLIC KEY", results[0].label
    assert_includes err.message, "truncated"
  end

  def test_decode_each_io_label_mismatch_raises_pem_error
    pem = "-----BEGIN PUBLIC KEY-----\nQQ==\n-----END PRIVATE KEY-----\n"
    io = StringIO.new(pem)
    assert_raises(PqcAsn1::PEMError) do
      PqcAsn1::PEM.decode_each(io) { |_r| }
    end
  end
end
