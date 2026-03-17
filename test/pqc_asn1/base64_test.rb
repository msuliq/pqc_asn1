# frozen_string_literal: true

require "test_helper"

class Base64Test < Minitest::Test
  def test_encode_empty
    assert_equal "", PqcAsn1::Base64.encode("")
  end

  def test_encode_one_byte
    assert_equal "QQ==", PqcAsn1::Base64.encode("A")
  end

  def test_encode_two_bytes
    assert_equal "QUI=", PqcAsn1::Base64.encode("AB")
  end

  def test_encode_three_bytes
    assert_equal "QUJD", PqcAsn1::Base64.encode("ABC")
  end

  def test_encode_hello_world
    assert_equal "SGVsbG8gV29ybGQ=", PqcAsn1::Base64.encode("Hello World")
  end

  def test_encode_line_wrapping
    # 48 bytes of input → 64 chars of base64 (exactly one line, no newline)
    data = "A" * 48
    encoded = PqcAsn1::Base64.encode(data)
    assert_equal 64, encoded.length
    refute_includes encoded, "\n"

    # 49 bytes → >64 chars, should have line wrapping
    data = "A" * 49
    encoded = PqcAsn1::Base64.encode(data)
    assert_includes encoded, "\n"
    lines = encoded.split("\n")
    assert_equal 64, lines.first.length
  end

  def test_encode_returns_frozen_us_ascii_string
    result = PqcAsn1::Base64.encode("test")
    assert result.frozen?
    assert_equal Encoding::US_ASCII, result.encoding
  end

  def test_decode_empty
    assert_equal "", PqcAsn1::Base64.decode("")
  end

  def test_decode_simple
    assert_equal "Hello World", PqcAsn1::Base64.decode("SGVsbG8gV29ybGQ=")
  end

  def test_decode_no_padding
    assert_equal "ABC", PqcAsn1::Base64.decode("QUJD")
  end

  def test_decode_with_whitespace
    assert_equal "Hello World", PqcAsn1::Base64.decode("SGVs\nbG8g\nV29y\nbGQ=")
  end

  def test_decode_invalid_character
    assert_raises(PqcAsn1::ParseError) do
      PqcAsn1::Base64.decode("SGVs!!!!")
    end
  end

  def test_decode_returns_frozen_binary_string
    result = PqcAsn1::Base64.decode("QUJD")
    assert result.frozen?
    assert_equal Encoding::ASCII_8BIT, result.encoding
  end

  def test_roundtrip
    data = (0..255).map(&:chr).join
    encoded = PqcAsn1::Base64.encode(data)
    decoded = PqcAsn1::Base64.decode(encoded)
    assert_equal data.b, decoded.b
  end

  def test_roundtrip_binary
    data = Array.new(1000) { rand(256) }.pack("C*")
    encoded = PqcAsn1::Base64.encode(data)
    decoded = PqcAsn1::Base64.decode(encoded)
    assert_equal data.b, decoded.b
  end

  # --- Padding validation ---

  def test_decode_rejects_data_after_padding
    assert_raises(PqcAsn1::ParseError) do
      PqcAsn1::Base64.decode("QQ==QUJD")
    end
  end

  def test_decode_rejects_data_after_single_pad
    assert_raises(PqcAsn1::ParseError) do
      PqcAsn1::Base64.decode("QUI=QUJD")
    end
  end

  def test_decode_rejects_padding_mid_stream
    assert_raises(PqcAsn1::ParseError) do
      PqcAsn1::Base64.decode("QQ==\nQUJD")
    end
  end
end
