# frozen_string_literal: true

require "test_helper"

class CursorTest < Minitest::Test
  def wtlv(tag, content)
    PqcAsn1::DER.write_tlv(tag, content)
  end

  def test_read_sequence
    inner = [0x06, 0x03, 0x55, 0x04, 0x03].pack("C*")
    seq = wtlv(0x30, inner)
    cursor = PqcAsn1::DER::Cursor.new(seq)
    inner_cursor = cursor.read_sequence
    assert_instance_of PqcAsn1::DER::Cursor, inner_cursor
    assert cursor.eof?
  end

  def test_read_oid
    oid_content = [0x55, 0x04, 0x03].pack("C*")
    oid_tlv = wtlv(0x06, oid_content)
    cursor = PqcAsn1::DER::Cursor.new(oid_tlv)
    result = cursor.read_oid
    assert_equal oid_content.b, result.b
    assert cursor.eof?
  end

  def test_read_integer
    int_tlv = [0x02, 0x01, 0x00].pack("C*")
    cursor = PqcAsn1::DER::Cursor.new(int_tlv)
    result = cursor.read_integer
    assert_equal [0x00].pack("C"), result
    assert cursor.eof?
  end

  def test_read_octet_string
    content = "\x01\x02\x03"
    tlv = wtlv(0x04, content)
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    result = cursor.read_octet_string
    assert_equal content.b, result.b
    assert cursor.eof?
  end

  def test_read_bit_string
    content = "\x00\xAA\xBB"
    tlv = wtlv(0x03, content)
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    result = cursor.read_bit_string
    assert_equal content.b, result.b
    assert cursor.eof?
  end

  def test_wrong_tag_raises
    tlv = wtlv(0x04, "data")
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    assert_raises(PqcAsn1::ParseError) do
      cursor.read(0x30)
    end
  end

  def test_remaining_and_eof
    content_a = wtlv(0x04, "AA")
    content_b = wtlv(0x04, "BB")
    cursor = PqcAsn1::DER::Cursor.new(content_a + content_b)
    refute cursor.eof?
    assert_equal content_a.bytesize + content_b.bytesize, cursor.remaining
    cursor.read(0x04)
    refute cursor.eof?
    cursor.read(0x04)
    assert cursor.eof?
    assert_equal 0, cursor.remaining
  end

  def test_nested_spki_parsing
    oid = PqcAsn1::OID::ML_DSA_44
    oid_tlv = PqcAsn1::OID.from_dotted(oid)
    pk_bytes = "\x42" * 32
    der = PqcAsn1::DER.build_spki(oid, pk_bytes, validate: false)

    outer = PqcAsn1::DER::Cursor.new(der)
    seq = outer.read_sequence
    assert outer.eof?

    alg = seq.read_sequence
    oid_content = alg.read(0x06)
    assert alg.eof?

    # oid_content is the OID value bytes (without TLV wrapper).
    # Strip tag + length byte from the full TLV to get just the value.
    expected_oid_content = oid_tlv.b[2..]
    assert_equal expected_oid_content, oid_content.b

    bs = seq.read_bit_string
    assert seq.eof?
    assert_equal 0, bs.getbyte(0)
    assert_equal pk_bytes.b, bs[1..].b
  end

  def test_nested_pkcs8_parsing
    oid = PqcAsn1::OID::ML_DSA_44
    oid_tlv = PqcAsn1::OID.from_dotted(oid)
    sk_bytes = "\xAB" * 64
    der = PqcAsn1::DER.build_pkcs8(oid, sk_bytes, validate: false)

    der_str = nil
    der.use { |b| der_str = b + "" }

    outer = PqcAsn1::DER::Cursor.new(der_str)
    seq = outer.read_sequence
    assert outer.eof?

    version = seq.read_integer
    assert_equal [0x00].pack("C"), version

    alg = seq.read_sequence
    oid_content = alg.read(0x06)
    expected_oid_content = oid_tlv.b[2..]
    assert_equal expected_oid_content, oid_content.b

    sk = seq.read_octet_string
    assert_equal sk_bytes.b, sk.b
    assert seq.eof?
  end

  def test_pos_attribute
    tlv = wtlv(0x04, "test")
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    assert_equal 0, cursor.pos
    cursor.read(0x04)
    assert_equal tlv.bytesize, cursor.pos
  end

  def test_data_is_frozen_binary
    cursor = PqcAsn1::DER::Cursor.new("test")
    assert cursor.data.frozen?
    assert_equal Encoding::ASCII_8BIT, cursor.data.encoding
  end

  def test_skip_advances_past_tlv
    content_a = wtlv(0x02, "\x00")
    content_b = wtlv(0x04, "data")
    cursor = PqcAsn1::DER::Cursor.new(content_a + content_b)
    result = cursor.skip(0x02)
    assert_equal cursor, result  # returns self for chaining
    assert_equal content_a.bytesize, cursor.pos
    assert_equal "data".b, cursor.read(0x04).b
    assert cursor.eof?
  end

  def test_skip_wrong_tag_raises
    tlv = wtlv(0x04, "data")
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    assert_raises(PqcAsn1::ParseError) do
      cursor.skip(0x30)
    end
  end

  def test_read_raw_returns_full_tlv
    content = "\x01\x02\x03"
    tlv = wtlv(0x04, content)
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    raw = cursor.read_raw(0x04)
    assert_equal tlv.b, raw.b
    assert cursor.eof?
  end

  def test_read_raw_advances_past_entire_tlv
    content_a = wtlv(0x04, "first")
    content_b = wtlv(0x04, "second")
    cursor = PqcAsn1::DER::Cursor.new(content_a + content_b)
    raw_a = cursor.read_raw(0x04)
    assert_equal content_a.b, raw_a.b
    refute cursor.eof?
    raw_b = cursor.read_raw(0x04)
    assert_equal content_b.b, raw_b.b
    assert cursor.eof?
  end

  def test_read_raw_wrong_tag_raises
    tlv = wtlv(0x04, "data")
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    assert_raises(PqcAsn1::ParseError) { cursor.read_raw(0x30) }
  end

  def test_read_raw_returns_frozen_binary
    tlv = wtlv(0x06, "\x55\x04\x03")
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    raw = cursor.read_raw(0x06)
    assert raw.frozen?
    assert_equal Encoding::ASCII_8BIT, raw.encoding
  end

  def test_skip_in_spki_navigation
    oid = PqcAsn1::OID::ML_DSA_44
    pk_bytes = "\x42" * 32
    der = PqcAsn1::DER.build_spki(oid, pk_bytes, validate: false)

    outer = PqcAsn1::DER::Cursor.new(der)
    seq = outer.read_sequence
    seq.skip(0x30)  # skip AlgorithmIdentifier without materializing
    bs = seq.read_bit_string
    assert seq.eof?
    assert_equal pk_bytes.b, bs[1..].b
  end

  # ----------------------------------------------------------------
  # Edge-case tests
  # ----------------------------------------------------------------

  def test_new_with_pos_at_end_is_immediately_eof
    data = wtlv(0x04, "hello")
    cursor = PqcAsn1::DER::Cursor.new(data, data.bytesize)
    assert cursor.eof?
    assert_equal 0, cursor.remaining
    assert_nil cursor.peek_tag
  end

  def test_new_with_pos_beyond_end_raises
    data = wtlv(0x04, "hello")
    assert_raises(ArgumentError) do
      PqcAsn1::DER::Cursor.new(data, data.bytesize + 1)
    end
  end

  def test_peek_tag_returns_nil_at_eof
    data = wtlv(0x04, "x")
    cursor = PqcAsn1::DER::Cursor.new(data)
    cursor.read(0x04)
    assert cursor.eof?
    assert_nil cursor.peek_tag
  end

  def test_peek_tag_returns_next_tag
    data = wtlv(0x02, "\x01") + wtlv(0x04, "data")
    cursor = PqcAsn1::DER::Cursor.new(data)
    assert_equal 0x02, cursor.peek_tag
    cursor.read(0x02)
    assert_equal 0x04, cursor.peek_tag
  end

  def test_nested_read_sequence_on_sub_cursor
    inner_seq = wtlv(0x30, wtlv(0x02, "\x01"))
    outer_seq = wtlv(0x30, inner_seq)
    der = wtlv(0x30, outer_seq)

    c1 = PqcAsn1::DER::Cursor.new(der)
    c2 = c1.read_sequence           # outermost SEQUENCE content
    c3 = c2.read_sequence           # middle SEQUENCE content
    c4 = c3.read_sequence           # innermost SEQUENCE content
    val = c4.read_integer
    assert_equal "\x01".b, val.b
    assert c4.eof?
    assert c3.eof?
    assert c2.eof?
    assert c1.eof?
  end

  def test_new_with_pos_in_middle
    a = wtlv(0x04, "AA")
    b = wtlv(0x04, "BB")
    data = a + b
    cursor = PqcAsn1::DER::Cursor.new(data, a.bytesize)
    assert_equal a.bytesize, cursor.pos
    assert_equal b.bytesize, cursor.remaining
    result = cursor.read(0x04)
    assert_equal "BB".b, result.b
    assert cursor.eof?
  end

  def test_data_returns_source_for_top_level_cursor
    data = wtlv(0x04, "hello").b.freeze
    cursor = PqcAsn1::DER::Cursor.new(data)
    # data method should return the source (zero-copy)
    assert_equal data, cursor.data
    assert cursor.data.frozen?
    assert_equal Encoding::ASCII_8BIT, cursor.data.encoding
  end

  def test_data_on_sub_cursor_returns_scoped_view
    inner = wtlv(0x02, "\x01") + wtlv(0x04, "data")
    der = wtlv(0x30, inner)
    outer = PqcAsn1::DER::Cursor.new(der)
    sub = outer.read_sequence
    sub_data = sub.data
    assert_equal inner.b, sub_data.b
    assert sub_data.frozen?
  end

  def test_read_raw_on_sub_cursor
    oid_tlv = wtlv(0x06, "\x55\x04\x03")
    seq = wtlv(0x30, oid_tlv)
    outer = PqcAsn1::DER::Cursor.new(seq)
    sub = outer.read_sequence
    raw = sub.read_raw(0x06)
    assert_equal oid_tlv.b, raw.b
    assert raw.frozen?
    assert sub.eof?
  end

  # ----------------------------------------------------------------
  # read_optional tests
  # ----------------------------------------------------------------

  def test_read_optional_returns_content_when_tag_matches
    content = "\x01\x02\x03"
    tlv = wtlv(0x04, content)
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    result = cursor.read_optional(0x04)
    assert_equal content.b, result.b
    assert cursor.eof?
  end

  def test_read_optional_returns_nil_when_tag_mismatches
    tlv = wtlv(0x04, "data")
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    result = cursor.read_optional(0x30)
    assert_nil result
    assert_equal 0, cursor.pos
  end

  def test_read_optional_returns_nil_at_eof
    tlv = wtlv(0x04, "x")
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    cursor.read(0x04)
    assert cursor.eof?
    assert_nil cursor.read_optional(0x04)
  end

  def test_read_optional_in_sequence_with_optional_field
    # Simulate a SEQUENCE with mandatory INTEGER + optional OCTET STRING
    int_tlv = wtlv(0x02, "\x01")
    opt_tlv = wtlv(0x04, "optional")
    seq_with = wtlv(0x30, int_tlv + opt_tlv)
    seq_without = wtlv(0x30, int_tlv)

    # With optional field present
    c = PqcAsn1::DER::Cursor.new(seq_with).read_sequence
    c.read(0x02)
    opt = c.read_optional(0x04)
    assert_equal "optional".b, opt.b
    assert c.eof?

    # Without optional field
    c = PqcAsn1::DER::Cursor.new(seq_without).read_sequence
    c.read(0x02)
    opt = c.read_optional(0x04)
    assert_nil opt
    assert c.eof?
  end

  # ----------------------------------------------------------------
  # skip_optional tests
  # ----------------------------------------------------------------

  def test_skip_optional_returns_self_when_tag_matches
    content_a = wtlv(0x02, "\x00")
    content_b = wtlv(0x04, "data")
    cursor = PqcAsn1::DER::Cursor.new(content_a + content_b)
    result = cursor.skip_optional(0x02)
    assert_equal cursor, result
    assert_equal content_a.bytesize, cursor.pos
  end

  def test_skip_optional_returns_nil_when_tag_mismatches
    tlv = wtlv(0x04, "data")
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    result = cursor.skip_optional(0x30)
    assert_nil result
    assert_equal 0, cursor.pos
  end

  def test_skip_optional_returns_nil_at_eof
    tlv = wtlv(0x04, "x")
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    cursor.read(0x04)
    assert cursor.eof?
    assert_nil cursor.skip_optional(0x04)
  end

  # ----------------------------------------------------------------
  # read_raw_optional tests
  # ----------------------------------------------------------------

  def test_read_raw_optional_returns_tlv_when_tag_matches
    content = "\x01\x02\x03"
    tlv = wtlv(0x04, content)
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    raw = cursor.read_raw_optional(0x04)
    assert_equal tlv.b, raw.b
    assert cursor.eof?
  end

  def test_read_raw_optional_returns_nil_when_tag_mismatches
    tlv = wtlv(0x04, "data")
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    result = cursor.read_raw_optional(0x30)
    assert_nil result
    assert_equal 0, cursor.pos
  end

  def test_read_raw_optional_returns_nil_at_eof
    tlv = wtlv(0x04, "x")
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    cursor.read(0x04)
    assert cursor.eof?
    assert_nil cursor.read_raw_optional(0x04)
  end

  def test_read_raw_optional_returns_frozen_binary
    tlv = wtlv(0x06, "\x55\x04\x03")
    cursor = PqcAsn1::DER::Cursor.new(tlv)
    raw = cursor.read_raw_optional(0x06)
    assert raw.frozen?
    assert_equal Encoding::ASCII_8BIT, raw.encoding
  end

  def test_detect_format_spki
    oid = PqcAsn1::OID::ML_DSA_44
    pk = "\x42" * 32
    spki = PqcAsn1::DER.build_spki(oid, pk, validate: false)
    assert_equal :spki, PqcAsn1::DER.detect_format(spki)
  end

  def test_detect_format_pkcs8
    oid = PqcAsn1::OID::ML_DSA_44
    sk = "\xAB" * 64
    pkcs8 = PqcAsn1::DER.build_pkcs8(oid, sk, validate: false)
    der_str = nil
    pkcs8.use { |b| der_str = b + "" }
    assert_equal :pkcs8, PqcAsn1::DER.detect_format(der_str)
  end

  def test_detect_format_nil_for_garbage
    assert_nil PqcAsn1::DER.detect_format("\x00\x00\x00")
    assert_nil PqcAsn1::DER.detect_format("")
    assert_nil PqcAsn1::DER.detect_format("\xFF")
  end

  def test_secure_buffer_slice
    sb = PqcAsn1::SecureBuffer.from_string("Hello, World!!")
    sliced = sb.slice(7, 5)
    assert_instance_of PqcAsn1::SecureBuffer, sliced
    assert_equal 5, sliced.bytesize
    sliced.use { |bytes| assert_equal "World", bytes }
  end

  def test_secure_buffer_slice_bounds_check
    sb = PqcAsn1::SecureBuffer.from_string("test")
    assert_raises(RangeError) { sb.slice(5, 1) }
    assert_raises(RangeError) { sb.slice(2, 3) }
    assert_raises(ArgumentError) { sb.slice(0, 0) }
  end

  def test_secure_buffer_slice_on_wiped_raises
    sb = PqcAsn1::SecureBuffer.from_string("secret")
    sb.wipe!
    assert_raises(RuntimeError) { sb.slice(0, 3) }
  end
end
