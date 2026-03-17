# frozen_string_literal: true

require "test_helper"

# Tests that load pre-computed fixture files from test/fixtures/.
#
# These act as stability/regression guards: if the DER encoding produced
# by build_spki or build_pkcs8 ever changes, the byte-level assertions
# catch it immediately.  Each fixture was generated once with the gem and
# committed so that future builds must produce identical bytes.
class FixtureTest < Minitest::Test
  FIXTURE_DIR = File.expand_path("../fixtures", __dir__)

  def fixture(name)
    File.binread(File.join(FIXTURE_DIR, name))
  end

  # --- SPKI fixtures ---

  def test_ml_dsa_44_spki_der_bytes
    der = fixture("ml_dsa_44_spki.der")
    expected = [
      0x30, 0x30, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
      0x03, 0x21, 0x00,
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
      0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
      0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    ].pack("C*")
    assert_equal expected.b, der.b
  end

  def test_ml_dsa_44_spki_parses_correctly
    der = fixture("ml_dsa_44_spki.der")
    parsed = PqcAsn1::DER.parse_spki(der)
    assert_equal PqcAsn1::OID::ML_DSA_44, parsed.oid
    assert_equal (1..32).map { |i| i }.pack("C*").b, parsed.key.b
    assert_nil parsed.parameters
  end

  def test_ml_dsa_44_spki_pem_roundtrip
    der = fixture("ml_dsa_44_spki.der")
    pem = fixture("ml_dsa_44_spki.pem")
    decoded_der = PqcAsn1::PEM.decode(pem, "PUBLIC KEY")
    assert_equal der.b, decoded_der.b
    parsed = PqcAsn1::DER.parse_spki(decoded_der)
    assert_equal PqcAsn1::OID::ML_DSA_44, parsed.oid
  end

  def test_ml_kem_768_spki_parses_correctly
    der = fixture("ml_kem_768_spki.der")
    parsed = PqcAsn1::DER.parse_spki(der)
    assert_equal PqcAsn1::OID::ML_KEM_768, parsed.oid
    assert_equal (0..31).map { |i| i * 4 }.pack("C*").b, parsed.key.b
  end

  def test_slh_dsa_sha2_128s_spki_parses_correctly
    der = fixture("slh_dsa_sha2_128s_spki.der")
    parsed = PqcAsn1::DER.parse_spki(der)
    assert_equal PqcAsn1::OID::SLH_DSA_SHA2_128S, parsed.oid
    assert_equal ([0xAB] * 32).pack("C*").b, parsed.key.b
  end

  def test_spki_pem_contains_correct_markers
    pem = fixture("ml_dsa_44_spki.pem")
    assert_includes pem, "-----BEGIN PUBLIC KEY-----"
    assert_includes pem, "-----END PUBLIC KEY-----"
  end

  def test_spki_der_matches_build_output
    pk = (1..32).map { |i| i }.pack("C*")
    built = PqcAsn1::DER.build_spki(PqcAsn1::OID::ML_DSA_44, pk, validate: false)
    assert_equal fixture("ml_dsa_44_spki.der").b, built.b
  end

  # --- PKCS#8 fixtures ---

  def test_ml_dsa_44_pkcs8_der_bytes
    der = fixture("ml_dsa_44_pkcs8.der")
    expected = [
      0x30, 0x52,
      0x02, 0x01, 0x00,
      0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
      0x04, 0x40
    ].pack("C*") + ([0xFF] * 64).pack("C*")
    assert_equal expected.b, der.b
  end

  def test_ml_dsa_44_pkcs8_parses_correctly
    der = fixture("ml_dsa_44_pkcs8.der")
    parsed = PqcAsn1::DER.parse_pkcs8(der)
    assert_equal PqcAsn1::OID::ML_DSA_44, parsed.oid
    parsed.key.use { |b| assert_equal ([0xFF] * 64).pack("C*").b, b }
    assert_nil parsed.parameters
  end

  def test_ml_dsa_44_pkcs8_pem_roundtrip
    der = fixture("ml_dsa_44_pkcs8.der")
    pem = fixture("ml_dsa_44_pkcs8.pem")
    decoded_der = PqcAsn1::PEM.decode(pem, "PRIVATE KEY")
    assert_equal der.b, decoded_der.b
    parsed = PqcAsn1::DER.parse_pkcs8(decoded_der)
    assert_equal PqcAsn1::OID::ML_DSA_44, parsed.oid
  end

  def test_ml_kem_512_pkcs8_parses_correctly
    der = fixture("ml_kem_512_pkcs8.der")
    parsed = PqcAsn1::DER.parse_pkcs8(der)
    assert_equal PqcAsn1::OID::ML_KEM_512, parsed.oid
    parsed.key.use { |b| assert_equal (0..63).map { |i| i }.pack("C*").b, b }
  end

  def test_pkcs8_pem_contains_correct_markers
    pem = fixture("ml_dsa_44_pkcs8.pem")
    assert_includes pem, "-----BEGIN PRIVATE KEY-----"
    assert_includes pem, "-----END PRIVATE KEY-----"
  end

  def test_pkcs8_der_matches_build_output
    sk = ([0xFF] * 64).pack("C*")
    built = PqcAsn1::DER.build_pkcs8(PqcAsn1::OID::ML_DSA_44, sk, validate: false)
    built.use { |b| assert_equal fixture("ml_dsa_44_pkcs8.der").b, b }
  end
end
