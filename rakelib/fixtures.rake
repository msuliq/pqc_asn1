# frozen_string_literal: true

# Auto-generate fixtures on first run (or when the directory is empty).
task test: :ensure_fixtures

task :ensure_fixtures do
  dir = "test/fixtures"
  unless File.directory?(dir) && !Dir["#{dir}/*"].empty?
    puts "test/fixtures/ is missing or empty — generating..."
    Rake::Task[:"fixtures:generate"].invoke
  end
end

namespace :fixtures do
  desc "Generate pre-computed DER/PEM test fixture files in test/fixtures/"
  task generate: :compile do
    require "pqc_asn1"
    require "fileutils"

    dir = File.expand_path("test/fixtures", __dir__ + "/..")
    FileUtils.mkdir_p(dir)

    fixtures = {}

    # SPKI fixtures
    fixtures["ml_dsa_44_spki.der"] = PqcAsn1::DER.build_spki(
      PqcAsn1::OID::ML_DSA_44,
      (1..32).map { |i| i }.pack("C*")
    )
    fixtures["ml_kem_768_spki.der"] = PqcAsn1::DER.build_spki(
      PqcAsn1::OID::ML_KEM_768,
      (0..31).map { |i| i * 4 }.pack("C*")
    )
    fixtures["slh_dsa_sha2_128s_spki.der"] = PqcAsn1::DER.build_spki(
      PqcAsn1::OID::SLH_DSA_SHA2_128S,
      ([0xAB] * 32).pack("C*")
    )

    # PKCS#8 fixtures
    fixtures["ml_dsa_44_pkcs8.der"] = PqcAsn1::DER.build_pkcs8(
      PqcAsn1::OID::ML_DSA_44,
      ([0xFF] * 64).pack("C*")
    )
    fixtures["ml_kem_512_pkcs8.der"] = PqcAsn1::DER.build_pkcs8(
      PqcAsn1::OID::ML_KEM_512,
      (0..63).map { |i| i }.pack("C*")
    )

    # PEM encodings for all DER fixtures.
    # PEM.encode accepts both String and SecureBuffer directly.
    fixtures.keys.grep(/\.der$/).each do |name|
      der = fixtures[name]
      label = name.include?("pkcs8") ? "PRIVATE KEY" : "PUBLIC KEY"
      fixtures[name.sub(".der", ".pem")] = PqcAsn1::PEM.encode(der, label)
    end

    fixtures.each do |name, data|
      path = File.join(dir, name)
      bytes = data.is_a?(PqcAsn1::SecureBuffer) ? data.use { |b| b.b } : data.b
      File.binwrite(path, bytes)
    end

    puts "  Generated #{fixtures.size} fixture files in #{dir}"
  end
end
