# frozen_string_literal: true

require_relative "lib/pqc_asn1/version"

Gem::Specification.new do |s|
  s.name = "pqc_asn1"
  s.version = PqcAsn1::VERSION
  s.authors = ["Suleyman Musayev"]
  s.email = ["slmusayev@gmail.com"]

  s.summary = "Algorithm-agnostic ASN.1/DER/PEM codec for post-quantum cryptography."
  s.description = "Minimal ASN.1/DER/PEM/Base64 codec implemented in C with no OpenSSL " \
    "dependency.  Designed for post-quantum key serialization (SPKI, PKCS#8) " \
    "but usable for any scheme that needs DER TLV encoding, Base64 with PEM " \
    "line wrapping, and PEM armor parsing.  Used by the ml_dsa gem and " \
    "reusable by ML-KEM, SLH-DSA, and other PQC implementations."
  s.homepage = "https://github.com/msuliq/pqc_asn1"
  s.license = "MIT OR Apache-2.0"
  s.metadata = {
    "rubygems_mfa_required" => "true",
    "homepage_uri" => s.homepage,
    "source_code_uri" => s.homepage,
    "changelog_uri" => "#{s.homepage}/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "#{s.homepage}/issues"
  }

  s.required_ruby_version = ">= 2.7.2"

  s.files = Dir[
    "lib/**/*.rb",
    "ext/**/*.{c,h,rb}",
    "data/**/*.yml",
    "CHANGELOG.md",
    "LICENSE",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "README.md"
  ]
  s.require_paths = ["lib"]
  s.extensions = ["ext/pqc_asn1/extconf.rb"]

  s.add_development_dependency "minitest", "~> 5.0"
  s.add_development_dependency "rake", "~> 13.0"
  s.add_development_dependency "rake-compiler", "~> 1.0"
end
