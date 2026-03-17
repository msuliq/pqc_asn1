# frozen_string_literal: true

require "rake/extensiontask"
require "rake/testtask"

begin
  require "standard/rake"
rescue LoadError
  # standard gem not available — lint task won't be defined
end

Rake::ExtensionTask.new("pqc_asn1_ext") do |ext|
  ext.lib_dir = "lib/pqc_asn1"
  ext.ext_dir = "ext/pqc_asn1"
end

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb"]
end

task test: :compile

namespace :test do
  Rake::TestTask.new(:fuzz) do |t|
    t.libs << "test" << "lib"
    t.test_files = FileList["test/pqc_asn1/fuzz_test.rb"]
    t.description = "Run fuzz / robustness tests only"
  end
  task fuzz: :compile

  Rake::TestTask.new(:property) do |t|
    t.libs << "test" << "lib"
    t.test_files = FileList["test/pqc_asn1/property_test.rb"]
    t.description = "Run property-based round-trip tests only"
  end
  task property: :compile
end

# Wire standard (when available) into the default task so lint always runs.
if Rake::Task.task_defined?(:standard)
  task default: [:standard, :test]
else
  task default: :test
end

# Vendor and fixture tasks live in rakelib/vendor.rake and rakelib/fixtures.rake.
