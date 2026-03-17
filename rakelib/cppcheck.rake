# frozen_string_literal: true

# Project-owned C source files (excludes vendored pqc_asn1.c / pqc_asn1.h).
CPPCHECK_SOURCES = FileList["ext/pqc_asn1/*.c", "ext/pqc_asn1/*.h"]
  .exclude("ext/pqc_asn1/pqc_asn1.c")
  .exclude("ext/pqc_asn1/pqc_asn1.h")

namespace :lint do
  desc "Run cppcheck on project-owned C extension files"
  task :c do
    exe = ENV.fetch("CPPCHECK", "cppcheck")

    unless system(exe, "--version", out: File::NULL, err: File::NULL)
      abort "cppcheck not found. Install it (brew install cppcheck / apt install cppcheck) or set CPPCHECK env var."
    end

    args = [
      exe,
      "--enable=warning,style,performance,portability",
      "--error-exitcode=1",
      "--suppress=missingIncludeSystem",
      "--inline-suppr",
      "--quiet",
      "-I", "ext/pqc_asn1",
      *CPPCHECK_SOURCES
    ]

    puts "Running: #{args.join(" ")}"
    system(*args) || abort("cppcheck reported findings — see above.")
    puts "cppcheck: clean"
  end
end
