# frozen_string_literal: true

require_relative "lib/ee_id_verification/version"

Gem::Specification.new do |spec|
  spec.name = "EE-ID-verification"
  spec.version = EeIdVerification::VERSION
  spec.authors = ["Angelos Kapsimanis"]
  spec.email = ["angelos@sorbet.ee"]

  spec.summary = "Estonian identity verification for Ruby applications"
  spec.description = "A comprehensive Ruby gem for Estonian digital identity verification supporting DigiDoc, Mobile-ID, and Smart-ID authentication methods. Provides a unified interface for secure authentication and digital signature verification using Estonia's e-identity infrastructure."
  spec.homepage = "https://github.com/sorbet-ee/EE-ID-verification"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sorbet-ee/EE-ID-verification"
  spec.metadata["changelog_uri"] = "https://github.com/sorbet-ee/EE-ID-verification/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Dependencies for ID card reading and certificate handling
  spec.add_dependency "pkcs11", "~> 0.3"     # PKCS#11 interface for Estonian ID cards
  spec.add_dependency "openssl", "~> 3.0"    # Certificate handling
  spec.add_dependency "net-http", "~> 0.3"   # HTTP client for OCSP
  spec.add_dependency "rexml", "~> 3.2"      # XML parsing for certificates

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
