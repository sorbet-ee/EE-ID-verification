# frozen_string_literal: true

require_relative "lib/ee_id_verification/version"

Gem::Specification.new do |spec|
  spec.name = "EE-ID-verification"
  spec.version = EeIdVerification::VERSION
  spec.authors = ["Angelos Kapsimanis"]
  spec.email = ["angelos@sorbet.ee"]

  spec.summary = "Estonian ID card authentication for Ruby"
  spec.description = "Simple Ruby library for authenticating users with Estonian ID cards using local card readers."
  spec.homepage = "https://github.com/sorbet-ee/EE-ID-verification"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sorbet-ee/EE-ID-verification"
  spec.metadata["changelog_uri"] = "https://github.com/sorbet-ee/EE-ID-verification/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.end_with?(".gem") ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile vendor/])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Essential dependencies only
  spec.add_dependency "pkcs11", "~> 0.3" # PKCS#11 interface for Estonian ID cards

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
