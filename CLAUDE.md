# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Development Commands

### Setup
```bash
bin/setup  # Install dependencies
```

### Testing
```bash
rake test              # Run all tests
rake test TEST=test/ee_id_verification/test_verification.rb  # Run specific test file
```

### Linting and Code Quality
```bash
rake rubocop           # Run RuboCop linter
rake rubocop:autocorrect  # Auto-fix linting issues
```

### Default Task (Tests + Linting)
```bash
rake  # Runs both tests and RuboCop
```

### Development Console
```bash
bin/console  # Interactive Ruby console with gem loaded
```

### Building the Gem
```bash
gem build EE-ID-verification.gemspec  # Build the gem package
```

## Project Scope

This Ruby gem provides Estonian identity verification functionality supporting three authentication methods:
- **DigiDoc**: ID-card based authentication using digital certificates
- **Mobile-ID**: Mobile phone-based authentication using SIM cards
- **Smart-ID**: App-based authentication for smartphones

The gem interfaces with Estonia's official e-identity infrastructure to enable secure authentication and digital signature verification in Ruby applications.

## Code Architecture

This is a Ruby gem for Estonian ID verification following standard Ruby gem conventions.

### Module Structure
The main module is `EeIdVerification` with:
- Entry point: `lib/ee_id_verification.rb`
- Version constant: `lib/ee_id_verification/version.rb`
- Authenticators: `lib/ee_id_verification/*_authenticator.rb`

### Key Development Considerations
- Ruby version requirement: >= 3.1.0
- Testing framework: Minitest
- Code style: RuboCop with double quotes for strings
- Type signatures: RBS files in `sig/` directory

### File Naming Convention
Files follow the standard Ruby gem conventions:
- `lib/ee_id_verification/feature_name.rb` for new features
- `test/ee_id_verification/test_feature_name.rb` for corresponding tests