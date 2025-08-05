# EE::ID::Verification

A Ruby gem for Estonian identity verification supporting DigiDoc, Mobile-ID, and Smart-ID authentication methods.

This gem provides a unified interface for verifying Estonian digital identities through the country's official e-identity infrastructure, enabling secure authentication and digital signature verification in Ruby applications.

## Features

- **DigiDoc** support for ID-card based authentication
- **Mobile-ID** verification for mobile phone-based authentication
- **Smart-ID** integration for app-based authentication
- Unified API for all authentication methods
- Certificate validation and parsing
- Personal data extraction (name, personal code, etc.)
- Session management for authentication flows

## Prerequisites

For Estonian ID card support, you need OpenSC installed:

**macOS:**
```bash
brew install opensc
```

**Ubuntu/Debian:**
```bash
sudo apt install opensc-pkcs11
```

## Installation

Install the gem and add to the application's Gemfile by executing:

```bash
bundle add EE-ID-verification
```

If bundler is not being used to manage dependencies, install the gem by executing:

```bash
gem install EE-ID-verification
```

## Quick Start

After installation, you can quickly test your Estonian ID card:

```bash
# Install dependencies
make install

# Test your Estonian ID card (requires card inserted)
make run_local_card_test
```

## Usage

### Basic Authentication Example

```ruby
require 'ee_id_verification'

# Initialize the verifier
verifier = EeIdVerification.new

# Mobile-ID authentication
mobile_auth = verifier.mobile_id_auth(
  phone_number: '+3725xxxxxxx',
  personal_code: '38001010101'
)

# Wait for user to confirm on mobile device
result = mobile_auth.poll_status

if result.authenticated?
  puts "User authenticated: #{result.name}"
  puts "Personal code: #{result.personal_code}"
end

# Smart-ID authentication
smart_auth = verifier.smart_id_auth(
  personal_code: '38001010101'
)

# DigiDoc (ID-card) authentication - requires card reader and Estonian ID card
if verifier.method_available?(:digidoc_local)
  session = verifier.digidoc_local_auth
  # User will be prompted for PIN1 via provide_pin method
  verifier.provide_pin(session.id, "1234")  # User's PIN1
  result = verifier.poll_status(session)
  
  if result.authenticated?
    puts "ID card authentication successful!"
    puts "Name: #{result.full_name}"
    puts "Personal code: #{result.personal_code}"
  end
end
```

### Configuration

```ruby
EeIdVerification.configure do |config|
  config.mobile_id_url = 'https://your-mobile-id-service.ee'
  config.smart_id_url = 'https://your-smart-id-service.ee'
  config.digidoc_service_url = 'https://your-digidoc-service.ee'
  
  # Optional: Set timeouts
  config.timeout = 30 # seconds
  config.poll_interval = 5 # seconds
end
```

### Digital Signature Verification

```ruby
# Verify a digitally signed document
signature_valid = verifier.verify_signature(
  document: document_data,
  signature: signature_data,
  certificate: signer_certificate
)
```

## ID Card Scripts

The `script/` directory contains utility scripts for testing ID card functionality:

### Prerequisites for ID Card Usage

1. **Card Reader**: Smart card reader connected to your computer
2. **Drivers**: Card reader drivers installed
3. **PC/SC Service**: Running on your system
   - macOS: Usually running by default
   - Linux: `sudo systemctl start pcscd`
   - Windows: Smart Card service

### Testing Your Estonian ID Card

```bash
make run_local_card_test
```
This command will test your Estonian ID card and display all available information.

### Security Notes
- **PIN codes are sensitive** - never share or store them
- You have **3 attempts** per PIN before it's blocked
- Certificates contain personal information

## Development

This gem uses a Makefile for common development tasks:

```bash
# Show all available commands
make help

# Install dependencies
make install

# Test Estonian ID card (requires card inserted)
make run_local_card_test

# Run basic tests
make test

# Build the gem
make build

# Clean build artifacts
make clean

# Check code syntax
make lint
```

### Development Setup

1. Clone the repository
2. Run `make setup` to install dependencies
3. Insert your Estonian ID card
4. Run `make run_local_card_test` to verify everything works

The test will display your card's information including:
- Personal name and code
- Certificate validity dates
- Birth date, gender, and age (parsed from personal code)

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/sorbet-ee/EE-ID-verification. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/sorbet-ee/EE-ID-verification/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the EE::ID::Verification project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/sorbet-ee/EE-ID-verification/blob/main/CODE_OF_CONDUCT.md).