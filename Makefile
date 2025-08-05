# EE-ID-verification Makefile
# Estonian Identity Verification Gem

.PHONY: help install test test_hardware run_local_card_test build clean lint validate

# Default target
help:
	@echo "EE-ID-verification - Estonian Identity Verification Gem"
	@echo "====================================================="
	@echo ""
	@echo "Available targets:"
	@echo "  help                   Show this help message"
	@echo "  install               Install gem dependencies"
	@echo "  test                  Run all tests (hardware tests skipped without HARDWARE_TESTS=1)"
	@echo "  test_hardware         Run all tests including hardware integration (requires card)"
	@echo "  run_local_card_test   Test Estonian ID card reading (requires card inserted)"
	@echo "  build                 Build the gem"
	@echo "  clean                 Clean build artifacts"
	@echo "  lint                  Run code linting"
	@echo "  validate              Validate gemspec and dependencies"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - OpenSC installed (brew install opensc on macOS)"
	@echo "  - Estonian ID card inserted in reader"
	@echo "  - Card reader connected"

# Install dependencies
install:
	@echo "📦 Installing gem dependencies..."
	bundle install
	@echo "✅ Dependencies installed successfully"

# Run the Estonian ID card test
run_local_card_test:
	@echo "🔍 Testing Estonian ID Card"
	@echo "=========================="
	@echo ""
	@echo "Prerequisites check:"
	@echo "- Estonian ID card should be inserted"
	@echo "- Card reader should be connected"
	@echo "- You'll need your PIN1 (4 digits) when prompted"
	@echo ""
	ruby script/test_id_card.rb

# Run all tests
test:
	@echo "🧪 Running comprehensive test suite..."
	@echo "📋 Test suite includes:"
	@echo "  - Models and data structures (test/models_test.rb)"
	@echo "  - Certificate reader with PKCS#11 integration (test/certificate_reader_test.rb)"
	@echo "  - DigiDoc Local authenticator with real hardware (test/digidoc_local_authenticator_test.rb)"
	@echo "  - End-to-end integration tests (test/verifier_integration_test.rb)"
	@echo ""
	@echo "⚠️  Hardware tests require Estonian ID card and ENV['HARDWARE_TESTS']=1"
	@echo ""
	bundle exec ruby -I lib:test test/models_test.rb
	bundle exec ruby -I lib:test test/certificate_reader_test.rb
	bundle exec ruby -I lib:test test/digidoc_local_authenticator_test.rb
	bundle exec ruby -I lib:test test/verifier_integration_test.rb
	@echo "✅ All tests completed"

# Run all tests including hardware integration
test_hardware:
	@echo "🧪 Running comprehensive test suite with hardware integration..."
	@echo "📋 Hardware tests will run - Estonian ID card required!"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - Estonian ID card inserted in reader"
	@echo "  - Card reader connected and working"
	@echo "  - OpenSC installed (brew install opensc)"
	@echo "  - You'll need your PIN1 for authentication tests"
	@echo ""
	@read -p "Press Enter to continue or Ctrl+C to cancel..."
	HARDWARE_TESTS=1 bundle exec ruby -I lib:test test/models_test.rb
	HARDWARE_TESTS=1 bundle exec ruby -I lib:test test/certificate_reader_test.rb
	HARDWARE_TESTS=1 bundle exec ruby -I lib:test test/digidoc_local_authenticator_test.rb
	HARDWARE_TESTS=1 bundle exec ruby -I lib:test test/verifier_integration_test.rb
	@echo "✅ All tests including hardware integration completed"

# Build the gem
build:
	@echo "🔨 Building gem..."
	gem build ee-id-verification.gemspec
	@echo "✅ Gem built successfully"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -f *.gem
	@echo "✅ Cleaned successfully"

# Lint code (syntax and warnings check)
lint:
	@echo "🔍 Linting code..."
	ruby -w -c lib/ee_id_verification.rb
	ruby -w -c lib/ee_id_verification/certificate_reader.rb
	ruby -w -c lib/ee_id_verification/digidoc_local_authenticator.rb
	ruby -w -c lib/ee_id_verification/models.rb
	ruby -w -c lib/ee_id_verification/base_authenticator.rb
	@echo "✅ Code syntax is valid with no warnings"

# Validate gemspec and dependencies
validate:
	@echo "🔍 Validating gemspec and dependencies..."
	ruby -e "spec = Gem::Specification.load('ee-id-verification.gemspec'); puts '✅ Gemspec is valid'"
	bundle install --quiet
	@echo "✅ Dependencies resolve correctly"

# Development setup
setup: install
	@echo "🚀 Development environment ready!"
	@echo ""
	@echo "To test your Estonian ID card:"
	@echo "  make run_local_card_test"
	@echo ""
	@echo "To build the gem:"
	@echo "  make build"