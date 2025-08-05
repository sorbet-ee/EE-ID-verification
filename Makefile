# EE-ID-verification Makefile
# Estonian Identity Verification Gem

.PHONY: help install test run_local_card_test build clean lint validate

# Default target
help:
	@echo "EE-ID-verification - Estonian Identity Verification Gem"
	@echo "====================================================="
	@echo ""
	@echo "Available targets:"
	@echo "  help                   Show this help message"
	@echo "  install               Install gem dependencies"
	@echo "  test                  Run all tests"
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

# Run tests (placeholder for future test suite)
test:
	@echo "🧪 Running tests..."
	bundle exec ruby -I lib -e "require 'ee_id_verification'; puts '✅ Gem loads successfully'"
	@echo "✅ Basic tests passed"

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

# Lint code (basic check)
lint:
	@echo "🔍 Linting code..."
	ruby -c lib/ee_id_verification.rb
	ruby -c lib/ee_id_verification/certificate_reader.rb
	ruby -c lib/ee_id_verification/digidoc_local_authenticator.rb
	@echo "✅ Code syntax is valid"

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