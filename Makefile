# Estonian ID Card Authentication - Development Makefile
# =====================================================
#
# This Makefile provides convenient development commands for the Estonian ID
# card authentication library. It handles dependency management, testing,
# building, and provides easy access to hardware testing with real cards.
#
# The library uses PKCS#11 interface to communicate with Estonian ID cards
# through OpenSC, providing secure authentication and personal data extraction.

# Declare all targets as phony to avoid conflicts with files of same names
.PHONY: help install test test_hardware run_local_card_test webeid_test build clean

# Default target - shows help when just running 'make'
help:
	@echo "Estonian ID Card Authentication"
	@echo "==============================="
	@echo ""
	@echo "Available targets:"
	@echo "  help                   Show this help message"
	@echo "  install               Install Ruby dependencies via Bundler"
	@echo "  test                  Run unit tests (hardware tests skipped)"
	@echo "  test_hardware         Run all tests including hardware integration"
	@echo "  run_local_card_test   Interactive test with real Estonian ID card"
	@echo "  webeid_test           Launch Web eID test app with HTTPS tunnel"
	@echo "  build                 Build the gem package for distribution"
	@echo "  clean                 Remove built gem files"
	@echo ""
	@echo "Prerequisites for hardware testing:"
	@echo "  - OpenSC installed (brew install opensc on macOS)"
	@echo "  - Estonian ID card inserted in reader" 
	@echo "  - PC/SC card reader connected and working"
	@echo "  - PIN1 available for authentication"

# Install Ruby dependencies using Bundler
# This ensures all required gems are available for development and testing
install:
	@echo "📦 Installing Ruby dependencies..."
	@echo "   This will install: pkcs11 gem and development dependencies"
	bundle install
	@echo "✅ Dependencies installed successfully"

# Run basic test suite without hardware requirements
# Skips tests that require actual Estonian ID card insertion
test:
	@echo "🧪 Running unit tests..."
	@echo "   Hardware tests are skipped unless HARDWARE_TESTS=1 is set"
	@echo "   This tests: API, models, personal code parsing, basic functionality"
	bundle exec ruby -Ilib:test test/ee_id_verification_test.rb
	@echo "✅ Unit tests completed"

# Run complete test suite including hardware integration tests
# Requires physical Estonian ID card and will prompt for PIN entry
test_hardware:
	@echo "🧪 Running complete test suite with hardware integration..."
	@echo "⚠️  This requires:"
	@echo "     - Estonian ID card inserted in reader"
	@echo "     - Working PC/SC card reader"
	@echo "     - Your PIN1 for authentication testing"
	@echo ""
	@echo "   The test will prompt you to enter your PIN1 when needed"
	HARDWARE_TESTS=1 bundle exec ruby -Ilib:test test/ee_id_verification_test.rb
	@echo "✅ Hardware integration tests completed"

# Interactive test with real Estonian ID card
# This is the simplest way to verify everything works with your card
run_local_card_test:
	@echo "🔍 Testing Estonian ID Card (Interactive)"
	@echo "========================================="
	@echo ""
	@echo "This will attempt to:"
	@echo "  1. Detect your Estonian ID card"
	@echo "  2. Connect via PKCS#11 interface"
	@echo "  3. Prompt for your PIN1"
	@echo "  4. Read and display your personal information"
	@echo ""
	@echo "⚠️  Requirements:"
	@echo "     - Estonian ID card must be inserted"
	@echo "     - Card reader must be connected"
	@echo "     - You'll need your PIN1 (4 digits)"
	@echo ""
	ruby script/test_id_card.rb

# Launch Web eID test application with HTTPS tunnel
# This provides a web interface to test Web eID authentication with Estonian ID cards
webeid_test:
	@echo "🌐 Launching Web eID Test Application"
	@echo "====================================="
	@echo ""
	@echo "This will start a web application for testing Web eID authentication:"
	@echo "  1. Starts local HTTP server on port 4567"
	@echo "  2. Creates secure HTTPS tunnel via Cloudflare"
	@echo "  3. Provides web interface for ID card authentication"
	@echo "  4. Tests real Web eID browser extension integration"
	@echo ""
	@echo "⚠️  Requirements:"
	@echo "     - Estonian ID card inserted in reader"
	@echo "     - Web eID browser extension installed"
	@echo "     - Web eID native application installed"
	@echo "     - Cloudflare tunnel (cloudflared) installed"
	@echo ""
	@echo "🚀 Starting Web eID test application..."
	@echo ""
	cd test/web_app && ./start.sh

# Build the gem package for distribution
# Creates .gem file that can be installed or published to RubyGems
build:
	@echo "🔨 Building gem package..."
	@echo "   This creates EE-ID-verification-x.x.x.gem file"
	gem build ee-id-verification.gemspec
	@echo "✅ Gem built successfully"
	@echo "   Install locally with: gem install *.gem"
	@echo "   Publish with: gem push *.gem"

# Clean up built artifacts
# Removes any .gem files created during build process
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -f *.gem
	@echo "✅ Cleanup completed"