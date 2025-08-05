# frozen_string_literal: true

require_relative "ee_id_verification/version"
require_relative "ee_id_verification/verifier"
require_relative "ee_id_verification/models"

# Estonian e-identity verification library.
#
# This gem provides a unified Ruby interface for authenticating users and verifying
# digital signatures using Estonian e-identity infrastructure. It supports all major
# Estonian authentication methods including ID cards, Mobile-ID, and Smart-ID.
#
# The library is designed with security, ease of use, and Estonian e-governance
# compliance in mind. It handles the complexities of different authentication
# protocols while providing a consistent API for developers.
#
# ## Supported Authentication Methods
#
# - **DigiDoc Local**: Direct ID card authentication via smart card readers
# - **DigiDoc Browser**: Web-based ID card authentication via browser extensions
# - **Mobile-ID**: Phone-based authentication with SIM card certificates
# - **Smart-ID**: App-based authentication for Baltic countries
#
# ## Key Features
#
# - Unified API across all authentication methods
# - Comprehensive digital signature verification
# - OCSP certificate revocation checking
# - Multi-language support (Estonian, English, Russian, Latvian, Lithuanian)
# - Thread-safe operation
# - Extensive error handling and logging
# - Production-ready security controls
#
# ## Basic Usage
#
#     require 'ee_id_verification'
#     
#     # Create verifier with Mobile-ID configuration
#     verifier = EeIdVerification.new(
#       mobile_id: {
#         service_url: "https://tsp.demo.sk.ee/mid-api",
#         service_uuid: "00000000-0000-0000-0000-000000000000",
#         service_name: "Demo Application"
#       }
#     )
#     
#     # Check available methods
#     puts verifier.available_methods # => [:mobile_id]
#     
#     # Authenticate user
#     session = verifier.mobile_id_auth(
#       phone_number: "+37200000766",
#       personal_code: "60001019906"
#     )
#     
#     puts "Verification code: #{session.verification_code}"
#     
#     # Poll for completion
#     loop do
#       result = verifier.poll_status(session)
#       case result.status
#       when :completed
#         puts "Welcome #{result.full_name}!"
#         break
#       when :failed
#         puts "Authentication failed: #{result.error}"
#         break
#       when :pending
#         sleep 2 # Continue polling
#       end
#     end
#
# ## Global Configuration
#
#     EeIdVerification.configure do |config|
#       config.mobile_id_config = {
#         service_url: "https://tsp.demo.sk.ee/mid-api",
#         service_uuid: "demo-uuid"
#       }
#       config.default_timeout = 300
#       config.default_language = "en"
#     end
#
# @see Verifier Main facade class for authentication operations
# @see https://www.id.ee/en/article/for-developers/
# @see https://github.com/SK-EID/MID
# @see https://github.com/SK-EID/smart-id-documentation
module EeIdVerification
  # Generic error class for the gem.
  class Error < StandardError; end

  # Module-level methods for convenient access
  class << self
    # Create a new verifier instance with configuration.
    #
    # This is the main entry point for using the library. Creates a Verifier
    # instance with the provided configuration, handling all authentication
    # method setup and validation.
    #
    # @param config [Hash] Configuration options for authentication methods
    # @option config [Hash] :digidoc_local Local ID card reader configuration
    # @option config [Hash] :digidoc_browser Browser extension configuration
    # @option config [Hash] :mobile_id Mobile-ID service configuration
    # @option config [Hash] :smart_id Smart-ID service configuration
    # @option config [Integer] :timeout (300) Default session timeout in seconds
    # @option config [String] :language ("en") Default language code
    # @option config [Logger] :logger Logger instance for debugging
    #
    # @return [Verifier] Configured verifier instance ready for authentication
    #
    # @example Basic usage
    #   verifier = EeIdVerification.new(
    #     mobile_id: {
    #       service_url: "https://tsp.demo.sk.ee/mid-api",
    #       service_uuid: "00000000-0000-0000-0000-000000000000"
    #     },
    #     timeout: 180
    #   )
    #
    # @example Multiple methods
    #   verifier = EeIdVerification.new(
    #     mobile_id: { service_url: "...", service_uuid: "..." },
    #     smart_id: { service_url: "...", relying_party_uuid: "..." },
    #     digidoc_local: { require_ocsp: true },
    #     language: "et"
    #   )
    def new(config = {})
      Verifier.new(config)
    end

    # Configure global default settings.
    #
    # Sets up global configuration that will be used as defaults for all
    # new verifier instances. This is useful for application-wide settings
    # that don't change between different verifier instances.
    #
    # Global configuration is particularly useful in Rails applications
    # where you can set it up once in an initializer.
    #
    # @yield [Configuration] Configuration object for modification
    # @return [Configuration] The global configuration object
    #
    # @example Rails initializer
    #   # config/initializers/ee_id_verification.rb
    #   EeIdVerification.configure do |config|
    #     config.mobile_id_config = {
    #       service_url: Rails.application.credentials.mobile_id_url,
    #       service_uuid: Rails.application.credentials.mobile_id_uuid,
    #       service_name: "My Rails App"
    #     }
    #     config.default_timeout = 300
    #     config.default_language = "en"
    #     config.logger = Rails.logger
    #   end
    #
    # @example Development vs Production
    #   EeIdVerification.configure do |config|
    #     if Rails.env.production?
    #       config.mobile_id_config[:service_url] = "https://tsp.sk.ee/mid-api"
    #     else
    #       config.mobile_id_config[:service_url] = "https://tsp.demo.sk.ee/mid-api"
    #     end
    #   end
    def configure
      @configuration ||= Configuration.new
      yield(@configuration) if block_given?
      @configuration
    end

    # Get the current global configuration.
    #
    # Returns the global configuration object that holds default settings
    # for all authentication methods. If no configuration has been set up,
    # returns a new Configuration object with default values.
    #
    # This is useful for inspecting current settings or for building
    # custom verifier instances that extend the global configuration.
    #
    # @return [Configuration] Global configuration object
    #
    # @example Inspecting configuration
    #   config = EeIdVerification.configuration
    #   puts "Default timeout: #{config.default_timeout}"
    #   puts "Mobile-ID configured: #{!config.mobile_id_config.empty?}"
    #
    # @example Building on global config
    #   global_config = EeIdVerification.configuration
    #   custom_verifier = EeIdVerification.new(
    #     global_config.mobile_id_config.merge(timeout: 600)
    #   )
    def configuration
      @configuration ||= Configuration.new
    end
  end
end