# frozen_string_literal: true

require_relative "models"
require_relative "digidoc_local_authenticator"
require_relative "digidoc_browser_authenticator"
require_relative "mobile_id_authenticator"
require_relative "smart_id_authenticator"

module EeIdVerification
  # Main facade class for Estonian e-identity verification.
  #
  # The Verifier class provides a unified interface for all Estonian e-identity
  # authentication methods. It acts as a factory and coordinator for different
  # authenticator implementations, handling configuration management and method
  # selection automatically.
  #
  # Supported authentication methods:
  # - DigiDoc Local: Direct ID card communication via card readers
  # - DigiDoc Browser: Web-based ID card authentication via browser extensions
  # - Mobile-ID: Phone-based authentication with SIM certificates
  # - Smart-ID: App-based authentication for Baltic countries
  #
  # Features:
  # - Automatic method availability detection
  # - Unified configuration management
  # - Session lifecycle management across all methods
  # - Digital signature verification
  # - Thread-safe operation with immutable configuration
  #
  # Architecture:
  # - Facade pattern: Simple interface hiding complexity
  # - Strategy pattern: Different authenticators for different methods
  # - Factory pattern: Automatic authenticator instantiation
  # - Configuration pattern: Centralized settings management
  #
  # @example Basic usage
  #   verifier = Verifier.new(
  #     mobile_id: {
  #       service_url: "https://tsp.demo.sk.ee/mid-api",
  #       service_uuid: "demo-uuid"
  #     },
  #     timeout: 300
  #   )
  #   
  #   # Check available methods
  #   puts verifier.available_methods # => [:mobile_id, :smart_id]
  #   
  #   # Authenticate user
  #   session = verifier.mobile_id_auth(
  #     phone_number: "+37200000766",
  #     personal_code: "60001019906"
  #   )
  #   
  #   # Poll for result
  #   result = verifier.poll_status(session)
  #   puts "Welcome #{result.full_name}!" if result.success?
  #
  # @see BaseAuthenticator
  # @see https://www.id.ee/en/article/for-developers/
  class Verifier
    # Configuration object containing all authenticator settings
    # @return [Configuration] Immutable configuration
    attr_reader :config
    
    # Hash of initialized authenticator instances keyed by method symbol
    # @return [Hash<Symbol, BaseAuthenticator>] Available authenticators
    attr_reader :authenticators

    # Initialize a new verifier with optional configuration.
    #
    # Creates and configures authenticator instances for all supported methods.
    # Configuration is validated during initialization to catch errors early.
    #
    # @param config [Hash] Configuration options for authenticators and global settings
    # @option config [Hash] :digidoc_local Configuration for local ID card authentication
    # @option config [Hash] :digidoc_browser Configuration for browser-based authentication
    # @option config [Hash] :mobile_id Configuration for Mobile-ID service
    # @option config [Hash] :smart_id Configuration for Smart-ID service
    # @option config [Integer] :timeout (300) Default session timeout in seconds
    # @option config [String] :language ("en") Default language for user messages
    # @option config [Logger] :logger Logger instance for debugging
    # @option config [Object] :cache_store Cache store for certificates and OCSP responses
    #
    # @example With Mobile-ID configuration
    #   verifier = Verifier.new(
    #     mobile_id: {
    #       service_url: "https://tsp.demo.sk.ee/mid-api",
    #       service_uuid: "00000000-0000-0000-0000-000000000000",
    #       service_name: "My Application"
    #     },
    #     timeout: 180,
    #     language: "et"
    #   )
    def initialize(config = {})
      @config = Configuration.new
      configure_with(config)
      initialize_authenticators
    end

    # Configure the verifier with a block.
    #
    # Allows post-initialization configuration changes. After configuration
    # changes, authenticator instances are recreated to pick up new settings.
    #
    # @yield [Configuration] Configuration object for modification
    # @return [void]
    #
    # @example
    #   verifier.configure do |config|
    #     config.mobile_id_config[:service_name] = "Updated Service"
    #     config.default_timeout = 600
    #   end
    def configure
      yield(@config) if block_given?
      initialize_authenticators # Recreate authenticators with new config
    end

    # Initiate DigiDoc local authentication (ID card reader).
    #
    # Starts authentication using a locally connected ID card reader.
    # Requires physical ID card insertion and PIN1 entry for completion.
    #
    # @param params [Hash] Authentication parameters (none required)
    # @return [AuthenticationSession] Session for polling and PIN provision
    # @raise [ServiceUnavailableError] If card readers are not available
    # @raise [AuthenticationError] If card cannot be read or is not present
    #
    # @example
    #   session = verifier.digidoc_local_auth
    #   # User will be prompted for PIN1 later via provide_pin method
    def digidoc_local_auth(params = {})
      authenticator = authenticators[:digidoc_local]
      ensure_available!(authenticator, "DigiDoc local service")
      authenticator.initiate_authentication(params)
    end

    # Initiate DigiDoc browser authentication (web extension).
    #
    # Starts authentication using browser extensions that communicate with
    # locally installed DigiDoc software. Requires proper CORS configuration.
    #
    # @param params [Hash] Authentication parameters
    # @option params [String] :origin Required web page origin for CORS validation
    # @return [AuthenticationSession] Session for browser extension processing
    # @raise [ServiceUnavailableError] If browser authentication is not configured
    # @raise [ArgumentError] If origin is missing or not allowed
    #
    # @example
    #   session = verifier.digidoc_browser_auth(
    #     origin: "https://secure-app.example.com"
    #   )
    #   # Browser extension handles user interaction
    def digidoc_browser_auth(params = {})
      authenticator = authenticators[:digidoc_browser]
      ensure_available!(authenticator, "DigiDoc browser service")
      authenticator.initiate_authentication(params)
    end

    # Initiate Mobile-ID authentication.
    #
    # Starts authentication using the Estonian Mobile-ID service.
    # User receives verification code on phone and must enter Mobile-ID PIN.
    #
    # @param params [Hash] Authentication parameters
    # @option params [String] :phone_number User's mobile phone number with country code
    # @option params [String] :personal_code Estonian personal identification code
    # @option params [String] :language ("en") Language for mobile screen messages
    # @return [AuthenticationSession] Session with verification code for user
    # @raise [ServiceUnavailableError] If Mobile-ID service is not configured
    # @raise [ArgumentError] If phone number or personal code is invalid
    #
    # @example
    #   session = verifier.mobile_id_auth(
    #     phone_number: "+37200000766",
    #     personal_code: "60001019906",
    #     language: "et"
    #   )
    #   puts "Show verification code: #{session.verification_code}"
    def mobile_id_auth(params = {})
      authenticator = authenticators[:mobile_id]
      ensure_available!(authenticator, "Mobile-ID")
      authenticator.initiate_authentication(params)
    end

    # Initiate Smart-ID authentication.
    #
    # Starts authentication using the Smart-ID service for Baltic countries.
    # User receives push notification in Smart-ID mobile app.
    #
    # @param params [Hash] Authentication parameters
    # @option params [String] :personal_code Personal identification code
    # @option params [String] :document_number Document number (alternative to personal_code)
    # @option params [String] :country ("EE") Country code ("EE", "LV", "LT")
    # @option params [Symbol] :interaction_type (:verification_code_choice) How user confirms
    # @option params [String] :language Language for mobile app messages
    # @return [AuthenticationSession] Session with verification code for user
    # @raise [ServiceUnavailableError] If Smart-ID service is not configured
    # @raise [ArgumentError] If personal code/document number is invalid
    #
    # @example Using personal code
    #   session = verifier.smart_id_auth(
    #     personal_code: "30303039914",
    #     country: "EE"
    #   )
    #   puts "Show verification code: #{session.verification_code}"
    #
    # @example Using document number
    #   session = verifier.smart_id_auth(
    #     document_number: "PNOEE-30303039914-MOCK-Q"
    #   )
    def smart_id_auth(params = {})
      authenticator = authenticators[:smart_id]
      ensure_available!(authenticator, "Smart-ID")
      authenticator.initiate_authentication(params)
    end

    # Poll authentication status for any active session.
    #
    # Checks the current status of an authentication session regardless of
    # the method used. Automatically routes to the appropriate authenticator
    # based on the session's method type.
    #
    # @param session [AuthenticationSession] Active authentication session
    # @return [AuthenticationResult] Current authentication status and user data
    # @raise [ArgumentError] If session is invalid or from unknown method
    #
    # @example Polling loop
    #   loop do
    #     result = verifier.poll_status(session)
    #     case result.status
    #     when :completed
    #       puts "Welcome #{result.full_name}!"
    #       break
    #     when :failed
    #       puts "Authentication failed: #{result.error}"
    #       break
    #     when :pending
    #       puts "Still waiting for user..."
    #       sleep 2
    #     end
    #   end
    def poll_status(session)
      authenticator = authenticator_for_session(session)
      authenticator.poll_status(session)
    end

    # Cancel authentication for any active session.
    #
    # Cancels an active authentication session regardless of method.
    # Cleans up resources and may notify external services depending
    # on the authentication method.
    #
    # @param session [AuthenticationSession] Session to cancel
    # @return [Boolean] true if cancellation was successful
    # @raise [ArgumentError] If session is invalid or from unknown method
    #
    # @example
    #   # User clicked cancel button
    #   if verifier.cancel_authentication(session)
    #     puts "Authentication cancelled"
    #   end
    def cancel_authentication(session)
      authenticator = authenticator_for_session(session)
      authenticator.cancel_authentication(session)
    end

    # Verify a digital signature using the appropriate method.
    #
    # Verifies digital signatures created with Estonian e-identity certificates.
    # Routes verification to the appropriate authenticator based on the method
    # that was used to create the signature.
    #
    # @param method [Symbol] Authentication method used for signing
    #   (:digidoc_local, :digidoc_browser, :mobile_id, :smart_id)
    # @param document [String] Original document content that was signed
    # @param signature [String] Digital signature to verify
    # @param certificate [String, OpenSSL::X509::Certificate] Signer's certificate
    # @return [SignatureVerificationResult] Comprehensive verification result
    # @raise [ArgumentError] If method is unknown or parameters are invalid
    #
    # @example
    #   result = verifier.verify_signature(
    #     method: :mobile_id,
    #     document: "Contract content to verify",
    #     signature: signature_bytes,
    #     certificate: signer_certificate
    #   )
    #   
    #   if result.valid?
    #     puts "Valid signature by #{result.signer_info[:common_name]}"
    #     puts "Signature level: #{result.signature_level}"
    #   else
    #     puts "Invalid signature: #{result.errors.join(', ')}"
    #   end
    def verify_signature(method:, document:, signature:, certificate:)
      authenticator = authenticators[method]
      unless authenticator
        raise ArgumentError, "Unknown authentication method: #{method}. Available: #{authenticators.keys.join(', ')}"
      end
      
      authenticator.verify_signature(
        document: document,
        signature: signature,
        certificate: certificate
      )
    end

    # Get list of currently available authentication methods.
    #
    # Returns array of method symbols for authentication methods that are
    # properly configured and available for use. Useful for showing users
    # which authentication options they can choose from.
    #
    # @return [Array<Symbol>] Available authentication method symbols
    #
    # @example
    #   methods = verifier.available_methods
    #   # => [:digidoc_local, :mobile_id, :smart_id]
    #   
    #   methods.each do |method|
    #     puts "#{method} is available"
    #   end
    def available_methods
      authenticators.select { |_, auth| auth.available? }.keys
    end

    # Check if a specific authentication method is available.
    #
    # Tests whether a particular authentication method is configured
    # and available for use.
    #
    # @param method [Symbol] Method to check (:digidoc_local, :mobile_id, etc.)
    # @return [Boolean] true if method is available, false otherwise
    #
    # @example
    #   if verifier.method_available?(:mobile_id)
    #     # Show Mobile-ID option in UI
    #   else
    #     # Hide Mobile-ID option
    #   end
    def method_available?(method)
      authenticator = authenticators[method]
      authenticator&.available? || false
    end

    private

    # Apply configuration options to the configuration object.
    #
    # Maps configuration hash keys to appropriate configuration object attributes.
    # This method handles the translation between the simple hash interface and
    # the structured configuration object.
    #
    # @param options [Hash] Configuration options
    # @private
    def configure_with(options)
      options.each do |key, value|
        case key
        when :digidoc_local
          @config.digidoc_local_config = value
        when :digidoc_browser
          @config.digidoc_browser_config = value
        when :mobile_id
          @config.mobile_id_config = value
        when :smart_id
          @config.smart_id_config = value
        when :timeout
          @config.default_timeout = value
        when :language
          @config.default_language = value
        when :logger
          @config.logger = value
        when :cache_store
          @config.cache_store = value
        else
          # Log warning for unknown configuration keys
          @config.logger&.warn("Unknown configuration key: #{key}")
        end
      end
    end

    # Initialize all authenticator instances with current configuration.
    #
    # Creates instances of all supported authenticators, merging method-specific
    # configuration with common settings. Each authenticator is responsible for
    # validating its own configuration during initialization.
    #
    # @private
    def initialize_authenticators
      @authenticators = {
        digidoc_local: DigiDocLocalAuthenticator.new(
          @config.digidoc_local_config.merge(common_config)
        ),
        digidoc_browser: DigiDocBrowserAuthenticator.new(
          @config.digidoc_browser_config.merge(common_config)
        ),
        mobile_id: MobileIdAuthenticator.new(
          @config.mobile_id_config.merge(common_config)
        ),
        smart_id: SmartIdAuthenticator.new(
          @config.smart_id_config.merge(common_config)
        )
      }
    rescue => e
      # Re-raise configuration errors with context
      raise ConfigurationError, "Failed to initialize authenticators: #{e.message}"
    end

    # Extract common configuration settings shared by all authenticators.
    #
    # @return [Hash] Common configuration settings
    # @private
    def common_config
      {
        timeout: @config.default_timeout,
        language: @config.default_language,
        logger: @config.logger,
        cache_store: @config.cache_store
      }.compact # Remove nil values
    end

    # Get the appropriate authenticator instance for a session.
    #
    # Routes session operations to the correct authenticator based on
    # the session's method attribute.
    #
    # @param session [AuthenticationSession] Session to find authenticator for
    # @return [BaseAuthenticator] Matching authenticator instance
    # @raise [ArgumentError] If session is invalid or method is unknown
    # @private
    def authenticator_for_session(session)
      unless session.respond_to?(:method)
        raise ArgumentError, "Invalid session object: missing method attribute"
      end

      authenticator = @authenticators[session.method]
      unless authenticator
        raise ArgumentError, "Unknown authentication method: #{session.method}. Available: #{@authenticators.keys.join(', ')}"
      end

      authenticator
    end

    # Ensure an authenticator is available before use.
    #
    # @param authenticator [BaseAuthenticator] Authenticator to check
    # @param name [String] Human-readable name for error messages
    # @raise [ServiceUnavailableError] If authenticator is not available
    # @private
    def ensure_available!(authenticator, name)
      unless authenticator.available?
        raise ServiceUnavailableError, "#{name} is not available or not configured properly"
      end
    end
  end
end