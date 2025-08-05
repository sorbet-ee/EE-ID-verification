# frozen_string_literal: true

module EeIdVerification
  # Abstract base class for all authentication methods in Estonian e-identity infrastructure.
  # This class defines the common interface that all authenticators must implement,
  # ensuring consistent behavior across different authentication methods (DigiDoc, Mobile-ID, Smart-ID).
  #
  # Each authenticator handles:
  # - Session initialization and management
  # - Authentication status polling
  # - Digital signature verification
  # - Configuration validation
  #
  # @abstract Subclass and implement all abstract methods
  class BaseAuthenticator
    # Configuration hash containing authenticator-specific settings
    attr_reader :config

    # Initialize a new authenticator with optional configuration
    #
    # @param config [Hash] Configuration options that override defaults
    # @option config [Integer] :timeout (300) Maximum time in seconds for authentication
    # @option config [Integer] :poll_interval (5) Interval in seconds between status polls
    # @option config [String] :language ("en") Language code for user-facing messages
    def initialize(config = {})
      # Merge provided config with defaults, allowing overrides
      @config = default_config.merge(config)
      # Validate the merged configuration
      validate_config!
    end

    # Initiate a new authentication session with the given parameters.
    # This method must be implemented by each authenticator to handle
    # their specific authentication initialization process.
    #
    # @abstract
    # @param params [Hash] Authentication parameters specific to each method
    #   - DigiDoc: May include certificate data
    #   - Mobile-ID: Requires phone_number and personal_code
    #   - Smart-ID: Requires personal_code or document_number
    # @return [AuthenticationSession] Session object containing:
    #   - Unique session ID
    #   - Authentication method
    #   - Status tracking
    #   - Method-specific metadata
    # @raise [NotImplementedError] Must be implemented by subclasses
    def initiate_authentication(params = {})
      raise NotImplementedError, "#{self.class} must implement #initiate_authentication"
    end

    # Poll the current status of an active authentication session.
    # Used to check if the user has completed authentication on their device.
    #
    # @abstract
    # @param session [AuthenticationSession] The active session to check
    # @return [AuthenticationResult] Current authentication status including:
    #   - Authentication success/failure
    #   - User details (if successful)
    #   - Error information (if failed)
    #   - Current status (pending/completed/failed)
    # @raise [NotImplementedError] Must be implemented by subclasses
    def poll_status(session)
      raise NotImplementedError, "#{self.class} must implement #poll_status"
    end

    # Cancel an active authentication session.
    # Cleans up resources and notifies the authentication service if needed.
    #
    # @abstract
    # @param session [AuthenticationSession] The session to cancel
    # @return [Boolean] true if successfully cancelled, false otherwise
    # @raise [NotImplementedError] Must be implemented by subclasses
    def cancel_authentication(session)
      raise NotImplementedError, "#{self.class} must implement #cancel_authentication"
    end

    # Verify a digital signature created with an Estonian e-identity certificate.
    # Validates both the signature and the certificate used for signing.
    #
    # @abstract
    # @param document [String] The original document content that was signed
    # @param signature [String] The digital signature to verify (format varies by method)
    # @param certificate [String] The signer's certificate (PEM or DER format)
    # @return [SignatureVerificationResult] Verification result containing:
    #   - Validity status
    #   - Signer information
    #   - Certificate details
    #   - Any validation errors
    # @raise [NotImplementedError] Must be implemented by subclasses
    def verify_signature(document:, signature:, certificate:)
      raise NotImplementedError, "#{self.class} must implement #verify_signature"
    end

    # Check if this authenticator is available and properly configured.
    # Used to determine which authentication methods can be offered to users.
    #
    # @abstract
    # @return [Boolean] true if the authenticator can be used, false otherwise
    # @raise [NotImplementedError] Must be implemented by subclasses
    def available?
      raise NotImplementedError, "#{self.class} must implement #available?"
    end

    protected

    # Provide default configuration values for this authenticator.
    # Subclasses should override and merge with super to add their specific defaults.
    #
    # @return [Hash] Default configuration options
    def default_config
      {
        timeout: 300,      # 5 minutes - maximum time for user to complete authentication
        poll_interval: 5,  # seconds - how often to check authentication status
        language: "en"     # default language for user-facing messages
      }
    end

    # Validate the configuration after initialization.
    # Subclasses should override to add specific validation logic.
    #
    # @raise [ConfigurationError] If configuration is invalid
    def validate_config!
      # Base validation - subclasses should call super and add their own
    end

    # Generate a unique session identifier using secure random UUID.
    # Used to track authentication sessions across multiple requests.
    #
    # @return [String] UUID v4 format session identifier
    def generate_session_id
      SecureRandom.uuid
    end

    # Get the current timestamp in UTC.
    # Used for session expiry and time-based validations.
    #
    # @return [Time] Current time in UTC
    def current_timestamp
      Time.now.utc
    end

    # Check if a session has expired based on its expiry time.
    #
    # @param session [AuthenticationSession] The session to check
    # @return [Boolean] true if session has expired, false otherwise
    def expired?(session)
      session.expires_at && session.expires_at < current_timestamp
    end
  end
end
