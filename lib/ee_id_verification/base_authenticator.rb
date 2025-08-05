# frozen_string_literal: true

module EeIdVerification
  # Base interface for all authentication methods
  class BaseAuthenticator
    attr_reader :config

    def initialize(config = {})
      @config = default_config.merge(config)
      validate_config!
    end

    # Initiate authentication process
    # @param params [Hash] Authentication parameters (varies by method)
    # @return [AuthenticationSession] Session object to track authentication
    def initiate_authentication(params = {})
      raise NotImplementedError, "#{self.class} must implement #initiate_authentication"
    end

    # Poll authentication status
    # @param session [AuthenticationSession] Active authentication session
    # @return [AuthenticationResult] Result of authentication attempt
    def poll_status(session)
      raise NotImplementedError, "#{self.class} must implement #poll_status"
    end

    # Cancel active authentication
    # @param session [AuthenticationSession] Session to cancel
    # @return [Boolean] Success status
    def cancel_authentication(session)
      raise NotImplementedError, "#{self.class} must implement #cancel_authentication"
    end

    # Verify digital signature
    # @param document [String] Document content
    # @param signature [String] Digital signature
    # @param certificate [String] Signer's certificate
    # @return [SignatureVerificationResult] Verification result
    def verify_signature(document:, signature:, certificate:)
      raise NotImplementedError, "#{self.class} must implement #verify_signature"
    end

    # Check if authenticator is available/configured
    # @return [Boolean]
    def available?
      raise NotImplementedError, "#{self.class} must implement #available?"
    end

    protected

    # Override in subclasses to provide default configuration
    def default_config
      {
        timeout: 300, # 5 minutes
        poll_interval: 5, # seconds
        language: "en"
      }
    end

    # Override in subclasses to validate specific configuration
    def validate_config!
      # Base validation
    end

    # Common utility methods for subclasses
    def generate_session_id
      SecureRandom.uuid
    end

    def current_timestamp
      Time.now.utc
    end

    def expired?(session)
      session.expires_at && session.expires_at < current_timestamp
    end
  end
end