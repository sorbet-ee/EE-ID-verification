# frozen_string_literal: true

require_relative "base_authenticator"

module EeIdVerification
  # DigiDoc authentication via browser extension/plugin
  class DigiDocBrowserAuthenticator < BaseAuthenticator
    def initiate_authentication(params = {})
      validate_authentication_params!(params)
      
      session = AuthenticationSession.new(
        id: generate_session_id,
        method: :digidoc_browser,
        status: :pending,
        created_at: current_timestamp,
        expires_at: current_timestamp + config[:timeout],
        challenge: generate_challenge,
        origin: params[:origin] || config[:origin]
      )

      # TODO: Implement browser-based DigiDoc authentication
      # This would involve:
      # 1. Generating authentication request for browser
      # 2. Providing JavaScript integration code
      # 3. Handling browser extension communication
      
      session
    end

    def poll_status(session)
      validate_session!(session)
      
      # TODO: Check if browser has completed authentication
      # This would:
      # 1. Check server-side session storage
      # 2. Verify browser response signature
      # 3. Extract user certificate data
      
      AuthenticationResult.new(
        session_id: session.id,
        status: :pending,
        authenticated: false
      )
    end

    def cancel_authentication(session)
      validate_session!(session)
      
      # TODO: Clean up browser session
      # Notify any waiting browser connections
      
      true
    end

    def verify_signature(document:, signature:, certificate:)
      # TODO: Implement browser-based signature verification
      # Similar to local but may use different format
      
      SignatureVerificationResult.new(
        valid: false,
        errors: ["Not implemented"]
      )
    end

    def available?
      # Browser-based authentication is generally available
      # Client-side will check for extension
      true
    end

    protected

    def default_config
      super.merge(
        origin: nil, # Required for CORS validation
        allowed_origins: [],
        browser_extension_id: nil,
        challenge_length: 32
      )
    end

    def validate_config!
      super
      
      if config[:allowed_origins].empty? && !config[:origin]
        raise ArgumentError, "Either origin or allowed_origins must be configured"
      end
    end

    private

    def validate_authentication_params!(params)
      unless params[:origin] || config[:origin]
        raise ArgumentError, "Origin is required for browser authentication"
      end

      if params[:origin] && !allowed_origin?(params[:origin])
        raise ArgumentError, "Origin not allowed: #{params[:origin]}"
      end
    end

    def validate_session!(session)
      raise ArgumentError, "Session cannot be nil" unless session
      raise ArgumentError, "Invalid session type" unless session.method == :digidoc_browser
      raise ArgumentError, "Session has expired" if expired?(session)
    end

    def allowed_origin?(origin)
      return true if config[:allowed_origins].include?("*")
      
      config[:allowed_origins].include?(origin) || config[:origin] == origin
    end

    def generate_challenge
      SecureRandom.base64(config[:challenge_length])
    end

    # Helper methods for browser integration
    def generate_browser_request(session)
      # TODO: Create request object for browser
      {
        session_id: session.id,
        challenge: session.challenge,
        origin: session.origin,
        extension_id: config[:browser_extension_id]
      }
    end

    def validate_browser_response(response, session)
      # TODO: Verify response from browser
      # Check signature, origin, challenge
    end

    def extract_certificate_from_response(response)
      # TODO: Parse certificate from browser response
    end
  end
end