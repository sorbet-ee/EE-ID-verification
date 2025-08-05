# frozen_string_literal: true

require_relative "base_authenticator"

module EeIdVerification
  # Smart-ID authentication using personal code or document number
  class SmartIdAuthenticator < BaseAuthenticator
    def initiate_authentication(params = {})
      validate_authentication_params!(params)
      
      session = AuthenticationSession.new(
        id: generate_session_id,
        method: :smart_id,
        status: :pending,
        created_at: current_timestamp,
        expires_at: current_timestamp + config[:timeout],
        personal_code: params[:personal_code],
        document_number: params[:document_number],
        country: params[:country] || "EE",
        verification_code: generate_verification_code,
        interaction_type: params[:interaction_type] || :verification_code_choice,
        language: params[:language] || config[:language]
      )

      # TODO: Implement Smart-ID service communication
      # This would:
      # 1. Send authentication request to Smart-ID service
      # 2. Get session ID and verification code
      # 3. User confirms in Smart-ID app
      
      session
    end

    def poll_status(session)
      validate_session!(session)
      
      # TODO: Poll Smart-ID service for status
      # This would:
      # 1. Check authentication progress
      # 2. Handle different states (RUNNING, COMPLETE, etc.)
      # 3. Extract user certificate when complete
      
      AuthenticationResult.new(
        session_id: session.id,
        status: :pending,
        authenticated: false,
        verification_code: session.verification_code,
        interaction_type: session.interaction_type
      )
    end

    def cancel_authentication(session)
      validate_session!(session)
      
      # TODO: Smart-ID doesn't support explicit cancellation
      # Mark as cancelled locally
      
      true
    end

    def verify_signature(document:, signature:, certificate:)
      # TODO: Smart-ID signature verification
      # Similar to Mobile-ID, uses X.509 certificates
      
      SignatureVerificationResult.new(
        valid: false,
        errors: ["Not implemented"]
      )
    end

    def available?
      # Check if Smart-ID service is configured
      !config[:service_url].nil?
    end

    protected

    def default_config
      super.merge(
        service_url: nil, # Smart-ID service endpoint
        relying_party_uuid: nil, # Service identifier
        relying_party_name: "EE-ID Verification", # Display name
        verification_code_length: 4,
        certificate_level: "QUALIFIED", # QUALIFIED or ADVANCED
        interaction_types: [:verification_code_choice, :display_text_and_pin],
        allowed_countries: ["EE", "LV", "LT"] # Baltic countries
      )
    end

    def validate_config!
      super
      
      unless config[:service_url]
        raise ArgumentError, "Smart-ID service URL is required"
      end

      unless config[:relying_party_uuid]
        raise ArgumentError, "Smart-ID relying party UUID is required"
      end

      unless %w[QUALIFIED ADVANCED].include?(config[:certificate_level])
        raise ArgumentError, "Invalid certificate level"
      end
    end

    private

    def validate_authentication_params!(params)
      unless params[:personal_code] || params[:document_number]
        raise ArgumentError, "Either personal code or document number is required"
      end

      if params[:personal_code] && !valid_personal_code?(params[:personal_code])
        raise ArgumentError, "Invalid personal code format"
      end

      if params[:country] && !config[:allowed_countries].include?(params[:country])
        raise ArgumentError, "Country not supported: #{params[:country]}"
      end

      if params[:interaction_type] && !config[:interaction_types].include?(params[:interaction_type])
        raise ArgumentError, "Invalid interaction type: #{params[:interaction_type]}"
      end
    end

    def validate_session!(session)
      raise ArgumentError, "Session cannot be nil" unless session
      raise ArgumentError, "Invalid session type" unless session.method == :smart_id
      raise ArgumentError, "Session has expired" if expired?(session)
    end

    def valid_personal_code?(code)
      # Basic validation for Baltic personal codes
      case code.length
      when 11 # Estonian
        code.match?(/^\d{11}$/)
      when 12 # Latvian (with hyphen)
        code.match?(/^\d{6}-\d{5}$/)
      else
        false
      end
    end

    def generate_verification_code
      # Generate verification code for Smart-ID app
      Array.new(config[:verification_code_length]) { rand(0..9) }.join
    end

    # Smart-ID specific helpers
    def build_authentication_request(session)
      # TODO: Build request based on identifier type
      if session.personal_code
        build_request_by_personal_code(session)
      else
        build_request_by_document_number(session)
      end
    end

    def build_request_by_personal_code(session)
      {
        relyingPartyUUID: config[:relying_party_uuid],
        relyingPartyName: config[:relying_party_name],
        certificateLevel: config[:certificate_level],
        hash: calculate_authentication_hash,
        hashType: "SHA256",
        displayText: display_text_for_session(session),
        nonce: SecureRandom.base64(30),
        capabilities: ["ADVANCED"],
        allowedInteractionsOrder: determine_interaction_order(session)
      }
    end

    def build_request_by_document_number(session)
      # Similar to personal code but different endpoint
      build_request_by_personal_code(session).merge(
        documentNumber: session.document_number
      )
    end

    def display_text_for_session(session)
      case session.interaction_type
      when :display_text_and_pin
        "Authenticate to #{config[:relying_party_name]}"
      else
        nil # Verification code only
      end
    end

    def determine_interaction_order(session)
      case session.interaction_type
      when :verification_code_choice
        [
          { type: "verificationCodeChoice", displayText60: generate_verification_code }
        ]
      when :display_text_and_pin
        [
          { type: "displayTextAndPIN", displayText200: display_text_for_session(session) }
        ]
      else
        []
      end
    end

    def calculate_authentication_hash
      # TODO: Generate proper authentication hash
      SecureRandom.base64(32)
    end

    def smart_id_endpoint(session)
      if session.personal_code
        "/authentication/pno/#{session.country}/#{session.personal_code}"
      else
        "/authentication/document/#{session.document_number}"
      end
    end
  end
end