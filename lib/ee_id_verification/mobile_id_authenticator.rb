# frozen_string_literal: true

require_relative "base_authenticator"

module EeIdVerification
  # Mobile-ID authentication using phone number and personal code
  class MobileIdAuthenticator < BaseAuthenticator
    def initiate_authentication(params = {})
      validate_authentication_params!(params)
      
      session = AuthenticationSession.new(
        id: generate_session_id,
        method: :mobile_id,
        status: :pending,
        created_at: current_timestamp,
        expires_at: current_timestamp + config[:timeout],
        phone_number: normalize_phone_number(params[:phone_number]),
        personal_code: params[:personal_code],
        verification_code: generate_verification_code,
        language: params[:language] || config[:language]
      )

      # TODO: Implement Mobile-ID service communication
      # This would:
      # 1. Send authentication request to Mobile-ID service
      # 2. Receive session ID from service
      # 3. Display verification code to user
      
      session
    end

    def poll_status(session)
      validate_session!(session)
      
      # TODO: Poll Mobile-ID service for status
      # This would:
      # 1. Check if user has confirmed on mobile device
      # 2. Retrieve authentication certificate
      # 3. Extract user data
      
      AuthenticationResult.new(
        session_id: session.id,
        status: :pending,
        authenticated: false,
        verification_code: session.verification_code
      )
    end

    def cancel_authentication(session)
      validate_session!(session)
      
      # TODO: Send cancellation to Mobile-ID service
      
      true
    end

    def verify_signature(document:, signature:, certificate:)
      # TODO: Mobile-ID signature verification
      # Uses standard X.509 certificate verification
      
      SignatureVerificationResult.new(
        valid: false,
        errors: ["Not implemented"]
      )
    end

    def available?
      # Check if Mobile-ID service is configured
      !config[:service_url].nil?
    end

    protected

    def default_config
      super.merge(
        service_url: nil, # Mobile-ID service endpoint
        service_uuid: nil, # Service identifier
        service_name: "EE-ID Verification", # Display name
        verification_code_length: 4,
        message_to_display: nil, # Custom message for mobile screen
        phone_number_country_code: "+372" # Estonia
      )
    end

    def validate_config!
      super
      
      unless config[:service_url]
        raise ArgumentError, "Mobile-ID service URL is required"
      end

      unless config[:service_uuid]
        raise ArgumentError, "Mobile-ID service UUID is required"
      end
    end

    private

    def validate_authentication_params!(params)
      unless params[:phone_number]
        raise ArgumentError, "Phone number is required"
      end

      unless params[:personal_code]
        raise ArgumentError, "Personal code is required"
      end

      unless valid_personal_code?(params[:personal_code])
        raise ArgumentError, "Invalid Estonian personal code format"
      end
    end

    def validate_session!(session)
      raise ArgumentError, "Session cannot be nil" unless session
      raise ArgumentError, "Invalid session type" unless session.method == :mobile_id
      raise ArgumentError, "Session has expired" if expired?(session)
    end

    def normalize_phone_number(phone)
      # Remove spaces and special characters
      normalized = phone.gsub(/[^0-9+]/, "")
      
      # Add country code if missing
      if normalized.start_with?("5")
        normalized = "#{config[:phone_number_country_code]}#{normalized}"
      end
      
      normalized
    end

    def valid_personal_code?(code)
      # Estonian personal code validation
      return false unless code.match?(/^\d{11}$/)
      
      # TODO: Implement full validation including:
      # 1. Century and gender check (first digit)
      # 2. Date validation
      # 3. Checksum validation
      
      true
    end

    def generate_verification_code
      # Generate random numeric code for user verification
      Array.new(config[:verification_code_length]) { rand(0..9) }.join
    end

    # Mobile-ID specific helpers
    def build_authentication_request(session)
      # TODO: Build request for Mobile-ID service
      {
        relyingPartyUUID: config[:service_uuid],
        relyingPartyName: config[:service_name],
        phoneNumber: session.phone_number,
        nationalIdentityNumber: session.personal_code,
        language: session.language.upcase,
        displayText: config[:message_to_display] || default_display_message,
        hash: calculate_authentication_hash,
        hashType: "SHA256"
      }
    end

    def default_display_message
      "Authenticate to #{config[:service_name]}"
    end

    def calculate_authentication_hash
      # TODO: Generate hash for authentication
      SecureRandom.base64(32)
    end
  end
end