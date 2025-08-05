# frozen_string_literal: true

require_relative "base_authenticator"

module EeIdVerification
  # Smart-ID authentication service integration for Baltic states.
  #
  # Smart-ID is a modern authentication and digital signing solution that works
  # across Estonia, Latvia, and Lithuania. It uses a mobile app for authentication
  # instead of physical tokens, providing convenient and secure digital identity.
  #
  # Authentication process:
  # 1. User provides personal code or document number
  # 2. Authentication request sent to Smart-ID service
  # 3. User receives notification in Smart-ID mobile app
  # 4. User confirms authentication with app PIN or biometrics
  # 5. Service returns authentication certificate and user data
  #
  # Key features:
  # - Cross-border support (Estonia, Latvia, Lithuania)
  # - Mobile app-based authentication (no physical device needed)
  # - Biometric authentication support
  # - Real-time certificate validation
  # - Multiple interaction types (verification codes, PIN)
  # - Qualified and advanced certificate levels
  #
  # Security considerations:
  # - Multi-factor authentication (device + PIN/biometrics)
  # - App-based certificate storage with hardware security
  # - Anti-replay protection with verification codes
  # - Certificate level validation (QUALIFIED vs ADVANCED)
  # - Cross-border certificate chain validation
  #
  # @example Basic usage
  #   authenticator = SmartIdAuthenticator.new(
  #     service_url: "https://sid.demo.sk.ee/smart-id-rp/v2/",
  #     relying_party_uuid: "00000000-0000-0000-0000-000000000000",
  #     relying_party_name: "Demo Service"
  #   )
  #   session = authenticator.initiate_authentication(
  #     personal_code: "30303039914",
  #     country: "EE"
  #   )
  #   puts "Verification code: #{session.verification_code}"
  #
  # @see https://www.smart-id.com/
  # @see https://github.com/SK-EID/smart-id-documentation
  class SmartIdAuthenticator < BaseAuthenticator
    # Initiate Smart-ID authentication for a user.
    #
    # Starts the Smart-ID authentication process by creating a session and
    # preparing the authentication request. Users can be identified by either
    # personal code or document number, depending on country and preference.
    #
    # The user will receive a push notification in their Smart-ID mobile app
    # with the verification code and authentication request details.
    #
    # @param params [Hash] Authentication parameters
    # @option params [String] :personal_code Personal identification code
    #   - Estonia: 11 digits (e.g., "30303039914")
    #   - Latvia: 12 digits with hyphen (e.g., "030303-12345")
    #   - Lithuania: 11 digits
    # @option params [String] :document_number Document number (alternative to personal_code)
    # @option params [String] :country ("EE") Country code ("EE", "LV", "LT")
    # @option params [Symbol] :interaction_type (:verification_code_choice)
    #   - :verification_code_choice - User sees verification code
    #   - :display_text_and_pin - User sees custom text and enters PIN
    # @option params [String] :language Language for mobile app messages
    # @return [AuthenticationSession] Session with verification code for user
    # @raise [ArgumentError] If required parameters are missing or invalid
    #
    # @example Using personal code
    #   session = authenticator.initiate_authentication(
    #     personal_code: "30303039914",
    #     country: "EE",
    #     interaction_type: :verification_code_choice
    #   )
    #
    # @example Using document number
    #   session = authenticator.initiate_authentication(
    #     document_number: "PNOEE-30303039914-MOCK-Q",
    #     country: "EE"
    #   )
    def initiate_authentication(params = {})
      validate_authentication_params!(params)

      AuthenticationSession.new(
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

      # TODO: Implement complete Smart-ID service communication
      # This would:
      # 1. Build authentication request based on identifier type
      # 2. Send POST request to Smart-ID service
      # 3. Receive session ID from service for status polling
      # 4. Store service session ID for later status checks
      # 5. Handle service-specific error conditions
    end

    # Poll the Smart-ID service for authentication status.
    #
    # Checks the current state of authentication in the Smart-ID service.
    # Smart-ID authentication is asynchronous - users need time to see the
    # notification and confirm in their mobile app.
    #
    # Possible Smart-ID states during polling:
    # - RUNNING: Authentication request is active, waiting for user
    # - COMPLETE: User has successfully authenticated
    # - USER_REFUSED: User declined the authentication request
    # - TIMEOUT: Authentication request expired
    # - DOCUMENT_UNUSABLE: User's certificate is blocked or unusable
    # - CLIENT_NOT_SUPPORTED: User's app version is too old
    #
    # @param session [AuthenticationSession] The active Smart-ID session
    # @return [AuthenticationResult] Current authentication status
    # @raise [ArgumentError] If session is invalid or expired
    #
    # @example Polling with state handling
    #   loop do
    #     result = authenticator.poll_status(session)
    #     case result.status
    #     when :completed
    #       puts "Authenticated: #{result.full_name}"
    #       break
    #     when :failed
    #       puts "Failed: #{result.error}"
    #       break
    #     when :pending
    #       puts "Check your Smart-ID app (code: #{result.verification_code})"
    #       sleep 3
    #     end
    #   end
    def poll_status(session)
      validate_session!(session)

      # TODO: Implement complete Smart-ID service polling
      # This would:
      # 1. Query Smart-ID service with session ID
      # 2. Handle different response states (RUNNING, COMPLETE, etc.)
      # 3. Retrieve and validate authentication certificate on success
      # 4. Extract personal data from certificate
      # 5. Validate certificate level (QUALIFIED vs ADVANCED)
      # 6. Perform certificate chain and OCSP validation

      AuthenticationResult.new(
        session_id: session.id,
        status: :pending,
        authenticated: false,
        verification_code: session.verification_code,
        interaction_type: session.interaction_type,
        metadata: {
          message: "Check your Smart-ID mobile app for authentication request"
        }
      )
    end

    # Cancel an active Smart-ID authentication session.
    #
    # Note: Smart-ID service doesn't support explicit cancellation of
    # authentication requests. Once sent, the request remains active until
    # the user responds or it times out. This method only performs local
    # cleanup and marks the session as cancelled in the application.
    #
    # @param session [AuthenticationSession] The session to cancel
    # @return [Boolean] Always returns true (local cancellation only)
    # @raise [ArgumentError] If session is invalid
    #
    # @example
    #   # User navigated away from authentication page
    #   authenticator.cancel_authentication(session)
    #   # Note: User may still see the request in Smart-ID app
    def cancel_authentication(session)
      validate_session!(session)

      # TODO: Handle Smart-ID session cleanup
      # Smart-ID service doesn't support explicit cancellation,
      # so this only performs local cleanup:
      # 1. Mark session as cancelled locally
      # 2. Stop polling the service
      # 3. Clean up any cached data
      # Note: User may still receive notification in mobile app

      true
    end

    # Verify a digital signature created with Smart-ID.
    #
    # Smart-ID signatures use standard PKI mechanisms with X.509 certificates
    # stored in the mobile app's secure element. The verification process
    # includes validation of certificate levels (QUALIFIED vs ADVANCED) and
    # cross-border certificate chain validation for Baltic states.
    #
    # The signature verification includes:
    # - Cryptographic signature validation using certificate public key
    # - Certificate chain verification against Estonian/Latvian/Lithuanian CAs
    # - Certificate revocation checking (OCSP)
    # - Certificate level validation (QUALIFIED for legal signatures)
    # - Smart-ID specific certificate policy validation
    #
    # @param document [String] The original document that was signed
    # @param signature [String] The digital signature to verify
    # @param certificate [String] The signer's Smart-ID certificate
    # @return [SignatureVerificationResult] Verification result with signer info
    #
    # @example
    #   result = authenticator.verify_signature(
    #     document: "Contract content",
    #     signature: smart_id_signature,
    #     certificate: smart_id_cert
    #   )
    #   if result.valid?
    #     puts "Signed by: #{result.signer_info[:common_name]}"
    #     puts "Certificate level: #{result.signature_level}" # QUALIFIED or ADVANCED
    #   end
    def verify_signature(document:, signature:, certificate:)
      # TODO: Implement complete Smart-ID signature verification
      # This would:
      # 1. Parse Smart-ID certificate and validate structure
      # 2. Verify signature cryptographically using certificate public key
      # 3. Validate certificate chain against Baltic CA roots
      # 4. Check certificate revocation status via OCSP
      # 5. Validate certificate level (QUALIFIED vs ADVANCED)
      # 6. Check Smart-ID specific certificate policies
      # 7. Extract signer information from certificate

      SignatureVerificationResult.new(
        valid: false,
        errors: ["Smart-ID signature verification not yet implemented"]
      )
    end

    # Check if Smart-ID authentication is available.
    #
    # Verifies that the Smart-ID service is properly configured with
    # required parameters. This method only checks configuration -
    # actual service availability should be tested with a health check.
    #
    # @return [Boolean] true if Smart-ID service is configured
    #
    # @example
    #   if authenticator.available?
    #     # Show Smart-ID as authentication option
    #   else
    #     # Hide Smart-ID option, show configuration error
    #   end
    def available?
      # Check if essential configuration is present
      !config[:service_url].nil? && !config[:relying_party_uuid].nil?
    end

    protected

    # Default configuration for Smart-ID authentication.
    #
    # @return [Hash] Default configuration options
    # @option return [String] :service_url Smart-ID REST API endpoint
    # @option return [String] :relying_party_uuid Unique identifier for your service
    # @option return [String] :relying_party_name Display name shown in mobile app
    # @option return [Integer] :verification_code_length Length of verification codes
    # @option return [String] :certificate_level Required certificate level
    # @option return [Array<Symbol>] :interaction_types Supported interaction types
    # @option return [Array<String>] :allowed_countries Supported Baltic countries
    def default_config
      super.merge(
        service_url: nil, # Must be configured: "https://sid.demo.sk.ee/smart-id-rp/v2/"
        relying_party_uuid: nil, # Must be configured: UUID from Smart-ID service
        relying_party_name: "EE-ID Verification", # Shown in user's Smart-ID app
        verification_code_length: 4, # Standard verification code length
        certificate_level: "QUALIFIED", # QUALIFIED (legal) or ADVANCED (basic)
        interaction_types: %i[verification_code_choice display_text_and_pin],
        allowed_countries: %w[EE LV LT] # Estonia, Latvia, Lithuania
      )
    end

    # Validate Smart-ID configuration.
    #
    # Ensures all required configuration parameters are present and valid.
    # Smart-ID requires service registration to obtain the relying party UUID
    # and access credentials.
    #
    # @raise [ArgumentError] If required configuration is missing or invalid
    def validate_config!
      super

      # Only validate if actually configured (otherwise just mark unavailable)
      if config[:service_url] && config[:relying_party_uuid]
        unless %w[QUALIFIED ADVANCED].include?(config[:certificate_level])
          raise ArgumentError, "Invalid certificate level: must be QUALIFIED or ADVANCED"
        end

        # Validate service URL format
        begin
          uri = URI.parse(config[:service_url])
          raise ArgumentError, "Smart-ID service URL must use HTTPS for security" unless uri.scheme == "https"
        rescue URI::InvalidURIError
          raise ArgumentError, "Invalid Smart-ID service URL format"
        end
      end

      # Validate allowed countries
      invalid_countries = config[:allowed_countries] - %w[EE LV LT]
      return if invalid_countries.empty?

      raise ArgumentError, "Invalid countries: #{invalid_countries.join(", ")}. Smart-ID supports EE, LV, LT only."
    end

    private

    # Validate parameters for Smart-ID authentication.
    #
    # Ensures required parameters are present and properly formatted.
    # Smart-ID supports identification by personal code or document number
    # across Baltic countries with different validation rules.
    #
    # @param params [Hash] Authentication parameters
    # @raise [ArgumentError] If parameters are missing or invalid
    def validate_authentication_params!(params)
      unless params[:personal_code] || params[:document_number]
        raise ArgumentError, "Either personal code or document number is required for Smart-ID"
      end

      if params[:personal_code] && !valid_personal_code?(params[:personal_code])
        raise ArgumentError, "Invalid personal code format for selected country"
      end

      if params[:country] && !config[:allowed_countries].include?(params[:country])
        raise ArgumentError,
              "Country not supported: #{params[:country]}. Supported: #{config[:allowed_countries].join(", ")}"
      end

      if params[:interaction_type] && !config[:interaction_types].include?(params[:interaction_type])
        raise ArgumentError,
              "Invalid interaction type: #{params[:interaction_type]}. Supported: #{config[:interaction_types].join(", ")}"
      end

      # Validate document number format if provided
      return unless params[:document_number] && !params[:document_number].match?(/^[A-Z0-9-]+$/)

      raise ArgumentError, "Invalid document number format (expected alphanumeric with hyphens)"
    end

    # Validate a Smart-ID authentication session.
    #
    # @param session [AuthenticationSession] The session to validate
    # @raise [ArgumentError] If session is nil, wrong type, or expired
    def validate_session!(session)
      raise ArgumentError, "Session cannot be nil" unless session
      raise ArgumentError, "Invalid session type: expected :smart_id" unless session.method == :smart_id
      raise ArgumentError, "Session has expired" if expired?(session)
    end

    # Validate personal identification codes for Baltic countries.
    #
    # Each Baltic country has different personal code formats:
    # - Estonia: 11 digits (GYYMMDDSSSC)
    # - Latvia: 11 digits with optional hyphen (DDMMYY-NNNNN)
    # - Lithuania: 11 digits (GYYMMDDSSSC)
    #
    # @param code [String] Personal identification code
    # @return [Boolean] true if format matches any supported country
    # @private
    #
    # @example
    #   valid_personal_code?("30303039914")    # => true (Estonian)
    #   valid_personal_code?("030303-12345")   # => true (Latvian)
    #   valid_personal_code?("39001010123")    # => true (Lithuanian)
    def valid_personal_code?(code)
      case code.length
      when 11
        # Estonian or Lithuanian format (11 digits)
        code.match?(/^\d{11}$/)
      when 12
        # Latvian format with hyphen (DDMMYY-NNNNN)
        code.match?(/^\d{6}-\d{5}$/)
      else
        false
      end
    end

    # Generate verification code for Smart-ID authentication.
    #
    # Creates a random numeric code that is displayed in the user's Smart-ID
    # mobile app during authentication. This code serves as visual confirmation
    # that the authentication request is legitimate and matches the web session.
    #
    # @return [String] Random verification code (e.g., "7542")
    # @private
    def generate_verification_code
      Array.new(config[:verification_code_length]) { rand(0..9) }.join
    end

    # Smart-ID specific helper methods

    # Build authentication request for Smart-ID REST API.
    #
    # Creates the appropriate request structure based on the identifier type
    # (personal code vs document number). Smart-ID uses different API endpoints
    # for different identifier types.
    #
    # @param session [AuthenticationSession] Session containing user data
    # @return [Hash] Request structure for Smart-ID API
    # @private
    def build_authentication_request(session)
      # Choose request builder based on identifier type
      if session.personal_code
        build_request_by_personal_code(session)
      else
        build_request_by_document_number(session)
      end
    end

    # Build authentication request using personal code identifier.
    #
    # Constructs request for the /authentication/pno/{country}/{personal_code} endpoint.
    # This is the most common way to identify Smart-ID users.
    #
    # @param session [AuthenticationSession] Session with personal code
    # @return [Hash] Request structure for personal code authentication
    # @private
    def build_request_by_personal_code(session)
      {
        relyingPartyUUID: config[:relying_party_uuid],
        relyingPartyName: config[:relying_party_name],
        certificateLevel: config[:certificate_level],
        hash: calculate_authentication_hash,
        hashType: "SHA256",
        displayText: display_text_for_session(session),
        nonce: SecureRandom.base64(30),
        capabilities: ["ADVANCED"], # Smart-ID app capabilities
        allowedInteractionsOrder: determine_interaction_order(session)
      }
    end

    # Build authentication request using document number identifier.
    #
    # Constructs request for the /authentication/document/{document_number} endpoint.
    # Used when personal code is not available or preferred.
    #
    # @param session [AuthenticationSession] Session with document number
    # @return [Hash] Request structure for document number authentication
    # @private
    def build_request_by_document_number(session)
      # Base request similar to personal code authentication
      base_request = build_request_by_personal_code(session)

      # Document number is included in URL path, not request body
      # but we include it here for completeness
      base_request.merge(
        documentNumber: session.document_number
      )
    end

    # Generate display text for Smart-ID mobile app.
    #
    # Returns appropriate text based on the interaction type.
    # Some interaction types show custom text, others only show verification codes.
    #
    # @param session [AuthenticationSession] Session with interaction type
    # @return [String, nil] Display text or nil for verification code only
    # @private
    def display_text_for_session(session)
      case session.interaction_type
      when :display_text_and_pin
        "Authenticate to #{config[:relying_party_name]}"
      else
        nil # Verification code only - no custom text
      end
    end

    # Determine interaction order for Smart-ID authentication.
    #
    # Smart-ID supports different interaction types that control how the
    # authentication request is presented in the mobile app.
    #
    # @param session [AuthenticationSession] Session with interaction preferences
    # @return [Array<Hash>] Interaction configuration for Smart-ID API
    # @private
    def determine_interaction_order(session)
      case session.interaction_type
      when :verification_code_choice
        # Show verification code for user confirmation
        [
          {
            type: "verificationCodeChoice",
            displayText60: "Verification code: #{session.verification_code}"
          }
        ]
      when :display_text_and_pin
        # Show custom text and require PIN entry
        [
          {
            type: "displayTextAndPIN",
            displayText200: display_text_for_session(session)
          }
        ]
      else
        # Default: no specific interaction requirements
        []
      end
    end

    # Calculate authentication hash for Smart-ID request.
    #
    # The hash is signed by the user's private key to prove identity.
    # In a complete implementation, this would be a hash of specific
    # data being authenticated (e.g., login session, transaction details).
    #
    # @return [String] Hash to be signed (Base64 encoded)
    # @private
    # @todo Implement proper hash calculation based on authentication context
    def calculate_authentication_hash
      # TODO: Generate proper authentication hash based on:
      # 1. Authentication context (login, transaction, etc.)
      # 2. Anti-replay nonce
      # 3. Service-specific data
      # 4. Timestamp for freshness
      # For now, return random challenge
      SecureRandom.base64(32)
    end

    # Generate Smart-ID API endpoint path for authentication.
    #
    # Returns the appropriate endpoint based on identifier type:
    # - Personal code: /authentication/pno/{country}/{personal_code}
    # - Document number: /authentication/document/{document_number}
    #
    # @param session [AuthenticationSession] Session with identifier data
    # @return [String] API endpoint path
    # @private
    def smart_id_endpoint(session)
      if session.personal_code
        "/authentication/pno/#{session.country}/#{session.personal_code}"
      else
        "/authentication/document/#{session.document_number}"
      end
    end
  end
end
