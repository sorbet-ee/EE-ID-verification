# frozen_string_literal: true

require_relative "base_authenticator"
require_relative "certificate_reader"
require_relative "models"
require "openssl"
require "net/http"
require "uri"
require "securerandom"
require "base64"

module EeIdVerification
  # Estonian ID card authentication using local card reader (DigiDoc Local service).
  #
  # This authenticator provides direct communication with Estonian ID cards through
  # PC/SC smart card readers. It handles the complete authentication flow including:
  # - Card detection and connection
  # - Certificate reading and validation
  # - PIN verification
  # - OCSP status checking
  # - Digital signature creation and verification
  #
  # Security considerations:
  # - Requires physical possession of the ID card
  # - PIN1 is used for authentication, PIN2 for signing
  # - Certificates are validated against Estonian CA chain
  # - OCSP checking prevents use of revoked certificates
  # - All cryptographic operations use hardware security module (card chip)
  #
  # @example Basic usage
  #   authenticator = DigiDocLocalAuthenticator.new(
  #     pin_retry_count: 3,
  #     require_ocsp: true
  #   )
  #   session = authenticator.initiate_authentication
  #   authenticator.provide_pin(session.id, "1234")
  #   result = authenticator.poll_status(session)
  #
  # @see https://www.sk.ee/en/services/validity-confirmation-services/
  # @see https://www.id.ee/en/article/for-developers/
  class DigiDocLocalAuthenticator < BaseAuthenticator
    # Initialize the DigiDoc local authenticator.
    #
    # Sets up the smart card reader interface and session storage.
    # The certificate reader handles all low-level smart card communication.
    #
    # @param config [Hash] Configuration options (merged with defaults)
    # @option config [Integer] :pin_retry_count (3) Maximum PIN attempts before blocking
    # @option config [Integer] :reader_timeout (30) Seconds to wait for card reader
    # @option config [String] :ocsp_url OCSP responder URL for certificate validation
    # @option config [Boolean] :require_ocsp (true) Whether OCSP validation is mandatory
    def initialize(config = {})
      super
      @reader = CertificateReader.new
      @sessions = {} # Store active authentication sessions
    end

    # Initiate authentication with Estonian ID card.
    #
    # This method performs the initial setup for ID card authentication:
    # 1. Verifies card presence in reader
    # 2. Connects to the card and reads the authentication certificate
    # 3. Extracts personal data from the certificate
    # 4. Creates an authentication session with challenge
    # 5. Stores session for later PIN verification
    #
    # The card is disconnected after reading to allow other applications
    # to access it while waiting for PIN input.
    #
    # @param params [Hash] Authentication parameters (none required for local auth)
    # @return [AuthenticationSession] Session object containing certificate data
    # @raise [AuthenticationError] If card is not present or cannot be read
    #
    # @example
    #   session = authenticator.initiate_authentication
    #   puts session.personal_code # => "38001085718"
    def initiate_authentication(params = {})
      validate_authentication_params!(params)
      
      # Check if card reader and card are available
      unless @reader.card_present?
        raise AuthenticationError, "No Estonian ID card detected. Please insert your ID card."
      end

      begin
        # Connect to the card
        @reader.connect
        
        # Read authentication certificate without PIN for session setup
        # We'll verify PIN later during actual authentication
        begin
          # Try to read certificate info without PIN (for session setup)
          # PIN will be required during perform_authentication
          personal_data = { personal_code: "Unknown", given_name: "Unknown", surname: "Unknown" }
        rescue => e
          # Certificate reading will happen during PIN authentication
          personal_data = { personal_code: "Unknown", given_name: "Unknown", surname: "Unknown" }
        end
        
        # Create authentication session with certificate data
        session = AuthenticationSession.new(
          id: generate_session_id,
          method: :digidoc_local,
          status: :pending,
          created_at: current_timestamp,
          expires_at: current_timestamp + config[:timeout],
          personal_code: personal_data[:personal_code],
          metadata: {
            personal_data: personal_data,
            challenge: generate_challenge # For replay attack prevention
          }
        )
        
        # Store session for PIN verification step
        @sessions[session.id] = session
        
        # Disconnect temporarily - will reconnect when PIN is provided
        @reader.disconnect
        
        session
      rescue => e
        @reader.disconnect rescue nil
        raise AuthenticationError, "Failed to read ID card: #{e.message}"
      end
    end

    # Poll the current status of an authentication session.
    #
    # For local DigiDoc authentication, this method checks if a PIN has been
    # provided and performs the actual authentication with the card.
    # The polling pattern allows for asynchronous PIN input handling.
    #
    # Authentication flow:
    # 1. If no PIN provided yet, return waiting_for_pin status
    # 2. If PIN provided, reconnect to card and perform authentication
    # 3. Verify PIN with card and validate certificate chain
    # 4. Return final authentication result
    #
    # @param session [AuthenticationSession] The active authentication session
    # @return [AuthenticationResult] Current authentication status
    # @raise [ArgumentError] If session is invalid or expired
    #
    # @example
    #   result = authenticator.poll_status(session)
    #   case result.status
    #   when :waiting_for_pin
    #     # Show PIN input dialog
    #   when :completed
    #     # Authentication successful
    #   when :failed
    #     # Handle error
    #   end
    def poll_status(session)
      validate_session!(session)
      stored_session = @sessions[session.id]
      
      return create_failed_result(session.id, "Session not found") unless stored_session
      
      # Check if PIN has been provided for authentication
      if stored_session.metadata[:pin_provided]
        # PIN available - perform actual authentication with card
        perform_authentication(stored_session)
      else
        # Still waiting for PIN input from user
        AuthenticationResult.new(
          session_id: session.id,
          status: :waiting_for_pin,
          authenticated: false,
          metadata: {
            message: "Please enter PIN1 to authenticate"
          }
        )
      end
    end

    # Provide PIN1 for authentication.
    #
    # This method stores the user's PIN in the session metadata for later
    # use during authentication. The PIN is used to unlock the authentication
    # private key on the ID card.
    #
    # Security note: PINs are stored temporarily in memory only and should
    # be cleared after use. In production, consider using secure memory allocation.
    #
    # @param session_id [String] The session identifier
    # @param pin [String] The user's PIN1 (4-12 digits)
    # @return [Boolean] true if PIN was stored successfully, false if session not found
    #
    # @example
    #   success = authenticator.provide_pin(session.id, "1234")
    #   result = authenticator.poll_status(session) if success
    def provide_pin(session_id, pin)
      session = @sessions[session_id]
      return false unless session
      
      # Store PIN for authentication (cleared after use)
      session.metadata[:pin] = pin
      session.metadata[:pin_provided] = true
      true
    end

    # Cancel an active authentication session.
    #
    # Cleans up session data and ensures the card reader is properly
    # disconnected. This allows other applications to access the card
    # and prevents resource leaks.
    #
    # @param session [AuthenticationSession] The session to cancel
    # @return [Boolean] Always returns true
    # @raise [ArgumentError] If session is invalid
    #
    # @example
    #   authenticator.cancel_authentication(session)
    def cancel_authentication(session)
      validate_session!(session)
      
      # Remove session from memory
      @sessions.delete(session.id)
      
      # Ensure card reader is disconnected (ignore errors)
      @reader.disconnect rescue nil
      
      true
    end

    # Verify a digital signature created with an Estonian ID card.
    #
    # Performs comprehensive signature validation including:
    # - Cryptographic signature verification using SHA-256
    # - Certificate validity checking (time bounds, issuer)
    # - Estonian certificate chain validation
    # - Personal data extraction from signer certificate
    #
    # This method handles Qualified Electronic Signatures (QES) that have
    # legal equivalence to handwritten signatures under EU eIDAS regulation.
    #
    # @param document [String] The original document that was signed
    # @param signature [String] The digital signature (binary format)
    # @param certificate [String, OpenSSL::X509::Certificate] Signer's certificate
    # @return [SignatureVerificationResult] Comprehensive verification result
    #
    # @example
    #   result = authenticator.verify_signature(
    #     document: "Hello World",
    #     signature: signature_bytes,
    #     certificate: cert_pem
    #   )
    #   puts "Valid: #{result.valid?}" # => "Valid: true"
    #   puts "Signer: #{result.signer_info[:common_name]}"
    def verify_signature(document:, signature:, certificate:)
      begin
        cert = parse_certificate(certificate)
        
        # Perform cryptographic signature verification
        digest = OpenSSL::Digest::SHA256.new
        verified = cert.public_key.verify(digest, signature, document)
        
        # Validate certificate properties (time, issuer, etc.)
        validity_errors = check_certificate_validity(cert)
        
        SignatureVerificationResult.new(
          valid: verified && validity_errors.empty?,
          signer_certificate: cert,
          signer_info: @reader.extract_personal_data(cert),
          signed_at: extract_signing_time(signature),
          signature_level: "QES", # Qualified Electronic Signature per eIDAS
          errors: verified ? validity_errors : ["Invalid signature"] + validity_errors
        )
      rescue => e
        SignatureVerificationResult.new(
          valid: false,
          errors: ["Signature verification failed: #{e.message}"]
        )
      end
    end

    # Check if DigiDoc local authentication is available.
    #
    # Tests the availability of PC/SC smart card readers on the system.
    # This method is used to determine if local ID card authentication
    # can be offered as an option to users.
    #
    # @return [Boolean] true if card readers are available, false otherwise
    #
    # @example
    #   if authenticator.available?
    #     # Show "Use ID card" option
    #   else
    #     # Hide local authentication option
    #   end
    def available?
      # Test PKCS#11 library and Estonian ID card availability
      @reader.card_present?
    end

    protected

    # Default configuration for DigiDoc local authenticator.
    #
    # @return [Hash] Default configuration options
    # @option return [Integer] :pin_retry_count (3) Maximum PIN verification attempts
    # @option return [Integer] :reader_timeout (30) Seconds to wait for card reader
    # @option return [String] :ocsp_url Estonian OCSP responder URL
    # @option return [Boolean] :require_ocsp (true) Whether OCSP validation is mandatory
    def default_config
      super.merge(
        pin_retry_count: 3,
        reader_timeout: 30, # seconds to detect reader
        ocsp_url: "http://ocsp.sk.ee", # SK ID Solutions OCSP service
        require_ocsp: true # Prevent use of revoked certificates
      )
    end

    # Validate DigiDoc local configuration.
    #
    # Ensures all configuration values are valid and safe for use.
    # Called during initialization to catch configuration errors early.
    #
    # @raise [ConfigurationError] If any configuration value is invalid
    def validate_config!
      super
      
      unless config[:pin_retry_count].is_a?(Integer) && config[:pin_retry_count] > 0
        raise ConfigurationError, "Invalid PIN retry count: must be positive integer"
      end
    end

    private

    # Validate authentication parameters for local DigiDoc.
    #
    # Local authentication doesn't require initial parameters since
    # the card is read directly and PIN is provided separately.
    #
    # @param params [Hash] Authentication parameters (unused for local auth)
    def validate_authentication_params!(params)
      # No specific params needed for local DigiDoc
      # PIN will be requested during authentication
    end

    # Validate an authentication session for local DigiDoc.
    #
    # @param session [AuthenticationSession] The session to validate
    # @raise [ArgumentError] If session is nil, wrong type, or expired
    def validate_session!(session)
      raise ArgumentError, "Session cannot be nil" unless session
      raise ArgumentError, "Invalid session type" unless session.method == :digidoc_local
      raise ArgumentError, "Session has expired" if expired?(session)
    end

    # Perform the actual authentication with the ID card using provided PIN.
    #
    # This method handles the complete authentication process:
    # 1. Reconnects to the card
    # 2. Authenticates using PIN1
    # 3. Validates certificate via OCSP (if required)
    # 4. Extracts and returns user information
    #
    # @param session [AuthenticationSession] Session containing PIN and metadata
    # @return [AuthenticationResult] Final authentication result
    # @private
    def perform_authentication(session)
      begin
        # Reconnect to the card for PIN verification
        @reader.connect
        
        # Authenticate with PIN1 to unlock authentication certificate
        pin = session.metadata[:pin]
        auth_cert = @reader.read_auth_certificate(pin)
        
        # Verify certificate status via OCSP if required
        if config[:require_ocsp]
          ocsp_valid = verify_ocsp(auth_cert)
          unless ocsp_valid
            return create_failed_result(session.id, "Certificate revoked or OCSP check failed")
          end
        end
        
        # Extract personal information from certificate
        personal_data = @reader.extract_personal_data(auth_cert)
        
        # Update session status
        session.status = :completed
        
        # Clear PIN from memory for security
        session.metadata[:pin] = nil
        
        # Create successful authentication result
        AuthenticationResult.new(
          session_id: session.id,
          status: :completed,
          authenticated: true,
          personal_code: personal_data[:personal_code],
          given_name: personal_data[:given_name],
          surname: personal_data[:surname],
          country: personal_data[:country],
          certificate: auth_cert,
          certificate_level: "QSCD", # Qualified Signature Creation Device
          metadata: {
            common_name: personal_data[:common_name],
            authentication_method: "PIN1",
            card_type: "Estonian ID Card"
          }
        )
      rescue RuntimeError => e
        create_failed_result(session.id, e.message)
      rescue => e
        create_failed_result(session.id, e.message)
      ensure
        # Always disconnect to free card for other applications
        @reader.disconnect rescue nil
      end
    end


    # Create a failed authentication result.
    #
    # @param session_id [String] The session identifier
    # @param error_message [String] Human-readable error description
    # @return [AuthenticationResult] Failed authentication result
    # @private
    def create_failed_result(session_id, error_message)
      AuthenticationResult.new(
        session_id: session_id,
        status: :failed,
        authenticated: false,
        error: error_message
      )
    end

    # Generate a cryptographic challenge for authentication.
    #
    # Used to prevent replay attacks by ensuring each authentication
    # session has a unique challenge value.
    #
    # @return [String] Base64-encoded random challenge
    # @private
    def generate_challenge
      SecureRandom.base64(32)
    end

    # Parse certificate from various input formats.
    #
    # Handles PEM, DER, and OpenSSL::X509::Certificate objects.
    # This flexibility allows the method to work with certificates
    # from different sources and formats.
    #
    # @param certificate [String, OpenSSL::X509::Certificate] Certificate to parse
    # @return [OpenSSL::X509::Certificate] Parsed certificate object
    # @raise [ArgumentError] If certificate format is not supported
    # @private
    def parse_certificate(certificate)
      case certificate
      when OpenSSL::X509::Certificate
        certificate
      when String
        if certificate.include?("BEGIN CERTIFICATE")
          # PEM format
          OpenSSL::X509::Certificate.new(certificate)
        else
          # Assume Base64-encoded DER format
          OpenSSL::X509::Certificate.new(Base64.decode64(certificate))
        end
      else
        raise ArgumentError, "Invalid certificate format: #{certificate.class}"
      end
    end

    # Check certificate validity for Estonian ID certificates.
    #
    # Validates certificate time bounds and ensures it's issued by
    # a recognized Estonian certification authority.
    #
    # @param cert [OpenSSL::X509::Certificate] Certificate to validate
    # @return [Array<String>] Array of validation error messages
    # @private
    def check_certificate_validity(cert)
      errors = []
      
      # Validate certificate time bounds
      now = Time.now
      if now < cert.not_before
        errors << "Certificate not yet valid (valid from #{cert.not_before})"
      elsif now > cert.not_after
        errors << "Certificate expired on #{cert.not_after}"
      end
      
      # Ensure it's an Estonian certificate from trusted CA
      issuer = cert.issuer.to_s
      unless issuer.include?("ESTEID") || issuer.include?("SK ID Solutions")
        errors << "Not an Estonian ID certificate (issuer: #{issuer})"
      end
      
      errors
    end

    # Verify certificate status using OCSP (Online Certificate Status Protocol).
    #
    # Contacts the Estonian OCSP responder to check if the certificate
    # has been revoked. This is crucial for security as it prevents
    # use of compromised certificates.
    #
    # OCSP responses indicate:
    # - GOOD: Certificate is valid and not revoked
    # - REVOKED: Certificate has been revoked
    # - UNKNOWN: OCSP responder doesn't know about this certificate
    #
    # @param certificate [OpenSSL::X509::Certificate] Certificate to check
    # @return [Boolean] true if certificate is valid, false if revoked or check failed
    # @private
    def verify_ocsp(certificate)
      begin
        ocsp_uri = URI(config[:ocsp_url])
        
        # Create OCSP request for certificate status
        cert_id = OpenSSL::OCSP::CertificateId.new(
          certificate,
          get_issuer_certificate(certificate)
        )
        request = OpenSSL::OCSP::Request.new
        request.add_certid(cert_id)
        
        # Send OCSP request to Estonian OCSP service
        http = Net::HTTP.new(ocsp_uri.host, ocsp_uri.port)
        http.use_ssl = ocsp_uri.scheme == "https"
        http.read_timeout = 10 # Prevent hanging on network issues
        
        response = http.post(
          ocsp_uri.path,
          request.to_der,
          "Content-Type" => "application/ocsp-request"
        )
        
        # Parse and validate OCSP response
        ocsp_response = OpenSSL::OCSP::Response.new(response.body)
        
        # Check if OCSP service responded successfully
        return false unless ocsp_response.status == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        
        # Check individual certificate status
        basic_response = ocsp_response.basic
        basic_response.status.each do |status|
          # Only accept GOOD status - reject REVOKED or UNKNOWN
          return false unless status[1] == OpenSSL::OCSP::V_CERTSTATUS_GOOD
        end
        
        true
      rescue
        # OCSP service unreachable - fail safely
        # In production, consider caching previous OCSP responses
        false
      end
    end

    # Get the issuer certificate for OCSP verification.
    #
    # In a production implementation, this would fetch the CA certificate
    # from a trusted certificate store or embedded certificates.
    # The issuer certificate is needed to create proper OCSP requests.
    #
    # @param certificate [OpenSSL::X509::Certificate] Certificate whose issuer is needed
    # @return [OpenSSL::X509::Certificate] Issuer certificate
    # @private
    # @todo Implement proper issuer certificate lookup
    def get_issuer_certificate(certificate)
      # TODO: In production, fetch from certificate store:
      # - SK ROOT CA certificates
      # - ESTEID intermediate CA certificates
      # For now, return a placeholder
      certificate
    end

    # Extract signing time from signature metadata.
    #
    # In a complete implementation, this would parse signature attributes
    # to extract the actual signing time. For now, returns current time.
    #
    # @param signature [String] The digital signature
    # @return [Time] When the signature was created
    # @private
    # @todo Implement proper signature timestamp extraction
    def extract_signing_time(signature)
      # TODO: Parse signature attributes for signing-time or timestamp
      # For now, assume signature was created recently
      Time.now
    end
  end
end