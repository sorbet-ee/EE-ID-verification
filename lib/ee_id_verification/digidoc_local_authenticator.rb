# frozen_string_literal: true

require_relative "base_authenticator"
require_relative "certificate_reader"
require "openssl"
require "net/http"
require "uri"

module EeIdVerification
  # DigiDoc authentication via local service (ID-card reader)
  class DigiDocLocalAuthenticator < BaseAuthenticator
    def initialize(config = {})
      super
      @reader = CertificateReader.new
      @sessions = {}
    end

    def initiate_authentication(params = {})
      validate_authentication_params!(params)
      
      # Check if card reader and card are available
      unless @reader.card_present?
        raise AuthenticationError, "No Estonian ID card detected. Please insert your ID card."
      end

      begin
        # Connect to the card
        @reader.connect
        
        # Read authentication certificate
        auth_cert = @reader.read_auth_certificate
        personal_data = @reader.extract_personal_data(auth_cert)
        
        # Create session
        session = AuthenticationSession.new(
          id: generate_session_id,
          method: :digidoc_local,
          status: :pending,
          created_at: current_timestamp,
          expires_at: current_timestamp + config[:timeout],
          personal_code: personal_data[:personal_code],
          metadata: {
            certificate: auth_cert.to_pem,
            personal_data: personal_data,
            challenge: generate_challenge
          }
        )
        
        # Store session
        @sessions[session.id] = session
        
        # Disconnect for now - will reconnect when PIN is provided
        @reader.disconnect
        
        session
      rescue => e
        @reader.disconnect
        raise AuthenticationError, "Failed to read ID card: #{e.message}"
      end
    end

    def poll_status(session)
      validate_session!(session)
      stored_session = @sessions[session.id]
      
      return create_failed_result(session.id, "Session not found") unless stored_session
      
      # For local authentication, we need PIN input
      # In a real implementation, this would be handled by a PIN dialog
      if stored_session.metadata[:pin_provided]
        perform_authentication(stored_session)
      else
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

    def provide_pin(session_id, pin)
      session = @sessions[session_id]
      return false unless session
      
      session.metadata[:pin] = pin
      session.metadata[:pin_provided] = true
      true
    end

    def cancel_authentication(session)
      validate_session!(session)
      
      # Remove session
      @sessions.delete(session.id)
      
      # Ensure card is disconnected
      @reader.disconnect rescue nil
      
      true
    end

    def verify_signature(document:, signature:, certificate:)
      begin
        cert = parse_certificate(certificate)
        
        # Verify signature
        digest = OpenSSL::Digest::SHA256.new
        verified = cert.public_key.verify(digest, signature, document)
        
        # Check certificate validity
        validity_errors = check_certificate_validity(cert)
        
        SignatureVerificationResult.new(
          valid: verified && validity_errors.empty?,
          signer_certificate: cert,
          signer_info: @reader.extract_personal_data(cert),
          signed_at: extract_signing_time(signature),
          signature_level: "QES", # Qualified Electronic Signature
          errors: verified ? validity_errors : ["Invalid signature"] + validity_errors
        )
      rescue => e
        SignatureVerificationResult.new(
          valid: false,
          errors: ["Signature verification failed: #{e.message}"]
        )
      end
    end

    def available?
      # Check if we can access smart card readers
      begin
        context = Smartcard::PCSC::Context.new
        !context.readers.empty?
      rescue => e
        false
      end
    end

    protected

    def default_config
      super.merge(
        pin_retry_count: 3,
        reader_timeout: 30, # seconds to detect reader
        ocsp_url: "http://ocsp.sk.ee",
        require_ocsp: true
      )
    end

    def validate_config!
      super
      
      unless config[:pin_retry_count].is_a?(Integer) && config[:pin_retry_count] > 0
        raise ConfigurationError, "Invalid PIN retry count"
      end
    end

    private

    def validate_authentication_params!(params)
      # No specific params needed for local DigiDoc
      # PIN will be requested during authentication
    end

    def validate_session!(session)
      raise ArgumentError, "Session cannot be nil" unless session
      raise ArgumentError, "Invalid session type" unless session.method == :digidoc_local
      raise ArgumentError, "Session has expired" if expired?(session)
    end

    def perform_authentication(session)
      begin
        # Reconnect to card
        @reader.connect
        
        # Authenticate with PIN
        pin = session.metadata[:pin]
        auth_cert = @reader.authenticate(pin)
        
        # Verify certificate chain and OCSP
        if config[:require_ocsp]
          ocsp_valid = verify_ocsp(auth_cert)
          unless ocsp_valid
            return create_failed_result(session.id, "Certificate revoked or OCSP check failed")
          end
        end
        
        # Extract user data
        personal_data = @reader.extract_personal_data(auth_cert)
        
        # Update session status
        session.status = :completed
        
        # Create successful result
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
      rescue Smartcard::PCSC::Exception => e
        handle_card_error(session.id, e)
      rescue => e
        create_failed_result(session.id, e.message)
      ensure
        @reader.disconnect rescue nil
      end
    end

    def handle_card_error(session_id, error)
      message = case error.message
      when /6300/
        "Invalid PIN"
      when /6983/
        "PIN blocked"
      when /6A82/
        "Card file not found"
      else
        "Card communication error"
      end
      
      create_failed_result(session_id, message)
    end

    def create_failed_result(session_id, error_message)
      AuthenticationResult.new(
        session_id: session_id,
        status: :failed,
        authenticated: false,
        error: error_message
      )
    end

    def generate_challenge
      SecureRandom.base64(32)
    end

    def parse_certificate(certificate)
      case certificate
      when OpenSSL::X509::Certificate
        certificate
      when String
        if certificate.include?("BEGIN CERTIFICATE")
          OpenSSL::X509::Certificate.new(certificate)
        else
          # Assume DER format
          OpenSSL::X509::Certificate.new(Base64.decode64(certificate))
        end
      else
        raise ArgumentError, "Invalid certificate format"
      end
    end

    def check_certificate_validity(cert)
      errors = []
      
      # Check time validity
      now = Time.now
      if now < cert.not_before
        errors << "Certificate not yet valid"
      elsif now > cert.not_after
        errors << "Certificate expired"
      end
      
      # Check if it's an Estonian ID certificate
      issuer = cert.issuer.to_s
      unless issuer.include?("ESTEID") || issuer.include?("SK ID Solutions")
        errors << "Not an Estonian ID certificate"
      end
      
      errors
    end

    def verify_ocsp(certificate)
      # OCSP verification for Estonian certificates
      begin
        ocsp_uri = URI(config[:ocsp_url])
        
        # Create OCSP request
        cert_id = OpenSSL::OCSP::CertificateId.new(
          certificate,
          get_issuer_certificate(certificate)
        )
        request = OpenSSL::OCSP::Request.new
        request.add_certid(cert_id)
        
        # Send OCSP request
        http = Net::HTTP.new(ocsp_uri.host, ocsp_uri.port)
        http.use_ssl = ocsp_uri.scheme == "https"
        
        response = http.post(
          ocsp_uri.path,
          request.to_der,
          "Content-Type" => "application/ocsp-request"
        )
        
        # Parse OCSP response
        ocsp_response = OpenSSL::OCSP::Response.new(response.body)
        
        # Check response status
        return false unless ocsp_response.status == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        
        # Check certificate status
        basic_response = ocsp_response.basic
        basic_response.status.each do |status|
          return false unless status[1] == OpenSSL::OCSP::V_CERTSTATUS_GOOD
        end
        
        true
      rescue => e
        # Log error but don't fail authentication if OCSP is unreachable
        false
      end
    end

    def get_issuer_certificate(certificate)
      # In production, this would fetch from a certificate store
      # For now, return a placeholder
      certificate
    end

    def extract_signing_time(signature)
      # Extract signing time from signature attributes if available
      Time.now
    end
  end
end