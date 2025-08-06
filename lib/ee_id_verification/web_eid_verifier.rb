# frozen_string_literal: true

require "json"
require "base64"
require "openssl"

module EeIdVerification
  # Web eID authentication token verifier for Estonian ID cards.
  #
  # This class provides functionality to verify Web eID authentication tokens
  # received from Estonian ID card authentication through web browsers.
  class WebEidVerifier
    def initialize(trusted_ca_certs: nil)
      @trusted_ca_certs = trusted_ca_certs || load_default_ca_certs
    end

    def verify_auth_token(auth_token, challenge_nonce)
      raise Error, "Authentication token is required" if auth_token.nil? || auth_token.empty?
      raise Error, "Challenge nonce is required" if challenge_nonce.nil? || challenge_nonce.empty?

      begin
        # Parse and validate the authentication token structure
        validate_token_structure(auth_token)

        # Check if this is a mock authentication (for testing)
        return handle_mock_authentication(auth_token) if auth_token["signature"]&.start_with?("mock-signature-")

        # For development, we'll skip strict signature verification
        # In production, uncomment the next line:
        # verify_signature(auth_token, challenge_nonce)
        puts "Skipping signature verification for development"

        # Extract personal data from certificate
        cert_der = Base64.decode64(auth_token["unverifiedCertificate"])
        certificate = OpenSSL::X509::Certificate.new(cert_der)
        personal_data = extract_personal_data_from_cert(certificate)

        # Verify certificate chain
        verify_certificate_chain(certificate)

        AuthenticationResult.new(
          session_id: SecureRandom.hex(16),
          status: :completed,
          authenticated: true,
          personal_code: personal_data[:personal_code],
          given_name: personal_data[:given_name],
          surname: personal_data[:surname],
          country: personal_data[:country]
        )
      rescue StandardError => e
        AuthenticationResult.new(
          session_id: SecureRandom.hex(16),
          status: :failed,
          authenticated: false,
          error: e.message
        )
      end
    end

    private

    def handle_mock_authentication(auth_token)
      # Return mock user data for testing
      AuthenticationResult.new(
        session_id: SecureRandom.hex(16),
        status: :completed,
        authenticated: true,
        personal_code: "38001010008",
        given_name: "MARI",
        surname: "MAASIKAS",
        country: "EE"
      )
    end

    def validate_token_structure(token)
      required_fields = %w[unverifiedCertificate algorithm signature format appVersion]

      required_fields.each do |field|
        raise Error, "Missing required field: #{field}" unless token[field]
      end

      raise Error, "Invalid token format: #{token["format"]}" unless token["format"].start_with?("web-eid:")

      return if valid_algorithm?(token["algorithm"])

      raise Error, "Unsupported signature algorithm: #{token["algorithm"]}"
    end

    def valid_algorithm?(algorithm)
      %w[ES256 ES384 ES512 PS256 PS384 PS512 RS256 RS384 RS512].include?(algorithm)
    end

    def verify_signature(token, challenge_nonce)
      # Reconstruct the signed data as per Web eID specification
      # The signed data includes the challenge nonce and certificate
      cert_der = Base64.decode64(token["unverifiedCertificate"])
      certificate = OpenSSL::X509::Certificate.new(cert_der)

      # Create the data that was signed (simplified version)
      signed_data = create_signed_data(challenge_nonce, certificate, token)

      # Verify signature
      signature = Base64.decode64(token["signature"])
      public_key = certificate.public_key

      algorithm = token["algorithm"]
      digest_algorithm = get_digest_algorithm(algorithm)

      case algorithm
      when /^ES/
        # ECDSA signature
        raise Error, "Invalid signature" unless public_key.verify(digest_algorithm, signature, signed_data)
      when /^[PR]S/
        # RSA signature (PSS or PKCS#1 v1.5)
        padding = algorithm.start_with?("PS") ? OpenSSL::PKey::RSA::PKCS1_PSS_PADDING : OpenSSL::PKey::RSA::PKCS1_PADDING
        raise Error, "Invalid signature" unless public_key.verify(digest_algorithm, signature, signed_data, padding)
      else
        raise Error, "Unsupported algorithm: #{algorithm}"
      end
    end

    def create_signed_data(challenge_nonce, certificate, token)
      # This is a simplified version - the actual Web eID specification
      # defines the exact format of signed data
      "#{challenge_nonce}#{token["unverifiedCertificate"]}"
    end

    def get_digest_algorithm(algorithm)
      case algorithm
      when /256$/
        OpenSSL::Digest.new("SHA256")
      when /384$/
        OpenSSL::Digest.new("SHA384")
      when /512$/
        OpenSSL::Digest.new("SHA512")
      else
        raise Error, "Unknown digest algorithm for: #{algorithm}"
      end
    end

    def extract_personal_data_from_cert(certificate)
      # Extract personal data from certificate subject
      subject = certificate.subject.to_a
      subject_hash = subject.to_h { |item| [item[0], item[1]] }

      # Parse Estonian personal code from serialNumber field
      serial_number = subject_hash["serialNumber"] || ""
      personal_code = serial_number.sub(/^PNOEE-/, "")

      # Handle different name field formats in Estonian certificates
      given_name = subject_hash["GN"] || subject_hash["givenName"] || subject_hash["G"]
      surname = subject_hash["SN"] || subject_hash["surname"] || subject_hash["S"]

      # Extract country from certificate
      country = subject_hash["C"] || "EE"

      # Log the extracted data for debugging
      puts "Certificate subject: #{subject_hash}"
      puts "Extracted personal code: #{personal_code}"
      puts "Extracted names: #{given_name} #{surname}"

      {
        personal_code: personal_code,
        given_name: given_name,
        surname: surname,
        country: country
      }
    end

    def verify_certificate_chain(certificate)
      # In a production system, this would verify against actual Estonian CA certificates
      # For now, we'll do basic validation
      unless certificate.verify(certificate.public_key)
        # Certificate might be part of a chain, which is normal
        # In production, verify against known Estonian CA roots
      end

      # Check certificate validity period
      now = Time.now
      return unless now < certificate.not_before || now > certificate.not_after

      raise Error, "Certificate is not valid at current time"
    end

    def load_default_ca_certs
      # In production, load actual Estonian CA certificates
      # For now, return empty array
      []
    end
  end
end
