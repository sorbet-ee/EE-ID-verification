# frozen_string_literal: true

module EeIdVerification
  # Authentication session tracking
  class AuthenticationSession
    attr_accessor :id, :method, :status, :created_at, :expires_at,
                  :phone_number, :personal_code, :document_number,
                  :verification_code, :challenge, :origin, :country,
                  :language, :interaction_type, :metadata

    def initialize(attributes = {})
      attributes.each do |key, value|
        send("#{key}=", value) if respond_to?("#{key}=")
      end
      @metadata ||= {}
    end

    def expired?
      expires_at && expires_at < Time.now.utc
    end

    def pending?
      status == :pending
    end

    def completed?
      status == :completed
    end

    def failed?
      status == :failed
    end
  end

  # Result of authentication attempt
  class AuthenticationResult
    attr_accessor :session_id, :status, :authenticated, :error,
                  :personal_code, :given_name, :surname, :country,
                  :date_of_birth, :certificate, :certificate_level,
                  :verification_code, :interaction_type, :metadata

    def initialize(attributes = {})
      attributes.each do |key, value|
        send("#{key}=", value) if respond_to?("#{key}=")
      end
      @authenticated ||= false
      @metadata ||= {}
    end

    def authenticated?
      authenticated == true
    end

    def full_name
      "#{given_name} #{surname}".strip if given_name || surname
    end

    def success?
      authenticated? && !error
    end

    def failure?
      !success?
    end
  end

  # Result of signature verification
  class SignatureVerificationResult
    attr_accessor :valid, :signer_certificate, :signer_info,
                  :signed_at, :signature_level, :errors, :warnings

    def initialize(attributes = {})
      attributes.each do |key, value|
        send("#{key}=", value) if respond_to?("#{key}=")
      end
      @valid ||= false
      @errors ||= []
      @warnings ||= []
    end

    def valid?
      valid == true && errors.empty?
    end

    def invalid?
      !valid?
    end
  end

  # Certificate information
  class CertificateInfo
    attr_accessor :subject, :issuer, :serial_number, :not_before,
                  :not_after, :public_key, :signature_algorithm,
                  :key_usage, :extended_key_usage, :policies

    def initialize(attributes = {})
      attributes.each do |key, value|
        send("#{key}=", value) if respond_to?("#{key}=")
      end
    end

    def valid_at?(time = Time.now)
      time.between?(not_before, not_after)
    end

    def expired?
      Time.now > not_after
    end

    def not_yet_valid?
      Time.now < not_before
    end
  end

  # Configuration holder
  class Configuration
    attr_accessor :digidoc_local_config, :digidoc_browser_config,
                  :mobile_id_config, :smart_id_config,
                  :default_timeout, :default_language,
                  :logger, :cache_store

    def initialize
      @digidoc_local_config = {}
      @digidoc_browser_config = {}
      @mobile_id_config = {}
      @smart_id_config = {}
      @default_timeout = 300 # 5 minutes
      @default_language = "en"
      @logger = nil
      @cache_store = nil
    end
  end

  # Custom exception classes for Estonian e-identity verification.
  #
  # Provides a hierarchy of specific exceptions that can be caught and handled
  # appropriately by calling applications. Each exception type indicates a
  # specific category of problem that may require different handling.

  # Base exception class for all e-identity verification errors.
  #
  # All other custom exceptions inherit from this class, allowing callers
  # to catch all library-specific errors with a single rescue clause.
  class VerificationError < StandardError; end

  # Configuration-related errors.
  #
  # Raised when required configuration is missing, invalid, or incompatible.
  # These errors typically occur during initialization and indicate setup problems.
  #
  # @example
  #   raise ConfigurationError, "Mobile-ID service URL is required"
  class ConfigurationError < VerificationError; end

  # Authentication process errors.
  #
  # Raised when authentication fails due to user actions, invalid credentials,
  # or service-side problems during the authentication process.
  #
  # @example
  #   raise AuthenticationError, "Invalid PIN - authentication failed"
  class AuthenticationError < VerificationError; end

  # Authentication timeout errors.
  #
  # Specific type of authentication error that occurs when users don't
  # complete authentication within the configured timeout period.
  #
  # @example
  #   raise TimeoutError, "User did not respond within 300 seconds"
  class TimeoutError < AuthenticationError; end

  # Certificate-related errors.
  #
  # Raised when certificate validation fails, certificates are expired,
  # revoked, or otherwise invalid for the requested operation.
  #
  # @example
  #   raise CertificateError, "Certificate has been revoked"
  class CertificateError < VerificationError; end

  # Service availability errors.
  #
  # Raised when external services (Mobile-ID, Smart-ID, OCSP) are unavailable
  # or not properly configured for use.
  #
  # @example
  #   raise ServiceUnavailableError, "Mobile-ID service is not available"
  class ServiceUnavailableError < VerificationError; end
end
