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
      time >= not_before && time <= not_after
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

  # Custom errors
  class VerificationError < StandardError; end
  class ConfigurationError < VerificationError; end
  class AuthenticationError < VerificationError; end
  class TimeoutError < AuthenticationError; end
  class CertificateError < VerificationError; end
  class ServiceUnavailableError < VerificationError; end
end