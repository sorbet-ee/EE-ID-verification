# frozen_string_literal: true

require_relative "models"
require_relative "digidoc_local_authenticator"
require_relative "digidoc_browser_authenticator"
require_relative "mobile_id_authenticator"
require_relative "smart_id_authenticator"

module EeIdVerification
  # Main facade for Estonian ID verification
  class Verifier
    attr_reader :config, :authenticators

    def initialize(config = {})
      @config = Configuration.new
      configure_with(config)
      initialize_authenticators
    end

    # Configure the verifier
    def configure
      yield(@config) if block_given?
      initialize_authenticators
    end

    # DigiDoc authentication via local service
    def digidoc_local_auth(params = {})
      authenticator = authenticators[:digidoc_local]
      ensure_available!(authenticator, "DigiDoc local service")
      authenticator.initiate_authentication(params)
    end

    # DigiDoc authentication via browser
    def digidoc_browser_auth(params = {})
      authenticator = authenticators[:digidoc_browser]
      ensure_available!(authenticator, "DigiDoc browser service")
      authenticator.initiate_authentication(params)
    end

    # Mobile-ID authentication
    def mobile_id_auth(params = {})
      authenticator = authenticators[:mobile_id]
      ensure_available!(authenticator, "Mobile-ID")
      authenticator.initiate_authentication(params)
    end

    # Smart-ID authentication
    def smart_id_auth(params = {})
      authenticator = authenticators[:smart_id]
      ensure_available!(authenticator, "Smart-ID")
      authenticator.initiate_authentication(params)
    end

    # Poll authentication status for any session
    def poll_status(session)
      authenticator = authenticator_for_session(session)
      authenticator.poll_status(session)
    end

    # Cancel authentication for any session
    def cancel_authentication(session)
      authenticator = authenticator_for_session(session)
      authenticator.cancel_authentication(session)
    end

    # Verify signature using appropriate method
    def verify_signature(method:, document:, signature:, certificate:)
      authenticator = authenticators[method]
      unless authenticator
        raise ArgumentError, "Unknown authentication method: #{method}"
      end
      
      authenticator.verify_signature(
        document: document,
        signature: signature,
        certificate: certificate
      )
    end

    # Check which authentication methods are available
    def available_methods
      authenticators.select { |_, auth| auth.available? }.keys
    end

    # Check if specific method is available
    def method_available?(method)
      authenticator = authenticators[method]
      authenticator&.available? || false
    end

    private

    def configure_with(options)
      options.each do |key, value|
        case key
        when :digidoc_local
          @config.digidoc_local_config = value
        when :digidoc_browser
          @config.digidoc_browser_config = value
        when :mobile_id
          @config.mobile_id_config = value
        when :smart_id
          @config.smart_id_config = value
        when :timeout
          @config.default_timeout = value
        when :language
          @config.default_language = value
        when :logger
          @config.logger = value
        when :cache_store
          @config.cache_store = value
        end
      end
    end

    def initialize_authenticators
      @authenticators = {
        digidoc_local: DigiDocLocalAuthenticator.new(
          @config.digidoc_local_config.merge(common_config)
        ),
        digidoc_browser: DigiDocBrowserAuthenticator.new(
          @config.digidoc_browser_config.merge(common_config)
        ),
        mobile_id: MobileIdAuthenticator.new(
          @config.mobile_id_config.merge(common_config)
        ),
        smart_id: SmartIdAuthenticator.new(
          @config.smart_id_config.merge(common_config)
        )
      }
    end

    def common_config
      {
        timeout: @config.default_timeout,
        language: @config.default_language,
        logger: @config.logger,
        cache_store: @config.cache_store
      }.compact
    end

    def authenticator_for_session(session)
      unless session.respond_to?(:method)
        raise ArgumentError, "Invalid session object"
      end

      authenticator = @authenticators[session.method]
      unless authenticator
        raise ArgumentError, "Unknown authentication method: #{session.method}"
      end

      authenticator
    end

    def ensure_available!(authenticator, name)
      unless authenticator.available?
        raise ServiceUnavailableError, "#{name} is not available or not configured"
      end
    end
  end
end