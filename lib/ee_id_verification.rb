# frozen_string_literal: true

require_relative "ee_id_verification/version"
require_relative "ee_id_verification/verifier"
require_relative "ee_id_verification/models"

module EeIdVerification
  class Error < StandardError; end

  # Main entry point for the gem
  class << self
    # Create a new verifier instance
    # @param config [Hash] Configuration options
    # @return [Verifier] Configured verifier instance
    def new(config = {})
      Verifier.new(config)
    end

    # Configure global defaults
    # @yield [Configuration] Configuration object
    def configure
      @configuration ||= Configuration.new
      yield(@configuration) if block_given?
      @configuration
    end

    # Get current configuration
    # @return [Configuration]
    def configuration
      @configuration ||= Configuration.new
    end
  end
end