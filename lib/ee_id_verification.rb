# frozen_string_literal: true

require "securerandom"
require_relative "ee_id_verification/version"
require_relative "ee_id_verification/certificate_reader"
require_relative "ee_id_verification/models"

# Estonian ID card authentication library.
#
# Simple Ruby interface for authenticating users with Estonian ID cards
# using local card readers. Focuses on DigiDoc Local authentication only.
#
# ## Basic Usage
#
#     require 'ee_id_verification'
#
#     # Create verifier
#     verifier = EeIdVerification.new
#
#     # Check if ID card is available
#     if verifier.available?
#       # Authenticate user
#       session = verifier.authenticate
#       puts "Enter PIN1: "
#       pin = gets.chomp
#
#       result = verifier.complete_authentication(session, pin)
#       puts "Welcome #{result.full_name}!" if result.success?
#     end
#
module EeIdVerification
  # Generic error class for the gem.
  class Error < StandardError; end

  # Main verifier class
  class Verifier
    # Initialize the verifier
    def initialize
      @reader = CertificateReader.new
      @sessions = {}
    end

    # Check if Estonian ID card authentication is available
    # @return [Boolean] true if card and reader are present
    def available?
      @reader.card_present?
    end

    # Start authentication process
    # @return [AuthenticationSession] session for PIN completion
    def authenticate
      raise Error, "No Estonian ID card detected" unless available?

      session = AuthenticationSession.new(
        id: SecureRandom.hex(16),
        method: :digidoc_local,
        status: :waiting_for_pin,
        created_at: Time.now,
        expires_at: Time.now + 300
      )

      @sessions[session.id] = session
      session
    end

    # Complete authentication with PIN
    # @param session [AuthenticationSession] session from authenticate
    # @param pin [String] user's PIN1
    # @return [AuthenticationResult] final result
    def complete_authentication(session, pin)
      stored_session = @sessions[session.id]
      return failed_result(session.id, "Session not found") unless stored_session
      return failed_result(session.id, "Session expired") if session.expired?

      begin
        @reader.connect
        cert = @reader.read_auth_certificate(pin)
        personal_data = @reader.extract_personal_data(cert)

        @sessions.delete(session.id)

        AuthenticationResult.new(
          session_id: session.id,
          status: :completed,
          authenticated: true,
          personal_code: personal_data[:personal_code],
          given_name: personal_data[:given_name],
          surname: personal_data[:surname],
          country: personal_data[:country]
        )
      rescue StandardError => e
        failed_result(session.id, e.message)
      ensure
        begin
          @reader.disconnect
        rescue StandardError
          nil
        end
      end
    end

    private

    def failed_result(session_id, error_message)
      AuthenticationResult.new(
        session_id: session_id,
        status: :failed,
        authenticated: false,
        error: error_message
      )
    end
  end

  # Module-level convenience method
  def self.new
    Verifier.new
  end
end
