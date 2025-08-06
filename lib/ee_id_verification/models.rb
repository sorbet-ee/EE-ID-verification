# frozen_string_literal: true

module EeIdVerification
  # Authentication session model for Estonian ID card authentication workflow.
  #
  # This class represents an active authentication session during the two-phase
  # authentication process used by Estonian ID cards. The authentication workflow
  # is designed to be secure and user-friendly:
  #
  # 1. Session Creation: When authentication starts, a session is created with
  #    a unique ID and initial status of :waiting_for_pin
  # 2. PIN Entry: User provides PIN1 which is verified directly on the card
  # 3. Session Completion: Upon successful PIN verification, session status
  #    changes to :completed and personal data is extracted
  #
  # The session-based approach provides several benefits:
  # - Separation of concerns between session management and authentication logic
  # - Timeout handling to prevent indefinite waiting for PIN entry
  # - State tracking for complex authentication workflows
  # - Security through session expiration and cleanup
  #
  # Session states:
  # - :waiting_for_pin - Session created, waiting for user PIN input
  # - :completed - Authentication successful, personal data available
  # - :failed - Authentication failed (wrong PIN, card error, etc.)
  # - :expired - Session timed out waiting for PIN entry
  #
  # @example Creating and managing a session
  #   session = AuthenticationSession.new(
  #     id: SecureRandom.uuid,
  #     method: :digidoc_local,
  #     status: :waiting_for_pin,
  #     created_at: Time.now,
  #     expires_at: Time.now + 300  # 5 minutes
  #   )
  #
  #   # Check if session is still valid
  #   if session.expired?
  #     puts "Session expired, please try again"
  #   end
  class AuthenticationSession
    # Session attributes for tracking authentication state
    # @!attribute [rw] id
    #   @return [String] Unique session identifier (typically UUID)
    # @!attribute [rw] method
    #   @return [Symbol] Authentication method used (:digidoc_local)
    # @!attribute [rw] status
    #   @return [Symbol] Current session status (:waiting_for_pin, :completed, :failed, :expired)
    # @!attribute [rw] created_at
    #   @return [Time] When the session was created
    # @!attribute [rw] expires_at
    #   @return [Time, nil] When the session expires (nil for no expiration)
    attr_accessor :id, :method, :status, :created_at, :expires_at

    # Initialize a new authentication session with the provided attributes.
    #
    # This constructor uses a flexible attribute assignment approach that allows
    # setting any of the session attributes through a hash. This pattern provides
    # flexibility for different authentication scenarios while maintaining a
    # clean interface.
    #
    # @param attributes [Hash] Session attributes to set
    # @option attributes [String] :id Unique session identifier
    # @option attributes [Symbol] :method Authentication method
    # @option attributes [Symbol] :status Initial session status
    # @option attributes [Time] :created_at Session creation time
    # @option attributes [Time] :expires_at Session expiration time
    # @example
    #   session = AuthenticationSession.new(
    #     id: "auth-123",
    #     status: :waiting_for_pin,
    #     created_at: Time.now
    #   )
    def initialize(attributes = {})
      # Dynamically set attributes using setter methods
      # This approach ensures only valid attributes are set and leverages
      # any custom setter logic that might be added in the future
      attributes.each do |key, value|
        send("#{key}=", value) if respond_to?("#{key}=")
      end
    end

    # Check if the authentication session has expired.
    #
    # Sessions expire to prevent security issues from long-lived authentication
    # attempts and to free up system resources. An expired session cannot be
    # used to complete authentication and should be discarded.
    #
    # The expiration check handles cases where no expiration time is set
    # (nil expires_at means the session never expires automatically).
    #
    # @return [Boolean] true if session has expired, false otherwise
    # @example
    #   session = AuthenticationSession.new(expires_at: Time.now - 60)
    #   puts "Expired!" if session.expired?
    def expired?
      expires_at && expires_at < Time.now
    end
  end

  # Authentication result model containing the outcome of Estonian ID card authentication.
  #
  # This class encapsulates all information returned from a completed (or failed)
  # authentication attempt. It provides a comprehensive view of the authentication
  # outcome including:
  #
  # - Authentication status and success/failure indicators
  # - Personal information extracted from the ID card certificate
  # - Error information if authentication failed
  # - Convenient methods for checking authentication state
  #
  # The result object serves as the primary interface between the authentication
  # system and consuming applications, providing all necessary information to
  # make authorization decisions and display user information.
  #
  # Personal data fields match those available in Estonian ID card certificates:
  # - personal_code: 11-digit Estonian personal identification code
  # - given_name: User's first/given name(s)
  # - surname: User's family/last name
  # - country: Country code (always "EE" for Estonian cards)
  #
  # @example Successful authentication result
  #   result = AuthenticationResult.new(
  #     session_id: "auth-123",
  #     status: :completed,
  #     authenticated: true,
  #     personal_code: "38001010008",
  #     given_name: "MARI",
  #     surname: "MAASIKAS",
  #     country: "EE"
  #   )
  #
  #   if result.success?
  #     puts "Welcome, #{result.full_name}!"
  #     log_successful_login(result.personal_code)
  #   end
  #
  # @example Failed authentication result
  #   result = AuthenticationResult.new(
  #     session_id: "auth-456",
  #     status: :failed,
  #     authenticated: false,
  #     error: "Invalid PIN1"
  #   )
  #
  #   if result.failure?
  #     puts "Authentication failed: #{result.error}"
  #   end
  class AuthenticationResult
    # Result attributes containing authentication outcome and personal data
    # @!attribute [rw] session_id
    #   @return [String] ID of the session this result belongs to
    # @!attribute [rw] status
    #   @return [Symbol] Final authentication status (:completed, :failed, etc.)
    # @!attribute [rw] authenticated
    #   @return [Boolean] Whether authentication was successful
    # @!attribute [rw] error
    #   @return [String, nil] Error message if authentication failed
    # @!attribute [rw] personal_code
    #   @return [String, nil] Estonian 11-digit personal identification code
    # @!attribute [rw] given_name
    #   @return [String, nil] User's first/given name from certificate
    # @!attribute [rw] surname
    #   @return [String, nil] User's family/last name from certificate
    # @!attribute [rw] country
    #   @return [String, nil] Country code from certificate (typically "EE")
    attr_accessor :session_id, :status, :authenticated, :error,
                  :personal_code, :given_name, :surname, :country

    # Initialize a new authentication result with the provided attributes.
    #
    # Similar to AuthenticationSession, this uses flexible attribute assignment
    # to allow setting result fields through a hash. The authenticated flag
    # defaults to false to ensure secure defaults - authentication must be
    # explicitly marked as successful.
    #
    # @param attributes [Hash] Result attributes to set
    # @option attributes [String] :session_id Associated session ID
    # @option attributes [Symbol] :status Authentication status
    # @option attributes [Boolean] :authenticated Success flag
    # @option attributes [String] :error Error message for failures
    # @option attributes [String] :personal_code Estonian personal code
    # @option attributes [String] :given_name User's first name
    # @option attributes [String] :surname User's last name
    # @option attributes [String] :country Country code
    # @example
    #   result = AuthenticationResult.new(
    #     authenticated: true,
    #     personal_code: "38001010008"
    #   )
    def initialize(attributes = {})
      # Set provided attributes using dynamic attribute assignment
      attributes.each do |key, value|
        send("#{key}=", value) if respond_to?("#{key}=")
      end

      # Ensure authenticated defaults to false for security
      # Authentication must be explicitly set to true to be considered successful
      @authenticated ||= false
    end

    # Check if the user was successfully authenticated.
    #
    # This is the primary method for determining authentication success.
    # It directly returns the authenticated flag which should only be true
    # if PIN verification succeeded and personal data was extracted.
    #
    # @return [Boolean] true if authentication was successful
    def authenticated?
      @authenticated
    end

    # Check if authentication was successful and no errors occurred.
    #
    # This method provides a more comprehensive success check than authenticated?
    # by also ensuring no error occurred during the process. This catches cases
    # where authentication might be marked as successful but an error was
    # encountered during personal data extraction.
    #
    # @return [Boolean] true if authenticated and no error present
    # @example
    #   if result.success?
    #     grant_access(result.personal_code)
    #   else
    #     show_error_message(result.error)
    #   end
    def success?
      authenticated? && !error
    end

    # Check if authentication failed or encountered an error.
    #
    # This is the inverse of success? and provides a convenient way to check
    # for any kind of authentication failure. Useful for error handling and
    # conditional logic in authentication flows.
    #
    # @return [Boolean] true if authentication failed or error occurred
    def failure?
      !success?
    end

    # Get the user's full name by combining given name and surname.
    #
    # Estonian ID certificates store names in separate fields (given name and
    # surname) following international X.509 certificate standards. This method
    # provides a convenient way to get the complete name for display purposes.
    #
    # The method handles various edge cases:
    # - Missing given name or surname (returns partial name)
    # - Both names missing (returns nil)
    # - Extra whitespace (cleaned up by join)
    #
    # @return [String, nil] Full name or nil if no name components available
    # @example
    #   result.given_name = "MARI"
    #   result.surname = "MAASIKAS"
    #   puts result.full_name  # => "MARI MAASIKAS"
    #
    #   result.given_name = nil
    #   result.surname = "MAASIKAS"
    #   puts result.full_name  # => "MAASIKAS"
    def full_name
      # Return nil if neither name component is available
      return nil unless given_name || surname

      # Combine available name components, filtering out nil values
      # compact removes nil values, join combines with space
      [given_name, surname].compact.join(" ")
    end
  end
end
