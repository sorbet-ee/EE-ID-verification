# frozen_string_literal: true

require "openssl"
require "pkcs11"
require "date"

module EeIdVerification
  # Estonian ID card certificate reader using PKCS#11 interface.
  #
  # This class provides secure access to Estonian ID cards through the industry-standard
  # PKCS#11 cryptographic interface. It handles all the low-level complexity of:
  # - PKCS#11 library loading and initialization
  # - Smart card slot detection and enumeration
  # - Estonian ID card identification and connection
  # - Certificate reading and X.509 parsing
  # - Personal data extraction from certificate fields
  # - Estonian personal code parsing and validation
  #
  # The implementation uses OpenSC (Open Smart Card development libraries) which
  # provides PKCS#11 drivers for Estonian ID cards. This is the recommended and
  # officially supported method for accessing Estonian e-identity infrastructure.
  #
  # Security considerations:
  # - Uses hardware security module (HSM) on the card for all cryptographic operations
  # - PIN verification is performed directly on the card, PIN never leaves the card
  # - Certificates are read from secure storage on the card
  # - Supports shared PKCS#11 library instance to avoid conflicts with other applications
  #
  # @example Basic usage
  #   reader = CertificateReader.new
  #   if reader.card_present?
  #     reader.connect
  #     cert = reader.read_auth_certificate("1234")  # PIN1
  #     personal_data = reader.extract_personal_data(cert)
  #     puts "Hello #{personal_data[:given_name]}!"
  #     reader.disconnect
  #   end
  class CertificateReader
    # Common PKCS#11 library locations across different operating systems.
    # These paths are searched in order to find the OpenSC PKCS#11 library.
    # OpenSC provides drivers for Estonian ID cards and many other smart cards.
    #
    # Path priority:
    # 1. Homebrew installations on macOS (most common for developers)
    # 2. System installations on Linux
    # 3. Alternative installation locations
    PKCS11_LIBRARY_PATHS = [
      "/opt/homebrew/lib/opensc-pkcs11.so",           # Homebrew on Apple Silicon
      "/opt/homebrew/lib/pkcs11/opensc-pkcs11.so",    # Alternative Homebrew path
      "/usr/local/lib/opensc-pkcs11.so",              # Homebrew on Intel Mac
      "/usr/lib/opensc-pkcs11.so",                    # Ubuntu/Debian system install
      "/opt/local/lib/opensc-pkcs11.so",              # MacPorts installation
      "/System/Library/OpenSC/lib/opensc-pkcs11.so", # macOS system install
      "/usr/local/lib/pkcs11/opensc-pkcs11.so"       # Alternative Linux path
    ].freeze

    # Initialize a new certificate reader instance.
    # Sets up internal state but does not connect to any card or load PKCS#11 library.
    # Connection and library loading happens lazily when needed.
    def initialize
      @pkcs11 = nil      # PKCS#11 library instance (loaded on demand)
      @slot = nil        # Smart card slot containing Estonian ID card
      @session = nil     # Active PKCS#11 session for card communication
      @connected = false # Connection state flag
    end

    # Check if Estonian ID card is present in any connected card reader.
    #
    # This method performs card detection by:
    # 1. Loading the PKCS#11 library if not already loaded
    # 2. Enumerating all smart card slots with tokens present
    # 3. Checking each slot's token info for Estonian ID card markers
    # 4. Returning true if at least one Estonian ID card is found
    #
    # The detection is safe and non-intrusive - it doesn't require PIN entry
    # or establish any connections to the card.
    #
    # @return [Boolean] true if Estonian ID card is detected, false otherwise
    # @example
    #   reader = CertificateReader.new
    #   if reader.card_present?
    #     puts "Estonian ID card detected!"
    #   else
    #     puts "Please insert your Estonian ID card"
    #   end
    def card_present?
      load_pkcs11_library
      return false unless @pkcs11

      # Get all slots that currently have tokens (cards) inserted
      slots = @pkcs11.slots(true)
      esteid_slots = find_esteid_slots(slots)
      !esteid_slots.empty?
    rescue StandardError
      # If anything goes wrong during detection, assume no card present
      # This prevents crashes when card readers are disconnected, etc.
      false
    end

    # Connect to the first available Estonian ID card.
    #
    # This method establishes a connection to an Estonian ID card by:
    # 1. Loading the PKCS#11 library
    # 2. Finding all slots with Estonian ID cards
    # 3. Selecting the first available card
    # 4. Preparing for future certificate reading operations
    #
    # Note: This method does not require PIN entry - it only establishes
    # the connection to the card. PIN will be required later when reading
    # certificates that require authentication.
    #
    # @return [Boolean] true if connection successful
    # @raise [RuntimeError] if PKCS#11 library not available
    # @raise [RuntimeError] if no Estonian ID card found
    # @example
    #   reader = CertificateReader.new
    #   reader.connect
    #   puts "Connected to Estonian ID card"
    def connect
      load_pkcs11_library
      raise "PKCS#11 library not available" unless @pkcs11

      # Find all slots with tokens and filter for Estonian ID cards
      slots = @pkcs11.slots(true)
      esteid_slots = find_esteid_slots(slots)
      raise "No Estonian ID card found" if esteid_slots.empty?

      # Use the first available Estonian ID card
      # In most cases users have only one card reader anyway
      @slot = esteid_slots.first
      @connected = true
      true
    end

    # Disconnect from the Estonian ID card and clean up resources.
    #
    # This method performs a clean shutdown by:
    # 1. Logging out from any active PKCS#11 sessions
    # 2. Closing all open sessions
    # 3. Cleaning up PKCS#11 library resources
    # 4. Resetting internal state
    #
    # It's important to disconnect properly to:
    # - Free the card for use by other applications
    # - Prevent resource leaks
    # - Ensure security by ending authenticated sessions
    #
    # All operations are wrapped in error handling to ensure cleanup
    # happens even if individual steps fail.
    def disconnect
      # Attempt to logout from PKCS#11 session (clears authentication state)
      begin
        @session&.logout
      rescue StandardError
        nil # Ignore logout errors - session might not be authenticated
      end

      # Close the PKCS#11 session
      begin
        @session&.close
      rescue StandardError
        nil # Ignore close errors - session might already be closed
      end

      # Reset session and connection state
      @session = nil
      @connected = false

      # Close the PKCS#11 library
      begin
        @pkcs11&.close
      rescue StandardError
        nil # Ignore close errors - library might already be closed
      end

      # Reset library state
      @pkcs11 = nil
    end

    # Check if currently connected to an Estonian ID card.
    #
    # @return [Boolean] true if connected and ready for operations
    def connected?
      @connected && @pkcs11 && @slot
    end

    # Read authentication certificate from Estonian ID card using PIN1.
    #
    # This method performs secure certificate reading by:
    # 1. Ensuring we're connected to a card
    # 2. Opening a PKCS#11 session with the card
    # 3. Authenticating with PIN1 (this happens on the card for security)
    # 4. Locating the authentication certificate
    # 5. Reading and parsing the X.509 certificate
    #
    # The authentication certificate is used for identity verification and
    # contains the user's personal information in the certificate subject.
    #
    # Security notes:
    # - PIN verification happens directly on the card's secure element
    # - PIN is never transmitted or stored in memory
    # - Failed PIN attempts are tracked by the card (3 attempts max)
    # - After 3 failed attempts, PIN1 becomes blocked
    #
    # @param pin [String] User's PIN1 (typically 4 digits, but can be longer)
    # @return [OpenSSL::X509::Certificate] The authentication certificate
    # @raise [RuntimeError] if not connected to card
    # @raise [RuntimeError] if PIN is incorrect
    # @raise [RuntimeError] if PIN is blocked
    # @raise [RuntimeError] if certificate not found
    # @example
    #   reader = CertificateReader.new
    #   reader.connect
    #   cert = reader.read_auth_certificate("1234")
    #   puts "Certificate valid until: #{cert.not_after}"
    def read_auth_certificate(pin)
      ensure_connected!

      # Open a session with the card if not already open
      @session ||= @slot.open

      # Authenticate with PIN1 - this happens securely on the card
      @session.login(PKCS11::CKU_USER, pin)

      # Find the authentication certificate among all certificates on card
      cert = find_auth_certificate
      raise "Authentication certificate not found" unless cert

      cert
    rescue PKCS11::CKR_PIN_INCORRECT
      raise "Invalid PIN1"
    rescue PKCS11::CKR_PIN_LOCKED
      raise "PIN1 is blocked"
    end

    # Extract personal data from an Estonian ID card certificate.
    #
    # Estonian ID certificates contain personal information in the X.509
    # certificate subject fields using standard and Estonian-specific field names:
    # - GN/givenName: Given name (first name)
    # - SN/surname: Surname (family name)
    # - serialNumber: Personal identification code (with PNOEE- prefix)
    # - C/countryName: Country code (always "EE" for Estonian cards)
    # - CN/commonName: Full name
    #
    # @param certificate [OpenSSL::X509::Certificate] X.509 certificate from card
    # @return [Hash] Personal data with symbolized keys
    # @option return [String] :given_name User's first name
    # @option return [String] :surname User's family name
    # @option return [String] :personal_code 11-digit Estonian personal code
    # @option return [String] :country Country code ("EE")
    # @option return [String] :common_name Full name as on certificate
    # @example
    #   cert = reader.read_auth_certificate("1234")
    #   data = reader.extract_personal_data(cert)
    #   puts "Name: #{data[:given_name]} #{data[:surname]}"
    #   puts "Personal code: #{data[:personal_code]}"
    def extract_personal_data(certificate)
      # Parse certificate subject into a hash for easy access
      # X.509 subject is an array of [OID, value, type] arrays
      subject = certificate.subject.to_a.to_h { |part| [part[0], part[1]] }

      {
        given_name: subject["GN"] || subject["givenName"],
        surname: subject["SN"] || subject["surname"],
        personal_code: extract_personal_code(subject["serialNumber"]),
        country: subject["C"] || subject["countryName"],
        common_name: subject["CN"] || subject["commonName"]
      }
    end

    # Parse Estonian personal identification code for demographic information.
    #
    # Estonian personal codes are 11-digit numbers that encode:
    # - Position 1: Century and gender (1-8)
    # - Positions 2-3: Year of birth (00-99)
    # - Positions 4-5: Month of birth (01-12)
    # - Positions 6-7: Day of birth (01-31)
    # - Positions 8-10: Serial number for same birth date
    # - Position 11: Check digit
    #
    # Century and gender encoding:
    # - 1,2: 1800-1899 (1=male, 2=female)
    # - 3,4: 1900-1999 (3=male, 4=female)
    # - 5,6: 2000-2099 (5=male, 6=female)
    # - 7,8: 2100-2199 (7=male, 8=female)
    #
    # @param personal_code [String] 11-digit Estonian personal code
    # @return [Hash] Parsed demographic information
    # @option return [Date] :birth_date Calculated birth date
    # @option return [String] :gender "Male" or "Female"
    # @option return [Integer] :age Current age in years
    # @example
    #   reader = CertificateReader.new
    #   info = reader.parse_personal_code("38001010008")
    #   puts "Born: #{info[:birth_date]} (#{info[:gender]}, age #{info[:age]})"
    def parse_personal_code(personal_code)
      # Validate format: exactly 11 digits
      return {} unless personal_code&.match?(/^\d{11}$/)

      # Extract components from the personal code
      century_gender = personal_code[0].to_i  # First digit: century and gender
      year = personal_code[1..2].to_i         # Year within century (00-99)
      month = personal_code[3..4].to_i        # Month (01-12)
      day = personal_code[5..6].to_i          # Day (01-31)

      # Decode century and gender from first digit
      century, gender = case century_gender
                        when 1, 2
                          [1800, century_gender == 1 ? "Male" : "Female"]
                        when 3, 4
                          [1900, century_gender == 3 ? "Male" : "Female"]
                        when 5, 6
                          [2000, century_gender == 5 ? "Male" : "Female"]
                        when 7, 8
                          [2100, century_gender == 7 ? "Male" : "Female"]
                        else
                          return {} # Invalid first digit
                        end

      # Calculate full birth year and create date
      birth_year = century + year
      birth_date = Date.new(birth_year, month, day)

      # Calculate current age accounting for whether birthday has passed this year
      today = Date.today
      age = today.year - birth_date.year
      age -= 1 if today < Date.new(today.year, birth_date.month, birth_date.day)

      {
        birth_date: birth_date,
        gender: gender,
        age: age
      }
    rescue StandardError
      # Return empty hash if date is invalid or any other error occurs
      {}
    end

    private

    # Ensure we're connected to a card before attempting operations.
    # @raise [RuntimeError] if not connected
    def ensure_connected!
      raise "Not connected to card" unless connected?
    end

    # Load PKCS#11 library on demand using shared instance.
    # Uses class-level shared library to avoid conflicts between instances.
    def load_pkcs11_library
      return if @pkcs11

      @pkcs11 = self.class.shared_pkcs11_library
    end

    # Get shared PKCS#11 library instance across all CertificateReader instances.
    #
    # This prevents conflicts when multiple instances try to initialize the same
    # PKCS#11 library, which can cause "already initialized" errors.
    #
    # @return [PKCS11, nil] Shared PKCS#11 library instance or nil if unavailable
    def self.shared_pkcs11_library
      @shared_pkcs11 ||= begin
        library_path = PKCS11_LIBRARY_PATHS.find { |path| File.exist?(path) }
        library_path ? PKCS11.open(library_path) : nil
      end
    rescue StandardError
      # If library initialization fails (e.g., already initialized by another process),
      # return nil to gracefully handle the error
      nil
    end

    # Find slots containing Estonian ID cards among all available smart card slots.
    #
    # Estonian ID cards can be identified by examining token information:
    # - Label contains "ESTEID" (Estonian Electronic ID)
    # - Manufacturer contains "SK" (SK ID Solutions, the issuer)
    # - Label contains "PIN1" or "PIN2" (PIN slot identifiers)
    # - Label contains Estonian text like "Isikutuvastus" (identification)
    #
    # @param slots [Array<PKCS11::Slot>] Array of PKCS#11 slots to examine
    # @return [Array<PKCS11::Slot>] Slots containing Estonian ID cards
    def find_esteid_slots(slots)
      slots.select do |slot|
        # Get token information from the slot
        token_info = slot.token_info
        label = token_info.label.strip
        manufacturer = token_info.manufacturerID.strip

        # Check for Estonian ID card identifying markers
        label.include?("ESTEID") ||
          manufacturer.include?("SK") ||
          label.match?(/PIN[12]/) ||
          label.include?("Isikutuvastus")
      rescue StandardError
        # If we can't read token info from this slot, skip it
        false
      end
    end

    # Find authentication certificate among all certificates stored on the card.
    #
    # Estonian ID cards contain multiple certificates for different purposes:
    # - Authentication certificate: For identity verification (uses PIN1)
    # - Signing certificate: For digital signatures (uses PIN2)
    #
    # Authentication certificates are identified by their key usage extension:
    # - Must have "Digital Signature" usage
    # - Must NOT have "Non Repudiation" usage (that's for signing certificates)
    #
    # @return [OpenSSL::X509::Certificate, nil] Authentication certificate or nil
    def find_auth_certificate
      # Find all certificate objects stored on the card
      objects = @session.find_objects(PKCS11::CKA_CLASS => PKCS11::CKO_CERTIFICATE)

      objects.each do |obj|
        # Get the raw certificate data (DER format)
        cert_der = obj[PKCS11::CKA_VALUE]
        next unless cert_der

        # Parse the X.509 certificate
        cert = OpenSSL::X509::Certificate.new(cert_der)

        # Check the key usage extension to determine certificate purpose
        key_usage = cert.extensions.find { |ext| ext.oid == "keyUsage" }
        next unless key_usage

        usage = key_usage.value

        # Authentication certificates have Digital Signature but not Non Repudiation
        return cert if usage.include?("Digital Signature") && !usage.include?("Non Repudiation")
      rescue StandardError
        # Skip certificates we can't parse
        next
      end

      nil
    end

    # Extract personal code from certificate serial number field.
    #
    # Estonian certificates store the personal identification code in the
    # serialNumber field with a "PNOEE-" prefix (Personal Number Of EstoniE).
    # This method strips the prefix to get the clean 11-digit personal code.
    #
    # @param serial_number [String, nil] Serial number from certificate
    # @return [String, nil] Clean personal code or nil if not found
    def extract_personal_code(serial_number)
      return nil unless serial_number

      # Remove the PNOEE- prefix if present, otherwise return as-is
      serial_number.start_with?("PNOEE-") ? serial_number[6..] : serial_number
    end
  end
end
