# frozen_string_literal: true

require "openssl"
require "pkcs11"
require "date"

module EeIdVerification
  # PKCS#11-based Estonian ID card certificate reader.
  #
  # This class provides access to Estonian ID cards through the PKCS#11 interface,
  # which is the standard and recommended approach for Estonian ID cards.
  # It replaces the raw smartcard API approach with proper PKCS#11 token access.
  #
  # @example Basic usage
  #   reader = CertificateReader.new
  #   if reader.card_present?
  #     reader.connect
  #     cert = reader.read_auth_certificate("1234")  # PIN1
  #     personal_data = reader.extract_personal_data(cert)
  #     puts "User: #{personal_data[:given_name]} #{personal_data[:surname]}"
  #     reader.disconnect
  #   end
  class CertificateReader
    # Common PKCS#11 library locations on macOS
    PKCS11_LIBRARY_PATHS = [
      "/opt/homebrew/lib/opensc-pkcs11.so",
      "/opt/homebrew/lib/pkcs11/opensc-pkcs11.so",
      "/usr/local/lib/opensc-pkcs11.so",
      "/usr/lib/opensc-pkcs11.so",
      "/opt/local/lib/opensc-pkcs11.so",
      "/System/Library/OpenSC/lib/opensc-pkcs11.so",
      "/usr/local/lib/pkcs11/opensc-pkcs11.so"
    ].freeze

    attr_reader :pkcs11, :auth_slot, :sign_slot, :auth_session, :sign_session

    # Initialize the PKCS#11 certificate reader
    def initialize
      @pkcs11 = nil
      @auth_slot = nil
      @sign_slot = nil
      @auth_session = nil
      @sign_session = nil
      @connected = false
    end

    # Check if Estonian ID card is present
    # @return [Boolean] true if Estonian ID card is detected
    def card_present?
      load_pkcs11_library
      return false unless @pkcs11

      slots = @pkcs11.slots(true) # Only slots with tokens
      esteid_slots = find_esteid_slots(slots)

      !esteid_slots.empty?
    rescue StandardError
      false
    end

    # Connect to the Estonian ID card
    # @return [Boolean] true if successfully connected
    # @raise [RuntimeError] if no Estonian ID card found
    def connect
      load_pkcs11_library
      raise "PKCS#11 library not available" unless @pkcs11

      slots = @pkcs11.slots(true)
      esteid_slots = find_esteid_slots(slots)

      raise "No Estonian ID card found" if esteid_slots.empty?

      # Find authentication and signing slots
      esteid_slots.each do |slot|
        token_info = slot.token_info
        label = token_info.label.strip

        if label.include?("PIN1") || label.include?("Isikutuvastus") || label.downcase.include?("auth")
          @auth_slot = slot
        elsif label.include?("PIN2") || label.include?("Allkirjastamine") || label.downcase.include?("sign")
          @sign_slot = slot
        end
      end

      # If we don't have distinct slots, use the first one for both
      @auth_slot = @sign_slot = esteid_slots.first if !@auth_slot && !@sign_slot && esteid_slots.any?

      raise "Could not identify Estonian ID card slots" unless @auth_slot

      @connected = true
      true
    end

    # Disconnect from the card
    def disconnect
      begin
        @auth_session&.logout
      rescue StandardError
        nil
      end
      begin
        @auth_session&.close
      rescue StandardError
        nil
      end
      begin
        @sign_session&.logout
      rescue StandardError
        nil
      end
      begin
        @sign_session&.close
      rescue StandardError
        nil
      end

      @auth_session = nil
      @sign_session = nil
      @connected = false

      begin
        @pkcs11&.close
      rescue StandardError
        nil
      end
      @pkcs11 = nil
    end

    # Check if connected to a card
    # @return [Boolean] true if connected
    def connected?
      @connected && @pkcs11 && @auth_slot
    end

    # Read authentication certificate with PIN1
    # @param pin [String] PIN1 (typically 4 digits)
    # @return [OpenSSL::X509::Certificate] authentication certificate
    # @raise [RuntimeError] if PIN verification fails or certificate cannot be read
    def read_auth_certificate(pin)
      ensure_connected!

      # Open authentication session if not already open
      @auth_session ||= @auth_slot.open

      # Login with PIN1
      begin
        @auth_session.login(PKCS11::CKU_USER, pin)
      rescue PKCS11::CKR_PIN_INCORRECT
        raise "Invalid PIN1 - authentication failed"
      rescue PKCS11::CKR_PIN_LOCKED
        raise "PIN1 is blocked - too many incorrect attempts"
      end

      # Find authentication certificate
      cert = find_certificate_by_type(:authentication)
      raise "Authentication certificate not found" unless cert

      cert
    end

    # Read signing certificate with PIN2
    # @param pin [String] PIN2 (typically 5+ digits)
    # @return [OpenSSL::X509::Certificate] signing certificate
    # @raise [RuntimeError] if PIN verification fails or certificate cannot be read
    def read_signing_certificate(pin)
      ensure_connected!

      # Use signing slot if available, otherwise use auth slot
      slot = @sign_slot || @auth_slot

      # Open signing session if not already open
      @sign_session ||= slot.open

      # Login with PIN2
      begin
        @sign_session.login(PKCS11::CKU_USER, pin)
      rescue PKCS11::CKR_PIN_INCORRECT
        raise "Invalid PIN2 - signing failed"
      rescue PKCS11::CKR_PIN_LOCKED
        raise "PIN2 is blocked - too many incorrect attempts"
      end

      # Find signing certificate
      cert = find_certificate_by_type(:signing)
      raise "Signing certificate not found" unless cert

      cert
    end

    # Extract personal data from certificate
    # @param certificate [OpenSSL::X509::Certificate] X.509 certificate
    # @return [Hash] personal data hash with keys: :given_name, :surname, :personal_code, :country, :common_name
    def extract_personal_data(certificate)
      subject_parts = certificate.subject.to_a
      subject_hash = {}
      subject_parts.each { |part| subject_hash[part[0]] = part[1] }

      {
        given_name: subject_hash["GN"] || subject_hash["givenName"],
        surname: subject_hash["SN"] || subject_hash["surname"],
        personal_code: extract_personal_code(subject_hash["serialNumber"]),
        country: subject_hash["C"] || subject_hash["countryName"],
        common_name: subject_hash["CN"] || subject_hash["commonName"]
      }
    end

    # Parse Estonian personal code for additional information
    # @param personal_code [String] 11-digit Estonian personal code
    # @return [Hash] parsed information with keys: :birth_date, :gender, :age
    def parse_personal_code(personal_code)
      return {} unless personal_code&.match?(/^\d{11}$/)

      century_gender = personal_code[0].to_i
      year = personal_code[1..2].to_i
      month = personal_code[3..4].to_i
      day = personal_code[5..6].to_i

      # Determine century and gender from first digit
      case century_gender
      when 1, 2
        century = 1800
        gender = century_gender == 1 ? "Male" : "Female"
      when 3, 4
        century = 1900
        gender = century_gender == 3 ? "Male" : "Female"
      when 5, 6
        century = 2000
        gender = century_gender == 5 ? "Male" : "Female"
      when 7, 8
        century = 2100
        gender = century_gender == 7 ? "Male" : "Female"
      else
        return {}
      end

      begin
        birth_year = century + year
        birth_date = Date.new(birth_year, month, day)

        # Calculate age
        today = Date.today
        age = today.year - birth_date.year
        age -= 1 if today < Date.new(today.year, birth_date.month, birth_date.day)

        {
          birth_date: birth_date,
          gender: gender,
          age: age
        }
      rescue StandardError
        {}
      end
    end

    private

    # Ensure we're connected to a card
    # @raise [RuntimeError] if not connected
    def ensure_connected!
      raise "Not connected to card. Call connect() first." unless connected?
    end

    # Load PKCS#11 library (shared across all instances)
    def load_pkcs11_library
      return if @pkcs11

      @pkcs11 = self.class.shared_pkcs11_library
    end

    # Get shared PKCS#11 library instance
    def self.shared_pkcs11_library
      @shared_pkcs11 ||= begin
        library_path = PKCS11_LIBRARY_PATHS.find { |path| File.exist?(path) }
        library_path ? PKCS11.open(library_path) : nil
      end
    rescue StandardError
      # If library is already initialized by another process, return nil
      # This will cause card_present? to return false, which is safe
      nil
    end

    # Find Estonian ID card slots
    # @param slots [Array] Array of PKCS#11 slots
    # @return [Array] Array of Estonian ID card slots
    def find_esteid_slots(slots)
      esteid_slots = []

      slots.each do |slot|
        token_info = slot.token_info
        label = token_info.label.strip
        manufacturer = token_info.manufacturerID.strip
        model = token_info.model.strip

        # Check if this looks like Estonian ID card
        if label.include?("ESTEID") ||
           manufacturer.include?("SK") ||
           model.include?("PKCS#15") ||
           label.match?(/PIN[12]/) ||
           label.include?("Isikutuvastus") ||
           label.include?("Allkirjastamine")
          esteid_slots << slot
        end
      rescue StandardError
        # Skip slots we can't read
        next
      end

      esteid_slots
    end

    # Find certificate by type (authentication or signing)
    # @param type [Symbol] :authentication or :signing
    # @return [OpenSSL::X509::Certificate, nil] certificate or nil if not found
    def find_certificate_by_type(type)
      session = type == :authentication ? @auth_session : (@sign_session || @auth_session)
      return nil unless session

      # Find all certificate objects
      objects = session.find_objects(PKCS11::CKA_CLASS => PKCS11::CKO_CERTIFICATE)

      objects.each do |obj|
        # Get certificate data
        cert_der = obj[PKCS11::CKA_VALUE]
        next unless cert_der

        cert = OpenSSL::X509::Certificate.new(cert_der)

        # Determine certificate type by key usage
        key_usage = cert.extensions.find { |ext| ext.oid == "keyUsage" }
        next unless key_usage

        usage_str = key_usage.value

        case type
        when :authentication
          # Authentication certificates have Digital Signature but not Non Repudiation
          return cert if usage_str.include?("Digital Signature") && !usage_str.include?("Non Repudiation")
        when :signing
          # Signing certificates have Non Repudiation
          return cert if usage_str.include?("Non Repudiation")
        end
      rescue StandardError
        # Skip certificates we can't parse
        next
      end

      nil
    end

    # Extract personal code from certificate serial number
    # Estonian certificates store personal code in serialNumber field with PNOEE- prefix
    # @param serial_number [String] Serial number from certificate
    # @return [String, nil] Personal code or nil if not found
    def extract_personal_code(serial_number)
      return nil unless serial_number

      # Remove PNOEE- prefix if present
      if serial_number.start_with?("PNOEE-")
        serial_number[6..]
      else
        serial_number
      end
    end
  end
end
