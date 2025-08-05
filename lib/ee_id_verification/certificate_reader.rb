# frozen_string_literal: true

require "openssl"
require "smartcard"

module EeIdVerification
  # Handles reading certificates from Estonian ID cards
  class CertificateReader
    # Estonian ID card ATR (Answer To Reset) patterns
    ESTEID_ATRS = [
      "3BFE1800008031FE45803180664090A4162A00830F9000EF", # EstEID 3.5 (2011)
      "3BFA1800008031FE45FE654944202F20504B4903",         # EstEID 3.5 (2018)
      "3BFE1800008031FE45803180664090A4561D0083119000EF", # EstEID 2018+
      "3BDB960080B1FE451F830012233F536549440F900066"      # EstEID Digi-ID
    ].freeze

    # Certificate file IDs on Estonian ID card
    AUTH_CERT_FID = [0xAA, 0xCE]  # Authentication certificate
    SIGN_CERT_FID = [0xDD, 0xCE]  # Signing certificate

    # APDU commands
    SELECT_MASTER_FILE = [0x00, 0xA4, 0x00, 0x0C]  # SELECT MF
    SELECT_FILE = [0x00, 0xA4, 0x02, 0x04]         # SELECT by FID
    READ_BINARY = [0x00, 0xB0]                      # READ BINARY

    attr_reader :context, :card, :readers

    def initialize
      @context = Smartcard::PCSC::Context.new
      @readers = @context.readers
      @card = nil
    end

    # List available card readers
    def list_readers
      @readers
    end

    # Check if Estonian ID card is present
    def card_present?
      return false if @readers.empty?

      @readers.any? do |reader|
        begin
          card_info = @context.card_status(reader)
          card_info[:state].include?(:present) && esteid_card?(card_info[:atr])
        rescue Smartcard::PCSC::Exception
          false
        end
      end
    end

    # Connect to the ID card
    def connect
      reader = find_reader_with_card
      raise "No Estonian ID card found" unless reader

      @card = @context.connect(reader)
      reset_card
      true
    end

    # Disconnect from the card
    def disconnect
      @card&.disconnect
      @card = nil
    end

    # Read authentication certificate
    def read_auth_certificate
      ensure_connected!
      cert_der = read_certificate_file(AUTH_CERT_FID)
      OpenSSL::X509::Certificate.new(cert_der)
    end

    # Read signing certificate
    def read_sign_certificate
      ensure_connected!
      cert_der = read_certificate_file(SIGN_CERT_FID)
      OpenSSL::X509::Certificate.new(cert_der)
    end

    # Extract personal data from authentication certificate
    def extract_personal_data(certificate)
      subject = certificate.subject.to_a
      
      {
        given_name: extract_field(subject, "GN"),
        surname: extract_field(subject, "SN"),
        personal_code: extract_field(subject, "serialNumber"),
        country: extract_field(subject, "C"),
        common_name: extract_field(subject, "CN")
      }
    end

    # Perform authentication with PIN1
    def authenticate(pin1)
      ensure_connected!
      
      # Verify PIN1 (authentication PIN)
      verify_pin(0x01, pin1)
      
      # Return authentication certificate for further processing
      read_auth_certificate
    end

    # Perform signing with PIN2
    def sign(data, pin2)
      ensure_connected!
      
      # Verify PIN2 (signing PIN)
      verify_pin(0x02, pin2)
      
      # Create signature (simplified - actual implementation would use proper padding)
      # This is a placeholder - real implementation needs proper PKCS#1 padding
      signing_cert = read_sign_certificate
      
      {
        signature: create_signature(data),
        certificate: signing_cert
      }
    end

    private

    def ensure_connected!
      raise "Not connected to card" unless @card
    end

    def find_reader_with_card
      @readers.find do |reader|
        begin
          card_info = @context.card_status(reader)
          card_info[:state].include?(:present) && esteid_card?(card_info[:atr])
        rescue Smartcard::PCSC::Exception
          false
        end
      end
    end

    def esteid_card?(atr)
      atr_hex = atr.map { |b| "%02X" % b }.join
      ESTEID_ATRS.include?(atr_hex)
    end

    def reset_card
      # Select Master File (root)
      response = @card.transmit(SELECT_MASTER_FILE + [0x00])
      check_response(response)
    end

    def read_certificate_file(fid)
      # Select the certificate file
      response = @card.transmit(SELECT_FILE + [0x02] + fid + [0x00])
      check_response(response)
      
      # Read the file size from FCI
      file_size = parse_file_size(response)
      
      # Read the certificate in chunks
      cert_data = []
      offset = 0
      
      while offset < file_size
        chunk_size = [file_size - offset, 255].min
        response = @card.transmit(
          READ_BINARY + 
          [offset >> 8, offset & 0xFF] + 
          [chunk_size]
        )
        
        check_response(response)
        cert_data.concat(response[0...-2])  # Remove SW bytes
        offset += chunk_size
      end
      
      cert_data.pack("C*")
    end

    def parse_file_size(fci_response)
      # Simple FCI parser - looks for file size in tag 0x80
      data = fci_response[0...-2]  # Remove SW bytes
      
      # Find tag 0x80 (file size)
      idx = data.index(0x80)
      return 0 unless idx
      
      len = data[idx + 1]
      size = 0
      
      len.times do |i|
        size = (size << 8) | data[idx + 2 + i]
      end
      
      size
    end

    def verify_pin(pin_ref, pin)
      pin_bytes = pin.chars.map(&:ord)
      
      # Pad PIN to 12 bytes with 0xFF
      while pin_bytes.length < 12
        pin_bytes << 0xFF
      end
      
      # VERIFY command
      response = @card.transmit(
        [0x00, 0x20, 0x00, pin_ref] + 
        [pin_bytes.length] + 
        pin_bytes
      )
      
      check_response(response)
    end

    def create_signature(data)
      # This is a placeholder - actual signing would require:
      # 1. Proper PKCS#1 padding
      # 2. MSE (Manage Security Environment) commands
      # 3. PSO (Perform Security Operation) commands
      # For now, return a dummy signature
      "\x00" * 256
    end

    def check_response(response)
      return if response.empty?
      
      sw1 = response[-2]
      sw2 = response[-1]
      sw = (sw1 << 8) | sw2
      
      case sw
      when 0x9000
        # Success
      when 0x6300
        raise "PIN verification failed"
      when 0x6983
        raise "Authentication method blocked"
      when 0x6A82
        raise "File not found"
      else
        raise "Card error: SW=#{sw.to_s(16)}"
      end
    end

    def extract_field(subject, field_name)
      field = subject.find { |f| f[0] == field_name }
      field ? field[1] : nil
    end
  end
end