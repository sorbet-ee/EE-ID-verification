#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "../lib/ee_id_verification"
require "openssl"

def print_section(title)
  puts "\n#{title}"
  puts "=" * title.length
end

def print_subsection(title)
  puts "\n#{title}:"
  puts "-" * (title.length + 1)
end

def format_certificate_field(name, value)
  if value.nil? || value.to_s.strip.empty?
    puts "   #{name}: (not available)"
  else
    puts "   #{name}: #{value}"
  end
end

def get_card_hardware_info
  begin
    # Get PKCS#11 library and slots directly
    library = EeIdVerification::CertificateReader.shared_pkcs11_library
    return { error: "PKCS#11 library not available" } unless library
    
    slots = library.slots(true)
    esteid_slots = slots.select do |slot|
      begin
        token_info = slot.token_info
        label = token_info.label.strip
        manufacturer = token_info.manufacturerID.strip
        
        label.include?("ESTEID") ||
          manufacturer.include?("SK") ||
          label.match?(/PIN[12]/) ||
          label.include?("Isikutuvastus")
      rescue
        false
      end
    end
    
    return { error: "No Estonian ID card slots found" } if esteid_slots.empty?
    
    slot = esteid_slots.first
    token_info = slot.token_info
    
    {
      token_label: token_info.label.strip,
      token_manufacturer: token_info.manufacturerID.strip,
      token_model: token_info.model.strip,
      token_serial: token_info.serialNumber.strip,
      slot_description: "Slot #{slot}"
    }
  rescue => e
    { error: e.message }
  end
end

puts "Estonian ID Card Test & Information Export"
puts "=========================================="

verifier = EeIdVerification.new
reader = EeIdVerification::CertificateReader.new

unless verifier.available?
  puts "❌ No Estonian ID card detected"
  puts "Please insert your ID card and ensure reader is connected"
  exit 1
end

puts "✅ Estonian ID card detected"

# Get hardware information before authentication
print_section("Card Reader & Hardware Information")
hardware_info = get_card_hardware_info

if hardware_info[:error]
  puts "⚠️  Could not retrieve hardware info: #{hardware_info[:error]}"
else
  format_certificate_field("Token Label", hardware_info[:token_label])
  format_certificate_field("Token Manufacturer", hardware_info[:token_manufacturer])
  format_certificate_field("Token Model", hardware_info[:token_model])
  format_certificate_field("Token Serial Number", hardware_info[:token_serial])
  format_certificate_field("Slot Description", hardware_info[:slot_description])
end

# Proceed with authentication
session = verifier.authenticate
puts "\n🔑 Enter your PIN1: "
pin = gets.chomp

result = verifier.complete_authentication(session, pin)

if result.success?
  print_section("🎉 Authentication Successful!")
  
  print_subsection("Basic Identity Information")
  format_certificate_field("Full Name", result.full_name)
  format_certificate_field("Given Name", result.given_name)
  format_certificate_field("Surname", result.surname)
  format_certificate_field("Personal Code", result.personal_code)
  format_certificate_field("Country", result.country)
  
  # Parse personal code for detailed demographics
  if result.personal_code
    personal_info = reader.parse_personal_code(result.personal_code)
    
    if personal_info && !personal_info.empty?
      print_subsection("Demographic Information")
      format_certificate_field("Birth Date", personal_info[:birth_date])
      format_certificate_field("Gender", personal_info[:gender])
      format_certificate_field("Age", "#{personal_info[:age]} years")
      
      # Calculate additional demographics
      if personal_info[:birth_date]
        birth_year = personal_info[:birth_date].year
        generation = case birth_year
                    when 1946..1964 then "Baby Boomer"
                    when 1965..1980 then "Generation X"
                    when 1981..1996 then "Millennial"
                    when 1997..2012 then "Generation Z"
                    else "Generation Alpha"
                    end
        format_certificate_field("Generation", generation)
        
        # Century calculation
        century_code = result.personal_code[0].to_i
        century_info = case century_code
                      when 1, 2 then "19th century (1800-1899)"
                      when 3, 4 then "20th century (1900-1999)"
                      when 5, 6 then "21st century (2000-2099)"
                      when 7, 8 then "22nd century (2100-2199)"
                      else "Unknown century"
                      end
        format_certificate_field("Birth Century", century_info)
      end
    end
  end
  
  # Get detailed certificate information
  begin
    reader.connect
    certificate = reader.read_auth_certificate(pin)
    
    print_subsection("Certificate Details")
    format_certificate_field("Certificate Type", "Authentication Certificate (PIN1)")
    format_certificate_field("Serial Number", certificate.serial.to_s)
    format_certificate_field("Version", "v#{certificate.version}")
    format_certificate_field("Valid From", certificate.not_before.strftime("%Y-%m-%d %H:%M:%S UTC"))
    format_certificate_field("Valid Until", certificate.not_after.strftime("%Y-%m-%d %H:%M:%S UTC"))
    
    # Check if certificate is still valid
    now = Time.now
    if now < certificate.not_before
      format_certificate_field("Status", "⚠️  Not yet valid")
    elsif now > certificate.not_after
      format_certificate_field("Status", "❌ Expired")
    else
      days_until_expiry = ((certificate.not_after - now) / (24 * 60 * 60)).to_i
      format_certificate_field("Status", "✅ Valid (expires in #{days_until_expiry} days)")
    end
    
    print_subsection("Certificate Issuer")
    issuer_parts = certificate.issuer.to_a.to_h { |part| [part[0], part[1]] }
    format_certificate_field("Common Name", issuer_parts["CN"])
    format_certificate_field("Organization", issuer_parts["O"])
    format_certificate_field("Country", issuer_parts["C"])
    format_certificate_field("Email", issuer_parts["emailAddress"])
    
    print_subsection("Certificate Subject")
    subject_parts = certificate.subject.to_a.to_h { |part| [part[0], part[1]] }
    format_certificate_field("Common Name", subject_parts["CN"])
    format_certificate_field("Given Name", subject_parts["GN"] || subject_parts["givenName"])
    format_certificate_field("Surname", subject_parts["SN"] || subject_parts["surname"])
    format_certificate_field("Serial Number", subject_parts["serialNumber"])
    format_certificate_field("Country", subject_parts["C"])
    format_certificate_field("Organization", subject_parts["O"])
    format_certificate_field("Organizational Unit", subject_parts["OU"])
    
    print_subsection("Cryptographic Information")
    public_key = certificate.public_key
    format_certificate_field("Algorithm", certificate.signature_algorithm)
    format_certificate_field("Public Key Type", public_key.class.name.split("::").last)
    
    if public_key.respond_to?(:n) # RSA key
      key_size = public_key.n.to_s(2).length
      format_certificate_field("Key Size", "#{key_size} bits")
      format_certificate_field("Exponent", public_key.e.to_s)
    end
    
    print_subsection("Certificate Extensions")
    certificate.extensions.each do |ext|
      case ext.oid
      when "keyUsage"
        format_certificate_field("Key Usage", ext.value)
      when "extendedKeyUsage"
        format_certificate_field("Extended Key Usage", ext.value)
      when "subjectKeyIdentifier"
        format_certificate_field("Subject Key ID", ext.value.gsub(":", " "))
      when "authorityKeyIdentifier"
        # Parse the authority key identifier
        aki_value = ext.value.gsub("keyid:", "").split("\n").first
        format_certificate_field("Authority Key ID", aki_value.gsub(":", " "))
      when "certificatePolicies"
        format_certificate_field("Certificate Policies", ext.value)
      when "crlDistributionPoints"
        format_certificate_field("CRL Distribution", ext.value.split("\n").join(", "))
      when "authorityInfoAccess"
        format_certificate_field("Authority Info Access", ext.value.split("\n").join(", "))
      else
        format_certificate_field(ext.oid, ext.value) if ext.value.length < 100
      end
    end
    
    print_subsection("Certificate Fingerprints")
    cert_der = certificate.to_der
    format_certificate_field("SHA-1", OpenSSL::Digest::SHA1.hexdigest(cert_der).upcase.scan(/.{2}/).join(":"))
    format_certificate_field("SHA-256", OpenSSL::Digest::SHA256.hexdigest(cert_der).upcase.scan(/.{2}/).join(":"))
    format_certificate_field("MD5", OpenSSL::Digest::MD5.hexdigest(cert_der).upcase.scan(/.{2}/).join(":"))
    
  rescue => e
    puts "\n⚠️  Could not retrieve detailed certificate information: #{e.message}"
  ensure
    reader.disconnect rescue nil
  end
  
else
  puts "\n❌ Authentication failed: #{result.error}"
  
  # Provide helpful error guidance
  case result.error
  when /PIN/i
    puts "\nTroubleshooting:"
    puts "- Verify you're using PIN1 (not PIN2 for signing)"
    puts "- Check if PIN is blocked (3 failed attempts)"
    puts "- Use DigiDoc4 client to unblock PIN if needed"
  when /card/i
    puts "\nTroubleshooting:"
    puts "- Ensure card is properly inserted"
    puts "- Check card reader connection"
    puts "- Try removing and reinserting the card"
  when /certificate/i
    puts "\nTroubleshooting:"
    puts "- Your card may be expired or damaged"
    puts "- Contact Estonian ID-card support: +372 677 3377"
  end
end

puts "\n" + "=" * 50
puts "Test completed at #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
