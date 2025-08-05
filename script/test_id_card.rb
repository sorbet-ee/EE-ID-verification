#!/usr/bin/env ruby
# frozen_string_literal: true

# Test the new PKCS#11-based certificate reader

require_relative "../lib/ee_id_verification"

puts "🔍 Testing Estonian ID Card"
puts "=" * 40

begin
  # Create the certificate reader
  reader = EeIdVerification::CertificateReader.new

  # Check if card is present
  puts "📱 Checking for Estonian ID card..."
  unless reader.card_present?
    puts "❌ No Estonian ID card detected. Please insert your card."
    exit 1
  end

  puts "✅ Estonian ID card detected!"

  # Connect to card
  puts "🔗 Connecting to card..."
  reader.connect
  puts "✅ Connected successfully"

  # Read authentication certificate
  print "🔑 Enter PIN1 (4 digits) for authentication: "
  pin1 = (gets || "").chomp

  puts "📄 Reading authentication certificate..."
  auth_cert = reader.read_auth_certificate(pin1)
  puts "✅ Authentication certificate read successfully"

  # Extract personal data
  puts "👤 Extracting personal information..."
  personal_data = reader.extract_personal_data(auth_cert)

  puts "\n🎯 Authentication Certificate Information:"
  puts "   👨 Name: #{personal_data[:given_name]} #{personal_data[:surname]}"
  puts "   🆔 Personal Code: #{personal_data[:personal_code]}"
  puts "   🌍 Country: #{personal_data[:country]}"
  puts "   📋 Common Name: #{personal_data[:common_name]}"

  # Parse personal code for additional info
  if personal_data[:personal_code]
    puts "\n📊 Personal Code Analysis:"
    pc_info = reader.parse_personal_code(personal_data[:personal_code])
    if pc_info[:birth_date]
      puts "   🎂 Birth Date: #{pc_info[:birth_date]}"
      puts "   ⚥ Gender: #{pc_info[:gender]}"
      puts "   📅 Age: #{pc_info[:age]} years"
    end
  end

  # Certificate details
  puts "\n📜 Certificate Details:"
  puts "   📅 Valid From: #{auth_cert.not_before}"
  puts "   📅 Valid Until: #{auth_cert.not_after}"
  puts "   🏢 Issuer: #{auth_cert.issuer}"
  puts "   🔢 Serial Number: #{auth_cert.serial}"

  # Check validity
  now = Time.now
  if now.between?(auth_cert.not_before, auth_cert.not_after)
    puts "   ✅ Certificate is currently valid"
  else
    puts "   ❌ Certificate is expired or not yet valid"
  end

  puts "\n🎉 Estonian ID card test completed successfully!"
rescue StandardError => e
  puts "❌ Error: #{e.message}"
  puts e.backtrace.first(5)
ensure
  reader&.disconnect
  puts "✅ Disconnected from card"
end
