#!/usr/bin/env ruby
# frozen_string_literal: true

# Script to extract certificates from Estonian ID card
# Usage: ruby script/extract_certificates.rb [--save]

require "bundler/setup"
require "ee_id_verification"
require "openssl"
require "fileutils"

class CertificateExtractor
  def initialize(save_to_files: false)
    @save_to_files = save_to_files
    @reader = EeIdVerification::CertificateReader.new
  end

  def run
    puts "Estonian ID Card Certificate Extractor"
    puts "=" * 50
    
    begin
      check_card
      extract_certificates
    rescue => e
      puts "\n❌ Error: #{e.message}"
      puts e.backtrace if ENV["DEBUG"]
    ensure
      @reader.disconnect rescue nil
    end
  end

  private

  def check_card
    print "\n🔍 Checking for Estonian ID card... "
    
    unless @reader.card_present?
      puts "❌ Not found"
      puts "\nPlease insert your Estonian ID card and try again."
      exit 1
    end
    
    puts "✅ Card detected"
    @reader.connect
  end

  def extract_certificates
    puts "\n📜 Extracting certificates..."
    puts "-" * 50
    
    # Extract authentication certificate
    puts "\n1️⃣  Authentication Certificate:"
    auth_cert = extract_and_display_cert(:auth)
    
    # Extract signing certificate
    puts "\n2️⃣  Signing Certificate:"
    sign_cert = extract_and_display_cert(:sign)
    
    if @save_to_files
      save_certificates(auth_cert, sign_cert)
    end
  end

  def extract_and_display_cert(type)
    cert = case type
    when :auth
      @reader.read_auth_certificate
    when :sign
      @reader.read_sign_certificate
    end
    
    # Extract personal data
    data = @reader.extract_personal_data(cert)
    
    puts "  👤 Subject: #{cert.subject}"
    puts "  📛 Name: #{data[:given_name]} #{data[:surname]}"
    puts "  🆔 Personal Code: #{data[:personal_code]}"
    puts "  🏛️  Issuer: #{cert.issuer}"
    puts "  📅 Valid From: #{cert.not_before}"
    puts "  📅 Valid Until: #{cert.not_after}"
    puts "  🔑 Serial Number: #{cert.serial.to_s(16).upcase}"
    
    # Check validity
    if cert.not_after < Time.now
      puts "  ⚠️  Status: EXPIRED"
    elsif cert.not_before > Time.now
      puts "  ⚠️  Status: NOT YET VALID"
    else
      puts "  ✅ Status: Valid"
    end
    
    # Key usage
    if type == :auth
      puts "  🔐 Usage: Authentication"
    else
      puts "  ✍️  Usage: Digital Signature"
    end
    
    # Public key info
    pub_key = cert.public_key
    if pub_key.is_a?(OpenSSL::PKey::RSA)
      puts "  🔑 Public Key: RSA #{pub_key.n.num_bits} bits"
    elsif pub_key.is_a?(OpenSSL::PKey::EC)
      puts "  🔑 Public Key: EC #{pub_key.group.curve_name}"
    end
    
    cert
  end

  def save_certificates(auth_cert, sign_cert)
    puts "\n\n💾 Saving certificates..."
    
    # Create output directory
    timestamp = Time.now.strftime("%Y%m%d_%H%M%S")
    output_dir = "certificates_#{timestamp}"
    FileUtils.mkdir_p(output_dir)
    
    # Extract personal code for filename
    data = @reader.extract_personal_data(auth_cert)
    personal_code = data[:personal_code]
    
    # Save authentication certificate
    auth_pem = File.join(output_dir, "#{personal_code}_auth.pem")
    File.write(auth_pem, auth_cert.to_pem)
    puts "  ✅ Authentication certificate: #{auth_pem}"
    
    auth_der = File.join(output_dir, "#{personal_code}_auth.der")
    File.write(auth_der, auth_cert.to_der)
    puts "  ✅ Authentication certificate (DER): #{auth_der}"
    
    # Save signing certificate
    sign_pem = File.join(output_dir, "#{personal_code}_sign.pem")
    File.write(sign_pem, sign_cert.to_pem)
    puts "  ✅ Signing certificate: #{sign_pem}"
    
    sign_der = File.join(output_dir, "#{personal_code}_sign.der")
    File.write(sign_der, sign_cert.to_der)
    puts "  ✅ Signing certificate (DER): #{sign_der}"
    
    # Create info file
    info_file = File.join(output_dir, "certificate_info.txt")
    File.open(info_file, 'w') do |f|
      f.puts "Estonian ID Card Certificate Information"
      f.puts "=" * 50
      f.puts "Extracted: #{Time.now}"
      f.puts "\nOwner Information:"
      f.puts "  Name: #{data[:given_name]} #{data[:surname]}"
      f.puts "  Personal Code: #{data[:personal_code]}"
      f.puts "  Country: #{data[:country]}"
      f.puts "\nCertificate Details:"
      f.puts "  Auth Certificate Serial: #{auth_cert.serial.to_s(16).upcase}"
      f.puts "  Sign Certificate Serial: #{sign_cert.serial.to_s(16).upcase}"
      f.puts "  Valid Until: #{[auth_cert.not_after, sign_cert.not_after].min}"
    end
    puts "  ✅ Certificate info: #{info_file}"
    
    puts "\n📁 All files saved to: #{output_dir}/"
  end
end

# Parse command line arguments
save_files = ARGV.include?("--save") || ARGV.include?("-s")

if ARGV.include?("--help") || ARGV.include?("-h")
  puts "Usage: #{$0} [options]"
  puts "Options:"
  puts "  --save, -s    Save certificates to files"
  puts "  --help, -h    Show this help"
  exit 0
end

# Run the extractor
CertificateExtractor.new(save_to_files: save_files).run