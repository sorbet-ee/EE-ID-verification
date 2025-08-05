#!/usr/bin/env ruby
# frozen_string_literal: true

# Script to read data from Estonian ID card
# Usage: ruby script/read_id_card.rb

require "bundler/setup"
require "ee_id_verification"
require "io/console"

class IdCardReader
  def initialize
    @verifier = EeIdVerification.new(
      digidoc_local: {
        require_ocsp: false  # Disable OCSP for testing
      }
    )
  end

  def run
    puts "Estonian ID Card Reader"
    puts "=" * 50
    
    begin
      check_card_availability
      read_card_data
    rescue => e
      puts "\n❌ Error: #{e.message}"
      puts e.backtrace if ENV["DEBUG"]
    end
  end

  private

  def check_card_availability
    print "\n🔍 Checking for card readers... "
    
    if @verifier.method_available?(:digidoc_local)
      puts "✅ Found"
      list_readers
    else
      puts "❌ Not found"
      puts "\nPlease ensure:"
      puts "- Card reader is connected"
      puts "- Card reader drivers are installed"
      puts "- PC/SC service is running"
      exit 1
    end
  end

  def list_readers
    reader = EeIdVerification::CertificateReader.new
    readers = reader.list_readers
    
    if readers.empty?
      puts "\n❌ No card readers detected"
      exit 1
    end
    
    puts "\n📟 Available card readers:"
    readers.each_with_index do |r, i|
      puts "  #{i + 1}. #{r}"
    end
    
    print "\n🔍 Checking for Estonian ID card... "
    if reader.card_present?
      puts "✅ Card detected"
    else
      puts "❌ No card detected"
      puts "\nPlease insert your Estonian ID card and try again."
      exit 1
    end
  end

  def read_card_data
    puts "\n📋 Reading card data..."
    puts "-" * 50
    
    # Start authentication session
    session = @verifier.digidoc_local_auth
    
    # Display personal data from certificate
    if session.metadata && session.metadata[:personal_data]
      data = session.metadata[:personal_data]
      
      puts "\n👤 Personal Information:"
      puts "  Name: #{data[:given_name]} #{data[:surname]}"
      puts "  Personal Code: #{data[:personal_code]}"
      puts "  Country: #{data[:country]}"
      puts "  Common Name: #{data[:common_name]}"
    end
    
    # Ask if user wants to authenticate
    print "\n🔐 Would you like to authenticate with PIN1? (y/n): "
    response = gets.chomp.downcase
    
    if response == 'y'
      authenticate_with_pin(session)
    else
      puts "\n✅ Card reading completed without authentication."
    end
  end

  def authenticate_with_pin(session)
    print "\n🔑 Enter PIN1: "
    pin = STDIN.noecho(&:gets).chomp
    puts # New line after hidden input
    
    # Provide PIN to the authenticator
    authenticator = @verifier.authenticators[:digidoc_local]
    authenticator.provide_pin(session.id, pin)
    
    print "\n⏳ Authenticating... "
    
    # Poll for result
    result = @verifier.poll_status(session)
    
    if result.authenticated?
      puts "✅ Success!"
      puts "\n🎉 Authentication successful!"
      puts "  Authenticated as: #{result.given_name} #{result.surname}"
      puts "  Certificate level: #{result.certificate_level}"
      
      if result.metadata
        puts "  Authentication method: #{result.metadata[:authentication_method]}"
        puts "  Card type: #{result.metadata[:card_type]}"
      end
    else
      puts "❌ Failed"
      puts "\n⚠️  Authentication failed: #{result.error}"
      
      if result.error&.include?("PIN")
        puts "\nNote: You have limited PIN attempts before the PIN is blocked."
      end
    end
  end
end

# Run the script
if __FILE__ == $0
  IdCardReader.new.run
end