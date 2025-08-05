#!/usr/bin/env ruby
# frozen_string_literal: true

# Simple test script to check card reader connectivity
# Usage: ruby script/test_card_reader.rb

require "bundler/setup"
require "smartcard"

class CardReaderTest
  def run
    puts "Estonian ID Card Reader Test"
    puts "=" * 50
    
    begin
      test_pcsc_service
      test_readers
      test_card_detection
    rescue => e
      puts "\n❌ Error: #{e.message}"
      puts e.backtrace if ENV["DEBUG"]
    end
  end

  private

  def test_pcsc_service
    print "\n🔍 Testing PC/SC service... "
    
    begin
      context = Smartcard::PCSC::Context.new
      puts "✅ Connected"
      @context = context
    rescue Smartcard::PCSC::Exception => e
      puts "❌ Failed"
      puts "\nPC/SC service is not available. Please ensure:"
      puts "- On macOS: SmartCard services are running"
      puts "- On Linux: pcscd service is running (sudo systemctl start pcscd)"
      puts "- On Windows: Smart Card service is running"
      exit 1
    end
  end

  def test_readers
    print "\n📟 Detecting card readers... "
    
    readers = @context.readers
    if readers.empty?
      puts "❌ No readers found"
      puts "\nPlease connect a smart card reader and try again."
      exit 1
    end
    
    puts "✅ Found #{readers.length} reader(s)"
    
    readers.each_with_index do |reader, i|
      puts "\n  Reader #{i + 1}: #{reader}"
      
      begin
        status = @context.card_status(reader)
        print "    Status: "
        
        if status[:state].include?(:present)
          puts "Card present ✅"
          
          # Display ATR (Answer To Reset)
          atr_hex = status[:atr].map { |b| "%02X" % b }.join
          puts "    ATR: #{atr_hex}"
          
          # Check if it's an Estonian ID card
          if esteid_card?(atr_hex)
            puts "    Type: Estonian ID Card 🇪🇪"
          else
            puts "    Type: Unknown card"
          end
        else
          puts "No card ❌"
        end
      rescue Smartcard::PCSC::Exception => e
        puts "Error reading status: #{e.message}"
      end
    end
  end

  def test_card_detection
    return unless @context
    
    puts "\n\n🔄 Monitoring card insertion/removal (Press Ctrl+C to stop)..."
    puts "-" * 50
    
    begin
      readers = @context.readers
      previous_states = {}
      
      loop do
        readers.each do |reader|
          begin
            status = @context.card_status(reader)
            current_state = status[:state].include?(:present)
            
            # Check if state changed
            if previous_states[reader].nil? || previous_states[reader] != current_state
              if current_state
                atr_hex = status[:atr].map { |b| "%02X" % b }.join
                card_type = esteid_card?(atr_hex) ? "Estonian ID Card" : "Unknown card"
                puts "\n✅ Card inserted in #{reader}"
                puts "   Type: #{card_type}"
                puts "   ATR: #{atr_hex}"
              else
                puts "\n❌ Card removed from #{reader}"
              end
              
              previous_states[reader] = current_state
            end
          rescue Smartcard::PCSC::Exception
            # Reader might have been disconnected
          end
        end
        
        sleep 0.5
      end
    rescue Interrupt
      puts "\n\n👋 Monitoring stopped"
    end
  end

  def esteid_card?(atr_hex)
    esteid_atrs = [
      "3BFE1800008031FE45803180664090A4162A00830F9000EF",
      "3BFA1800008031FE45FE654944202F20504B4903",
      "3BFE1800008031FE45803180664090A4561D0083119000EF",
      "3BDB960080B1FE451F830012233F536549440F900066"
    ]
    
    esteid_atrs.include?(atr_hex)
  end
end

# Run the test
if __FILE__ == $0
  CardReaderTest.new.run
end