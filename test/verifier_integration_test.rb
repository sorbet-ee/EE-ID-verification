# frozen_string_literal: true

require "test_helper"

class VerifierIntegrationTest < Minitest::Test
  def setup
    @verifier = EeIdVerification.new
  end

  def test_verifier_creation_and_basic_functionality
    assert_kind_of EeIdVerification::Verifier, @verifier
    assert_respond_to @verifier, :available_methods
    assert_respond_to @verifier, :method_available?
  end

  def test_available_methods_detection
    methods = @verifier.available_methods
    assert_kind_of Array, methods
    
    # Should only include methods that are actually available
    methods.each do |method|
      assert @verifier.method_available?(method), "Method #{method} should be available if in available_methods"
    end
    
    puts "\n📋 Available authentication methods: #{methods.inspect}"
    
    # DigiDoc Local should be available if hardware is present
    if @verifier.method_available?(:digidoc_local)
      puts "✅ DigiDoc Local (Estonian ID card) is available"
    else
      puts "⚠️  DigiDoc Local not available (no card reader or card)"
    end
  end

  def test_digidoc_local_availability_requirements
    # Test the availability logic
    available = @verifier.method_available?(:digidoc_local)
    
    if available
      # If available, should be able to get authenticator
      auth = @verifier.authenticators[:digidoc_local]
      assert_kind_of EeIdVerification::DigiDocLocalAuthenticator, auth
      assert auth.available?
    else
      puts "\n⚠️  DigiDoc Local not available. To enable:"
      puts "   1. Install OpenSC: brew install opensc (macOS)"
      puts "   2. Connect card reader"
      puts "   3. Insert Estonian ID card"
    end
  end

  def test_end_to_end_digidoc_local_authentication
    skip "Skipping hardware test - set ENV['HARDWARE_TESTS'] to run" unless ENV['HARDWARE_TESTS']
    
    unless @verifier.method_available?(:digidoc_local)
      error_msg = "DigiDoc Local authentication not available. Please:\n" \
                  "1. Insert your Estonian ID card\n" \
                  "2. Ensure card reader is connected\n" \
                  "3. Install OpenSC (brew install opensc)"
      flunk error_msg
    end

    puts "\n🔍 Starting end-to-end DigiDoc Local authentication test"
    
    # Step 1: Initiate authentication
    session = @verifier.digidoc_local_auth
    assert_kind_of EeIdVerification::AuthenticationSession, session
    assert_equal :digidoc_local, session.method
    
    puts "✅ Step 1: Authentication session initiated"
    puts "   Session ID: #{session.id[0..8]}..."
    
    # Step 2: Check initial status
    result = @verifier.poll_status(session)
    assert_equal :waiting_for_pin, result.status
    refute result.authenticated?
    
    puts "✅ Step 2: Waiting for PIN as expected"
    
    # Step 3: Provide PIN
    print "🔑 Enter your PIN1 (4 digits): "
    pin1 = gets.chomp
    
    success = @verifier.authenticators[:digidoc_local].provide_pin(session.id, pin1)
    assert success, "PIN provision should succeed"
    
    puts "✅ Step 3: PIN provided"
    
    # Step 4: Complete authentication
    result = @verifier.poll_status(session)
    
    if result.status == :completed
      assert result.authenticated?
      assert_kind_of String, result.personal_code
      assert_match(/^\d{11}$/, result.personal_code)
      
      puts "🎉 Step 4: Authentication completed successfully!"
      puts "   Name: #{result.full_name}"
      puts "   Personal Code: #{result.personal_code}"
      puts "   Country: #{result.country}"
      puts "   Certificate Level: #{result.certificate_level}"
      
      # Verify personal code parsing works
      if result.personal_code
        reader = @verifier.authenticators[:digidoc_local].instance_variable_get(:@reader)
        parsed = reader.parse_personal_code(result.personal_code)
        
        if parsed[:birth_date]
          puts "   Birth Date: #{parsed[:birth_date]}"
          puts "   Gender: #{parsed[:gender]}"
          puts "   Age: #{parsed[:age]}"
        end
      end
      
    elsif result.status == :failed
      flunk "Authentication failed: #{result.error}"
    else
      flunk "Unexpected status: #{result.status}"
    end
  end

  def test_session_management_and_cleanup
    skip "Skipping hardware test - set ENV['HARDWARE_TESTS'] to run" unless ENV['HARDWARE_TESTS']
    
    unless @verifier.method_available?(:digidoc_local)
      flunk "DigiDoc Local required for session management test"
    end

    # Create multiple sessions
    session1 = @verifier.digidoc_local_auth
    session2 = @verifier.digidoc_local_auth
    
    assert_not_equal session1.id, session2.id, "Sessions should have unique IDs"
    
    # Cancel sessions
    assert @verifier.cancel_authentication(session1)
    assert @verifier.cancel_authentication(session2)
    
    puts "\n✅ Session management test completed"
  end

  def test_configuration_and_customization
    # Test custom configuration
    custom_verifier = EeIdVerification.new(
      digidoc_local: {
        pin_retry_count: 5,
        require_ocsp: false
      },
      timeout: 600
    )
    
    assert_kind_of EeIdVerification::Verifier, custom_verifier
    
    # Should have same availability as default
    assert_equal @verifier.method_available?(:digidoc_local), 
                 custom_verifier.method_available?(:digidoc_local)
  end

  def test_error_handling_and_edge_cases
    # Test with invalid session
    fake_session = EeIdVerification::AuthenticationSession.new(
      id: "fake-123",
      method: :digidoc_local,
      status: :pending,
      created_at: Time.now,
      expires_at: Time.now + 300
    )
    
    # Should handle invalid session gracefully
    if @verifier.method_available?(:digidoc_local)
      result = @verifier.poll_status(fake_session)
      assert_equal :failed, result.status
      assert_includes result.error.downcase, "not found"
    end
  end

  def test_concurrent_access_safety
    skip "Skipping hardware test - set ENV['HARDWARE_TESTS'] to run" unless ENV['HARDWARE_TESTS']
    
    unless @verifier.method_available?(:digidoc_local)
      skip "DigiDoc Local not available for concurrency test"
    end

    # Test that multiple verifier instances can coexist
    verifier2 = EeIdVerification.new
    
    assert_equal @verifier.method_available?(:digidoc_local),
                 verifier2.method_available?(:digidoc_local)
    
    # Both should be able to create sessions
    session1 = @verifier.digidoc_local_auth
    session2 = verifier2.digidoc_local_auth
    
    assert_not_equal session1.id, session2.id
    
    # Clean up
    @verifier.cancel_authentication(session1)
    verifier2.cancel_authentication(session2)
  end

  def test_method_not_available_handling
    # Test handling of methods that are not available
    unavailable_methods = [:mobile_id, :smart_id, :digidoc_browser]
    
    unavailable_methods.each do |method|
      refute @verifier.method_available?(method), "#{method} should not be available in test environment"
    end
    
    # Trying to use unavailable method should raise error
    assert_raises(EeIdVerification::ServiceUnavailableError) do
      @verifier.mobile_id_auth(phone_number: "+3725551234", personal_code: "38001010008")
    end
  end

  def test_global_configuration
    # Test global configuration functionality
    original_config = EeIdVerification.configuration
    
    EeIdVerification.configure do |config|
      config.default_timeout = 900
      config.default_language = "et"
    end
    
    new_config = EeIdVerification.configuration
    assert_equal 900, new_config.default_timeout
    assert_equal "et", new_config.default_language
    
    # New verifier should use global config
    global_verifier = EeIdVerification.new
    assert_kind_of EeIdVerification::Verifier, global_verifier
  end
end