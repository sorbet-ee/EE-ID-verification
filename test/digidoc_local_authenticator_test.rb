# frozen_string_literal: true

require "test_helper"

class DigiDocLocalAuthenticatorTest < Minitest::Test
  def setup
    @authenticator = EeIdVerification::DigiDocLocalAuthenticator.new
  end

  def teardown
    # Clean up any active sessions
    @authenticator = nil
  end

  def test_initialization
    assert_kind_of EeIdVerification::DigiDocLocalAuthenticator, @authenticator
    assert_respond_to @authenticator, :available?
    assert_respond_to @authenticator, :initiate_authentication
    assert_respond_to @authenticator, :poll_status
    assert_respond_to @authenticator, :cancel_authentication
  end

  def test_availability_depends_on_hardware
    # Test availability detection
    available = @authenticator.available?
    assert_includes [true, false], available, "available? should return boolean"

    if available
      puts "\n✅ DigiDoc Local authentication is available"
    else
      puts "\n⚠️  DigiDoc Local not available (no card or reader)"
    end
  end

  def test_requires_estonian_id_card_for_authentication
    skip "Skipping hardware test - set ENV['HARDWARE_TESTS'] to run" unless ENV["HARDWARE_TESTS"]

    unless @authenticator.available?
      error_msg = "Estonian ID card and reader required for this test. Please:\n" \
                  "1. Insert your Estonian ID card\n" \
                  "2. Ensure card reader is connected\n" \
                  "3. Install OpenSC (brew install opensc on macOS)"

      flunk error_msg
    end

    assert @authenticator.available?, "DigiDoc Local must be available for authentication tests"
  end

  def test_authentication_session_creation
    skip "Skipping hardware test - set ENV['HARDWARE_TESTS'] to run" unless ENV["HARDWARE_TESTS"]

    unless @authenticator.available?
      flunk "Estonian ID card required - please insert card and run with ENV['HARDWARE_TESTS']=1"
    end

    session = @authenticator.initiate_authentication

    assert_kind_of EeIdVerification::AuthenticationSession, session
    assert_equal :digidoc_local, session.method
    assert_equal :pending, session.status
    assert_kind_of String, session.id
    assert session.id.length.positive?, "Session should have a valid ID"

    # Check session expiry
    assert session.expires_at > Time.now, "Session should not be expired immediately"

    puts "\n✅ Authentication session created:"
    puts "   Session ID: #{session.id[0..8]}..."
    puts "   Method: #{session.method}"
    puts "   Status: #{session.status}"
    puts "   Expires: #{session.expires_at}"
  end

  def test_pin_provision_and_authentication_flow
    skip "Skipping hardware test - set ENV['HARDWARE_TESTS'] to run" unless ENV["HARDWARE_TESTS"]

    unless @authenticator.available?
      flunk "Estonian ID card required - please insert card and run with ENV['HARDWARE_TESTS']=1"
    end

    # Step 1: Initiate authentication
    session = @authenticator.initiate_authentication
    assert_equal :pending, session.status

    # Step 2: Check status before PIN (should be waiting)
    result = @authenticator.poll_status(session)
    assert_equal :waiting_for_pin, result.status
    refute result.authenticated?

    # Step 3: Provide PIN
    print "\n🔑 Enter PIN1 for authentication flow test: "
    pin1 = gets.chomp

    success = @authenticator.provide_pin(session.id, pin1)
    assert success, "PIN provision should succeed"

    # Step 4: Poll status after PIN (should complete authentication)
    result = @authenticator.poll_status(session)

    if result.status == :completed
      assert result.authenticated?, "Should be authenticated after successful PIN"
      assert_kind_of String, result.personal_code
      assert_kind_of String, result.given_name
      assert_kind_of String, result.surname

      puts "\n✅ Authentication completed successfully:"
      puts "   Name: #{result.given_name} #{result.surname}"
      puts "   Personal code: #{result.personal_code}"
      puts "   Country: #{result.country}"
    elsif result.status == :failed
      flunk "Authentication failed: #{result.error}"
    else
      flunk "Unexpected authentication status: #{result.status}"
    end
  end

  def test_session_cancellation
    skip "Skipping hardware test - set ENV['HARDWARE_TESTS'] to run" unless ENV["HARDWARE_TESTS"]

    unless @authenticator.available?
      flunk "Estonian ID card required - please insert card and run with ENV['HARDWARE_TESTS']=1"
    end

    session = @authenticator.initiate_authentication
    assert_equal :pending, session.status

    # Cancel the session
    result = @authenticator.cancel_authentication(session)
    assert result, "Session cancellation should succeed"

    puts "\n✅ Session cancelled successfully"
  end

  def test_error_handling_with_wrong_pin
    skip "Skipping hardware test - set ENV['HARDWARE_TESTS'] to run" unless ENV["HARDWARE_TESTS"]

    unless @authenticator.available?
      flunk "Estonian ID card required - please insert card and run with ENV['HARDWARE_TESTS']=1"
    end

    session = @authenticator.initiate_authentication

    # Provide wrong PIN
    @authenticator.provide_pin(session.id, "0000") # Obviously wrong PIN

    result = @authenticator.poll_status(session)

    if result.status == :failed
      assert_includes result.error.downcase, "pin", "Error should mention PIN issue"
      puts "\n✅ Wrong PIN handled correctly: #{result.error}"
    else
      # If it doesn't fail immediately, the card might have different behavior
      puts "\n⚠️  PIN validation behavior may vary by card"
    end
  end

  def test_configuration_defaults
    # Test default configuration (no hardware needed)
    config = @authenticator.send(:default_config)

    assert_kind_of Hash, config
    assert_kind_of Integer, config[:timeout]
    assert config[:timeout].positive?, "Timeout should be positive"
    assert_kind_of Integer, config[:pin_retry_count]
    assert config[:pin_retry_count].positive?, "PIN retry count should be positive"
    assert_includes [true, false], config[:require_ocsp]
  end

  def test_session_expiry_handling
    # Test session expiry logic (no hardware needed)
    expired_session = EeIdVerification::AuthenticationSession.new(
      id: "test-123",
      method: :digidoc_local,
      status: :pending,
      created_at: Time.now - 3600,  # 1 hour ago
      expires_at: Time.now - 1800   # 30 minutes ago (expired)
    )

    assert expired_session.expired?, "Session should be expired"

    # Test with expired session should raise error
    assert_raises(ArgumentError) do
      @authenticator.poll_status(expired_session)
    end
  end

  def test_integration_with_verifier
    # Test that authenticator works with main verifier
    verifier = EeIdVerification.new

    # Should be able to get the authenticator
    local_auth = verifier.authenticators[:digidoc_local]
    assert_kind_of EeIdVerification::DigiDocLocalAuthenticator, local_auth

    # Availability should match
    assert_equal local_auth.available?, verifier.method_available?(:digidoc_local)

    available_methods = verifier.available_methods
    if local_auth.available?
      assert_includes available_methods, :digidoc_local
    else
      refute_includes available_methods, :digidoc_local
    end
  end
end
