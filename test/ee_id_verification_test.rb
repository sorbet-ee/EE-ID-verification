# frozen_string_literal: true

require "test_helper"

class EeIdVerificationTest < Minitest::Test
  def setup
    @verifier = EeIdVerification.new
  end

  def test_that_it_has_a_version_number
    refute_nil ::EeIdVerification::VERSION
  end

  def test_verifier_creation
    assert_kind_of EeIdVerification::Verifier, @verifier
    assert_respond_to @verifier, :available?
    assert_respond_to @verifier, :authenticate
    assert_respond_to @verifier, :complete_authentication
  end

  def test_availability_detection
    available = @verifier.available?
    assert_includes [true, false], available

    if available
      puts "\n✅ Estonian ID card detected"
    else
      puts "\n⚠️  No Estonian ID card detected"
    end
  end

  def test_authentication_session_model
    session = EeIdVerification::AuthenticationSession.new(
      id: "test-123",
      method: :digidoc_local,
      status: :waiting_for_pin,
      created_at: Time.now,
      expires_at: Time.now + 300
    )

    assert_equal "test-123", session.id
    assert_equal :digidoc_local, session.method
    assert_equal :waiting_for_pin, session.status
    refute session.expired?
  end

  def test_authentication_result_model
    result = EeIdVerification::AuthenticationResult.new(
      session_id: "test-123",
      status: :completed,
      authenticated: true,
      personal_code: "38001010008",
      given_name: "TEST",
      surname: "USER",
      country: "EE"
    )

    assert_equal "test-123", result.session_id
    assert_equal :completed, result.status
    assert result.authenticated?
    assert result.success?
    assert_equal "TEST USER", result.full_name
  end

  def test_personal_code_parsing
    reader = EeIdVerification::CertificateReader.new

    result = reader.parse_personal_code("38001010008")
    assert_equal "Male", result[:gender]
    assert_equal 1980, result[:birth_date].year
    assert_kind_of Integer, result[:age]

    result = reader.parse_personal_code("invalid")
    assert_empty result
  end

  def test_end_to_end_authentication
    skip "Hardware test - set ENV['HARDWARE_TESTS'] to run" unless ENV["HARDWARE_TESTS"]

    flunk "Estonian ID card required. Please insert card and run with HARDWARE_TESTS=1" unless @verifier.available?

    session = @verifier.authenticate
    assert_kind_of EeIdVerification::AuthenticationSession, session
    assert_equal :waiting_for_pin, session.status

    print "\n🔑 Enter PIN1 for test: "
    pin = gets.chomp

    result = @verifier.complete_authentication(session, pin)

    if result.success?
      puts "\n✅ Authentication successful!"
      puts "Name: #{result.full_name}"
      puts "Personal Code: #{result.personal_code}"
      assert result.authenticated?
      assert_match(/^\d{11}$/, result.personal_code)
    else
      flunk "Authentication failed: #{result.error}"
    end
  end
end
