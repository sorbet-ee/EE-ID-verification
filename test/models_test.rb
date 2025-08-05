# frozen_string_literal: true

require "test_helper"

class ModelsTest < Minitest::Test
  def test_authentication_session_creation
    session = EeIdVerification::AuthenticationSession.new(
      id: "test-123",
      method: :digidoc_local,
      status: :pending,
      created_at: Time.now,
      expires_at: Time.now + 300,
      personal_code: "38001010008"
    )
    
    assert_equal "test-123", session.id
    assert_equal :digidoc_local, session.method
    assert_equal :pending, session.status
    assert_equal "38001010008", session.personal_code
    assert_kind_of Hash, session.metadata
  end

  def test_authentication_session_status_methods
    session = EeIdVerification::AuthenticationSession.new(status: :pending)
    assert session.pending?
    refute session.completed?
    refute session.failed?
    
    session.status = :completed
    refute session.pending?
    assert session.completed?
    refute session.failed?
    
    session.status = :failed
    refute session.pending?
    refute session.completed?
    assert session.failed?
  end

  def test_authentication_session_expiry
    # Not expired
    session = EeIdVerification::AuthenticationSession.new(
      expires_at: Time.now + 300
    )
    refute session.expired?
    
    # Expired
    session.expires_at = Time.now - 300
    assert session.expired?
    
    # No expiry set
    session.expires_at = nil
    refute session.expired?
  end

  def test_authentication_result_creation
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
    assert_equal "38001010008", result.personal_code
    assert_equal "TEST USER", result.full_name
  end

  def test_authentication_result_success_failure
    # Successful result
    success_result = EeIdVerification::AuthenticationResult.new(
      authenticated: true,
      error: nil
    )
    assert success_result.success?
    refute success_result.failure?
    
    # Failed result with error
    failed_result = EeIdVerification::AuthenticationResult.new(
      authenticated: false,
      error: "Invalid PIN"
    )
    refute failed_result.success?
    assert failed_result.failure?
    
    # Authenticated but with error (edge case)
    edge_result = EeIdVerification::AuthenticationResult.new(
      authenticated: true,
      error: "Warning message"
    )
    refute edge_result.success?  # Should be false because of error
    assert edge_result.failure?
  end

  def test_signature_verification_result
    result = EeIdVerification::SignatureVerificationResult.new(
      valid: true,
      signer_info: { name: "Test User" },
      signed_at: Time.now,
      signature_level: "QES"
    )
    
    assert result.valid?
    refute result.invalid?
    assert_equal "Test User", result.signer_info[:name]
    assert_equal "QES", result.signature_level
    assert_kind_of Array, result.errors
    assert_kind_of Array, result.warnings
  end

  def test_signature_verification_result_with_errors
    result = EeIdVerification::SignatureVerificationResult.new(
      valid: true,
      errors: ["Certificate expired"]
    )
    
    # Should be invalid if there are errors, regardless of valid flag
    refute result.valid?
    assert result.invalid?
    assert_includes result.errors, "Certificate expired"
  end

  def test_certificate_info_creation
    cert_info = EeIdVerification::CertificateInfo.new(
      subject: "CN=Test User",
      issuer: "CN=Test CA",
      not_before: Time.now - 86400,  # Yesterday
      not_after: Time.now + 86400    # Tomorrow
    )
    
    assert_equal "CN=Test User", cert_info.subject
    assert_equal "CN=Test CA", cert_info.issuer
    assert cert_info.valid_at?(Time.now)
    refute cert_info.expired?
    refute cert_info.not_yet_valid?
  end

  def test_certificate_info_validity_checks
    now = Time.now
    
    # Future certificate (not yet valid)
    future_cert = EeIdVerification::CertificateInfo.new(
      not_before: now + 86400,
      not_after: now + 172800
    )
    refute future_cert.valid_at?(now)
    refute future_cert.expired?
    assert future_cert.not_yet_valid?
    
    # Expired certificate
    expired_cert = EeIdVerification::CertificateInfo.new(
      not_before: now - 172800,
      not_after: now - 86400
    )
    refute expired_cert.valid_at?(now)
    assert expired_cert.expired?
    refute expired_cert.not_yet_valid?
  end

  def test_configuration_defaults
    config = EeIdVerification::Configuration.new
    
    assert_kind_of Hash, config.digidoc_local_config
    assert_kind_of Hash, config.digidoc_browser_config
    assert_kind_of Hash, config.mobile_id_config
    assert_kind_of Hash, config.smart_id_config
    
    assert_equal 300, config.default_timeout
    assert_equal "en", config.default_language
  end

  def test_custom_exceptions_hierarchy
    # Test exception hierarchy
    assert EeIdVerification::ConfigurationError < EeIdVerification::VerificationError
    assert EeIdVerification::AuthenticationError < EeIdVerification::VerificationError
    assert EeIdVerification::TimeoutError < EeIdVerification::AuthenticationError
    assert EeIdVerification::CertificateError < EeIdVerification::VerificationError
    assert EeIdVerification::ServiceUnavailableError < EeIdVerification::VerificationError
    assert EeIdVerification::VerificationError < StandardError
  end

  def test_exception_raising_and_catching
    # Test that exceptions can be raised and caught properly
    assert_raises(EeIdVerification::ConfigurationError) do
      raise EeIdVerification::ConfigurationError, "Test configuration error"
    end
    
    # Test catching with parent class
    assert_raises(EeIdVerification::VerificationError) do
      raise EeIdVerification::AuthenticationError, "Test auth error"
    end
    
    # Test timeout is a subclass of authentication error
    assert_raises(EeIdVerification::AuthenticationError) do
      raise EeIdVerification::TimeoutError, "Test timeout"
    end
  end

  def test_metadata_handling
    session = EeIdVerification::AuthenticationSession.new
    assert_kind_of Hash, session.metadata
    
    session.metadata[:custom_field] = "test_value"
    assert_equal "test_value", session.metadata[:custom_field]
    
    result = EeIdVerification::AuthenticationResult.new
    assert_kind_of Hash, result.metadata
    
    result.metadata[:verification_method] = "PIN1"
    assert_equal "PIN1", result.metadata[:verification_method]
  end

  def test_full_name_generation
    # Both names present
    result = EeIdVerification::AuthenticationResult.new(
      given_name: "John",
      surname: "Doe"
    )
    assert_equal "John Doe", result.full_name
    
    # Only given name
    result.surname = nil
    assert_equal "John", result.full_name
    
    # Only surname
    result.given_name = nil
    result.surname = "Doe"
    assert_equal "Doe", result.full_name
    
    # No names
    result.surname = nil
    assert_nil result.full_name
    
    # Empty strings
    result.given_name = ""
    result.surname = ""
    assert_equal "", result.full_name
  end
end