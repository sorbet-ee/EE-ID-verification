# frozen_string_literal: true

require "test_helper"

module EeIdVerification
  class TestVerification < Minitest::Test
    def test_that_it_has_a_version_number
      refute_nil ::EeIdVerification::VERSION
    end

    def test_it_can_create_verifier
      verifier = EeIdVerification.new
      assert_instance_of EeIdVerification::Verifier, verifier
    end
  end
end
