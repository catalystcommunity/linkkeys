# frozen_string_literal: true

require_relative 'test_helper'

class TestConformanceEnvelopes < Minitest::Test
  include ConformanceHelper

  def verify_case(c)
    payload = ConformanceHelper.hex(c['payload_cbor_hex'])
    signature = ConformanceHelper.hex(c['signature_hex'])
    verify_key = ConformanceHelper.hex(c['verify_key_hex'])

    signature_input = LinkkeysLocalRp::LocalRp.envelope_signature_input(c['context'], payload)
    assert_equal c['signature_input_cbor_hex'], signature_input.unpack1('H*'),
                 "signature_input mismatch for #{c['name'] || c['structure']}"

    begin
      LinkkeysLocalRp::Crypto.verify_with_algorithm(
        LinkkeysLocalRp::Crypto::SigningAlgorithm::ED25519, signature_input, signature, verify_key
      )
      true
    rescue LinkkeysLocalRp::Crypto::VerificationFailed
      false
    end
  end

  def test_positive_cases
    envelopes_vector['cases'].each do |c|
      assert verify_case(c) == c['expected_valid'], "positive case failed: #{c['structure']}"
    end
  end

  def test_negative_cases
    envelopes_vector['negative_cases'].each do |c|
      assert verify_case(c) == c['expected_valid'], "negative case failed: #{c['name']}"
    end
  end
end
