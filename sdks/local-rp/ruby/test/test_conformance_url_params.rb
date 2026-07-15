# frozen_string_literal: true

require_relative 'test_helper'

class TestConformanceUrlParams < Minitest::Test
  include ConformanceHelper

  def test_positive_cases
    url_params_vector['cases'].each do |c|
      cbor_bytes = ConformanceHelper.hex(c['cbor_hex'])
      encoded = LinkkeysLocalRp::UrlParams.b64url_encode(cbor_bytes)
      assert_equal c['base64url_unpadded'], encoded, "encode mismatch: #{c['name']}"

      decoded = LinkkeysLocalRp::UrlParams.b64url_decode(c['base64url_unpadded'])
      assert_equal c['cbor_hex'], decoded.unpack1('H*'), "decode mismatch: #{c['name']}"
    end
  end

  def test_negative_cases
    url_params_vector['negative_cases'].each do |c|
      assert_raises(LinkkeysLocalRp::UrlParams::DecodeError, c['name']) do
        LinkkeysLocalRp::UrlParams.b64url_decode(c['input'])
      end
    end
  end

  def test_login_request_and_callback_round_trip
    signed_case = url_params_vector['cases'].find { |c| c['name'] == 'signed_local_rp_login_request' }
    signed = LinkkeysLocalRp::UrlParams.signed_local_rp_login_request_from_url_param(signed_case['base64url_unpadded'])
    assert_equal signed_case['cbor_hex'], signed.to_cbor.unpack1('H*')

    callback_case = url_params_vector['cases'].find { |c| c['name'] == 'local_rp_encrypted_callback' }
    callback = LinkkeysLocalRp::UrlParams.local_rp_encrypted_callback_from_url_param(callback_case['base64url_unpadded'])
    assert_equal callback_case['cbor_hex'], callback.to_cbor.unpack1('H*')
  end
end
