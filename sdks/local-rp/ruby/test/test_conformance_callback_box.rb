# frozen_string_literal: true

require_relative 'test_helper'

class TestConformanceCallbackBox < Minitest::Test
  include ConformanceHelper

  def open_case(c)
    encrypted = LinkkeysLocalRp::Types::LocalRpEncryptedCallback.new(
      header: ConformanceHelper.hex(c['header_cbor_hex']),
      ciphertext: ConformanceHelper.hex(c['ciphertext_hex'])
    )
    allowed_suites = c['allowed_suites']
    decrypt_key = ConformanceHelper.hex(c['decrypt_private_key_hex'])
    LinkkeysLocalRp::LocalRp.open_local_rp_callback(encrypted, decrypt_key, allowed_suites)
  end

  def test_positive_cases
    callback_box_vector['positive_cases'].each do |c|
      _header, signed_payload = open_case(c)
      assert_equal c['plaintext_cbor_hex'], signed_payload.to_cbor.unpack1('H*'), "suite #{c['suite']}"
    end
  end

  def test_negative_cases
    callback_box_vector['negative_cases'].each do |c|
      assert_raises(StandardError, c['name']) { open_case(c) }
    end
  end

  def test_kdf_context_matches
    callback_box_vector['positive_cases'].each do |c|
      suite = c['suite']
      ephemeral_public = ConformanceHelper.hex(c['ephemeral_public_key_hex'])
      recipient_public = ConformanceHelper.hex(c['recipient_public_key_hex'])
      tag = 'linkkeys-local-rp-callback-box'.b
      expected_context = tag + suite.b + ephemeral_public + recipient_public
      assert_equal c['kdf_context_hex'], expected_context.unpack1('H*')
      assert_equal c['aad_hex'], (expected_context + ConformanceHelper.hex(c['header_cbor_hex'])).unpack1('H*')
    end
  end
end
