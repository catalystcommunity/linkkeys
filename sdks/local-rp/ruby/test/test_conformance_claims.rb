# frozen_string_literal: true

require_relative 'test_helper'

class TestConformanceClaims < Minitest::Test
  include ConformanceHelper

  # `now` for signature-quorum/expiry checks -- coincides with every
  # fixture's attested_at/created_at, and is safely before claim 1's
  # far-future expires_at (2126) and after nothing else in the file has an
  # expiry.
  NOW = LinkkeysLocalRp::Timeutil.parse_rfc3339('2026-01-01T00:00:00+00:00')

  ERROR_CLASS_FOR = {
    'signature_invalid' => LinkkeysLocalRp::Claims::SignatureInvalid,
    'key_not_found' => LinkkeysLocalRp::Claims::KeyNotFound
  }.freeze

  def build_domain_key(k)
    LinkkeysLocalRp::Types::DomainPublicKey.new(
      key_id: k['key_id'],
      public_key: ConformanceHelper.hex(k['public_key_hex']),
      fingerprint: k['fingerprint_hex'],
      algorithm: k['algorithm'],
      key_usage: k['key_usage'],
      created_at: k['created_at'],
      expires_at: k['expires_at'],
      revoked_at: k['revoked_at'],
      signed_by_key_id: nil,
      key_signature: nil
    )
  end

  # claims.json's domain_keys is a flat list (every entry happens to share
  # one domain in this fixture); group it into the DomainKeySet list shape
  # Claims.verify_claim / complete_local_login actually consume.
  def build_domain_key_sets(list)
    list.group_by { |k| k['domain'] }.map do |domain, keys|
      LinkkeysLocalRp::Claims::DomainKeySet.new(domain: domain, keys: keys.map { |k| build_domain_key(k) })
    end
  end

  def default_domain_key_sets
    @default_domain_key_sets ||= build_domain_key_sets(claims_vector['domain_keys'])
  end

  def build_claim_signature(s)
    LinkkeysLocalRp::Types::ClaimSignature.new(
      domain: s['domain'], signed_by_key_id: s['signed_by_key_id'], signature: ConformanceHelper.hex(s['signature_hex'])
    )
  end

  def build_claim(claim_h)
    LinkkeysLocalRp::Types::Claim.new(
      claim_id: claim_h['claim_id'],
      user_id: claim_h['user_id'],
      claim_type: claim_h['claim_type'],
      claim_value: ConformanceHelper.hex(claim_h['claim_value_hex']),
      signatures: claim_h['signatures'].map { |s| build_claim_signature(s) },
      attested_at: claim_h['attested_at'],
      created_at: claim_h['created_at'],
      expires_at: claim_h['expires_at'],
      revoked_at: claim_h['revoked_at']
    )
  end

  def find_domain_public_key(domain_keys_hashes, key_id)
    entry = domain_keys_hashes.find { |k| k['key_id'] == key_id }
    raise "fixture key #{key_id} not found" if entry.nil?

    ConformanceHelper.hex(entry['public_key_hex'])
  end

  # --- positive cases -----------------------------------------------------

  def test_registry_constants
    assert_equal claims_vector['tag'], LinkkeysLocalRp::Claims::CLAIM_PAYLOAD_TAG
  end

  def test_positive_case_wire_round_trip
    claims_vector['cases'].each do |c|
      claim = build_claim(c['claim'])
      encoded = claim.to_cbor.unpack1('H*')
      assert_equal c['claim_cbor_hex'], encoded, "encode mismatch: #{c['name']}"

      decoded = LinkkeysLocalRp::Types::Claim.from_cbor(ConformanceHelper.hex(c['claim_cbor_hex']))
      reencoded = decoded.to_cbor.unpack1('H*')
      assert_equal c['claim_cbor_hex'], reencoded, "decode->encode round-trip mismatch: #{c['name']}"

      # The bstr/tstr trap: claim_value must survive the round trip as raw
      # bytes (ASCII-8BIT), never coerced into a UTF-8 text string, even for
      # the case whose bytes happen to be valid UTF-8.
      assert_equal ::Encoding::ASCII_8BIT, decoded.claim_value.encoding, "claim_value not decoded as bstr: #{c['name']}"
      assert_equal ConformanceHelper.hex(c['claim']['claim_value_hex']), decoded.claim_value, "claim_value bytes mismatch: #{c['name']}"
    end
  end

  # Independent of the SDK's own claim_sign_payload construction: verify
  # each fixture's signed_payload_cbor_hex/signature_hex directly against
  # the domain's public key using the raw Ed25519 primitive, so a correct
  # verify_claim run below can't be hiding a payload-construction bug that
  # happens to be self-consistent.
  def test_signed_payload_independent_ed25519_verification
    claims_vector['cases'].each do |c|
      c['claim']['signatures'].each do |s|
        payload = ConformanceHelper.hex(s['signed_payload_cbor_hex'])
        signature = ConformanceHelper.hex(s['signature_hex'])
        public_key = find_domain_public_key(claims_vector['domain_keys'], s['signed_by_key_id'])

        LinkkeysLocalRp::Crypto.verify_with_algorithm(
          LinkkeysLocalRp::Crypto::SigningAlgorithm::ED25519, payload, signature, public_key
        )
      rescue LinkkeysLocalRp::Crypto::VerificationFailed => e
        flunk "#{c['name']} / #{s['signed_by_key_id']}: independent Ed25519 verification failed: #{e.message}"
      end
    end
  end

  def test_positive_cases_verify_claim
    claims_vector['cases'].each do |c|
      claim = build_claim(c['claim'])
      LinkkeysLocalRp::Claims.verify_claim(claim, c['subject_domain'], default_domain_key_sets, NOW)
    rescue LinkkeysLocalRp::Claims::Error => e
      flunk "#{c['name']}: expected verify_claim to succeed, raised #{e.class}: #{e.message}"
    end
  end

  # --- decode negatives ----------------------------------------------------

  def test_decode_negative_cases
    claims_vector['decode_negative_cases'].each do |c|
      refute c['expected_decode_ok'], "fixture bug: #{c['name']} should have expected_decode_ok=false"

      assert_raises(LinkkeysLocalRp::Cbor::DecodeError, "#{c['name']}: decode should have been rejected") do
        LinkkeysLocalRp::Types::Claim.from_cbor(ConformanceHelper.hex(c['claim_cbor_hex']))
      end
    end
  end

  # --- verification negatives ----------------------------------------------

  def test_verification_negative_cases
    claims_vector['negative_cases'].each do |c|
      claim = LinkkeysLocalRp::Types::Claim.from_cbor(ConformanceHelper.hex(c['claim_cbor_hex']))
      domain_key_sets = c['domain_keys'] ? build_domain_key_sets(c['domain_keys']) : default_domain_key_sets
      expected_class = ERROR_CLASS_FOR.fetch(c['expected_error']) do
        flunk "#{c['name']}: unmapped expected_error #{c['expected_error']}"
      end

      assert_raises(expected_class, "#{c['name']}: expected #{c['expected_error']}") do
        LinkkeysLocalRp::Claims.verify_claim(claim, c['subject_domain'], domain_key_sets, NOW)
      end
    end
  end

  # --- ticket redemption response -------------------------------------------

  def test_ticket_redemption_response_round_trip_and_claim_verification
    trr = claims_vector['ticket_redemption_response']
    response = LinkkeysLocalRp::Types::LocalRpTicketRedemptionResponse.from_cbor(
      ConformanceHelper.hex(trr['response_cbor_hex'])
    )

    assert_equal trr['user_id'], response.user_id
    assert_equal trr['user_domain'], response.user_domain
    assert_equal trr['ticket_expires_at'], response.ticket_expires_at
    assert_equal claims_vector['cases'].length, response.claims.length

    reencoded = response.to_cbor.unpack1('H*')
    assert_equal trr['response_cbor_hex'], reencoded, 'response round-trip mismatch'

    # Decoding without verifying fails the point (README's own words) --
    # verify every embedded claim's signatures through the exact path
    # complete_local_login uses.
    response.claims.each_with_index do |claim, i|
      assert_equal ::Encoding::ASCII_8BIT, claim.claim_value.encoding, "claims[#{i}].claim_value not bstr"
      LinkkeysLocalRp::Claims.verify_claim(claim, response.user_domain, default_domain_key_sets, NOW)
    rescue LinkkeysLocalRp::Claims::Error => e
      flunk "claims[#{i}] (#{claim.claim_id}): expected verify_claim to succeed, raised #{e.class}: #{e.message}"
    end
  end
end
