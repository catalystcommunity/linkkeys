# frozen_string_literal: true

require_relative 'test_helper'

class TestConformanceRevocations < Minitest::Test
  include ConformanceHelper

  def build_key(k)
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

  def build_certificate(cert_h)
    sigs = cert_h['signatures'].map do |s|
      LinkkeysLocalRp::Types::ClaimSignature.new(
        domain: s['domain'], signed_by_key_id: s['signed_by_key_id'], signature: ConformanceHelper.hex(s['signature_hex'])
      )
    end
    LinkkeysLocalRp::Types::RevocationCertificate.new(
      target_key_id: cert_h['target_key_id'], target_fingerprint: cert_h['target_fingerprint'],
      revoked_at: cert_h['revoked_at'], signatures: sigs
    )
  end

  def domain_keys
    @domain_keys ||= revocations_vector['domain_keys'].map { |k| build_key(k) }
  end

  def test_registry_constants
    assert_equal revocations_vector['quorum'], LinkkeysLocalRp::Revocation::REVOCATION_QUORUM
    assert_equal revocations_vector['tag'], LinkkeysLocalRp::Revocation::REVOCATION_TAG
  end

  def test_certificate_cbor_round_trip
    revocations_vector['certificate_cases'].each do |c|
      cert = build_certificate(c['certificate'])
      assert_equal c['certificate_cbor_hex'], cert.to_cbor.unpack1('H*'), c['name']
    end
  end

  def test_all_certificate_cases
    now = LinkkeysLocalRp::Timeutil.parse_rfc3339('2026-01-01T00:07:00+00:00')
    revocations_vector['certificate_cases'].each do |c|
      cert = build_certificate(c['certificate'])

      count = LinkkeysLocalRp::Revocation.count_valid_signers(cert, domain_keys, c['verify_domain'], now)
      assert_equal c['expected_counted_signers'], count, "#{c['name']}: counted signers"

      valid = begin
        LinkkeysLocalRp::Revocation.verify_revocation_certificate(cert, domain_keys, c['verify_domain'], now)
        true
      rescue LinkkeysLocalRp::Revocation::RevocationError
        false
      end
      assert_equal c['expected_valid'], valid, "#{c['name']}: overall validity"
    end
  end

  def test_application_case_before_and_after_revocation
    app = revocations_vector['application_case']
    env = app['envelope']
    signed = LinkkeysLocalRp::Types::SignedLocalRpCallbackPayload.new(
      payload: ConformanceHelper.hex(env['payload_cbor_hex']),
      signing_key_id: env['signing_key_id'],
      signature: ConformanceHelper.hex(env['signature_hex'])
    )
    now = LinkkeysLocalRp::Timeutil.parse_rfc3339(app['verify_now'])
    skew = app['clock_skew_seconds']

    before_ok = begin
      LinkkeysLocalRp::LocalRp.verify_local_rp_callback_payload(signed, domain_keys, now, skew)
      true
    rescue LinkkeysLocalRp::LocalRp::Error
      false
    end
    assert_equal app['expected_valid_before_revocation'], before_ok

    cert_case = revocations_vector['certificate_cases'].find { |c| c['name'] == 'valid_quorum_two_siblings' }
    cert = build_certificate(cert_case['certificate'])
    trusted_after = LinkkeysLocalRp::Revocation.apply_revocations(domain_keys, [cert], revocations_vector['domain'], now)

    after_ok = begin
      LinkkeysLocalRp::LocalRp.verify_local_rp_callback_payload(signed, trusted_after, now, skew)
      true
    rescue LinkkeysLocalRp::LocalRp::Error
      false
    end
    assert_equal app['expected_valid_after_revocation'], after_ok
  end
end
