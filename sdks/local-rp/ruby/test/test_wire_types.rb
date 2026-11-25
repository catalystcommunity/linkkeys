# frozen_string_literal: true

require_relative 'test_helper'

# Wire-shape checks for the CSIL `timestamp` type (CBOR tag 0, UTC text),
# named-number enums (CBOR unsigned integers), and the whole-second rule for
# timestamps inside signed tuple payloads.
class TestWireTypes < Minitest::Test
  include ConformanceHelper

  Cbor = LinkkeysLocalRp::Cbor
  Types = LinkkeysLocalRp::Types

  def redemption_request(issued_at)
    Types::LocalRpTicketRedemptionRequest.new(claim_ticket: 'ticket'.b, fingerprint: 'fp', issued_at: issued_at)
  end

  def test_timestamp_encodes_as_tag_zero_in_utc
    tree = Cbor.decode(redemption_request('2026-01-01T02:00:00+02:00').to_cbor)
    assert_equal Cbor::CborTag.new(0, '2026-01-01T00:00:00Z'), tree['issued_at']

    frac = Cbor.decode(redemption_request('2026-01-01T00:00:00.250Z').to_cbor)
    assert_equal '2026-01-01T00:00:00.250Z', frac['issued_at'].value
  end

  def test_untagged_or_wrong_tag_timestamp_is_rejected
    good = Cbor.decode(redemption_request('2026-01-01T00:00:00Z').to_cbor)

    untagged = good.merge('issued_at' => '2026-01-01T00:00:00Z')
    assert_raises(Cbor::DecodeError) { Types::LocalRpTicketRedemptionRequest.from_cbor(Cbor.encode(untagged)) }

    epoch = good.merge('issued_at' => Cbor::CborTag.new(1, 1_767_225_600))
    assert_raises(Cbor::DecodeError) { Types::LocalRpTicketRedemptionRequest.from_cbor(Cbor.encode(epoch)) }

    garbage = good.merge('issued_at' => Cbor::CborTag.new(0, 'not a time'))
    assert_raises(Cbor::DecodeError) { Types::LocalRpTicketRedemptionRequest.from_cbor(Cbor.encode(garbage)) }
  end

  def domain_key_tree
    key = Types::DomainPublicKey.new(
      key_id: 'k1', public_key: ("\x01" * 32).b, fingerprint: 'fp', algorithm: 'ed25519', key_usage: 'sign',
      created_at: '2026-01-01T00:00:00Z', expires_at: '2027-01-01T00:00:00Z'
    )
    Cbor.decode(key.to_cbor)
  end

  def test_enums_are_unsigned_integers
    tree = domain_key_tree
    assert_equal 1, tree['algorithm']
    assert_equal 1, tree['key_usage']

    key = Types::DomainPublicKey.from_cbor(Cbor.encode(tree.merge('key_usage' => 2)))
    assert_equal 'encrypt', key.key_usage
  end

  def test_text_or_unknown_enum_is_rejected
    tree = domain_key_tree
    assert_raises(Cbor::DecodeError) { Types::DomainPublicKey.from_cbor(Cbor.encode(tree.merge('key_usage' => 'sign'))) }
    assert_raises(Cbor::DecodeError) { Types::DomainPublicKey.from_cbor(Cbor.encode(tree.merge('algorithm' => 99))) }
  end

  def test_callback_header_with_unknown_suite_number_fails_to_decode
    header = Types::LocalRpCallbackHeader.new(
      fingerprint: 'fp', nonce: 'n'.b, state: 's'.b, suite: 'aes-256-gcm',
      ephemeral_public_key: ("\x09" * 32).b, aead_nonce: ("\x00" * 12).b,
      issued_at: '2026-01-01T00:00:00Z', expires_at: '2026-01-01T00:05:00Z'
    )
    tree = Cbor.decode(header.to_cbor)
    assert_equal 1, tree['suite']
    encrypted = Types::LocalRpEncryptedCallback.new(header: Cbor.encode(tree.merge('suite' => 99)), ciphertext: ''.b)
    assert_raises(LinkkeysLocalRp::LocalRp::DecodeFailed) do
      LinkkeysLocalRp::LocalRp.open_local_rp_callback(encrypted, ("\x02" * 32).b, ['aes-256-gcm'])
    end
  end

  def test_claim_with_fractional_signed_time_fails_verification
    c = claims_vector['cases'].first
    domain_keys = claims_vector['domain_keys'].group_by { |k| k['domain'] }.map do |domain, keys|
      LinkkeysLocalRp::Claims::DomainKeySet.new(
        domain: domain,
        keys: keys.map do |k|
          Types::DomainPublicKey.new(
            key_id: k['key_id'], public_key: ConformanceHelper.hex(k['public_key_hex']), fingerprint: k['fingerprint_hex'],
            algorithm: k['algorithm'], key_usage: k['key_usage'], created_at: k['created_at'], expires_at: k['expires_at']
          )
        end
      )
    end
    claim = Types::Claim.from_cbor(ConformanceHelper.hex(c['claim_cbor_hex']))
    now = Time.utc(2026, 1, 1)
    LinkkeysLocalRp::Claims.verify_claim(claim, c['subject_domain'], domain_keys, now)

    claim.attested_at = '2026-01-01T00:00:00.5Z'
    assert_raises(LinkkeysLocalRp::Claims::SignatureInvalid) do
      LinkkeysLocalRp::Claims.verify_claim(claim, c['subject_domain'], domain_keys, now)
    end
  end

  def test_revocation_with_fractional_revoked_at_counts_no_signers
    c = revocations_vector['certificate_cases'].find { |x| x['expected_counted_signers'] == 2 }
    keys = revocations_vector['domain_keys'].map do |k|
      Types::DomainPublicKey.new(
        key_id: k['key_id'], public_key: ConformanceHelper.hex(k['public_key_hex']), fingerprint: k['fingerprint_hex'],
        algorithm: k['algorithm'], key_usage: k['key_usage'], created_at: k['created_at'], expires_at: k['expires_at']
      )
    end
    cert = Types::RevocationCertificate.from_cbor(ConformanceHelper.hex(c['certificate_cbor_hex']))
    now = Time.utc(2026, 1, 1, 0, 7)
    assert_equal 2, LinkkeysLocalRp::Revocation.count_valid_signers(cert, keys, c['verify_domain'], now)

    cert.revoked_at = cert.revoked_at.sub('Z', '.5Z')
    assert_equal 0, LinkkeysLocalRp::Revocation.count_valid_signers(cert, keys, c['verify_domain'], now)
  end
end
