# frozen_string_literal: true

require_relative 'crypto'
require_relative 'cbor'
require_relative 'types'
require_relative 'timeutil'

module LinkkeysLocalRp
  # Claim signature/revocation/expiry verification.
  #
  # Mirrors `crates/liblinkkeys/src/claims.rs` for exactly the pieces
  # `complete_local_login` needs: per-signer-domain signature quorum,
  # revocation, and expiry. `sign_claim` is included only so this package's
  # own flow tests can build fake claims (IDP-side operation; the SDK itself
  # only ever verifies claims returned from a ticket redemption, never signs
  # them).
  module Claims
    CLAIM_PAYLOAD_TAG = 'linkkeys-claim-v2'

    class Error < StandardError; end
    class SignatureInvalid < Error; end

    class UnsupportedAlgorithm < Error
      attr_reader :algorithm

      def initialize(algorithm)
        @algorithm = algorithm
        super("unsupported signing algorithm: #{algorithm}")
      end
    end

    class KeyNotFound < Error
      attr_reader :key_id

      def initialize(key_id)
        @key_id = key_id
        super("signing key not found: #{key_id}")
      end
    end

    class KeyRevoked < Error
      attr_reader :key_id

      def initialize(key_id)
        @key_id = key_id
        super("signing key has been revoked: #{key_id}")
      end
    end

    class KeyExpired < Error
      attr_reader :key_id

      def initialize(key_id)
        @key_id = key_id
        super("signing key has expired: #{key_id}")
      end
    end

    class Revoked < Error; end
    class Expired < Error; end
    class BadExpiry < Error; end
    class Unsigned < Error; end

    class DomainKeysUnavailable < Error
      attr_reader :domain

      def initialize(domain)
        @domain = domain
        super("no public keys available for signing domain: #{domain}")
      end
    end

    class DomainUnverified < Error
      attr_reader :domain

      def initialize(domain)
        @domain = domain
        super("no valid signature for signing domain: #{domain}")
      end
    end

    DomainKeySet = Struct.new(:domain, :keys, keyword_init: true)

    ClaimSpec = Struct.new(
      :claim_id, :claim_type, :claim_value, :user_id, :subject_domain, :attested_at, :expires_at,
      keyword_init: true
    )

    ClaimSigner = Struct.new(:domain, :key_id, :algorithm, :private_key_bytes, keyword_init: true)

    module_function

    # The subject is bound as the single full identity `user_id@subject_domain`
    # (not the bare user_id), so a claim about a user_id at one domain can't
    # be replayed as the same user_id at another. `signing_domain` -- the
    # attestor for *this* signature -- is bound per-signature.
    def claim_sign_payload(claim_id, claim_type, claim_value, user_id, subject_domain, signing_domain, expires_at, attested_at)
      subject = "#{user_id}@#{subject_domain}"
      payload = [CLAIM_PAYLOAD_TAG, claim_id, claim_type, claim_value, subject, signing_domain, expires_at, attested_at]
      Cbor.encode(payload)
    end
    private_class_method :claim_sign_payload

    # Sign a claim with one or more keys, producing a Claim carrying one
    # ClaimSignature per signer. IDP-side operation; see module docs.
    def sign_claim(spec, signers)
      signatures = signers.map do |signer|
        payload = claim_sign_payload(
          spec.claim_id, spec.claim_type, spec.claim_value, spec.user_id, spec.subject_domain,
          signer.domain, spec.expires_at, spec.attested_at
        )
        signature = Crypto.sign_with_algorithm(signer.algorithm, payload, signer.private_key_bytes)
        Types::ClaimSignature.new(domain: signer.domain, signed_by_key_id: signer.key_id, signature: signature)
      end

      Types::Claim.new(
        claim_id: spec.claim_id,
        user_id: spec.user_id,
        claim_type: spec.claim_type,
        claim_value: spec.claim_value,
        signatures: signatures,
        attested_at: spec.attested_at,
        created_at: spec.attested_at,
        expires_at: spec.expires_at,
        revoked_at: nil
      )
    end

    def verify_one_signature(sig, payload, keys, now)
      key = keys.find { |k| k.key_id == sig.signed_by_key_id }
      raise KeyNotFound, sig.signed_by_key_id if key.nil?
      raise SignatureInvalid, 'key is not a signing key' unless key.key_usage == 'sign'

      # This gates the SIGNING KEY's own revocation/expiry (not the claim's,
      # which verify_claim checks separately).
      validity = Crypto.signing_key_validity(key.expires_at, key.revoked_at, now)
      raise KeyRevoked, key.key_id if validity == Crypto::KeyValidity::REVOKED
      raise KeyExpired, key.key_id if [Crypto::KeyValidity::EXPIRED, Crypto::KeyValidity::BAD_EXPIRY].include?(validity)

      begin
        Crypto.resolve_and_verify(key.algorithm, payload, sig.signature, key.public_key)
      rescue Crypto::UnsupportedAlgorithm
        raise UnsupportedAlgorithm, key.algorithm
      rescue Crypto::Error
        raise SignatureInvalid, 'claim signature verification failed'
      end
    end
    private_class_method :verify_one_signature

    # Every distinct domain that signed must contribute at least one
    # signature from a currently-valid key of that domain.
    def verify_claim_signatures(claim, subject_domain, domain_keys, now)
      raise Unsigned, 'claim has no signatures' if claim.signatures.empty?

      domains = claim.signatures.map(&:domain).uniq.sort
      domains.each do |signing_domain|
        key_set = domain_keys.find { |s| s.domain == signing_domain }
        raise DomainKeysUnavailable, signing_domain if key_set.nil?

        payload = claim_sign_payload(
          claim.claim_id, claim.claim_type, claim.claim_value, claim.user_id, subject_domain,
          signing_domain, claim.expires_at, claim.attested_at
        )

        last_err = DomainUnverified.new(signing_domain)
        satisfied = false
        claim.signatures.each do |sig|
          next unless sig.domain == signing_domain

          begin
            verify_one_signature(sig, payload, key_set.keys, now)
            satisfied = true
            break
          rescue Error => e
            last_err = e
          end
        end
        raise last_err unless satisfied
      end
    end

    # Full claim verification: the cryptographic per-domain quorum plus the
    # claim's own revocation and expiry. All must pass.
    def verify_claim(claim, subject_domain, domain_keys, now)
      verify_claim_signatures(claim, subject_domain, domain_keys, now)

      raise Revoked, 'claim has been revoked' unless claim.revoked_at.nil?

      return if claim.expires_at.nil?

      begin
        expires = Timeutil.parse_rfc3339(claim.expires_at)
      rescue ArgumentError => e
        raise BadExpiry, e.message
      end
      raise Expired, 'claim has expired' if now > expires
    end
  end
end
