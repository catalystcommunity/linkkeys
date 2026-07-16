# frozen_string_literal: true

require_relative 'crypto'
require_relative 'cbor'
require_relative 'types'

module LinkkeysLocalRp
  # Sibling-signed key revocation certificate verification.
  #
  # Mirrors `crates/liblinkkeys/src/revocation.rs`. Only verification is
  # ported here -- building/signing a revocation certificate is a
  # domain-admin/server-side operation, out of scope for a local-RP SDK.
  # This SDK verifies revocation certificates fetched alongside domain keys
  # (`Rpc.fetch_domain_keys`) so it can drop a key a quorum-verified sibling
  # revocation targets *before* any envelope or claim verification consults
  # the key set.
  #
  # Wire-precision gotchas, per `sdks/local-rp/conformance/README.md`'s
  # `revocations.json` section (these are exactly what the vectors punish):
  #
  # - The signed payload is `CBOR([tag, target_key_id, target_fingerprint,
  #   revoked_at, signing_domain])` -- a FIVE-element CBOR array with the
  #   domain-separation tag `linkkeys-key-revocation-v1alpha` first. This is the
  #   older house tuple pattern, NOT the local-RP envelopes' two-element
  #   `CBOR([context, payload])` framing.
  # - The verifier recomputes each signature's payload from that
  #   signature's WIRE `domain` field; the `domain` parameter only
  #   *filters* which signatures are eligible. (This is what defeats
  #   cross-domain signature reuse: a signature whose wire `domain` lies
  #   about its binding recomputes to different bytes and fails.)
  # - Sibling-key validity (expiry/revocation) is a WALL-CLOCK check in the
  #   Rust implementation (`check_signing_key_valid` takes no `now`); this
  #   port defaults `now` to the wall clock and only accepts an override
  #   for tests.
  # - Invalid signatures are silently skipped; distinctness is by signer
  #   key id; the only failure mode is an insufficient count of valid
  #   signers.
  module Revocation
    # Minimum number of distinct sibling signatures required to revoke a
    # key.
    REVOCATION_QUORUM = 2

    REVOCATION_TAG = 'linkkeys-key-revocation-v1alpha'

    # The certificate did not reach the sibling-signature quorum.
    class RevocationError < StandardError
      attr_reader :got, :need

      def initialize(got, need)
        @got = got
        @need = need
        super("revocation certificate has #{got} valid sibling signature(s), need #{need}")
      end
    end

    module_function

    # The canonical signed bytes: CBOR([tag, target_key_id,
    # target_fingerprint, revoked_at, signing_domain]) -- the signing
    # sibling's domain is bound per-signature to stop cross-domain reuse.
    def revocation_payload(target_key_id, target_fingerprint, revoked_at, signing_domain)
      Cbor.encode([REVOCATION_TAG, target_key_id, target_fingerprint, revoked_at, signing_domain])
    end

    # Count the DISTINCT signer key ids whose signature survives every
    # filtering rule (not the target, wire domain equals `domain`, signer
    # key present + currently-valid signing key) and cryptographically
    # verifies over the recomputed payload. `now` defaults to the wall
    # clock (see module docs) -- the override exists for deterministic
    # tests only.
    def count_valid_signers(cert, domain_keys, domain, now = nil)
      now ||= Time.now.getutc

      valid_signers = {}
      cert.signatures.each do |sig|
        # A key can never authorize its own revocation.
        next if sig.signed_by_key_id == cert.target_key_id
        # The signature must be bound to this domain (filter only; the
        # payload below is recomputed from the signature's own wire
        # field).
        next unless sig.domain == domain

        key = domain_keys.find { |k| k.key_id == sig.signed_by_key_id }
        next if key.nil?
        next unless key.key_usage == 'sign'
        next unless Crypto.signing_key_validity(key.expires_at, key.revoked_at, now) == Crypto::KeyValidity::VALID

        payload = revocation_payload(cert.target_key_id, cert.target_fingerprint, cert.revoked_at, sig.domain)
        begin
          Crypto.resolve_and_verify(key.algorithm, payload, sig.signature, key.public_key)
        rescue Crypto::Error
          next
        end
        valid_signers[sig.signed_by_key_id] = true
      end

      valid_signers.size
    end

    # Verify a revocation certificate against a domain's public key set.
    # Requires at least REVOCATION_QUORUM DISTINCT signing keys of `domain`,
    # each currently valid and NOT the target key, to have signed the
    # canonical payload. Raises RevocationError on insufficient quorum.
    def verify_revocation_certificate(cert, domain_keys, domain, now = nil)
      got = count_valid_signers(cert, domain_keys, domain, now)
      raise RevocationError.new(got, REVOCATION_QUORUM) if got < REVOCATION_QUORUM
    end

    # Apply quorum-verified revocation certificates to a trusted key set:
    # any key a valid certificate targets is dropped, no matter what the
    # fetched key entry itself says (its own revoked_at may well be unset
    # -- that is the whole point of the sibling-certificate channel).
    # Certificates that fail verification are ignored. Returns the filtered
    # list.
    def apply_revocations(trusted, revocations, domain, now = nil)
      result = trusted.dup
      revocations.each do |cert|
        begin
          verify_revocation_certificate(cert, result, domain, now)
        rescue RevocationError
          next
        end
        result = result.reject { |k| k.key_id == cert.target_key_id }
      end
      result
    end
  end
end
