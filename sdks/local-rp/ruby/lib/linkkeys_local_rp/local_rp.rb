# frozen_string_literal: true

require_relative 'crypto'
require_relative 'types'
require_relative 'timeutil'
require_relative 'cbor'

module LinkkeysLocalRp
  # DNS-less local RP identity: pure protocol helpers.
  #
  # Mirrors `crates/liblinkkeys/src/local_rp.rs` (read that file's module
  # docs and `dns-less-local-rp-design.md`'s "Wire Precision (Normative)"
  # section first -- this module implements it byte-for-byte). Summary of
  # the shape:
  #
  # - Every signed structure uses the envelope pattern: the payload is
  #   CBOR-encoded once, and the signature covers
  #   `CBOR([context: tstr, payload: bstr])` -- a two-element CBOR array,
  #   never a bare `context || payload` concatenation (see
  #   `envelope_signature_input`).
  # - Four mandatory, structure-specific context strings stop a signature
  #   over one structure from ever verifying as another.
  # - The descriptor, login request, and ticket-redemption envelopes are
  #   self-asserted (verified against the local RP's own embedded signing
  #   key, SSH-host style). The callback payload envelope is domain-signed
  #   (verified against fetched domain public keys, keyed by
  #   `signing_key_id`).
  # - The callback ciphertext is a variant of the sealed-box construction,
  #   extended with negotiated-suite selection and cleartext-header AAD
  #   binding -- see `seal_local_rp_callback` / `open_local_rp_callback`.
  #
  # This module performs no I/O and never reads the system clock -- every
  # "current time" is an explicit `now` parameter, so verification stays
  # deterministic and testable against fixed conformance vectors.
  #
  # Only the subset actually used by an RP (build+sign the
  # descriptor/login-request/ticket-redemption; verify+open the callback) is
  # exercised at runtime by this SDK. `build_local_rp_callback_payload` /
  # `sign_local_rp_callback_payload` / `seal_local_rp_callback` are IDP-side
  # operations -- included here (mirroring `liblinkkeys::local_rp`, which
  # serves both sides) purely so this package's own test suite can act as a
  # self-contained fake IDP in the flow tests.
  module LocalRp
    CTX_LOCAL_RP_DESCRIPTOR = 'linkkeys-local-rp-descriptor'
    CTX_LOCAL_RP_LOGIN_REQUEST = 'linkkeys-local-rp-login-request'
    CTX_LOCAL_RP_CALLBACK = 'linkkeys-local-rp-callback'
    CTX_LOCAL_RP_TICKET_REDEMPTION = 'linkkeys-local-rp-ticket-redemption'

    DEFAULT_CLOCK_SKEW_SECONDS = 300

    LOCAL_RP_CALLBACK_BOX_TAG = 'linkkeys-local-rp-callback-box'.b

    # ---------------------------------------------------------------
    # Errors. Base class for every local-RP protocol verification failure.
    # Per the conformance suite's own README: "Exact error *types* are
    # intentionally not part of the contract ... only pass/fail is
    # portable" -- callers that only need pass/fail can rescue this one
    # base class; the subclasses below exist for the flow tests and for
    # apps that want richer diagnostics without ever seeing key material,
    # nonces, tokens, tickets, or claim values in a message (AGENTS.md's
    # error-handling rule).
    # ---------------------------------------------------------------

    class Error < StandardError; end
    class DecodeFailed < Error; end
    class InvalidKeyLength < Error; end
    class FingerprintMismatch < Error; end
    class NotYetValid < Error; end
    class Expired < Error; end
    class BadTimestamp < Error; end
    class NonceMismatch < Error; end
    class StateMismatch < Error; end
    class AudienceMismatch < Error; end
    class IssuerMismatch < Error; end
    class CallbackUrlMismatch < Error; end

    class UnsupportedSuite < Error
      attr_reader :suite_id

      def initialize(suite_id)
        @suite_id = suite_id
        super("unsupported AEAD suite: #{suite_id}")
      end
    end

    class SuiteNotAdvertised < Error
      attr_reader :suite_id

      def initialize(suite_id)
        @suite_id = suite_id
        super("AEAD suite was not advertised/allowed: #{suite_id}")
      end
    end

    class HeaderPayloadMismatch < Error
      attr_reader :field

      def initialize(field)
        @field = field
        super("callback header does not match signed payload field: #{field}")
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

    class SignatureInvalid < Error; end

    class UnsupportedSigningAlgorithm < Error
      attr_reader :algorithm

      def initialize(algorithm)
        @algorithm = algorithm
        super("unsupported signing algorithm: #{algorithm}")
      end
    end

    module_function

    # `CBOR([context, payload_bytes])` -- a two-element CBOR array, context
    # string first (CBOR text string), then the exact payload bytes (CBOR
    # byte string). Deliberately NOT a bare `context || payload`
    # concatenation.
    def envelope_signature_input(context, payload_bytes)
      Cbor.encode([context, payload_bytes])
    end

    # ---------------------------------------------------------------
    # Timestamps / expirations
    # ---------------------------------------------------------------

    # Check an (issued_at, expires_at) pair against `now`, tolerant of
    # `skew_seconds` of clock skew in either direction. Boundaries are
    # inclusive: exactly `now - skew == expires_at` still passes, and
    # exactly one second past either boundary fails. Raises on failure.
    def check_timestamps(issued_at, expires_at, now, skew_seconds)
      begin
        issued = Timeutil.parse_rfc3339(issued_at)
        expires = Timeutil.parse_rfc3339(expires_at)
      rescue ArgumentError => e
        raise BadTimestamp, e.message
      end

      skew = skew_seconds
      raise NotYetValid, 'timestamp is not yet valid' if (now + skew) < issued
      raise Expired, 'timestamp has expired' if (now - skew) > expires
    end

    module ExpirationLevel
      OK = 'ok'
      NOTICE = 'notice'
      WARNING = 'warning'
      CRITICAL = 'critical'
      EXPIRED = 'expired'
    end

    ExpirationStatus = Struct.new(:level, :expires_at, :now, keyword_init: true)

    # `check_expirations(expires_at, now) -> ExpirationStatus` (design doc,
    # "Expiration Helper"): notice at 180 days remaining, warning at 90,
    # critical at 30, expired once now >= expires_at. No clock-skew
    # tolerance (unlike check_timestamps) -- expiry warnings are advisory,
    # day-granularity facts, not a replay/freshness security boundary.
    def check_expirations(expires_at, now)
      begin
        expires = Timeutil.parse_rfc3339(expires_at)
      rescue ArgumentError => e
        raise BadTimestamp, e.message
      end

      remaining = expires - now
      day = 86_400
      level =
        if now >= expires
          ExpirationLevel::EXPIRED
        elsif remaining <= 30 * day
          ExpirationLevel::CRITICAL
        elsif remaining <= 90 * day
          ExpirationLevel::WARNING
        elsif remaining <= 180 * day
          ExpirationLevel::NOTICE
        else
          ExpirationLevel::OK
        end
      ExpirationStatus.new(level: level, expires_at: expires, now: now)
    end

    # ---------------------------------------------------------------
    # Nonce/state/audience/issuer/callback-url checks
    # ---------------------------------------------------------------

    # Constant-time comparison (`OpenSSL.fixed_length_secure_compare`, not
    # `==`): nonce and state are unpredictable-to-the-attacker secrets the
    # app committed to at begin_local_login time, so a timing side channel
    # on the comparison must not leak how many leading bytes an
    # attacker-supplied value got right. `fixed_length_secure_compare`
    # itself requires both inputs be the same length (it raises
    # ArgumentError otherwise), so a length mismatch is treated as a
    # mismatch up front rather than letting that error escape.
    def secure_bytes_equal?(a, b)
      return false if a.bytesize != b.bytesize

      OpenSSL.fixed_length_secure_compare(a, b)
    end
    private_class_method :secure_bytes_equal?

    def verify_nonce_state(expected_nonce, expected_state, actual_nonce, actual_state)
      raise NonceMismatch, 'nonce does not match' unless secure_bytes_equal?(expected_nonce, actual_nonce)
      raise StateMismatch, 'state does not match' unless secure_bytes_equal?(expected_state, actual_state)
    end

    def verify_audience(payload_audience_fingerprint, local_rp_fingerprint)
      return if payload_audience_fingerprint == local_rp_fingerprint

      raise AudienceMismatch, 'audience fingerprint does not match'
    end

    def verify_issuer(payload_user_domain, expected_domain)
      return if payload_user_domain == expected_domain

      raise IssuerMismatch, 'issuing domain does not match'
    end

    def verify_callback_url(payload_callback_url, arrived_url)
      return if payload_callback_url == arrived_url

      raise CallbackUrlMismatch, 'callback URL does not match'
    end

    # ---------------------------------------------------------------
    # Descriptor (build + sign only -- verification is the IDP's job)
    # ---------------------------------------------------------------

    # `fingerprint` is always derived from `signing_public_key` -- callers
    # cannot set it directly, so it can never drift from the key it names.
    def build_local_rp_descriptor(
      app_name, local_domain_hint, signing_public_key, encryption_public_key,
      supported_suites, created_at, expires_at
    )
      Types::LocalRpDescriptor.new(
        app_name: app_name,
        local_domain_hint: local_domain_hint,
        signing_public_key: signing_public_key,
        encryption_public_key: encryption_public_key,
        fingerprint: Crypto.fingerprint(signing_public_key),
        supported_suites: supported_suites.dup,
        created_at: created_at,
        expires_at: expires_at
      )
    end

    def sign_local_rp_descriptor(descriptor, private_key_bytes)
      descriptor_bytes = descriptor.to_cbor
      signature_input = envelope_signature_input(CTX_LOCAL_RP_DESCRIPTOR, descriptor_bytes)
      signature = Crypto.sign_with_algorithm(Crypto::SigningAlgorithm::ED25519, signature_input, private_key_bytes)
      Types::SignedLocalRpDescriptor.new(descriptor: descriptor_bytes, signature: signature)
    end

    # ---------------------------------------------------------------
    # Login request (build + sign only)
    # ---------------------------------------------------------------

    def build_local_rp_login_request(
      descriptor, callback_url, nonce, state, requested_claims, required_claims, issued_at, expires_at
    )
      Types::LocalRpLoginRequest.new(
        descriptor: descriptor,
        callback_url: callback_url,
        nonce: nonce,
        state: state,
        requested_claims: requested_claims.dup,
        required_claims: required_claims.dup,
        issued_at: issued_at,
        expires_at: expires_at
      )
    end

    def sign_local_rp_login_request(request, private_key_bytes)
      request_bytes = request.to_cbor
      signature_input = envelope_signature_input(CTX_LOCAL_RP_LOGIN_REQUEST, request_bytes)
      signature = Crypto.sign_with_algorithm(Crypto::SigningAlgorithm::ED25519, signature_input, private_key_bytes)
      Types::SignedLocalRpLoginRequest.new(request: request_bytes, signature: signature)
    end

    # ---------------------------------------------------------------
    # Ticket redemption (build + sign -- the RP's possession proof)
    # ---------------------------------------------------------------

    def build_local_rp_ticket_redemption_request(claim_ticket, fingerprint, issued_at)
      Types::LocalRpTicketRedemptionRequest.new(claim_ticket: claim_ticket, fingerprint: fingerprint, issued_at: issued_at)
    end

    def sign_local_rp_ticket_redemption_request(request, private_key_bytes)
      request_bytes = request.to_cbor
      signature_input = envelope_signature_input(CTX_LOCAL_RP_TICKET_REDEMPTION, request_bytes)
      signature = Crypto.sign_with_algorithm(Crypto::SigningAlgorithm::ED25519, signature_input, private_key_bytes)
      Types::SignedLocalRpTicketRedemptionRequest.new(request: request_bytes, signature: signature)
    end

    # ---------------------------------------------------------------
    # Callback payload (build + sign -- IDP-side, used only by this
    # package's own fake-IDP flow tests) / verify (RP-side, used by
    # complete_local_login)
    # ---------------------------------------------------------------

    def build_local_rp_callback_payload(
      user_id, user_domain, claim_ticket, audience_fingerprint, callback_url,
      nonce, state, issued_at, expires_at
    )
      Types::LocalRpCallbackPayload.new(
        user_id: user_id,
        user_domain: user_domain,
        claim_ticket: claim_ticket,
        audience_fingerprint: audience_fingerprint,
        callback_url: callback_url,
        nonce: nonce,
        state: state,
        issued_at: issued_at,
        expires_at: expires_at
      )
    end

    def sign_local_rp_callback_payload(payload, key_id, algorithm, private_key_bytes)
      payload_bytes = payload.to_cbor
      signature_input = envelope_signature_input(CTX_LOCAL_RP_CALLBACK, payload_bytes)
      signature = Crypto.sign_with_algorithm(algorithm, signature_input, private_key_bytes)
      Types::SignedLocalRpCallbackPayload.new(payload: payload_bytes, signing_key_id: key_id, signature: signature)
    end

    # Reject a signing key that is not currently a signing key, or is
    # revoked/expired -- shared by every verify path that resolves a key by
    # id.
    def check_signing_key_valid(key, now)
      raise SignatureInvalid, 'key is not a signing key' unless key.key_usage == 'sign'

      validity = Crypto.signing_key_validity(key.expires_at, key.revoked_at, now)
      raise KeyRevoked, key.key_id if validity == Crypto::KeyValidity::REVOKED
      raise KeyExpired, key.key_id if [Crypto::KeyValidity::EXPIRED, Crypto::KeyValidity::BAD_EXPIRY].include?(validity)
    end
    private_class_method :check_signing_key_valid

    # Verify a domain-signed callback payload envelope against a set of
    # domain public keys: resolve signing_key_id, reject a
    # revoked/expired/non-signing key, verify the envelope signature,
    # decode, then check issued_at/expires_at bounds. Nothing inside the
    # payload is trusted before this succeeds.
    def verify_local_rp_callback_payload(signed, domain_public_keys, now, skew_seconds)
      key = domain_public_keys.find { |k| k.key_id == signed.signing_key_id }
      raise KeyNotFound, signed.signing_key_id if key.nil?

      check_signing_key_valid(key, now)

      signature_input = envelope_signature_input(CTX_LOCAL_RP_CALLBACK, signed.payload)
      begin
        Crypto.resolve_and_verify(key.algorithm, signature_input, signed.signature, key.public_key)
      rescue Crypto::UnsupportedAlgorithm
        raise UnsupportedSigningAlgorithm, key.algorithm
      rescue Crypto::Error
        raise SignatureInvalid, 'callback payload signature verification failed'
      end

      payload = Types::LocalRpCallbackPayload.from_cbor(signed.payload)
      check_timestamps(payload.issued_at, payload.expires_at, now, skew_seconds)
      payload
    end

    # Cross-check the cleartext callback header's routing fields against
    # the authoritative copies inside the decrypted, signature-verified
    # payload. The header is already bound as AEAD associated data, but a
    # verifier must still consult the signed copies rather than trusting
    # the header alone.
    def check_callback_header_matches_payload(header, payload)
      raise HeaderPayloadMismatch, 'fingerprint' unless header.fingerprint == payload.audience_fingerprint
      raise HeaderPayloadMismatch, 'nonce' unless header.nonce == payload.nonce
      raise HeaderPayloadMismatch, 'state' unless header.state == payload.state
      raise HeaderPayloadMismatch, 'issued_at' unless header.issued_at == payload.issued_at
      raise HeaderPayloadMismatch, 'expires_at' unless header.expires_at == payload.expires_at
    end

    # ---------------------------------------------------------------
    # Callback sealed box (Wire Precision: "Callback sealed box")
    # ---------------------------------------------------------------

    # Derive the AEAD key and construct the KDF info/AAD-prefix context:
    # `tag || suite_id_utf8 || ephemeral_public(32) || recipient_public(32)`,
    # raw concatenation. Returns [aead_key, context].
    def local_rp_callback_kdf(suite, ephemeral_public, recipient_public, shared_secret)
      suite_id = suite.b
      context = LOCAL_RP_CALLBACK_BOX_TAG + suite_id + ephemeral_public + recipient_public
      key = Crypto.hkdf_sha256_expand(shared_secret, context, 32)
      [key, context]
    end
    private_class_method :local_rp_callback_kdf

    # Seal a SignedLocalRpCallbackPayload into a LocalRpEncryptedCallback for
    # `recipient_encryption_public_key`, under `suite`. IDP-side operation
    # -- included here purely so this package's own tests can build a
    # self-contained fake IDP (see module docs).
    #
    # `ephemeral_private_key`/`aead_nonce` are deterministic-testing hooks:
    # production callers must leave both nil so real OS randomness is used.
    def seal_local_rp_callback(
      signed_payload, suite, recipient_encryption_public_key, fingerprint, nonce, state, issued_at, expires_at,
      ephemeral_private_key: nil, aead_nonce: nil
    )
      require 'securerandom'
      ephemeral_private = ephemeral_private_key || SecureRandom.random_bytes(32)
      nonce_bytes = aead_nonce || SecureRandom.random_bytes(12)

      ephemeral_public = Crypto.x25519_public_from_private(ephemeral_private)
      shared_secret = Crypto.x25519_diffie_hellman(ephemeral_private, recipient_encryption_public_key)
      Crypto.reject_low_order(shared_secret)

      plaintext = signed_payload.to_cbor

      header = Types::LocalRpCallbackHeader.new(
        fingerprint: fingerprint,
        nonce: nonce,
        state: state,
        suite: suite,
        ephemeral_public_key: ephemeral_public,
        aead_nonce: nonce_bytes,
        issued_at: issued_at,
        expires_at: expires_at
      )
      header_bytes = header.to_cbor

      aead_key, kdf_context = local_rp_callback_kdf(suite, ephemeral_public, recipient_encryption_public_key, shared_secret)
      aad = kdf_context + header_bytes
      ciphertext = Crypto.aead_encrypt(suite, aead_key, nonce_bytes, aad, plaintext)

      Types::LocalRpEncryptedCallback.new(header: header_bytes, ciphertext: ciphertext)
    end

    # Open a LocalRpEncryptedCallback with the local RP's encryption private
    # key. `allowed_suites` is the local RP's own supported-suite list (from
    # its descriptor): a header advertising a suite NOT in that list is
    # rejected even if it is otherwise a valid registry id (Wire Precision:
    # "The SDK must decrypt only with a suite listed in its own
    # descriptor").
    #
    # Returns [header, signed_payload] -- the still-domain-signature-
    # unverified payload envelope. Callers must still call
    # verify_local_rp_callback_payload against fetched domain keys, and then
    # check_callback_header_matches_payload, before trusting the result.
    def open_local_rp_callback(encrypted, recipient_encryption_private_key, allowed_suites)
      header = begin
        Types::LocalRpCallbackHeader.from_cbor(encrypted.header)
      rescue StandardError => e
        raise DecodeFailed, "callback header: #{e.message}"
      end

      suite = Crypto::AeadSuite.parse_str(header.suite)
      raise UnsupportedSuite, header.suite if suite.nil?
      raise SuiteNotAdvertised, header.suite unless allowed_suites.include?(suite)

      raise InvalidKeyLength, 'ephemeral_public_key must be 32 bytes' unless header.ephemeral_public_key.bytesize == 32
      raise InvalidKeyLength, 'aead_nonce must be 12 bytes' unless header.aead_nonce.bytesize == 12

      recipient_public = Crypto.x25519_public_from_private(recipient_encryption_private_key)
      shared_secret =
        begin
          Crypto.x25519_diffie_hellman(recipient_encryption_private_key, header.ephemeral_public_key)
        rescue Crypto::EncryptionFailed => e
          raise DecodeFailed, "callback decryption failed: #{e.message}"
        end
      Crypto.reject_low_order(shared_secret)

      aead_key, kdf_context = local_rp_callback_kdf(suite, header.ephemeral_public_key, recipient_public, shared_secret)
      aad = kdf_context + encrypted.header

      plaintext =
        begin
          Crypto.aead_decrypt(suite, aead_key, header.aead_nonce, aad, encrypted.ciphertext)
        rescue Crypto::Error => e
          raise DecodeFailed, "callback decryption failed: #{e.message}"
        end

      signed_payload =
        begin
          Types::SignedLocalRpCallbackPayload.from_cbor(plaintext)
        rescue StandardError => e
          raise DecodeFailed, "callback payload: #{e.message}"
        end

      [header, signed_payload]
    end
  end
end
