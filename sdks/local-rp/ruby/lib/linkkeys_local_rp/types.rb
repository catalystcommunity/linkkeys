# frozen_string_literal: true

require_relative 'cbor'

module LinkkeysLocalRp
  # Hand-written CBOR struct codecs for exactly the CSIL types this SDK
  # touches. No csilgen Ruby target exists yet (see the filed csilgen
  # request), so — mirroring the design doc's "hand-write the minimal wire
  # codec in a clearly-marked module" instruction — these are byte-for-byte
  # ports of the generated Python SDK's `generated/codec.py` per-struct
  # encode/decode function pairs. Field encode ORDER below is load-bearing:
  # it was read directly off the generated Python codec's own field-append
  # order (matching the CSIL struct's declared field order) and verified
  # against every `*_cbor_hex` fixture in `sdks/local-rp/conformance/`.
  # Decode order does not matter (map lookup by key), only encode order
  # does.
  #
  # Every struct is a plain Ruby `Struct` (keyword-init) with a `to_cbor`
  # instance method and a `from_cbor` class method attached in the class
  # body, rather than Python's "define functions, then monkey-patch onto the
  # dataclass" pattern — Ruby has no equivalent post-hoc-attach idiom that's
  # more idiomatic than just defining the methods directly.
  module Types
    Cbor = LinkkeysLocalRp::Cbor

    # ---------------------------------------------------------------
    # Local RP descriptor / login request
    # ---------------------------------------------------------------

    LocalRpDescriptor = Struct.new(
      :app_name, :local_domain_hint, :signing_public_key, :encryption_public_key,
      :fingerprint, :supported_suites, :created_at, :expires_at,
      keyword_init: true
    ) do
      def self.to_map(v)
        m = {}
        m['app_name'] = v.app_name
        m['created_at'] = v.created_at
        m['expires_at'] = v.expires_at
        m['fingerprint'] = v.fingerprint
        m['supported_suites'] = v.supported_suites
        m['local_domain_hint'] = v.local_domain_hint unless v.local_domain_hint.nil?
        m['signing_public_key'] = v.signing_public_key
        m['encryption_public_key'] = v.encryption_public_key
        m
      end

      def self.from_map(tree)
        new(
          app_name: tree['app_name'],
          local_domain_hint: tree['local_domain_hint'],
          signing_public_key: tree['signing_public_key'],
          encryption_public_key: tree['encryption_public_key'],
          fingerprint: tree['fingerprint'],
          supported_suites: tree['supported_suites'],
          created_at: tree['created_at'],
          expires_at: tree['expires_at']
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    SignedLocalRpDescriptor = Struct.new(:descriptor, :signature, keyword_init: true) do
      def self.to_map(v) = { 'signature' => v.signature, 'descriptor' => v.descriptor }
      def self.from_map(tree) = new(descriptor: tree['descriptor'], signature: tree['signature'])
      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    LocalRpLoginRequest = Struct.new(
      :descriptor, :callback_url, :nonce, :state,
      :requested_claims, :required_claims, :issued_at, :expires_at,
      keyword_init: true
    ) do
      def self.to_map(v)
        {
          'nonce' => v.nonce,
          'state' => v.state,
          'issued_at' => v.issued_at,
          'descriptor' => SignedLocalRpDescriptor.to_map(v.descriptor),
          'expires_at' => v.expires_at,
          'callback_url' => v.callback_url,
          'required_claims' => v.required_claims,
          'requested_claims' => v.requested_claims
        }
      end

      def self.from_map(tree)
        new(
          descriptor: SignedLocalRpDescriptor.from_map(tree['descriptor']),
          callback_url: tree['callback_url'],
          nonce: tree['nonce'],
          state: tree['state'],
          requested_claims: tree['requested_claims'],
          required_claims: tree['required_claims'],
          issued_at: tree['issued_at'],
          expires_at: tree['expires_at']
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    SignedLocalRpLoginRequest = Struct.new(:request, :signature, keyword_init: true) do
      def self.to_map(v) = { 'request' => v.request, 'signature' => v.signature }
      def self.from_map(tree) = new(request: tree['request'], signature: tree['signature'])
      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    # ---------------------------------------------------------------
    # Callback header / envelope / payload
    # ---------------------------------------------------------------

    LocalRpCallbackHeader = Struct.new(
      :fingerprint, :nonce, :state, :suite, :ephemeral_public_key, :aead_nonce,
      :issued_at, :expires_at,
      keyword_init: true
    ) do
      def self.to_map(v)
        {
          'nonce' => v.nonce,
          'state' => v.state,
          'suite' => v.suite,
          'issued_at' => v.issued_at,
          'aead_nonce' => v.aead_nonce,
          'expires_at' => v.expires_at,
          'fingerprint' => v.fingerprint,
          'ephemeral_public_key' => v.ephemeral_public_key
        }
      end

      def self.from_map(tree)
        new(
          fingerprint: tree['fingerprint'],
          nonce: tree['nonce'],
          state: tree['state'],
          suite: tree['suite'],
          ephemeral_public_key: tree['ephemeral_public_key'],
          aead_nonce: tree['aead_nonce'],
          issued_at: tree['issued_at'],
          expires_at: tree['expires_at']
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    LocalRpEncryptedCallback = Struct.new(:header, :ciphertext, keyword_init: true) do
      def self.to_map(v) = { 'header' => v.header, 'ciphertext' => v.ciphertext }
      def self.from_map(tree) = new(header: tree['header'], ciphertext: tree['ciphertext'])
      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    LocalRpCallbackPayload = Struct.new(
      :user_id, :user_domain, :claim_ticket, :audience_fingerprint, :callback_url,
      :nonce, :state, :issued_at, :expires_at,
      keyword_init: true
    ) do
      def self.to_map(v)
        {
          'nonce' => v.nonce,
          'state' => v.state,
          'user_id' => v.user_id,
          'issued_at' => v.issued_at,
          'expires_at' => v.expires_at,
          'user_domain' => v.user_domain,
          'callback_url' => v.callback_url,
          'claim_ticket' => v.claim_ticket,
          'audience_fingerprint' => v.audience_fingerprint
        }
      end

      def self.from_map(tree)
        new(
          user_id: tree['user_id'],
          user_domain: tree['user_domain'],
          claim_ticket: tree['claim_ticket'],
          audience_fingerprint: tree['audience_fingerprint'],
          callback_url: tree['callback_url'],
          nonce: tree['nonce'],
          state: tree['state'],
          issued_at: tree['issued_at'],
          expires_at: tree['expires_at']
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    SignedLocalRpCallbackPayload = Struct.new(:payload, :signing_key_id, :signature, keyword_init: true) do
      def self.to_map(v)
        { 'payload' => v.payload, 'signature' => v.signature, 'signing_key_id' => v.signing_key_id }
      end

      def self.from_map(tree)
        new(payload: tree['payload'], signing_key_id: tree['signing_key_id'], signature: tree['signature'])
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    # ---------------------------------------------------------------
    # Ticket redemption
    # ---------------------------------------------------------------

    LocalRpTicketRedemptionRequest = Struct.new(:claim_ticket, :fingerprint, :issued_at, keyword_init: true) do
      def self.to_map(v)
        { 'issued_at' => v.issued_at, 'fingerprint' => v.fingerprint, 'claim_ticket' => v.claim_ticket }
      end

      def self.from_map(tree)
        new(claim_ticket: tree['claim_ticket'], fingerprint: tree['fingerprint'], issued_at: tree['issued_at'])
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    SignedLocalRpTicketRedemptionRequest = Struct.new(:request, :signature, keyword_init: true) do
      def self.to_map(v) = { 'request' => v.request, 'signature' => v.signature }
      def self.from_map(tree) = new(request: tree['request'], signature: tree['signature'])
      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    LocalRpTicketRedemptionResponse = Struct.new(
      :user_id, :user_domain, :claims, :ticket_expires_at, keyword_init: true
    ) do
      def self.to_map(v)
        {
          'claims' => v.claims.map { |c| Claim.to_map(c) },
          'user_id' => v.user_id,
          'user_domain' => v.user_domain,
          'ticket_expires_at' => v.ticket_expires_at
        }
      end

      def self.from_map(tree)
        new(
          user_id: tree['user_id'],
          user_domain: tree['user_domain'],
          claims: tree['claims'].map { |c| Claim.from_map(c) },
          ticket_expires_at: tree['ticket_expires_at']
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    # ---------------------------------------------------------------
    # Domain keys, claims, revocation
    # ---------------------------------------------------------------

    DomainPublicKey = Struct.new(
      :key_id, :public_key, :fingerprint, :algorithm, :key_usage,
      :created_at, :expires_at, :revoked_at, :signed_by_key_id, :key_signature,
      keyword_init: true
    ) do
      def self.to_map(v)
        m = {}
        m['key_id'] = v.key_id
        m['algorithm'] = v.algorithm
        m['key_usage'] = v.key_usage
        m['created_at'] = v.created_at
        m['expires_at'] = v.expires_at
        m['public_key'] = v.public_key
        m['revoked_at'] = v.revoked_at unless v.revoked_at.nil?
        m['fingerprint'] = v.fingerprint
        m['key_signature'] = v.key_signature unless v.key_signature.nil?
        m['signed_by_key_id'] = v.signed_by_key_id unless v.signed_by_key_id.nil?
        m
      end

      def self.from_map(tree)
        new(
          key_id: tree['key_id'],
          public_key: tree['public_key'],
          fingerprint: tree['fingerprint'],
          algorithm: tree['algorithm'],
          key_usage: tree['key_usage'],
          created_at: tree['created_at'],
          expires_at: tree['expires_at'],
          revoked_at: tree['revoked_at'],
          signed_by_key_id: tree['signed_by_key_id'],
          key_signature: tree['key_signature']
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    ClaimSignature = Struct.new(:domain, :signed_by_key_id, :signature, keyword_init: true) do
      def self.to_map(v) = { 'domain' => v.domain, 'signature' => v.signature, 'signed_by_key_id' => v.signed_by_key_id }

      def self.from_map(tree)
        new(domain: tree['domain'], signed_by_key_id: tree['signed_by_key_id'], signature: tree['signature'])
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    Claim = Struct.new(
      :claim_id, :user_id, :claim_type, :claim_value, :signatures,
      :attested_at, :created_at, :expires_at, :revoked_at,
      keyword_init: true
    ) do
      def self.to_map(v)
        m = {}
        m['user_id'] = v.user_id
        m['claim_id'] = v.claim_id
        m['claim_type'] = v.claim_type
        m['created_at'] = v.created_at
        m['expires_at'] = v.expires_at unless v.expires_at.nil?
        m['revoked_at'] = v.revoked_at unless v.revoked_at.nil?
        m['signatures'] = v.signatures.map { |s| ClaimSignature.to_map(s) }
        m['attested_at'] = v.attested_at
        m['claim_value'] = v.claim_value
        m
      end

      def self.from_map(tree)
        claim_value = tree['claim_value']
        # CSIL declares claim_value as bytes (bstr, CBOR major type 2) --
        # never text (tstr, major type 3). Cbor.decode already distinguishes
        # the two on the way in: a decoded bstr keeps ASCII-8BIT encoding, a
        # decoded tstr is forced to UTF-8 (see cbor.rb). A wire message that
        # encoded claim_value as tstr must be REJECTED here, not silently
        # accepted as a same-bytes-different-type value -- an SDK that
        # accepts it also produces wrong claim-signature payloads (see
        # sdks/local-rp/conformance/README.md's claims.json section).
        unless claim_value.is_a?(String) && claim_value.encoding == ::Encoding::ASCII_8BIT
          raise Cbor::DecodeError, 'Claim.claim_value must be a CBOR byte string (bstr), not text (tstr)'
        end

        new(
          claim_id: tree['claim_id'],
          user_id: tree['user_id'],
          claim_type: tree['claim_type'],
          claim_value: claim_value,
          signatures: tree['signatures'].map { |s| ClaimSignature.from_map(s) },
          attested_at: tree['attested_at'],
          created_at: tree['created_at'],
          expires_at: tree['expires_at'],
          revoked_at: tree['revoked_at']
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    RevocationCertificate = Struct.new(
      :target_key_id, :target_fingerprint, :revoked_at, :signatures, keyword_init: true
    ) do
      def self.to_map(v)
        {
          'revoked_at' => v.revoked_at,
          'signatures' => v.signatures.map { |s| ClaimSignature.to_map(s) },
          'target_key_id' => v.target_key_id,
          'target_fingerprint' => v.target_fingerprint
        }
      end

      def self.from_map(tree)
        new(
          target_key_id: tree['target_key_id'],
          target_fingerprint: tree['target_fingerprint'],
          revoked_at: tree['revoked_at'],
          signatures: tree['signatures'].map { |s| ClaimSignature.from_map(s) }
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    # ---------------------------------------------------------------
    # RPC request/response payload types
    # ---------------------------------------------------------------

    EmptyRequest = Struct.new(:x, keyword_init: true) do
      def self.to_map(_v) = {}
      def self.from_map(_tree) = new
      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    GetDomainKeysResponse = Struct.new(
      :domain, :keys, :recent_revocations_available, keyword_init: true
    ) do
      def self.to_map(v)
        m = { 'keys' => v.keys.map { |k| DomainPublicKey.to_map(k) }, 'domain' => v.domain }
        m['recent_revocations_available'] = v.recent_revocations_available unless v.recent_revocations_available.nil?
        m
      end

      def self.from_map(tree)
        new(
          domain: tree['domain'],
          keys: tree['keys'].map { |k| DomainPublicKey.from_map(k) },
          recent_revocations_available: tree['recent_revocations_available']
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    GetRevocationsRequest = Struct.new(:since, keyword_init: true) do
      def self.to_map(v)
        m = {}
        m['since'] = v.since unless v.since.nil?
        m
      end

      def self.from_map(tree) = new(since: tree['since'])
      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    GetRevocationsResponse = Struct.new(:revocations, keyword_init: true) do
      def self.to_map(v) = { 'revocations' => v.revocations.map { |r| RevocationCertificate.to_map(r) } }

      def self.from_map(tree)
        new(revocations: tree['revocations'].map { |r| RevocationCertificate.from_map(r) })
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end
  end
end
