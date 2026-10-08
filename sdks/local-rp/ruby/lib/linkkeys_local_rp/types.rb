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

    # ---------------------------------------------------------------
    # Act-as grants (grantee side). The core encoder sorts map keys
    # canonically, so the field order in each `to_map` does not change the
    # bytes. The decoders check shapes, because these maps come from an
    # audience or a home domain.
    # ---------------------------------------------------------------

    module ActAsShape
      module_function

      def map!(tree, name)
        raise Cbor::DecodeError, "#{name}: expected a CBOR map" unless tree.is_a?(Hash)

        tree
      end

      def text!(tree, key, optional: false)
        v = tree[key]
        return nil if v.nil? && optional
        raise Cbor::DecodeError, "#{key}: expected text" unless v.is_a?(String) && v.encoding != ::Encoding::ASCII_8BIT

        v
      end

      def bytes!(tree, key)
        v = tree[key]
        raise Cbor::DecodeError, "#{key}: expected bytes" unless v.is_a?(String) && v.encoding == ::Encoding::ASCII_8BIT

        v
      end

      def int!(tree, key, optional: false)
        v = tree[key]
        return nil if v.nil? && optional
        raise Cbor::DecodeError, "#{key}: expected an integer" unless v.is_a?(Integer)

        v
      end

      def array!(tree, key)
        v = tree[key]
        raise Cbor::DecodeError, "#{key}: expected an array" unless v.is_a?(Array)

        v
      end
    end

    ApplicationRef = Struct.new(:subject_user_id, :subject_domain, :application_id, keyword_init: true) do
      def self.to_map(v)
        { 'subject_user_id' => v.subject_user_id, 'subject_domain' => v.subject_domain, 'application_id' => v.application_id }
      end

      def self.from_map(tree)
        ActAsShape.map!(tree, 'ApplicationRef')
        new(
          subject_user_id: ActAsShape.text!(tree, 'subject_user_id'),
          subject_domain: ActAsShape.text!(tree, 'subject_domain'),
          application_id: ActAsShape.text!(tree, 'application_id')
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    GranteeRef = Struct.new(:application, :local_rp_descriptor_fingerprint, keyword_init: true) do
      def self.to_map(v)
        m = {}
        m['application'] = ApplicationRef.to_map(v.application) unless v.application.nil?
        m['local_rp_descriptor_fingerprint'] = v.local_rp_descriptor_fingerprint unless v.local_rp_descriptor_fingerprint.nil?
        m
      end

      def self.from_map(tree)
        ActAsShape.map!(tree, 'GranteeRef')
        new(
          application: tree['application'].nil? ? nil : ApplicationRef.from_map(tree['application']),
          local_rp_descriptor_fingerprint: ActAsShape.text!(tree, 'local_rp_descriptor_fingerprint', optional: true)
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    ApplicationKeySignature = Struct.new(:signed_by_key_id, :signature, keyword_init: true) do
      def self.to_map(v) = { 'signed_by_key_id' => v.signed_by_key_id, 'signature' => v.signature }

      def self.from_map(tree)
        ActAsShape.map!(tree, 'ApplicationKeySignature')
        new(signed_by_key_id: ActAsShape.text!(tree, 'signed_by_key_id'), signature: ActAsShape.bytes!(tree, 'signature'))
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    GranteeProof = Struct.new(:application_instance_id, :local_rp_descriptor, :signature, keyword_init: true) do
      def self.to_map(v)
        m = { 'signature' => ApplicationKeySignature.to_map(v.signature) }
        m['application_instance_id'] = v.application_instance_id unless v.application_instance_id.nil?
        m['local_rp_descriptor'] = SignedLocalRpDescriptor.to_map(v.local_rp_descriptor) unless v.local_rp_descriptor.nil?
        m
      end

      def self.from_map(tree)
        ActAsShape.map!(tree, 'GranteeProof')
        descriptor = tree['local_rp_descriptor']
        new(
          application_instance_id: ActAsShape.text!(tree, 'application_instance_id', optional: true),
          local_rp_descriptor: descriptor.nil? ? nil : SignedLocalRpDescriptor.from_map(ActAsShape.map!(descriptor, 'SignedLocalRpDescriptor')),
          signature: ApplicationKeySignature.from_map(tree['signature'])
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    SignedActAsScopeSet = Struct.new(:scope_set, :signer_instance_id, :signatures, keyword_init: true) do
      def self.to_map(v)
        {
          'scope_set' => v.scope_set,
          'signer_instance_id' => v.signer_instance_id,
          'signatures' => v.signatures.map { |s| ApplicationKeySignature.to_map(s) }
        }
      end

      def self.from_map(tree)
        ActAsShape.map!(tree, 'SignedActAsScopeSet')
        signatures = ActAsShape.array!(tree, 'signatures')
        raise Cbor::DecodeError, 'signatures: expected at least one signature' if signatures.empty?

        new(
          scope_set: ActAsShape.bytes!(tree, 'scope_set'),
          signer_instance_id: ActAsShape.text!(tree, 'signer_instance_id'),
          signatures: signatures.map { |s| ApplicationKeySignature.from_map(s) }
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    # The optional `grantee_handle_claim` is not modeled: it is a signed handle
    # claim about the account that enrolled an application grantee. A local RP
    # has no enrolling account, so it never sends one.
    ActAsGrantRequest = Struct.new(
      :grantee, :scope_set, :requested_lifetime_seconds, :requested_renewal_window_seconds,
      :callback_url, :nonce, :requested_at, :expires_at,
      keyword_init: true
    ) do
      def self.to_map(v)
        m = {
          'grantee' => GranteeRef.to_map(v.grantee),
          'scope_set' => SignedActAsScopeSet.to_map(v.scope_set),
          'callback_url' => v.callback_url,
          'nonce' => v.nonce,
          'requested_at' => v.requested_at,
          'expires_at' => v.expires_at
        }
        m['requested_lifetime_seconds'] = v.requested_lifetime_seconds unless v.requested_lifetime_seconds.nil?
        unless v.requested_renewal_window_seconds.nil?
          m['requested_renewal_window_seconds'] = v.requested_renewal_window_seconds
        end
        m
      end

      def self.from_map(tree)
        ActAsShape.map!(tree, 'ActAsGrantRequest')
        new(
          grantee: GranteeRef.from_map(tree['grantee']),
          scope_set: SignedActAsScopeSet.from_map(tree['scope_set']),
          requested_lifetime_seconds: ActAsShape.int!(tree, 'requested_lifetime_seconds', optional: true),
          requested_renewal_window_seconds: ActAsShape.int!(tree, 'requested_renewal_window_seconds', optional: true),
          callback_url: ActAsShape.text!(tree, 'callback_url'),
          nonce: ActAsShape.text!(tree, 'nonce'),
          requested_at: ActAsShape.text!(tree, 'requested_at'),
          expires_at: ActAsShape.text!(tree, 'expires_at')
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    # SignedActAsGrantRequest / SignedActAsRefreshRequest share one shape.
    signed_request_body = proc do
      def self.to_map(v) = { 'request' => v.request, 'proof' => GranteeProof.to_map(v.proof) }

      def self.from_map(tree)
        ActAsShape.map!(tree, name)
        new(request: ActAsShape.bytes!(tree, 'request'), proof: GranteeProof.from_map(tree['proof']))
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end
    SignedActAsGrantRequest = Struct.new(:request, :proof, keyword_init: true, &signed_request_body)
    SignedActAsRefreshRequest = Struct.new(:request, :proof, keyword_init: true, &signed_request_body)

    ActAsRefreshRequest = Struct.new(:grant_id, :grantee, :requested_at, :expires_at, :nonce, keyword_init: true) do
      def self.to_map(v)
        {
          'grant_id' => v.grant_id,
          'grantee' => GranteeRef.to_map(v.grantee),
          'requested_at' => v.requested_at,
          'expires_at' => v.expires_at,
          'nonce' => v.nonce
        }
      end

      def self.from_map(tree)
        ActAsShape.map!(tree, 'ActAsRefreshRequest')
        new(
          grant_id: ActAsShape.text!(tree, 'grant_id'),
          grantee: GranteeRef.from_map(tree['grantee']),
          requested_at: ActAsShape.text!(tree, 'requested_at'),
          expires_at: ActAsShape.text!(tree, 'expires_at'),
          nonce: ActAsShape.text!(tree, 'nonce')
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    RefreshActAsGrantRequest = Struct.new(:request, keyword_init: true) do
      def self.to_map(v) = { 'request' => SignedActAsRefreshRequest.to_map(v.request) }

      def self.from_map(tree)
        ActAsShape.map!(tree, 'RefreshActAsGrantRequest')
        new(request: SignedActAsRefreshRequest.from_map(tree['request']))
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    # `grant` stays the exact CBOR(ActAsGrant) bytes the home domain signed.
    SignedActAsGrant = Struct.new(:grant, :signatures, keyword_init: true) do
      def self.to_map(v) = { 'grant' => v.grant, 'signatures' => v.signatures.map { |s| ClaimSignature.to_map(s) } }

      def self.from_map(tree)
        ActAsShape.map!(tree, 'SignedActAsGrant')
        signatures = ActAsShape.array!(tree, 'signatures').map do |s|
          ActAsShape.map!(s, 'ClaimSignature')
          ClaimSignature.new(
            domain: ActAsShape.text!(s, 'domain'),
            signed_by_key_id: ActAsShape.text!(s, 'signed_by_key_id'),
            signature: ActAsShape.bytes!(s, 'signature')
          )
        end
        new(grant: ActAsShape.bytes!(tree, 'grant'), signatures: signatures)
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    RefreshActAsGrantResponse = Struct.new(:grant, :signed, keyword_init: true) do
      def self.to_map(v) = { 'grant' => SignedActAsGrant.to_map(v.grant), 'signed' => v.signed }

      def self.from_map(tree)
        ActAsShape.map!(tree, 'RefreshActAsGrantResponse')
        signed = tree['signed']
        raise Cbor::DecodeError, 'signed: expected a bool' unless [true, false].include?(signed)

        new(grant: SignedActAsGrant.from_map(tree['grant']), signed: signed)
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    ActAsPresentation = Struct.new(:grant_hash, :audience, :request_digest, :presented_at, :nonce, keyword_init: true) do
      def self.to_map(v)
        {
          'grant_hash' => v.grant_hash,
          'audience' => ApplicationRef.to_map(v.audience),
          'request_digest' => v.request_digest,
          'presented_at' => v.presented_at,
          'nonce' => v.nonce
        }
      end

      def self.from_map(tree)
        ActAsShape.map!(tree, 'ActAsPresentation')
        new(
          grant_hash: ActAsShape.bytes!(tree, 'grant_hash'),
          audience: ApplicationRef.from_map(tree['audience']),
          request_digest: ActAsShape.bytes!(tree, 'request_digest'),
          presented_at: ActAsShape.text!(tree, 'presented_at'),
          nonce: ActAsShape.bytes!(tree, 'nonce')
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    SignedActAsPresentation = Struct.new(:presentation, :proof, keyword_init: true) do
      def self.to_map(v) = { 'presentation' => v.presentation, 'proof' => GranteeProof.to_map(v.proof) }

      def self.from_map(tree)
        ActAsShape.map!(tree, 'SignedActAsPresentation')
        new(presentation: ActAsShape.bytes!(tree, 'presentation'), proof: GranteeProof.from_map(tree['proof']))
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    ActAsCredential = Struct.new(:grant, :presentation, keyword_init: true) do
      def self.to_map(v)
        { 'grant' => SignedActAsGrant.to_map(v.grant), 'presentation' => SignedActAsPresentation.to_map(v.presentation) }
      end

      def self.from_map(tree)
        ActAsShape.map!(tree, 'ActAsCredential')
        new(grant: SignedActAsGrant.from_map(tree['grant']), presentation: SignedActAsPresentation.from_map(tree['presentation']))
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end
  end
end
