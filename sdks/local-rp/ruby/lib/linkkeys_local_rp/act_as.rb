# frozen_string_literal: true

require 'digest'
require 'openssl'
require 'securerandom'
require 'uri'
require_relative 'begin'
require_relative 'browser'
require_relative 'crypto'
require_relative 'dns'
require_relative 'local_rp'
require_relative 'rpc'
require_relative 'transport'
require_relative 'types'
require_relative 'url_params'

module LinkkeysLocalRp
  # Act-as grants, grantee side only (docs/spec/reserved/act-as-grants.md).
  # Mirrors `crates/liblinkkeys/src/act_as.rs` (`GranteeSigner::LocalRp`,
  # `sign_grant_request`, `sign_refresh_request`, `present`).
  #
  # A local RP can be the GRANTEE of an act-as grant: a user lets this app
  # act as the user at an enrolled application (the audience). A local RP
  # can never be an audience, because a peer cannot resolve its keys through
  # DNS. The home domain accepts a local-RP grantee only after it approved
  # that local RP.
  #
  # Every signature covers `CBOR([tag, payload_bytes])` and is made with the
  # descriptor signing key. The proof carries the signed descriptor, and its
  # `signed_by_key_id` is the descriptor fingerprint.
  #
  # `key_material` is anything with `descriptor`, `fingerprint`, and
  # `signing_private_key` (an `Identity::LocalRpKeyMaterial`).
  module ActAs
    GRANT_REQUEST_TAG = 'linkkeys-act-as-grant-request-v1alpha'
    REFRESH_REQUEST_TAG = 'linkkeys-act-as-refresh-request-v1alpha'
    PRESENTATION_TAG = 'linkkeys-act-as-presentation-v1alpha'

    # Default request window of a grant request, in seconds.
    DEFAULT_REQUEST_WINDOW_SECONDS = 300
    # Largest request window the reference home domain accepts, in seconds.
    MAX_REQUEST_WINDOW_SECONDS = 900
    # Request window of a refresh request, in seconds.
    REFRESH_WINDOW_SECONDS = 300

    # Invalid input to an act-as call, or a callback without its parameters.
    class Error < StandardError; end

    BeginActAsConfig = Struct.new(
      :key_material, :user_domain, :scope_set, :callback_url, :now,
      :requested_lifetime_seconds, :requested_renewal_window_seconds, :dns, :request_window_seconds,
      keyword_init: true
    )

    ActAsRedirect = Struct.new(:redirect_url, keyword_init: true)

    # State to keep between `begin_act_as` and `complete_act_as_callback`.
    # Single-use.
    PendingActAs = Struct.new(:nonce, :user_domain, :callback_url, keyword_init: true) do
      def to_h = { 'nonce' => nonce, 'user_domain' => user_domain, 'callback_url' => callback_url }

      def self.from_h(data)
        new(nonce: data['nonce'], user_domain: data['user_domain'], callback_url: data['callback_url'])
      end
    end

    # `signed` is true when the home domain made a new signature for this call.
    RefreshResult = Struct.new(:grant, :signed, keyword_init: true)

    PresentationResult = Struct.new(:credential, :credential_cbor, keyword_init: true)

    module_function

    # Whole-second RFC3339 in UTC, ending in `Z` (`act_as::format_time`).
    def format_time(time) = time.getutc.strftime('%Y-%m-%dT%H:%M:%SZ')

    # SHA-256 of `SignedActAsGrant.grant`. A presentation binds this value.
    def grant_hash(grant_bytes) = Digest::SHA256.digest(grant_bytes)

    # The local-RP form of `GranteeRef`.
    def local_rp_grantee(key_material)
      Types::GranteeRef.new(local_rp_descriptor_fingerprint: key_material.fingerprint)
    end

    def prove(key_material, tag, payload)
      signature = Crypto.sign_with_algorithm(
        Crypto::SigningAlgorithm::ED25519,
        LocalRp.envelope_signature_input(tag, payload),
        key_material.signing_private_key
      )
      Types::GranteeProof.new(
        local_rp_descriptor: key_material.descriptor,
        signature: Types::ApplicationKeySignature.new(signed_by_key_id: key_material.fingerprint, signature: signature)
      )
    end
    private_class_method :prove

    # CBOR text fields must be UTF-8 Strings: a BINARY String encodes as a
    # CBOR byte string (see `Cbor`). Input from a web framework is often
    # BINARY, so text inputs are copied as UTF-8 here.
    def text!(name, value)
      raise Error, "#{name} must be a String" unless value.is_a?(String)

      utf8 = value.dup.force_encoding(::Encoding::UTF_8)
      raise Error, "#{name} must be valid UTF-8" unless utf8.valid_encoding?

      utf8
    end
    private_class_method :text!

    def fresh_nonce = UrlParams.b64url_encode(SecureRandom.random_bytes(32)).encode(::Encoding::UTF_8)
    private_class_method :fresh_nonce

    # Sign an `ActAsGrantRequest` with the descriptor signing key. Pure.
    def sign_grant_request(request, key_material)
      bytes = request.to_cbor
      Types::SignedActAsGrantRequest.new(request: bytes, proof: prove(key_material, GRANT_REQUEST_TAG, bytes))
    end

    # Sign an `ActAsRefreshRequest` with the descriptor signing key. Pure.
    def sign_refresh_request(request, key_material)
      bytes = request.to_cbor
      Types::SignedActAsRefreshRequest.new(request: bytes, proof: prove(key_material, REFRESH_REQUEST_TAG, bytes))
    end

    # `base64url-no-pad(CBOR(SignedActAsGrantRequest))`, the `signed_request` value.
    def signed_grant_request_to_url_param(signed) = UrlParams.b64url_encode(signed.to_cbor)

    def check_optional_seconds!(name, value, minimum)
      return if value.nil?
      raise Error, "#{name} must be a whole number >= #{minimum}" unless value.is_a?(Integer) && value >= minimum
    end
    private_class_method :check_optional_seconds!

    # Sign an `ActAsGrantRequest` and return
    # `[ActAsRedirect, PendingActAs]`. The redirect sends the browser to the
    # user's home domain (`/auth/act-as`). Browser endpoint discovery and
    # fallback are the same as `begin_local_login`. `scope_set` is the
    # audience's `SignedActAsScopeSet` as CBOR bytes, exactly as the
    # audience sent it.
    def begin_act_as(config)
      begin
        Begin.validate_callback_scheme!(config.callback_url)
        _username, domain = Begin.parse_identity_input!(config.user_domain)
      rescue Begin::Error => e
        raise Error, e.message
      end
      check_optional_seconds!('requested_lifetime_seconds', config.requested_lifetime_seconds, 1)
      check_optional_seconds!('requested_renewal_window_seconds', config.requested_renewal_window_seconds, 0)
      window = config.request_window_seconds || DEFAULT_REQUEST_WINDOW_SECONDS
      unless window.is_a?(Integer) && window.between?(1, MAX_REQUEST_WINDOW_SECONDS)
        raise Error, "request_window_seconds must be 1..#{MAX_REQUEST_WINDOW_SECONDS}"
      end

      scope_set = begin
        Types::SignedActAsScopeSet.from_cbor(config.scope_set)
      rescue StandardError => e # malformed CBOR can surface as TypeError/NoMethodError too
        raise LocalRp::DecodeFailed, "scope set: #{e.message}"
      end

      nonce = fresh_nonce
      request = Types::ActAsGrantRequest.new(
        grantee: local_rp_grantee(config.key_material),
        scope_set: scope_set,
        requested_lifetime_seconds: config.requested_lifetime_seconds,
        requested_renewal_window_seconds: config.requested_renewal_window_seconds,
        callback_url: text!('callback_url', config.callback_url),
        nonce: nonce,
        requested_at: format_time(config.now),
        expires_at: format_time(config.now + window)
      )
      signed = sign_grant_request(request, config.key_material)
      dns = config.dns || Dns::SystemDnsResolver.new
      redirect_url = Browser.resolve_browser_endpoint(
        dns, domain, Browser::BROWSER_ROUTE_ACT_AS, signed_grant_request_to_url_param(signed)
      )
      [
        ActAsRedirect.new(redirect_url: redirect_url),
        PendingActAs.new(nonce: nonce, user_domain: domain, callback_url: config.callback_url)
      ]
    end

    # Read `act_as_grant_id` and `nonce` from the callback and return the
    # grant id. `arrived` is the full callback URL, its query string, or a
    # Hash of query parameters. The nonce must equal the pending nonce
    # (constant-time compare).
    def complete_act_as_callback(pending, arrived)
      pairs =
        if arrived.is_a?(Hash)
          arrived.flat_map { |k, v| Array(v).map { |x| [k.to_s, x] } }
        else
          query = arrived.include?('://') ? URI.parse(arrived).query.to_s : arrived.delete_prefix('?')
          URI.decode_www_form(query)
        end
      # A repeated parameter is ambiguous: refuse it rather than pick one.
      if %w[act_as_grant_id nonce].any? { |key| pairs.count { |k, _| k == key } > 1 }
        raise Error, 'callback repeats an act-as parameter'
      end
      params = pairs.to_h
      grant_id = params['act_as_grant_id']
      nonce = params['nonce']
      raise Error, 'callback needs act_as_grant_id and nonce' if grant_id.nil? || grant_id.empty? || nonce.nil?

      expected = pending.nonce.b
      actual = nonce.b
      unless expected.bytesize == actual.bytesize && OpenSSL.fixed_length_secure_compare(expected, actual)
        raise LocalRp::NonceMismatch, 'nonce does not match'
      end

      grant_id
    end

    # Fetch the grant, or a renewed grant, with `ActAs/refresh-grant` on the
    # user's home domain (`PendingActAs#user_domain`). Uses the same
    # discovery and pinned TCP path as claim-ticket redemption. Returns a
    # `RefreshResult`.
    def refresh_act_as_grant(key_material, user_domain, grant_id, now, transport: nil, dns: nil)
      raise Error, 'grant_id must not be empty' if grant_id.nil? || grant_id.empty?

      request = Types::ActAsRefreshRequest.new(
        grant_id: text!('grant_id', grant_id),
        grantee: local_rp_grantee(key_material),
        requested_at: format_time(now),
        expires_at: format_time(now + REFRESH_WINDOW_SECONDS),
        nonce: fresh_nonce
      )
      signed = sign_refresh_request(request, key_material)
      response = Rpc.refresh_act_as_grant(
        transport || Transport::StdTransport.new,
        dns || Dns::SystemDnsResolver.new,
        user_domain,
        signed
      )
      check_returned_grant(response.grant.grant, grant_id, user_domain, key_material)
      RefreshResult.new(grant: response.grant, signed: response.signed)
    end

    # The audience checks the grant signature. This only checks that the home
    # domain returned the grant the call asked for, so a confused or hostile
    # server cannot hand this grantee another grant.
    def check_returned_grant(grant_bytes, grant_id, user_domain, key_material)
      tree = Cbor.decode(grant_bytes)
      raise Error, 'refresh-grant returned a grant that is not a map' unless tree.is_a?(Hash)
      raise Error, 'refresh-grant returned another grant id' unless tree['grant_id'] == grant_id

      grantee = tree['grantee']
      unless grantee.is_a?(Hash) && grantee['application'].nil? &&
             grantee['local_rp_descriptor_fingerprint'] == key_material.fingerprint
        raise Error, 'refresh-grant returned a grant for another grantee'
      end
      domain = tree['subject_domain']
      return if domain.is_a?(String) && domain.downcase(:ascii) == user_domain.to_s.downcase(:ascii)

      raise Error, 'refresh-grant returned a grant from another subject domain'
    end

    # Build and sign the `ActAsCredential` for one call to the audience.
    # `request_digest` is defined by the audience's protocol. Use a fresh
    # `nonce` per call. Pure. Returns a `PresentationResult`.
    def present(grant, audience, request_digest, now, nonce, key_material)
      presentation = Types::ActAsPresentation.new(
        grant_hash: grant_hash(grant.grant),
        audience: Types::ApplicationRef.new(
          subject_user_id: text!('subject_user_id', audience.subject_user_id),
          subject_domain: text!('subject_domain', audience.subject_domain),
          application_id: text!('application_id', audience.application_id)
        ),
        request_digest: request_digest.b,
        presented_at: format_time(now),
        nonce: nonce.b
      )
      bytes = presentation.to_cbor
      credential = Types::ActAsCredential.new(
        grant: grant,
        presentation: Types::SignedActAsPresentation.new(
          presentation: bytes, proof: prove(key_material, PRESENTATION_TAG, bytes)
        )
      )
      PresentationResult.new(credential: credential, credential_cbor: credential.to_cbor)
    end
  end
end
