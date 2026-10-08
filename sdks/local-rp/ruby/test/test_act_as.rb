# frozen_string_literal: true

# Act-as grantee tests: the `local_rp_grantee` case of
# `sdks/regular-rp/conformance/act_as_grantee_signing.json` byte for byte,
# begin act-as browser discovery with fake DNS, and the callback nonce
# check. The refresh call is tested against the fake IDP in test_flow.rb.
# No test here touches the network.

require_relative 'test_helper'

class TestActAs < Minitest::Test
  ActAs = LinkkeysLocalRp::ActAs
  T = LinkkeysLocalRp::Types

  VECTOR_PATH = File.expand_path('../../../regular-rp/conformance/act_as_grantee_signing.json', __dir__)
  VECTORS = JSON.parse(File.read(VECTOR_PATH))
  CASE = VECTORS['cases'].find { |c| c['name'] == 'local_rp_grantee' }
  GRANTEE = VECTORS['local_rp_grantee']

  KeyMaterial = Struct.new(:descriptor, :fingerprint, :signing_private_key, keyword_init: true)

  IDENTITY_DOMAIN = 'ident.example.test'
  CALLBACK = 'http://app.lan:8080/act-as/callback'

  class MapDns
    def initialize(records) = @records = records

    def txt_lookup(name)
      @records.fetch(name) { raise "no fake record for #{name}" }
    end
  end

  def hex(str) = [str].pack('H*')
  def to_hex(bytes) = bytes.unpack1('H*')
  def parse_time(str) = Time.iso8601(str)

  def key_material
    @key_material ||= KeyMaterial.new(
      descriptor: T::SignedLocalRpDescriptor.from_cbor(hex(GRANTEE['signed_descriptor_cbor_hex'])),
      fingerprint: GRANTEE['fingerprint'],
      signing_private_key: hex(GRANTEE['signing_private_key_hex'])
    )
  end

  def scope_set_bytes = hex(CASE['grant_request']['inputs']['scope_set_signed_cbor_hex'])

  def test_vector_descriptor_round_trips
    assert_equal GRANTEE['signed_descriptor_cbor_hex'], to_hex(key_material.descriptor.to_cbor)
    assert_equal key_material.fingerprint, CASE['grantee']['local_rp_descriptor_fingerprint']
  end

  def test_vector_grant_request
    inputs = CASE['grant_request']['inputs']
    signed = ActAs.sign_grant_request(
      T::ActAsGrantRequest.new(
        grantee: T::GranteeRef.new(local_rp_descriptor_fingerprint: key_material.fingerprint),
        scope_set: T::SignedActAsScopeSet.from_cbor(scope_set_bytes),
        requested_lifetime_seconds: inputs['requested_lifetime_seconds'],
        requested_renewal_window_seconds: inputs['requested_renewal_window_seconds'],
        callback_url: inputs['callback_url'],
        nonce: inputs['nonce'],
        requested_at: inputs['requested_at'],
        expires_at: inputs['expires_at']
      ),
      key_material
    )
    assert_equal CASE['grant_request']['request_cbor_hex'], to_hex(signed.request)
    assert_equal CASE['grant_request']['signature_input_cbor_hex'],
                 to_hex(LinkkeysLocalRp::LocalRp.envelope_signature_input(ActAs::GRANT_REQUEST_TAG, signed.request))
    assert_equal CASE['grant_request']['signed_cbor_hex'], to_hex(signed.to_cbor)
    assert_equal CASE['grant_request']['url_param'], ActAs.signed_grant_request_to_url_param(signed)
  end

  def test_vector_refresh_request
    inputs = CASE['refresh_request']['inputs']
    signed = ActAs.sign_refresh_request(
      T::ActAsRefreshRequest.new(
        grant_id: inputs['grant_id'],
        grantee: T::GranteeRef.new(local_rp_descriptor_fingerprint: key_material.fingerprint),
        requested_at: inputs['requested_at'],
        expires_at: inputs['expires_at'],
        nonce: inputs['nonce']
      ),
      key_material
    )
    assert_equal CASE['refresh_request']['request_cbor_hex'], to_hex(signed.request)
    assert_equal CASE['refresh_request']['signed_cbor_hex'], to_hex(signed.to_cbor)
  end

  def test_vector_presentation_and_credential
    inputs = CASE['presentation']['inputs']
    grant = T::SignedActAsGrant.from_cbor(hex(inputs['grant_signed_cbor_hex']))
    assert_equal CASE['presentation']['grant_hash_hex'], to_hex(ActAs.grant_hash(grant.grant))
    audience = T::ApplicationRef.new(**inputs['audience'].transform_keys(&:to_sym))
    result = ActAs.present(
      grant, audience, hex(inputs['request_digest_hex']), parse_time(inputs['presented_at']),
      hex(inputs['nonce_hex']), key_material
    )
    assert_equal CASE['presentation']['presentation_cbor_hex'], to_hex(result.credential.presentation.presentation)
    assert_equal CASE['presentation']['credential_cbor_hex'], to_hex(result.credential_cbor)
  end

  def test_format_time_drops_fraction
    assert_equal '2026-10-06T12:05:00Z', ActAs.format_time(Time.utc(2026, 10, 6, 12, 5, 0.987r))
  end

  # ---------------------------------------------------------------
  # begin_act_as
  # ---------------------------------------------------------------

  def begin_act_as(dns, **overrides)
    fields = {
      key_material: key_material,
      user_domain: "alice@#{IDENTITY_DOMAIN}",
      scope_set: scope_set_bytes,
      callback_url: CALLBACK,
      now: parse_time(CASE['grant_request']['inputs']['requested_at']),
      requested_lifetime_seconds: 1800,
      dns: dns
    }.merge(overrides)
    ActAs.begin_act_as(ActAs::BeginActAsConfig.new(**fields))
  end

  def test_begin_uses_discovered_host_and_signs_verifiable_request
    redirect, pending = begin_act_as(MapDns.new("_linkkeys_apis.#{IDENTITY_DOMAIN}" => ['v=lk1 https=login.example.test/linkkeys']))
    uri = URI.parse(redirect.redirect_url)
    assert_equal 'https://login.example.test/linkkeys/auth/act-as', "#{uri.scheme}://#{uri.host}#{uri.path}"
    query = URI.decode_www_form(uri.query)
    assert_equal ['signed_request'], query.map(&:first)
    assert_equal IDENTITY_DOMAIN, pending.user_domain
    assert_equal CALLBACK, pending.callback_url
    assert_equal 43, pending.nonce.length

    signed = T::SignedActAsGrantRequest.from_cbor(LinkkeysLocalRp::UrlParams.b64url_decode(query.first.last))
    request = T::ActAsGrantRequest.from_cbor(signed.request)
    inputs = CASE['grant_request']['inputs']
    assert_equal pending.nonce, request.nonce
    assert_equal key_material.fingerprint, request.grantee.local_rp_descriptor_fingerprint
    assert_nil request.grantee.application
    assert_equal inputs['requested_at'], request.requested_at
    assert_equal inputs['expires_at'], request.expires_at
    assert_equal 1800, request.requested_lifetime_seconds
    assert_nil request.requested_renewal_window_seconds
    assert_equal CALLBACK, request.callback_url
    assert_equal to_hex(scope_set_bytes), to_hex(request.scope_set.to_cbor)
    assert_equal key_material.fingerprint, signed.proof.signature.signed_by_key_id
    assert_equal GRANTEE['signed_descriptor_cbor_hex'], to_hex(signed.proof.local_rp_descriptor.to_cbor)
    public_key = T::LocalRpDescriptor.from_cbor(key_material.descriptor.descriptor).signing_public_key
    LinkkeysLocalRp::Crypto.verify_with_algorithm(
      LinkkeysLocalRp::Crypto::SigningAlgorithm::ED25519,
      LinkkeysLocalRp::LocalRp.envelope_signature_input(ActAs::GRANT_REQUEST_TAG, signed.request),
      signed.proof.signature.signature,
      public_key
    )
  end

  def test_begin_text_fields_stay_text_for_binary_input
    redirect, = begin_act_as(MapDns.new({}), callback_url: CALLBACK.b)
    param = URI.decode_www_form(URI.parse(redirect.redirect_url).query).first.last
    signed = T::SignedActAsGrantRequest.from_cbor(LinkkeysLocalRp::UrlParams.b64url_decode(param))
    assert_equal CALLBACK, T::ActAsGrantRequest.from_cbor(signed.request).callback_url
  end

  def test_begin_falls_back_to_identity_domain
    redirect, = begin_act_as(MapDns.new({}))
    assert redirect.redirect_url.start_with?("https://#{IDENTITY_DOMAIN}/auth/act-as?signed_request="), redirect.redirect_url
  end

  def test_begin_makes_fresh_nonce
    _, a = begin_act_as(MapDns.new({}))
    _, b = begin_act_as(MapDns.new({}))
    refute_equal a.nonce, b.nonce
  end

  def test_begin_rejects_bad_input
    [
      { request_window_seconds: 901 },
      { request_window_seconds: 0 },
      { callback_url: 'javascript:alert(1)' },
      { user_domain: 'not a domain' },
      { requested_renewal_window_seconds: -1 },
      { requested_lifetime_seconds: 0 }
    ].each do |overrides|
      assert_raises(ActAs::Error, overrides.inspect) { begin_act_as(MapDns.new({}), **overrides) }
    end
    assert_raises(LinkkeysLocalRp::LocalRp::DecodeFailed) { begin_act_as(MapDns.new({}), scope_set: "\xff".b) }
    assert_raises(LinkkeysLocalRp::LocalRp::DecodeFailed) { begin_act_as(MapDns.new({}), scope_set: "\x41\x00".b) }
    assert_raises(LinkkeysLocalRp::LocalRp::DecodeFailed) { begin_act_as(MapDns.new({}), scope_set: "\x59\x01".b) }
  end

  # ---------------------------------------------------------------
  # complete_act_as_callback
  # ---------------------------------------------------------------

  def test_callback_returns_grant_id_on_nonce_match
    _, pending = begin_act_as(MapDns.new({}))
    arrived = "#{CALLBACK}?act_as_grant_id=grant-42&nonce=#{pending.nonce}"
    assert_equal 'grant-42', ActAs.complete_act_as_callback(pending, arrived)
    assert_equal 'grant-42', ActAs.complete_act_as_callback(pending, "?#{URI.parse(arrived).query}")
    assert_equal 'grant-42', ActAs.complete_act_as_callback(pending, { 'act_as_grant_id' => 'grant-42', 'nonce' => pending.nonce })
  end

  def test_callback_rejects_nonce_mismatch_and_missing_parameters
    _, pending = begin_act_as(MapDns.new({}))
    wrong = pending.nonce[0..-2] + (pending.nonce.end_with?('A') ? 'B' : 'A')
    assert_raises(LinkkeysLocalRp::LocalRp::NonceMismatch) do
      ActAs.complete_act_as_callback(pending, "#{CALLBACK}?act_as_grant_id=grant-42&nonce=#{wrong}")
    end
    assert_raises(LinkkeysLocalRp::LocalRp::NonceMismatch) do
      ActAs.complete_act_as_callback(pending, "#{CALLBACK}?act_as_grant_id=grant-42&nonce=short")
    end
    assert_raises(ActAs::Error) { ActAs.complete_act_as_callback(pending, "#{CALLBACK}?nonce=#{pending.nonce}") }
    assert_raises(ActAs::Error) { ActAs.complete_act_as_callback(pending, "#{CALLBACK}?act_as_grant_id=grant-42") }
    # A repeated parameter is refused, even when one value is correct.
    assert_raises(ActAs::Error) do
      ActAs.complete_act_as_callback(pending, "#{CALLBACK}?act_as_grant_id=evil&act_as_grant_id=grant-42&nonce=#{pending.nonce}")
    end
    assert_raises(ActAs::Error) do
      ActAs.complete_act_as_callback(pending, "#{CALLBACK}?act_as_grant_id=grant-42&nonce=#{pending.nonce}&nonce=x")
    end
    assert_raises(ActAs::Error) do
      ActAs.complete_act_as_callback(pending, { 'act_as_grant_id' => %w[evil grant-42], 'nonce' => pending.nonce })
    end
  end
end
