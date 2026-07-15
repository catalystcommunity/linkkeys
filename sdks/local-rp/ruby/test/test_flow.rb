# frozen_string_literal: true

require_relative 'test_helper'
require 'socket'
require 'openssl'

# Flow tests: complete_local_login's full verification chain, end to end,
# against a real (but locally spun up, fake-identity) LinkKeys IDP --
# DNS-pinned TLS, CSIL-RPC framing, and all. Only two things are faked: the
# DNS TXT answers (FakeDnsResolver, so no real network/DNS is touched) and
# the IDP's identity itself (a throwaway domain signing key generated for
# this test, not a real LinkKeys deployment). Mirrors
# `sdks/local-rp/python/tests/test_flow.py` (happy path + one test per
# verification-chain failure).
#
# Canned callback/ticket-redemption/domain-keys responses are built with
# LinkkeysLocalRp::LocalRp/::Claims directly (the same pure protocol layer
# complete_local_login itself calls), using the same fixed, publicly-known
# test key seeds as sdks/local-rp/conformance/keys.json (local_rp.signing =
# 0x01 repeated, local_rp.encryption = 0x02 repeated, domain_signing_key =
# 0x03 repeated) so this test suite and the conformance vectors describe
# the same identities.
class TestFlow < Minitest::Test
  # Test-only signal a hostile-IDP `dispatch` lambda can raise to make
  # `spawn_fake_idp`'s server thread close the connection without sending
  # any response at all -- simulating a dropped/errored RPC call at the
  # transport level (as opposed to `encode_error_response`, which simulates
  # a well-formed CSIL-RPC error reply). The server loop's existing
  # `rescue StandardError => next` already treats this exactly like any
  # other dispatch failure: skip the response, close the connection.
  class DropConnection < StandardError; end

  LOCAL_RP_SIGNING_SEED = ("\x01" * 32).b
  LOCAL_RP_ENCRYPTION_PRIVATE = ("\x02" * 32).b
  DOMAIN_SIGNING_SEED = ("\x03" * 32).b
  DOMAIN_KEY_ID = 'test-domain-key-1'
  USER_DOMAIN = 'example.test'
  CALLBACK_URL = 'http://localhost/callback'

  # ---------------------------------------------------------------
  # Test doubles
  # ---------------------------------------------------------------

  # Canned DNS answers for exactly one domain.
  class FakeDnsResolver
    def initialize(linkkeys_txt, apis_txt)
      @linkkeys_txt = linkkeys_txt
      @apis_txt = apis_txt
    end

    def txt_lookup(name)
      return [@linkkeys_txt] if name == "_linkkeys.#{USER_DOMAIN}"
      return [@apis_txt] if name == "_linkkeys_apis.#{USER_DOMAIN}"

      raise "no fake record for #{name}"
    end
  end

  # Self-signed Ed25519 TLS cert derived from a domain signing key --
  # test-support only, mirroring what a real LinkKeys IDP's TLS listener
  # does. Returns an OpenSSL::X509::Certificate + OpenSSL::PKey::PKey pair.
  def generate_domain_tls_cert(domain_name, ed25519_seed)
    pkey = OpenSSL::PKey.new_raw_private_key('ED25519', ed25519_seed)
    name = OpenSSL::X509::Name.parse("/CN=#{domain_name}")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = OpenSSL::BN.rand(64)
    cert.subject = name
    cert.issuer = name
    cert.public_key = pkey
    cert.not_before = Time.now - 86_400
    cert.not_after = Time.now + (86_400 * 3650)
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    cert.add_extension(ef.create_extension('subjectAltName', "DNS:#{domain_name}", false))
    cert.sign(pkey, nil)
    [cert, pkey]
  end

  def decode_request_envelope(data)
    value = LinkkeysLocalRp::Cbor.decode(data)
    payload_tag = value['payload']
    payload = payload_tag.is_a?(LinkkeysLocalRp::Cbor::CborTag) ? payload_tag.value : ''.b
    [value['service'], value['op'], payload]
  end

  def encode_ok_response(payload)
    LinkkeysLocalRp::Cbor.encode({ 'v' => 1, 'status' => 0, 'payload' => LinkkeysLocalRp::Cbor::CborTag.new(24, payload) })
  end

  def encode_error_response(status, message)
    LinkkeysLocalRp::Cbor.encode(
      { 'v' => 1, 'status' => status, 'error' => message, 'payload' => LinkkeysLocalRp::Cbor::CborTag.new(24, ''.b) }
    )
  end

  # Spawns a background thread that accepts up to `expected_requests` TLS
  # connections on a fresh loopback port, presenting a certificate derived
  # from `domain_seed` (so its SPKI fingerprint is whatever the test's DNS
  # answer pins to), and answers each with dispatch.call(service, op,
  # payload). Returns "host:port". Tolerates a connection that closes
  # without sending any bytes (the "bad pin" scenario: the client never
  # sends a request after a failed pin check).
  def spawn_fake_idp(domain_seed, expected_requests, &dispatch)
    cert, pkey = generate_domain_tls_cert(USER_DOMAIN, domain_seed)

    ctx = OpenSSL::SSL::SSLContext.new
    ctx.cert = cert
    ctx.key = pkey

    listener = TCPServer.new('127.0.0.1', 0)
    _host, port = listener.addr[3], listener.addr[1]

    thread = Thread.new do
      expected_requests.times do
        conn = begin
          listener.accept
        rescue StandardError
          next
        end
        tls = OpenSSL::SSL::SSLSocket.new(conn, ctx)
        tls.sync_close = true
        begin
          tls.accept
        rescue OpenSSL::SSL::SSLError
          conn.close
          next
        end
        begin
          len_bytes = tls.read(4)
          next if len_bytes.nil? || len_bytes.bytesize < 4

          length = len_bytes.unpack1('N')
          buf = +''.b
          buf << tls.read(length - buf.bytesize) while buf.bytesize < length
          next if buf.bytesize != length

          service, op, payload = decode_request_envelope(buf)
          resp = dispatch.call(service, op, payload)
          tls.write([resp.bytesize].pack('N'))
          tls.write(resp)
        rescue StandardError
          next
        ensure
          tls.close
        end
      end
    end

    ["127.0.0.1:#{port}", thread]
  end

  # ---------------------------------------------------------------
  # Scenario construction
  # ---------------------------------------------------------------

  def fixed_key_material(now)
    signing_pkey = OpenSSL::PKey.new_raw_private_key('ED25519', LOCAL_RP_SIGNING_SEED)
    signing_public_key = signing_pkey.raw_public_key
    encryption_public_key = LinkkeysLocalRp::Crypto.x25519_public_from_private(LOCAL_RP_ENCRYPTION_PRIVATE)

    created_at = LinkkeysLocalRp::Timeutil.to_rfc3339(now - 86_400)
    expires_at = LinkkeysLocalRp::Timeutil.to_rfc3339(now + (86_400 * 3650))
    descriptor = LinkkeysLocalRp::LocalRp.build_local_rp_descriptor(
      'Flow Test App', nil, signing_public_key, encryption_public_key,
      %w[aes-256-gcm chacha20-poly1305], created_at, expires_at
    )
    fingerprint = descriptor.fingerprint
    signed_descriptor = LinkkeysLocalRp::LocalRp.sign_local_rp_descriptor(descriptor, LOCAL_RP_SIGNING_SEED)

    LinkkeysLocalRp::Identity::LocalRpKeyMaterial.new(
      signing_private_key: LOCAL_RP_SIGNING_SEED,
      signing_public_key: signing_public_key,
      encryption_private_key: LOCAL_RP_ENCRYPTION_PRIVATE,
      encryption_public_key: encryption_public_key,
      descriptor: signed_descriptor,
      fingerprint: fingerprint
    )
  end

  def domain_public_key(now)
    sibling_key(DOMAIN_SIGNING_SEED, DOMAIN_KEY_ID, now)
  end

  def sibling_key(seed, key_id, now)
    pkey = OpenSSL::PKey.new_raw_private_key('ED25519', seed)
    pk = pkey.raw_public_key
    LinkkeysLocalRp::Types::DomainPublicKey.new(
      key_id: key_id, public_key: pk, fingerprint: LinkkeysLocalRp::Crypto.fingerprint(pk),
      algorithm: 'ed25519', key_usage: 'sign', signed_by_key_id: nil, key_signature: nil,
      created_at: LinkkeysLocalRp::Timeutil.to_rfc3339(now - (86_400 * 30)),
      expires_at: LinkkeysLocalRp::Timeutil.to_rfc3339(now + (86_400 * 365)),
      revoked_at: nil
    )
  end

  Scenario = Struct.new(
    :mutate_payload, :mutate_domain_key, :mutate_claim, :mutate_redemption,
    :dns_fingerprint_override, :extra_domain_keys, :revocation_certs,
    :revocations_behavior, :required_claims, :claim_user_id, :expected_requests,
    keyword_init: true
  ) do
    def initialize(**kwargs)
      super(
        mutate_payload: kwargs[:mutate_payload] || ->(_p) {},
        mutate_domain_key: kwargs[:mutate_domain_key] || ->(_k) {},
        mutate_claim: kwargs[:mutate_claim] || ->(_c) {},
        # Applied to the LocalRpTicketRedemptionResponse the fake IDP will
        # return from LocalRp/redeem-claim-ticket, after it's built but
        # before the fake IDP starts serving -- lets a hostile-IDP test
        # claim a different user_id/user_domain, or empty out the claim
        # list, without otherwise disturbing the signed callback payload it
        # must be cross-checked against.
        mutate_redemption: kwargs[:mutate_redemption] || ->(_r) {},
        dns_fingerprint_override: kwargs[:dns_fingerprint_override],
        extra_domain_keys: kwargs[:extra_domain_keys] || [],
        revocation_certs: kwargs[:revocation_certs] || [],
        # 'ok' (default): answer get-revocations normally. 'error': answer
        # with a well-formed CSIL-RPC error reply. 'drop': close the
        # connection without responding at all. Both non-'ok' values must
        # make fetch_domain_keys fail closed (FIX B).
        revocations_behavior: kwargs[:revocations_behavior] || 'ok',
        # Overrides begin_local_login's required_claims (defaults to
        # DEFAULT_REQUIRED_CLAIMS, i.e. ["handle"]) so tests can exercise
        # required-claims enforcement independently of the default claim
        # set.
        required_claims: kwargs[:required_claims],
        # Overrides the user_id the "handle" claim is SIGNED for (default
        # "user-1", matching the callback payload's user_id). Setting this
        # to a different value produces a claim with a cryptographically
        # VALID signature that nonetheless names the wrong subject -- i.e.
        # it isolates the claim.user_id == payload.user_id cross-check from
        # claim signature verification, which a mismatch introduced by
        # tampering post-signing would not do (that would just fail
        # signature verification instead).
        claim_user_id: kwargs[:claim_user_id],
        # Served from DomainKeys/get-revocations on every scenario now
        # (FIX B: the client fetches revocations unconditionally, not
        # gated on recent_revocations_available) -- so the happy path is
        # three RPCs: get-domain-keys, get-revocations, redeem-claim-ticket.
        expected_requests: kwargs[:expected_requests] || 3
      )
    end
  end

  def run_scenario(scenario)
    now = Time.now.utc
    key_material = fixed_key_material(now)

    _redirect, pending = LinkkeysLocalRp.begin_local_login(
      LinkkeysLocalRp::Begin::BeginLocalLoginConfig.new(
        key_material: key_material, callback_url: CALLBACK_URL, user_domain: USER_DOMAIN, now: now,
        required_claims: scenario.required_claims
      )
    )

    domain_key = domain_public_key(now)
    scenario.mutate_domain_key.call(domain_key)

    claim_ticket = ("\x07" * 32).b
    payload = LinkkeysLocalRp::LocalRp.build_local_rp_callback_payload(
      'user-1', USER_DOMAIN, claim_ticket, key_material.fingerprint, CALLBACK_URL,
      pending.nonce, pending.state, LinkkeysLocalRp::Timeutil.to_rfc3339(now),
      LinkkeysLocalRp::Timeutil.to_rfc3339(now + 300)
    )
    scenario.mutate_payload.call(payload)

    signed_payload = LinkkeysLocalRp::LocalRp.sign_local_rp_callback_payload(
      payload, DOMAIN_KEY_ID, LinkkeysLocalRp::Crypto::SigningAlgorithm::ED25519, DOMAIN_SIGNING_SEED
    )

    encrypted = LinkkeysLocalRp::LocalRp.seal_local_rp_callback(
      signed_payload, LinkkeysLocalRp::Crypto::AeadSuite::AES_256_GCM, key_material.encryption_public_key,
      payload.audience_fingerprint, payload.nonce, payload.state, payload.issued_at, payload.expires_at
    )
    encrypted_token = LinkkeysLocalRp::UrlParams.local_rp_encrypted_callback_to_url_param(encrypted)
    arrived_url = "#{CALLBACK_URL}?encrypted_token=#{encrypted_token}"

    claim = LinkkeysLocalRp::Claims.sign_claim(
      LinkkeysLocalRp::Claims::ClaimSpec.new(
        claim_id: 'claim-1', claim_type: 'handle', claim_value: 'flowtestuser'.b,
        user_id: scenario.claim_user_id || 'user-1', subject_domain: USER_DOMAIN,
        attested_at: LinkkeysLocalRp::Timeutil.to_rfc3339(now)
      ),
      [
        LinkkeysLocalRp::Claims::ClaimSigner.new(
          domain: USER_DOMAIN, key_id: DOMAIN_KEY_ID,
          algorithm: LinkkeysLocalRp::Crypto::SigningAlgorithm::ED25519, private_key_bytes: DOMAIN_SIGNING_SEED
        )
      ]
    )
    scenario.mutate_claim.call(claim)

    ticket_expires_at = LinkkeysLocalRp::Timeutil.to_rfc3339(now + 3600)
    redemption_response = LinkkeysLocalRp::Types::LocalRpTicketRedemptionResponse.new(
      user_id: 'user-1', user_domain: USER_DOMAIN, claims: [claim], ticket_expires_at: ticket_expires_at
    )
    scenario.mutate_redemption.call(redemption_response)

    served_keys = [domain_key] + scenario.extra_domain_keys
    revocations_available = scenario.revocation_certs.empty? ? nil : true

    dispatch = lambda do |service, op, _payload|
      if [service, op] == %w[DomainKeys get-domain-keys]
        resp = LinkkeysLocalRp::Types::GetDomainKeysResponse.new(
          domain: USER_DOMAIN, keys: served_keys, recent_revocations_available: revocations_available
        )
        encode_ok_response(resp.to_cbor)
      elsif [service, op] == %w[DomainKeys get-revocations]
        case scenario.revocations_behavior
        when 'error'
          encode_error_response(2, 'fake IDP simulated a get-revocations failure')
        when 'drop'
          raise DropConnection
        else
          resp = LinkkeysLocalRp::Types::GetRevocationsResponse.new(revocations: scenario.revocation_certs)
          encode_ok_response(resp.to_cbor)
        end
      elsif [service, op] == %w[LocalRp redeem-claim-ticket]
        encode_ok_response(redemption_response.to_cbor)
      else
        encode_error_response(2, "fake IDP has no handler for #{service}/#{op}")
      end
    end

    tcp_addr, thread = spawn_fake_idp(DOMAIN_SIGNING_SEED, scenario.expected_requests, &dispatch)

    real_fingerprint = LinkkeysLocalRp::Crypto.fingerprint(domain_key.public_key)
    pinned_fingerprint = scenario.dns_fingerprint_override || real_fingerprint
    pinned = [pinned_fingerprint] + scenario.extra_domain_keys.map { |k| LinkkeysLocalRp::Crypto.fingerprint(k.public_key) }
    dns = FakeDnsResolver.new(
      "v=lk1 #{pinned.map { |fp| "fp=#{fp}" }.join(' ')}",
      "v=lk1 tcp=#{tcp_addr}"
    )
    transport = LinkkeysLocalRp::Transport::StdTransport.new

    begin
      LinkkeysLocalRp.complete_local_login(key_material, pending, encrypted_token, arrived_url, now, transport: transport, dns: dns)
    ensure
      thread.join(5)
    end
  end

  # ---------------------------------------------------------------
  # Tests
  # ---------------------------------------------------------------

  def test_happy_path_returns_verified_login
    verified = run_scenario(Scenario.new)
    assert_equal 'user-1', verified.user_id
    assert_equal USER_DOMAIN, verified.user_domain
    assert_equal 1, verified.claims.length
    assert_equal 'handle', verified.claims[0].claim_type
    assert_equal 64, verified.local_rp_fingerprint.length
    assert_equal 1, verified.domain_public_keys.length
  end

  def test_wrong_audience_fingerprint_is_rejected
    mutate = ->(p) { p.audience_fingerprint = 'b' * 64 }
    # get-domain-keys + get-revocations both happen (FIX B: unconditional)
    # before envelope verification -- which is where this fails -- ever
    # runs, so ticket redemption is never attempted.
    assert_raises(LinkkeysLocalRp::LocalRp::Error) { run_scenario(Scenario.new(mutate_payload: mutate, expected_requests: 2)) }
  end

  def test_wrong_issuer_domain_is_rejected
    mutate = ->(p) { p.user_domain = 'attacker.test' }
    assert_raises(LinkkeysLocalRp::LocalRp::Error) { run_scenario(Scenario.new(mutate_payload: mutate, expected_requests: 2)) }
  end

  def test_nonce_mismatch_is_rejected
    mutate = ->(p) { p.nonce = ("\xEE" * 32).b }
    assert_raises(LinkkeysLocalRp::LocalRp::Error) { run_scenario(Scenario.new(mutate_payload: mutate, expected_requests: 2)) }
  end

  def test_expired_callback_payload_is_rejected
    mutate = lambda do |p|
      n = Time.now.utc
      p.issued_at = LinkkeysLocalRp::Timeutil.to_rfc3339(n - 7200)
      p.expires_at = LinkkeysLocalRp::Timeutil.to_rfc3339(n - 3600)
    end
    assert_raises(LinkkeysLocalRp::LocalRp::Error) { run_scenario(Scenario.new(mutate_payload: mutate, expected_requests: 2)) }
  end

  def test_dns_fingerprint_pin_mismatch_is_rejected
    # Fails during the TLS pin check (the fake IDP's real cert fingerprint
    # no longer matches the pinned set) -- either way it must never reach
    # a verified result.
    assert_raises(StandardError) { run_scenario(Scenario.new(dns_fingerprint_override: 'c' * 64, expected_requests: 1)) }
  end

  def test_revoked_signing_key_is_rejected
    mutate = ->(k) { k.revoked_at = LinkkeysLocalRp::Timeutil.to_rfc3339(Time.now.utc) }
    assert_raises(LinkkeysLocalRp::LocalRp::Error) { run_scenario(Scenario.new(mutate_domain_key: mutate, expected_requests: 2)) }
  end

  def test_tampered_claim_signature_is_rejected
    mutate = lambda do |c|
      next if c.signatures.empty?

      sig = c.signatures[0].signature.dup
      sig.setbyte(0, sig.getbyte(0) ^ 0xFF)
      c.signatures[0].signature = sig
    end
    assert_raises(LinkkeysLocalRp::Claims::Error) { run_scenario(Scenario.new(mutate_claim: mutate)) }
  end

  def test_certificate_revoked_signing_key_fails_completion
    # The fetched key entry for the callback-signing key carries NO
    # revoked_at of its own -- only the sibling-signed revocation
    # certificate (fetched via DomainKeys/get-revocations and APPLIED to
    # the trusted set) reveals it is dead. An SDK that skips the fetch, or
    # verifies the certificate without applying it, would incorrectly
    # complete this login.
    now = Time.now.utc
    sibling_seeds = [("\x0E" * 32).b, ("\x0F" * 32).b]
    siblings = sibling_seeds.each_with_index.map { |seed, i| sibling_key(seed, "sibling-key-#{i + 1}", now) }

    target = domain_public_key(now)
    revoked_at = LinkkeysLocalRp::Timeutil.to_rfc3339(now)
    signatures = sibling_seeds.zip(siblings).map do |seed, key|
      payload = LinkkeysLocalRp::Revocation.revocation_payload(target.key_id, target.fingerprint, revoked_at, USER_DOMAIN)
      sig = LinkkeysLocalRp::Crypto.sign_with_algorithm(LinkkeysLocalRp::Crypto::SigningAlgorithm::ED25519, payload, seed)
      LinkkeysLocalRp::Types::ClaimSignature.new(domain: USER_DOMAIN, signed_by_key_id: key.key_id, signature: sig)
    end
    cert = LinkkeysLocalRp::Types::RevocationCertificate.new(
      target_key_id: target.key_id, target_fingerprint: target.fingerprint, revoked_at: revoked_at, signatures: signatures
    )

    scenario = Scenario.new(
      extra_domain_keys: siblings,
      revocation_certs: [cert],
      # get-domain-keys + get-revocations, then envelope verification fails
      # (the callback-signing key has been dropped from the trusted set)
      # before ticket redemption is ever attempted.
      expected_requests: 2
    )
    assert_raises(LinkkeysLocalRp::LocalRp::Error) { run_scenario(scenario) }
  end

  # ---------------------------------------------------------------
  # Hostile-IDP tests (security review: FIX A/B) -- a fake IDP that has
  # already passed every prior check (valid domain keys, valid envelope
  # signature, valid claim signatures) but then lies at exactly one more
  # point in the flow. Each of these must fail closed.
  # ---------------------------------------------------------------

  def test_redemption_user_id_mismatch_is_rejected
    # (1) The ticket-redemption response claims a different user than the
    # signed callback payload named. A malicious/compromised IDP -- or a
    # compromise of only the unauthenticated ticket-redemption RPC leg --
    # must not be able to swap the completed identity this way.
    mutate = ->(r) { r.user_id = 'attacker-user' }
    assert_raises(LinkkeysLocalRp::Complete::IdentityMismatch) { run_scenario(Scenario.new(mutate_redemption: mutate)) }
  end

  def test_redemption_domain_mismatch_is_rejected
    # (1, domain variant) Same as above but for user_domain instead of
    # user_id.
    mutate = ->(r) { r.user_domain = 'attacker.test' }
    assert_raises(LinkkeysLocalRp::Complete::IdentityMismatch) { run_scenario(Scenario.new(mutate_redemption: mutate)) }
  end

  def test_claim_user_id_mismatch_is_rejected
    # (2) A claim with a cryptographically VALID signature (it was signed
    # for a different user_id from the start, not tampered with after
    # signing) that nonetheless doesn't match the signed callback payload's
    # user_id. Signature validity alone is not sufficient -- the subject
    # binding must also match, or a claim about one user could be replayed
    # as if it were another user's claim on the same domain.
    assert_raises(LinkkeysLocalRp::Complete::IdentityMismatch) { run_scenario(Scenario.new(claim_user_id: 'someone-else')) }
  end

  def test_required_claims_empty_is_rejected
    # (3) The login demanded a required claim (the default required set is
    # ["handle"]), but the IDP's redemption response comes back with no
    # claims at all. Must fail closed rather than silently completing an
    # under-claimed login.
    mutate = ->(r) { r.claims = [] }
    assert_raises(LinkkeysLocalRp::Complete::RequiredClaimsNotSatisfied) do
      run_scenario(Scenario.new(mutate_redemption: mutate))
    end
  end

  def test_required_claims_insufficient_is_rejected
    # (3, insufficient variant) The login required both "handle" and
    # "email", but the IDP only ever returns a "handle" claim. A partial
    # claim set must not be silently accepted as satisfying the
    # requirement.
    assert_raises(LinkkeysLocalRp::Complete::RequiredClaimsNotSatisfied) do
      run_scenario(Scenario.new(required_claims: %w[handle email]))
    end
  end

  def test_get_revocations_error_fails_closed
    # (4) The domain's get-revocations RPC returns a well-formed CSIL-RPC
    # error. Before the fix this was swallowed ("best-effort") and treated
    # as an empty revocation list; it must now be fatal -- we would rather
    # abort the login than proceed on a key set we couldn't confirm isn't
    # missing a revocation.
    assert_raises(LinkkeysLocalRp::Rpc::Error) do
      run_scenario(Scenario.new(revocations_behavior: 'error', expected_requests: 2))
    end
  end

  def test_get_revocations_dropped_connection_fails_closed
    # (4, drop variant) The domain's get-revocations call is dropped at the
    # transport level (connection closed with no response) rather than
    # answered with an explicit error. Must fail closed identically to an
    # explicit error reply.
    assert_raises(LinkkeysLocalRp::Rpc::Error) do
      run_scenario(Scenario.new(revocations_behavior: 'drop', expected_requests: 2))
    end
  end
end
