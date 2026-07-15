# Accepting regular (DNS-pinned) LinkKeys logins from Ruby

This document is for a Ruby app developer who wants to let users log in with
**any** LinkKeys identity provider on the internet — the normal, DNS-pinned
protocol flow. That is **not** what the `linkkeys_local_rp` gem in this
directory implements. See "local-RP vs regular-RP" near the end before you
start copying code from here.

## Architecture: your app never touches a private key

A regular LinkKeys login needs a relying-party (RP) server that holds a
LinkKeys **domain key** — it signs outbound auth requests and decrypts the
tokens that come back. Your Ruby app is not supposed to hold that key
itself. Instead you run a second, small deployment: the same `linkkeys`
server binary as any identity provider, just configured in RP mode (no login
UI, no human user accounts, `rp.enabled: true`). Your app talks to *that*
server over the network, authenticated with a plain API key, and never sees
a private key. See `docs/DEPLOYING-RP.md` for the full deployment (Helm
chart, values, gateway TLS passthrough) — this document picks up once that
RP server is running and focuses on the Ruby side.

```
 Browser                Your Ruby App            Your RP server           Identity Provider
    |                         |                         |                         |
    |--- log in with -------->|                         |                         |
    |    you@idp.example      |-- Rp/sign-request ----->|                         |
    |                         |<--- signed_request ------|                         |
    |<--- redirect to ------- |                         |                         |
    |     idp /auth/authorize |                         |                         |
    |------------------------------------- user authenticates at the IDP -------->|
    |<--------------------------------------------- redirect to your /callback ---|
    |    ?encrypted_token=...                            |                         |
    |--- GET /callback ------>|                         |                         |
    |                         |-- Rp/decrypt-token ----->|                         |
    |                         |<--- signed_assertion ----|                         |
    |                         |-- Rp/verify-assertion -->|-- verifies vs IDP's --->|
    |                         |<--- verified assertion --|    published keys       |
    |                         |-- Rp/userinfo-fetch ---->|-- redeems claims ------>|
    |                         |<--- UserInfo -------------|                         |
    |<--- session cookie -----|                         |                         |
```

Your RP server is itself a full participant in the DNS-pinned trust model
(it has its own `_linkkeys`/`_linkkeys_apis` TXT records), and your app's
connection *to* it is pinned the same way every other LinkKeys TCP peer
connection is: by the RP server's own DNS-published key fingerprints, not by
a certificate authority.

## Prerequisites

1. **Deploy your RP server.** Follow `docs/DEPLOYING-RP.md`. You need its
   TCP endpoint (`tcpPort`, default `4987`) reachable from your app.

2. **Initialize domain keys and create a service account for your app**,
   inside the RP server:

   ```sh
   linkkeys domain init
   linkkeys user create my-webapp "My Web Application" --api-key --relation api_access
   # Save the printed API key -- it will not be shown again.
   ```

   `--relation api_access` grants the `api_access` relation at creation
   time. If you forgot it, or need to grant it to an already-existing
   service account, use the standalone grant command instead (DB-direct,
   idempotent, run where the RP server's database lives — `deploy/live.sh`
   uses this same command for live deployments):

   ```sh
   linkkeys relation grant-local my-webapp api_access
   ```

   This is not optional and not automatic. Every `Rp` operation your app
   calls below requires the caller's API key to carry the dedicated
   `api_access` relation on the RP's domain (SEC-06) — a valid API key
   alone is rejected with `Forbidden`. Confirmed directly in the source:
   `crates/linkkeys/src/services/authorization.rs`'s
   `required_relation_for_op` maps `"Rp" => Some(RELATION_API_ACCESS)`
   (`RELATION_API_ACCESS = "api_access"`), enforced by
   `crates/linkkeys/src/tcp/mod.rs`'s dispatch before any `Rp` op runs, and
   the CLI's `GrantLocal` subcommand (`crates/linkkeys/src/cli/mod.rs`) is
   what `linkkeys relation grant-local` runs.

3. **Check DNS** for your RP server's own domain:

   ```sh
   linkkeys domain dns-check
   ```

   This prints the `_linkkeys` TXT record (`fp=` fingerprints — pin these
   in your app's config below) and the `_linkkeys_apis` TXT record
   (`tcp=`/`https=`) it expects to find published. Publish them. Your app
   pins to the `fp=` values directly (as a small fixed list in
   configuration, the same way you'd pin a certificate's public key) — it
   does not need to re-resolve DNS on every call, though it's free to.

4. **Your app needs no DNS entries of its own** for this flow beyond a
   reachable `callback_url` the identity provider's browser redirect can
   reach.

## The login flow, wire-level

Everything below is **TCP CSIL-RPC only** (`csil/linkkeys.csil`'s `Rp`
service) — never HTTP. `docs/DEPLOYING-RP.md`'s "Web App Integration"
section is accurate on this point: the old `POST /v1alpha/*.json` HTTP
routes were removed when server-to-server traffic moved to TCP, and the
generic HTTP CBOR-RPC carrier (`POST /csil/v1/rpc`) explicitly rejects
`verify-assertion`/`userinfo-fetch` because it runs inside an async runtime
with no outbound server-to-server context — only the TCP carrier has that.
`demoappsite/src/main.rs`, the checked-in Rust reference RP web app, bears
this out: its `rp_call` helper drives everything through
`linkkeys_rpc_client::send_request(..., "Rp", op, payload, Some(&api_key))`
and contains no HTTP calls to its RP server at all.

```
service Rp {
    sign-request:      RpSignRequest      -> RpSignResponse,
    decrypt-token:      RpDecryptRequest   -> RpDecryptResponse,
    verify-assertion:   RpVerifyRequest    -> RpVerifyResponse,
    userinfo-fetch:     RpUserInfoRequest  -> UserInfo,
    issue-attestation:  RpIssueAttestationRequest -> RpIssueAttestationResponse
}
```

1. **`Rp/sign-request`** `{callback_url, nonce, requested_claims?}` →
   `{signed_request}`. Your app generates a fresh `nonce` and calls this
   before ever redirecting the browser.
2. **Redirect the browser** to
   `https://<user's chosen domain>/auth/authorize?...&signed_request=<...>`
   (`user_hint=` is optional — a login-form-prefill hint, not a trust
   input).
3. The identity provider authenticates the user and redirects the browser
   back to your `callback_url` with `?encrypted_token=<...>`.
4. **`Rp/decrypt-token`** `{encrypted_token}` → `{signed_assertion}`.
5. **`Rp/verify-assertion`** `{signed_assertion, expected_domain}` →
   `{assertion, verified}`. `expected_domain` is the domain your app
   expected to authenticate against — the one you asked the user for at
   step 1 — checked against the assertion's own `domain` field on the
   server side. Your app must additionally check `assertion.nonce` against
   the nonce it generated at step 1 and `assertion.domain` against the same
   `expected_domain` — the server verifies the assertion is cryptographically
   genuine, not that it's the *specific* login attempt your app started.
   **Nonce single-use is your app's job entirely**, not the wire protocol's
   — see "App responsibilities" below.
6. **`Rp/userinfo-fetch`** (optional) `{token, api_base, domain}` → claims.
   `token` is the `signed_assertion` string from step 4; `api_base` and
   `domain` identify the issuing IDP (the RP server redeems the claims from
   there — it holds the domain key needed to prove it's the assertion's
   audience, your app does not).

**The trap to know about:** every `Rp` call's CSIL-RPC request envelope
carries your API key in its `auth` field
(`crates/csilgen-transport/src/rpc.rs`'s `RpcRequest.auth`) as the **raw
key string** — no `Bearer ` prefix. That convention belongs to the
remaining HTTP surfaces (`Authorization: Bearer <key>`), not this one. Send
`Bearer lk_...` here and authentication fails outright.

## Complete Ruby walkthrough

There's no packaged regular-RP client for Ruby — the `linkkeys_local_rp`
gem in this directory implements the *different*, DNS-less local-RP mode
(see "local-RP vs regular-RP" below). What follows builds a small RP client
directly, reusing this gem's canonical CBOR codec, TLS pinning, TCP
transport, DNS TXT parsing, and its already-hand-written `Claim`/
`ClaimSignature` struct codecs (all of which are protocol-mode-agnostic),
and hand-writing only the `Rp`-service-specific CSIL types and the envelope
framing this gem's own `Rpc` module doesn't expose (its frame/envelope
helpers are `private_class_method` and never send an `auth` field, because
the local-RP protocol they serve never authenticates with an API key).

Everything below that doesn't require a live RP server + IDP — CBOR/struct
round trips, envelope construction (including the raw-key `auth` field),
redirect-URL construction, the signed auth-state cookie, and the
nonce-replay/single-use logic, including running the actual HTTP handler
functions against fake sockets — was really executed with system Ruby
3.4.8 while writing this document. See "What actually ran" at the end of
this section.

### `rp_client.rb` — the reusable glue

```ruby
# frozen_string_literal: true

# A minimal regular-RP client: talks TCP CSIL-RPC to your OWN RP server,
# authenticated with an API key. This is NOT part of the linkkeys_local_rp
# gem -- that gem implements the different, DNS-less local-RP mode. Every
# `require` below pulls in genuine gem plumbing (Cbor, Tls, Transport, Dns,
# Rpc::MAX_FRAME_SIZE, Types::Claim/ClaimSignature) that is protocol-mode
# agnostic; only the envelope framing with an `auth` field is inlined here,
# because LinkkeysLocalRp::Rpc's own frame/envelope helpers are
# private_class_method and have no `auth` field -- the local-RP protocol
# they serve never authenticates with an API key.
require 'linkkeys_local_rp/cbor'
require 'linkkeys_local_rp/types'
require 'linkkeys_local_rp/tls'
require 'linkkeys_local_rp/transport'
require 'linkkeys_local_rp/dns'
require 'linkkeys_local_rp/rpc' # only for MAX_FRAME_SIZE

require 'securerandom'
require 'uri'

module RegularRp
  Cbor = LinkkeysLocalRp::Cbor
  CSIL_RPC_VERSION = 1
  TAG_ENCODED_CBOR = 24

  class RpCallError < StandardError; end

  RpConfig = Struct.new(
    :tcp_addr,        # "host:port" of YOUR RP server, e.g. "127.0.0.1:4987"
    :fingerprints,     # Array<String> -- fp= values from `linkkeys domain dns-check`
    :api_key,          # your service account's API key (must hold api_access)
    :domain,           # your RP's own domain, sent as relying_party=
    :required_claims,  # Array<String> claim_types your app treats as mandatory
    keyword_init: true
  )

  # ---------------------------------------------------------------
  # Hand-written CBOR codecs for the CSIL types the `Rp` service uses.
  # These are NOT in linkkeys_local_rp/types.rb (that file only covers the
  # local-RP flow's own types) -- written directly from csil/linkkeys.csil's
  # "Relying Party (Rp) helper Types" and "Identity Assertions" sections.
  # Map key ORDER below does not affect the wire bytes: Cbor.encode always
  # sorts a Hash's entries by the bytewise order of their *encoded* keys
  # (RFC 8949 canonical form), so this only needs the right keys and shapes.
  # Claim/ClaimSignature are reused as-is from linkkeys_local_rp/types.rb --
  # UserInfo.claims is exactly a `[* Claim]` per csil/linkkeys.csil, the same
  # Claim shape the local-RP ticket-redemption response already carries.
  # ---------------------------------------------------------------
  module Types
    Claim = LinkkeysLocalRp::Types::Claim
    ClaimSignature = LinkkeysLocalRp::Types::ClaimSignature

    RequestedClaim = Struct.new(:claim_type, :datatype, keyword_init: true) do
      def self.to_map(v) = { 'claim_type' => v.claim_type, 'datatype' => v.datatype }
      def self.from_map(t) = new(claim_type: t['claim_type'], datatype: t['datatype'])
      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    ClaimRequest = Struct.new(:required, :optional, keyword_init: true) do
      def self.to_map(v)
        {
          'required' => v.required.map { |r| RequestedClaim.to_map(r) },
          'optional' => v.optional.map { |r| RequestedClaim.to_map(r) }
        }
      end

      def self.from_map(t)
        new(
          required: t['required'].map { |r| RequestedClaim.from_map(r) },
          optional: t['optional'].map { |r| RequestedClaim.from_map(r) }
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    RpSignRequest = Struct.new(:callback_url, :nonce, :requested_claims, keyword_init: true) do
      def self.to_map(v)
        m = { 'callback_url' => v.callback_url, 'nonce' => v.nonce }
        m['requested_claims'] = ClaimRequest.to_map(v.requested_claims) unless v.requested_claims.nil?
        m
      end

      def self.from_map(t)
        new(
          callback_url: t['callback_url'],
          nonce: t['nonce'],
          requested_claims: t['requested_claims'] && ClaimRequest.from_map(t['requested_claims'])
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    RpSignResponse = Struct.new(:signed_request, keyword_init: true) do
      def self.to_map(v) = { 'signed_request' => v.signed_request }
      def self.from_map(t) = new(signed_request: t['signed_request'])
      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    RpDecryptRequest = Struct.new(:encrypted_token, keyword_init: true) do
      def self.to_map(v) = { 'encrypted_token' => v.encrypted_token }
      def self.from_map(t) = new(encrypted_token: t['encrypted_token'])
      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    RpDecryptResponse = Struct.new(:signed_assertion, keyword_init: true) do
      def self.to_map(v) = { 'signed_assertion' => v.signed_assertion }
      def self.from_map(t) = new(signed_assertion: t['signed_assertion'])
      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    RpVerifyRequest = Struct.new(:signed_assertion, :expected_domain, keyword_init: true) do
      def self.to_map(v) = { 'signed_assertion' => v.signed_assertion, 'expected_domain' => v.expected_domain }
      def self.from_map(t) = new(signed_assertion: t['signed_assertion'], expected_domain: t['expected_domain'])
      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    IdentityAssertion = Struct.new(
      :user_id, :domain, :audience, :nonce, :issued_at, :expires_at,
      :authorized_claims, :display_name,
      keyword_init: true
    ) do
      def self.to_map(v)
        m = {
          'user_id' => v.user_id, 'domain' => v.domain, 'audience' => v.audience,
          'nonce' => v.nonce, 'issued_at' => v.issued_at, 'expires_at' => v.expires_at,
          'authorized_claims' => v.authorized_claims
        }
        m['display_name'] = v.display_name unless v.display_name.nil?
        m
      end

      def self.from_map(t)
        new(
          user_id: t['user_id'], domain: t['domain'], audience: t['audience'],
          nonce: t['nonce'], issued_at: t['issued_at'], expires_at: t['expires_at'],
          authorized_claims: t['authorized_claims'], display_name: t['display_name']
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    RpVerifyResponse = Struct.new(:assertion, :verified, keyword_init: true) do
      def self.to_map(v) = { 'assertion' => IdentityAssertion.to_map(v.assertion), 'verified' => v.verified }

      def self.from_map(t)
        new(assertion: IdentityAssertion.from_map(t['assertion']), verified: t['verified'])
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    RpUserInfoRequest = Struct.new(:token, :api_base, :domain, keyword_init: true) do
      def self.to_map(v) = { 'token' => v.token, 'api_base' => v.api_base, 'domain' => v.domain }
      def self.from_map(t) = new(token: t['token'], api_base: t['api_base'], domain: t['domain'])
      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end

    UserInfo = Struct.new(:user_id, :domain, :display_name, :claims, keyword_init: true) do
      def self.to_map(v)
        {
          'user_id' => v.user_id, 'domain' => v.domain, 'display_name' => v.display_name,
          'claims' => v.claims.map { |c| Claim.to_map(c) }
        }
      end

      def self.from_map(t)
        new(
          user_id: t['user_id'], domain: t['domain'], display_name: t['display_name'],
          claims: t['claims'].map { |c| Claim.from_map(c) }
        )
      end

      def to_cbor = Cbor.encode(self.class.to_map(self))
      def self.from_cbor(data) = from_map(Cbor.decode(data))
    end
  end

  # ---------------------------------------------------------------
  # CSIL-RPC envelope framing, WITH the `auth` field the `Rp` service
  # requires (crates/csilgen-transport/src/rpc.rs's RpcRequest.auth). Note
  # the trap: this is the RAW API key, no "Bearer " prefix -- that
  # convention belongs to the HTTP surfaces this SDK does not use.
  # ---------------------------------------------------------------
  module_function

  def build_request_envelope(op, payload_bytes, api_key)
    envelope = {
      'v' => CSIL_RPC_VERSION,
      'service' => 'Rp',
      'op' => op,
      'payload' => Cbor::CborTag.new(TAG_ENCODED_CBOR, payload_bytes),
      'auth' => api_key
    }
    Cbor.encode(envelope)
  end

  def parse_response_envelope(response_bytes)
    envelope = Cbor.decode(response_bytes)
    status = envelope['status']
    raise RpCallError, "server error (status=#{status}): #{envelope['error']}" unless status == 0

    payload_tag = envelope['payload']
    payload_tag.is_a?(Cbor::CborTag) ? payload_tag.value : ''.b
  end

  def send_frame(sock, data)
    sock.write([data.bytesize].pack('N'))
    sock.write(data)
  end

  def recv_exact(sock, n)
    chunks = []
    remaining = n
    while remaining.positive?
      chunk = sock.read(remaining)
      raise RpCallError, 'connection closed before expected bytes were received' if chunk.nil? || chunk.empty?

      chunks << chunk
      remaining -= chunk.bytesize
    end
    chunks.join
  end

  def recv_frame(sock)
    max = LinkkeysLocalRp::Rpc::MAX_FRAME_SIZE
    length = recv_exact(sock, 4).unpack1('N')
    raise RpCallError, "peer frame too large (#{length} bytes, max #{max})" if length > max

    recv_exact(sock, length)
  end

  # Call one `Rp/<op>` on your RP server: TLS-pinned to its published
  # fingerprints (LinkkeysLocalRp::Tls, the same SPKI-fingerprint pinning
  # every LinkKeys TCP peer uses), authenticated with your app's API key.
  # No client certificate is presented -- your app holds no domain key.
  def rp_call(rp_config, op, req_struct, response_class)
    transport = LinkkeysLocalRp::Transport::StdTransport.new
    raw_sock = transport.dial(rp_config.tcp_addr)
    hostname = LinkkeysLocalRp::Tls.extract_hostname(rp_config.tcp_addr)
    tls_sock = LinkkeysLocalRp::Tls.dial_tls_pinned(raw_sock, hostname, rp_config.fingerprints)
    begin
      request_bytes = build_request_envelope(op, req_struct.to_cbor, rp_config.api_key)
      send_frame(tls_sock, request_bytes)
      response_bytes = recv_frame(tls_sock)
      payload = parse_response_envelope(response_bytes)
      response_class.from_cbor(payload)
    ensure
      tls_sock.close
    end
  end

  # Look up the IDP's own `_linkkeys_apis` TXT record for its `https=` base
  # URL; fall back to `https://<domain>` if there is none (matching the Rust
  # reference RP client, `demoappsite/src/main.rs`'s `resolve_api_base`).
  def resolve_api_base(domain, dns_resolver = LinkkeysLocalRp::Dns::SystemDnsResolver.new)
    name = LinkkeysLocalRp::Dns.linkkeys_apis_dns_name(domain)
    begin
      dns_resolver.txt_lookup(name).each do |txt|
        apis = begin
          LinkkeysLocalRp::Dns.parse_linkkeys_apis_txt(txt)
        rescue LinkkeysLocalRp::Dns::DnsParseError
          next
        end
        return apis.https_base if apis.https_base
      end
    rescue StandardError
      nil # fall through to the direct fallback below
    end
    "https://#{domain}"
  end

  def default_claim_request
    Types::ClaimRequest.new(
      required: [Types::RequestedClaim.new(claim_type: 'display_name', datatype: 'text')],
      optional: [Types::RequestedClaim.new(claim_type: 'email', datatype: 'email')]
    )
  end

  def build_authorize_redirect(rp_config, api_base, callback_url, nonce, signed_request, user_hint)
    query = URI.encode_www_form(
      'callback_url' => callback_url,
      'nonce' => nonce,
      'user_hint' => user_hint || '',
      'relying_party' => rp_config.domain,
      'signed_request' => signed_request
    )
    "#{api_base}/auth/authorize?#{query}"
  end

  # Returns [redirect_url, pending]. `pending` must be carried across the
  # redirect round trip (see AuthState below) and consumed exactly once by
  # complete_login.
  def begin_login(rp_config, callback_url, user_domain, user_hint: nil)
    nonce = SecureRandom.uuid
    sign_resp = rp_call(
      rp_config, 'sign-request',
      Types::RpSignRequest.new(callback_url: callback_url, nonce: nonce, requested_claims: default_claim_request),
      Types::RpSignResponse
    )
    api_base = resolve_api_base(user_domain)
    redirect_url = build_authorize_redirect(rp_config, api_base, callback_url, nonce, sign_resp.signed_request, user_hint)
    pending = { 'nonce' => nonce, 'domain' => user_domain, 'api_base' => api_base }
    [redirect_url, pending]
  end

  # `pending` is whatever `begin_login` returned. The caller must have
  # retrieved-and-invalidated it exactly once before calling this (see
  # AuthState's nonce single-use store) -- this method itself performs the
  # nonce/domain equality checks against the verified assertion, but does
  # NOT track replay across calls; that is the app's job.
  def complete_login(rp_config, pending, encrypted_token)
    decrypt_resp = rp_call(
      rp_config, 'decrypt-token',
      Types::RpDecryptRequest.new(encrypted_token: encrypted_token),
      Types::RpDecryptResponse
    )
    verify_resp = rp_call(
      rp_config, 'verify-assertion',
      Types::RpVerifyRequest.new(signed_assertion: decrypt_resp.signed_assertion, expected_domain: pending['domain']),
      Types::RpVerifyResponse
    )
    raise RpCallError, 'assertion did not verify' unless verify_resp.verified

    assertion = verify_resp.assertion
    raise RpCallError, 'nonce mismatch -- possible replay attack' if assertion.nonce != pending['nonce']
    raise RpCallError, 'domain mismatch' if assertion.domain != pending['domain']

    rp_call(
      rp_config, 'userinfo-fetch',
      Types::RpUserInfoRequest.new(token: decrypt_resp.signed_assertion, api_base: pending['api_base'], domain: pending['domain']),
      Types::UserInfo
    )
  end
end
```

### `auth_state.rb` — the signed auth-state cookie + nonce single-use store

`demoappsite/src/main.rs` (the Rust reference RP) carries the pending
login's nonce/domain/api_base across the browser redirect round trip in
Rocket's *private* (encrypted+signed) cookie jar — that tamper-protection is
built into the framework. A plain Ruby `TCPServer` app has no such jar, so
this signs the cookie value by hand with HMAC-SHA256, and separately tracks
which nonces have already been redeemed so the same callback URL can't be
replayed:

```ruby
# frozen_string_literal: true

require 'openssl'
require 'json'
require 'securerandom'

# HMAC-signed auth-state cookie: carries `begin_login`'s `pending` hash
# (nonce/domain/api_base) across the browser redirect round trip without
# server-side session storage for THAT correlation step.
#
# This alone is NOT single-use -- a signed cookie can be replayed by
# resubmitting the same callback URL. Single-use is enforced separately by
# NonceStore below, which is what actually makes `complete_login`
# unreplayable.
module AuthState
  class TamperedState < StandardError; end
  class ExpiredState < StandardError; end

  # In a real deployment this key must be persisted (env var / secret
  # manager) and stable across process restarts -- a freshly generated key
  # invalidates every in-flight login on deploy. Generated here only because
  # this is a self-contained example.
  SECRET = ENV.fetch('AUTH_STATE_SECRET') { SecureRandom.random_bytes(32) }

  module_function

  def b64url(bytes) = [bytes].pack('m0').tr('+/', '-_').delete('=')

  def b64url_decode(str)
    padded = str.tr('-_', '+/')
    padded += '=' * ((4 - (padded.length % 4)) % 4)
    padded.unpack1('m0')
  end

  # `pending` is the Hash `RegularRp.begin_login` returned, plus an
  # `issued_at` timestamp this module adds for expiry.
  def sign(pending, now: Time.now.getutc)
    payload = JSON.generate(pending.merge('issued_at' => now.to_i))
    mac = OpenSSL::HMAC.digest('SHA256', SECRET, payload)
    "#{b64url(payload.b)}.#{b64url(mac)}"
  end

  # Verifies the HMAC (constant-time) and a max-age, then returns the
  # original pending Hash (with `issued_at` still present, ignorable by the
  # caller). Raises rather than returning nil/false so a caller can't
  # accidentally treat a tampered cookie as "no cookie".
  def verify(cookie_value, now: Time.now.getutc, max_age_seconds: 600)
    payload_b64, mac_b64 = cookie_value.split('.', 2)
    raise TamperedState, 'malformed auth-state cookie' if payload_b64.nil? || mac_b64.nil?

    payload = b64url_decode(payload_b64)
    expected_mac = OpenSSL::HMAC.digest('SHA256', SECRET, payload)
    given_mac = b64url_decode(mac_b64)
    raise TamperedState, 'auth-state signature mismatch' unless OpenSSL.secure_compare(expected_mac, given_mac)

    pending = JSON.parse(payload)
    age = now.to_i - pending['issued_at'].to_i
    raise ExpiredState, 'auth-state cookie expired' if age.negative? || age > max_age_seconds

    pending
  rescue JSON::ParserError, ArgumentError
    raise TamperedState, 'auth-state cookie could not be decoded'
  end
end

# Server-side single-use tracking for nonces. A signed cookie proves the
# callback wasn't forged and wasn't tampered with; it does NOT prove the
# callback hasn't been replayed (the browser, a proxy log, or an attacker
# with the URL can resubmit it verbatim). This store is what turns "the
# assertion's nonce equals the nonce I generated" into "...and I have never
# accepted this nonce before" -- the actual single-use guarantee.
#
# In-memory + a single mutex is enough for one process; a real multi-worker
# deployment needs a shared store (Redis SETNX, a DB row with a unique
# index) with the same semantics: `claim!` must be atomic, and only the
# first caller for a given nonce may proceed.
class NonceStore
  def initialize
    @seen = {}
    @mutex = Mutex.new
  end

  # Returns true the first time `nonce` is claimed, false on every
  # subsequent call (replay). Also expires entries older than `ttl_seconds`
  # so the store doesn't grow without bound.
  def claim!(nonce, now: Time.now.getutc, ttl_seconds: 600)
    @mutex.synchronize do
      @seen.delete_if { |_, claimed_at| now.to_i - claimed_at > ttl_seconds }
      return false if @seen.key?(nonce)

      @seen[nonce] = now.to_i
      true
    end
  end
end
```

### `app.rb` — the HTTP handler pair

A `WEBrick`-or-Rack handler pair is the natural shape for this, but **this
system has neither installed** — `webrick` moved out of Ruby's default
gems after Ruby 3.0 and isn't present here (`gem list` shows no `webrick`,
`rack`, `sinatra`, or `puma`), so `require 'webrick'` fails outright. This
uses a small hand-rolled HTTP/1.1 handler directly over stdlib `TCPServer`
instead — one thread per connection, no gem dependency. A Sinatra/Rails/
Rack app looks structurally identical: two routes, same calls into
`RegularRp`.

```ruby
# frozen_string_literal: true

# app.rb -- the web app side. Run your RP server separately (see
# docs/DEPLOYING-RP.md) and set RP_TCP_ADDR / RP_FINGERPRINTS / RP_API_KEY /
# RP_DOMAIN before starting this.
#
# There is no WEBrick or Rack gem installed on this system (WEBrick moved
# out of Ruby's default gems after 3.0, and no Rack-based server is bundled
# either), so this is a small hand-rolled HTTP/1.1 handler directly over
# `TCPServer` -- fully stdlib, no gem dependency, one thread per connection.
# A Rails/Sinatra/Rack app looks structurally identical: two routes, same
# calls into RegularRp.

require 'socket'
require 'uri'
require 'securerandom'
require_relative 'rp_client'
require_relative 'auth_state'

NONCES = NonceStore.new
SESSIONS = {}
SESSIONS_MUTEX = Mutex.new

# ---- request parsing / response writing (no WEBrick/Rack available) ----

def parse_request_line(line)
  method, target, = line.split(' ')
  path, _, query_string = target.partition('?')
  query = query_string.empty? ? {} : URI.decode_www_form(query_string).to_h
  [method, path, query]
end

def read_headers(sock)
  headers = {}
  while (line = sock.gets)
    line = line.chomp("\r\n")
    break if line.empty?

    name, _, value = line.partition(':')
    headers[name.strip.downcase] = value.strip
  end
  headers
end

def read_cookie(headers, name)
  jar = headers['cookie']
  return nil if jar.nil?

  jar.split(';').each do |pair|
    k, _, v = pair.strip.partition('=')
    return v if k == name
  end
  nil
end

def write_response(sock, status, headers, body)
  sock.write "HTTP/1.1 #{status}\r\n"
  headers.each { |k, v| sock.write "#{k}: #{v}\r\n" }
  sock.write "Content-Length: #{body.bytesize}\r\n"
  sock.write "Connection: close\r\n\r\n"
  sock.write body
end

def redirect(sock, location, set_cookie: nil)
  headers = { 'Location' => location }
  headers['Set-Cookie'] = set_cookie if set_cookie
  write_response(sock, '302 Found', headers, '')
end

# ---- routes ----

def handle_login(sock, query, rp_config, callback_url)
  domain = query['domain'].to_s.strip
  if domain.empty?
    write_response(sock, '400 Bad Request', {}, '?domain=<identity provider domain> is required')
    return
  end

  redirect_url, pending = RegularRp.begin_login(rp_config, callback_url, domain)
  state_cookie = AuthState.sign(pending)
  redirect(sock, redirect_url, set_cookie: "auth_state=#{state_cookie}; HttpOnly; SameSite=Lax; Path=/")
rescue RegularRp::RpCallError => e
  write_response(sock, '502 Bad Gateway', {}, "Failed to contact RP service: #{e.message}")
end

def handle_callback(sock, query, headers, rp_config)
  raw_state = read_cookie(headers, 'auth_state')
  if raw_state.nil?
    write_response(sock, '400 Bad Request', {}, 'No auth state found -- login flow may have expired')
    return
  end

  pending = begin
    AuthState.verify(raw_state)
  rescue AuthState::TamperedState, AuthState::ExpiredState => e
    write_response(sock, '400 Bad Request', {}, "Invalid auth state: #{e.message}")
    return
  end

  # Single-use: claim the nonce BEFORE touching the RP server. A resubmitted
  # callback URL (same cookie, same query string replayed by a browser back
  # button, a proxy log, or an attacker) is rejected right here, even if the
  # assertion underneath would otherwise verify fine.
  unless NONCES.claim!(pending['nonce'])
    write_response(sock, '400 Bad Request', {}, 'This login has already been completed or has expired')
    return
  end

  encrypted_token = query['encrypted_token'].to_s
  if encrypted_token.empty?
    write_response(sock, '400 Bad Request', {}, 'Missing encrypted_token')
    return
  end

  user_info = RegularRp.complete_login(rp_config, pending, encrypted_token)

  missing = rp_config.required_claims - user_info.claims.map(&:claim_type)
  unless missing.empty?
    write_response(sock, '400 Bad Request', {}, "Required claims were not shared: #{missing.join(', ')}")
    return
  end

  session_id = SecureRandom.uuid
  SESSIONS_MUTEX.synchronize do
    SESSIONS[session_id] = {
      'user_id' => user_info.user_id,
      'domain' => user_info.domain,
      'display_name' => user_info.display_name,
      'claims' => user_info.claims.to_h { |c| [c.claim_type, c.claim_value] }
    }
  end
  redirect(sock, '/', set_cookie: "session_id=#{session_id}; HttpOnly; SameSite=Lax; Path=/")
rescue RegularRp::RpCallError => e
  write_response(sock, '400 Bad Request', {}, "Login failed: #{e.message}")
end

def handle_connection(sock, rp_config, callback_url)
  request_line = sock.gets
  return if request_line.nil?

  method, path, query = parse_request_line(request_line)
  headers = read_headers(sock)

  case [method, path]
  when ['GET', '/login'] then handle_login(sock, query, rp_config, callback_url)
  when ['GET', '/callback'] then handle_callback(sock, query, headers, rp_config)
  else write_response(sock, '404 Not Found', {}, 'not found')
  end
ensure
  sock.close
end

if $PROGRAM_NAME == __FILE__
  rp_config = RegularRp::RpConfig.new(
    tcp_addr: ENV.fetch('RP_TCP_ADDR', '127.0.0.1:4987'),
    fingerprints: ENV.fetch('RP_FINGERPRINTS', '').split(',').map(&:strip).reject(&:empty?),
    api_key: ENV.fetch('RP_API_KEY'),
    domain: ENV.fetch('RP_DOMAIN'),
    required_claims: ENV.fetch('REQUIRED_CLAIMS', 'display_name').split(',')
  )
  callback_url = ENV.fetch('CALLBACK_URL', 'http://localhost:8080/callback')

  server = TCPServer.new('0.0.0.0', (ENV['PORT'] || 8080).to_i)
  loop do
    client = server.accept
    Thread.new { handle_connection(client, rp_config, callback_url) }
  end
end
```

To run for real: `RP_TCP_ADDR=... RP_FINGERPRINTS=fp1,fp2,fp3 RP_API_KEY=... RP_DOMAIN=myapp.example.com ruby -I sdks/local-rp/ruby/lib app.rb` (the `-I` puts the gem's `lib/` on the load path so `require 'linkkeys_local_rp/...'` in `rp_client.rb` resolves without installing the gem).

### What actually ran

The socket/TLS parts of `rp_call` need a live RP server to exercise (there
is no fake-carrier seam exposed for this mode the way `dispatch_for_test`
is for the Rust server-side tests, and standing one up is outside a docs
task). Everything else above has no network dependency and was run for
real, with system Ruby 3.4.8, as `ruby -I sdks/local-rp/ruby/lib probe.rb`
against a scratch copy of the three files above plus a test script — 28
checks, all passing:

```
OK   RequestedClaim round-trip
OK   ClaimRequest round-trip
OK   RpSignRequest round-trip (with requested_claims)
OK   RpSignRequest round-trip (requested_claims omitted)
OK   RpSignResponse round-trip
OK   RpDecryptRequest/Response round-trip
OK   RpVerifyRequest round-trip
OK   IdentityAssertion + RpVerifyResponse round-trip (with display_name)
OK   IdentityAssertion round-trip (display_name omitted)
OK   RpUserInfoRequest round-trip
OK   UserInfo round-trip (reusing LinkkeysLocalRp::Types::Claim)
OK   envelope carries raw API key in `auth` (no Bearer prefix)
OK   parse_response_envelope: success status
OK   parse_response_envelope: error status raises RpCallError
OK   send_frame/recv_frame round trip over a StringIO-backed fake socket
OK   recv_frame rejects an oversized length prefix before reading
OK   build_authorize_redirect produces a well-formed URL with expected params
OK   build_authorize_redirect handles nil user_hint (empty string, not "nil")
OK   AuthState sign/verify round trip
OK   AuthState.verify rejects a tampered payload
OK   AuthState.verify rejects a malformed cookie (no dot separator)
OK   AuthState.verify rejects an expired cookie
OK   NonceStore#claim! is single-use: first true, replay false
OK   NonceStore#claim! expires old entries after ttl
OK   404 for an unknown route
OK   /login with empty domain -> 400, never reaches the network
OK   /callback with no auth_state cookie -> 400, never reaches the network
OK   /callback replay: second use of the same auth_state cookie is rejected before any network call
OK   /callback with a tampered auth_state cookie -> 400, never reaches the network

ALL CHECKS PASSED
```

In particular: every `Types` struct round-trips through CBOR
(`X.from_cbor(x.to_cbor) == x`, including the optional-field-omitted cases
for `requested_claims` and `display_name`); the request envelope was
decoded back apart to confirm `service == "Rp"`, `auth` equals the raw key
string with no `Bearer ` prefix, and `payload` is CBOR tag 24 wrapping a
correctly-round-tripping request; both a success-status and an
error-status response envelope were parsed, the latter confirmed to raise
`RpCallError` with the server's message intact; `send_frame`/`recv_frame`
were run against a `StringIO`-backed fake socket (a real byte-oriented I/O
object, just not a real network socket) for both a normal frame and an
oversized-length-prefix rejection; `build_authorize_redirect` was parsed
back with `URI`/`URI.decode_www_form` to confirm every expected query
parameter, including the `user_hint: nil` → empty-string case;
`AuthState.sign`/`.verify` round-tripped, and separately rejected a
payload with one substring tampered (still MACs internally-consistent
JSON, correctly caught as `TamperedState`), a cookie with no `.`
separator, and an expired cookie; `NonceStore#claim!` was shown to be
single-use (second call on the same nonce returns `false`) and to garbage
collect after its TTL; and `app.rb`'s actual `handle_connection` method was
called directly against `FakeSocket` objects (a `StringIO`-backed stand-in
implementing `#gets`/`#write`/`#close`) to drive real HTTP request text
through the real routing/parsing/cookie code for a 404, an empty-domain
`/login`, a cookie-less `/callback`, a **replayed** `/callback` (proving
the nonce-store rejection fires before any RP call would happen), and a
**tampered-cookie** `/callback` — all without opening a single real
network connection. No SDK code was modified to make any of this work.

## App responsibilities

This mirrors what every other LinkKeys SDK in this repo hands back to the
app (see this gem's own `README.md`, "App developer responsibilities"):

- **Nonce single-use.** The server does not track your nonces for you —
  `assertion.nonce == pending['nonce']` only proves the callback matches
  *a* login you started; it does not by itself stop the same callback URL
  from being replayed. `NonceStore#claim!` above is what actually enforces
  single-use: it's consulted (and the nonce marked used) *before*
  `complete_login` ever calls the RP server, so a second hit with the same
  cookie is rejected outright regardless of whether the underlying
  assertion would still verify. A single Ruby process's in-memory `Mutex`
  + `Hash` is enough for a demo; a real multi-worker/multi-process
  deployment needs a shared atomic store (Redis `SETNX`, a DB row with a
  unique index on the nonce) with the same "claim, don't just check"
  semantics.
- **The signed auth-state cookie is not itself single-use.** `AuthState`
  proves the cookie wasn't forged or tampered with (HMAC-SHA256,
  constant-time compare) and hasn't expired — it does not, by itself, stop
  replay. That's `NonceStore`'s job, deliberately kept as a separate
  concern: signing answers "is this genuinely mine and unmodified?",
  the nonce store answers "have I already redeemed this?".
- **Sessions.** `complete_login` returns verified protocol facts
  (`UserInfo`: `user_id`, `domain`, `display_name`, `claims`) and nothing
  else — it does not create a session, set a cookie, or touch a database.
  Building a local session/user record from those facts, and deciding how
  long it lives, is entirely your app's call. The in-memory `SESSIONS`
  hash in `app.rb` above is demo-only storage, lost on restart and not
  shared across processes — use a real session store for anything beyond
  a demo.
- **API key storage.** `RP_CONFIG.api_key` (`RpConfig#api_key`) is a bearer
  credential for your RP server's `Rp` service — anyone holding it can mint
  sign/decrypt/verify calls as your app (though not forge assertions
  outright; the RP server's own domain key is what actually signs/
  decrypts). Store it the same way you'd store a database credential:
  environment/secret manager, never committed, never logged. Never log the
  API key, `encrypted_token`, `signed_assertion`, `auth_state` cookie
  value, or claim values (AGENTS.md's "Error Handling": never log keys,
  claim values, session tokens, or credentials).
- **`AUTH_STATE_SECRET` storage.** Same tier as the API key — anyone
  holding it can forge `auth_state` cookies (though, again, not forge the
  underlying cryptographic assertion). It must also be **stable** across
  process restarts/redeploys, unlike the API key: generating a fresh one
  invalidates every login currently in flight.
- **Fingerprint pinning.** `RP_FINGERPRINTS` is your trust anchor for the
  connection to your own RP server. Rotate it whenever the RP server's
  signing keys rotate (re-run `linkkeys domain dns-check` and update your
  app's config) — an out-of-date fingerprint list means
  `Tls.dial_tls_pinned` starts refusing the connection outright (fails
  closed, not open).

## local-RP vs regular-RP

| | Local RP (`linkkeys_local_rp` gem, this directory) | Regular RP (this document) |
|---|---|---|
| App identity | A locally-generated Ed25519 key fingerprint (SSH-host-key style) | A DNS domain your app owns (or your RP server owns on its behalf) |
| DNS required | No | Yes — `_linkkeys` + `_linkkeys_apis` TXT records |
| Where keys live | In the app itself (`LinkkeysLocalRp.local_rp_identity_to_bytes`) | In a separate RP server process your app talks to over TCP |
| Admission | Explicit per-domain approval (`linkkeys local-rp approve <fingerprint>`) — pending until an admin approves | Ordinary DNS-pinned trust, same as any LinkKeys peer |
| Ruby support | This gem (`LinkkeysLocalRp.begin_local_login`/`complete_local_login`) | None packaged — hand-write the glue this document shows, reusing this gem's `Cbor`/`Tls`/`Transport`/`Dns`/`Types::Claim` modules |
| Best for | LAN tools, self-hosted apps with no public DNS, desktop apps | Any app that already has (or can get) a domain |

This document covers the **regular** flow: your app runs its own
DNS-pinned RP server, and users log in with identities on any LinkKeys
domain that publishes standard `_linkkeys`/`_linkkeys_apis` DNS records.
That's almost certainly what you want for a normal web app.

The `linkkeys_local_rp` gem that actually lives in this directory
(`sdks/local-rp/ruby/`) implements something different: **DNS-less local-RP
identity** (see `dns-less-local-rp-design.md` at the repo root, and
`docs/local-rp-app-developer-guide.md`, `docs/local-rp-operator-guide.md`,
`docs/local-rp-security-tradeoffs.md`, `docs/local-rp-key-lifecycle.md`).
That mode is for apps with **no public DNS at all** — a LAN jukebox, a
desktop tool, a self-hosted service on a home network — where the app's
identity is a locally-generated signing key fingerprint (SSH-host-key
style) rather than a domain, and it must be individually approved per
LinkKeys IDP before it can redeem claim tickets. It needs no RP server of
its own and never touches a domain key, but every IDP has to explicitly
trust its fingerprint first, and revoking that trust kills the app's
access to that IDP outright. Use it if you genuinely have no DNS name to
hang an RP server off of; otherwise use the flow in this document.
