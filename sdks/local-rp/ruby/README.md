# linkkeys_local_rp (Ruby)

Ruby SDK for LinkKeys' **DNS-less local RP identity** mode — see
`dns-less-local-rp-design.md` at the repo root for the full design; this gem
implements its "SDK API Shape" section. It lets a locally installed app (a
LAN jukebox, a desktop tool, a self-hosted service with no public DNS) use
LinkKeys for login without running its own DNS-pinned relying party. The
app's identity is the fingerprint of a locally-generated signing key
(SSH-host-key style), not a domain.

Mirrors the Rust reference SDK (`sdks/local-rp/rust/`) and the Python SDK
(`sdks/local-rp/python/`) module-for-module — read the Rust crate's README
first if you want the fullest protocol picture; this one notes only where
Ruby differs.

**Zero gem dependencies.** Everything is built on Ruby's standard library:
the bundled `openssl` gem (Ed25519, X25519, AES-256-GCM, ChaCha20-Poly1305,
HKDF, SHA-256) and stdlib `resolv` (DNS TXT lookups). There is no csilgen
Ruby target yet, so the CSIL-RPC wire codec and framing are hand-written in
this gem — see "No generated code" below.

## Requirements

- **Ruby >= 3.1**, developed and tested against system Ruby **3.4.8**.
- **OpenSSL >= 1.1.1** linked into Ruby's `openssl` gem (needed for raw
  Ed25519/X25519 key import/export via `OpenSSL::PKey.new_raw_private_key`/
  `new_raw_public_key`/`#raw_public_key`, and for `chacha20-poly1305` cipher
  support). Tested against OpenSSL 3.6.1. Every crypto primitive this SDK
  uses was verified directly against `sdks/local-rp/conformance/`'s fixed
  test vectors (byte-exact plaintext/ciphertext/signature matches) before
  being relied on — see `lib/linkkeys_local_rp/crypto.rb`'s docs for the
  HKDF/AEAD details that make this portable.
- No external gems. `Gemfile`/`bundle` are unnecessary; `require
  "linkkeys_local_rp"` after adding `lib/` to `$LOAD_PATH` (or installing
  the gem) is enough.

## Package layout

```
sdks/local-rp/ruby/
  linkkeys_local_rp.gemspec
  lib/
    linkkeys_local_rp.rb        # public API surface (re-exports + top-level
                                 # helper methods)
    linkkeys_local_rp/
      version.rb
      cbor.rb                   # hand-written canonical/deterministic CBOR
                                 # codec -- see "No generated code" below
      types.rb                  # hand-written CBOR struct codecs for the
                                 # ~19 CSIL types this SDK touches (exact
                                 # wire field order verified against every
                                 # conformance fixture)
      identity.rb                # generate_local_rp_identity + byte
                                 # storage helpers
      begin.rb                   # begin_local_login
      act_as.rb                  # act-as grantee: begin_act_as,
                                 # complete_act_as_callback,
                                 # refresh_act_as_grant, present
      browser.rb                 # _linkkeys_apis https= discovery + browser
                                 # URL builder
      complete.rb                 # complete_local_login (the full
                                 # verification chain)
      local_rp.rb                  # pure protocol helpers (envelope
                                 # sign/verify, callback seal/open,
                                 # timestamp/expiration checks) -- mirrors
                                 # crates/liblinkkeys/src/local_rp.rs
      claims.rb                    # claim signature/revocation/expiry
                                 # verification -- mirrors
                                 # crates/liblinkkeys/src/claims.rs
      revocation.rb                 # sibling-signed key revocation
                                 # certificate verification + application
                                 # to the trusted key set -- mirrors
                                 # crates/liblinkkeys/src/revocation.rs
      crypto.rb                     # Ed25519/X25519/AEAD/HKDF/fingerprint
                                 # wrappers over the bundled `openssl` gem
      dns.rb                         # _linkkeys/_linkkeys_apis TXT
                                 # parsing, key pinning, the DnsResolver
                                 # duck-type seam + SystemDnsResolver
                                 # (stdlib Resolv::DNS)
      tls.rb                          # SPKI-fingerprint TLS pinning (the
                                 # trust anchor for every TCP peer this SDK
                                 # talks to)
      transport.rb                     # the TCP dial seam + AddressPolicy
      rpc.rb                            # hand-rolled CSIL-RPC framing +
                                 # fetch_domain_keys / redeem_claim_ticket /
                                 # refresh_act_as_grant
      url_params.rb                     # base64url-unpadded URL-parameter
                                 # helpers (named to avoid colliding with
                                 # Ruby's built-in `Encoding` class)
      timeutil.rb                        # RFC3339 parse/format shared by
                                 # every module
  test/
    test_helper.rb
    test_conformance_*.rb          # one file per conformance vector JSON
                                 # file
    test_flow.rb                    # fake-IDP end-to-end flow tests
    test_act_as.rb                  # act-as grantee vectors, begin, callback
    run_all.rb                       # loads and runs every test_*.rb file
```

## No generated code

CSIL types and the CSIL-RPC client are normally csilgen-generated for each
SDK language; **no csilgen Ruby target exists yet**. Per this task's
instructions, `lib/linkkeys_local_rp/cbor.rb` and `types.rb` hand-write the
minimal wire codec instead: a canonical/deterministic CBOR core (RFC 8949
§4.2.1 — map entries sorted by the bytewise lexicographic order of their
*encoded* keys, exactly mirroring the Java SDK's `Cbor.java` and the Rust
reference codec's baked-in field order) plus hand-written `to_cbor`/
`from_cbor` pairs for the ~19 struct types this SDK actually touches.
`lib/linkkeys_local_rp/rpc.rb` likewise hand-rolls the CSIL-RPC envelope +
4-byte-big-endian-length-prefixed TCP framing directly — the same approach
the Rust and Python reference SDKs take. (Historically the generated client
wrappers in other languages also passed a lowercased service name unusable
for the real wire; that csilgen defect has since been fixed, but no Ruby
generator target exists yet, so hand-rolling remains the Ruby path
regardless.)

Every byte-level construction here (envelope signature inputs, the callback
sealed box, revocation-certificate payloads, claim payloads, CBOR struct
field order, base64url encoding) was verified directly against
`sdks/local-rp/conformance/`'s fixed test vectors before being relied on
elsewhere in this SDK — see the test suite.

A request for a csilgen Ruby target has been filed at
`~/repos/catalystcommunity/csilgen/docs/csilgen-requests/`.

## Quickstart

```ruby
require "linkkeys_local_rp"

# Once, at install/setup time -- persist the returned bytes with ordinary
# application-secret care.
identity = LinkkeysLocalRp.generate_local_rp_identity(
  LinkkeysLocalRp::Identity::GenerateLocalRpIdentityConfig.new(
    app_name: "My LAN Jukebox", now: Time.now.utc
  )
)
stored_bytes = LinkkeysLocalRp.local_rp_identity_to_bytes(identity)

# Later, per login attempt:
identity = LinkkeysLocalRp.local_rp_identity_from_bytes(stored_bytes)
redirect, pending = LinkkeysLocalRp.begin_local_login(
  LinkkeysLocalRp::Begin::BeginLocalLoginConfig.new(
    key_material: identity,
    callback_url: "http://jukebox.lan:8080/auth/callback",
    user_domain: "alice@example.com",
    now: Time.now.utc
    # dns: my_dns_resolver  # optional; defaults to Dns::SystemDnsResolver.new
  )
)
# App: persist `pending` (e.g. pending.to_h into a session), then redirect
# the browser to redirect.redirect_url.

# On callback (app's HTTP handler received `arrived_url` with an
# `encrypted_token=` query parameter):
verified = LinkkeysLocalRp.complete_local_login(
  identity, pending, encrypted_token, arrived_url, Time.now.utc
)
# verified.user_id, verified.user_domain, verified.claims, ... -- session
# creation, local user records, and authorization are all the app's own
# responsibility.
```

## App developer responsibilities

- **Key material**: persist the bytes from `local_rp_identity_to_bytes`
  with ordinary application-secret care (same tier as a database credential
  or API key) — see `Identity` module docs. The private key fields don't
  directly identify a user, but they control this app's entire local RP
  identity.
- **`PendingLogin`**: persist it (e.g. via `.to_h`/`.from_h`, which
  hex-encodes the byte fields for JSON-safety) between `begin_local_login`
  and `complete_local_login`, and discard it after one completion attempt.
  This gem owns no storage and cannot enforce single-use itself.
- **Sessions, local user records, authorization**: entirely the app's. This
  gem returns verified protocol facts (`VerifiedLocalLogin`); it never
  creates a session or writes to an app database.
- **Transport/DNS seams**: `LinkkeysLocalRp::Transport::StdTransport` and
  `LinkkeysLocalRp::Dns::SystemDnsResolver` are the defaults, but
  `complete_local_login` accepts any duck-typed `transport:`/`dns:` object
  responding to `#dial(host_port) -> socket-like` /
  `#txt_lookup(name) -> Array<String>` respectively — inject your own for
  testing or hardened DNS (e.g. a DoH client).

## Browser endpoint discovery

`begin_local_login` does one DNS TXT lookup of `_linkkeys_apis.<domain>`
(the identity domain). The `https=` value of the first valid `v=lk1` record
names the browser-facing host. The redirect URL uses that host. A path
prefix in the `https=` value is kept. The identity domain stays in
`pending.user_domain`. Verification binds to the identity domain, never to
the discovered host.

Pass `dns:` to inject a resolver object that responds to
`txt_lookup(name) -> Array<String>`. Omit it to use
`Dns::SystemDnsResolver.new`.

The lookup never fails the call. The redirect falls back to
`https://<domain>` when:

- the DNS lookup fails,
- no valid record has an `https=` value, or
- the discovered base is not valid (not `https`, no host, or it carries
  userinfo, a query, or a fragment).

The helpers are exported for regular-RP glue too:
`LinkkeysLocalRp.resolve_browser_base(dns, identity_domain)` returns the
base, and `LinkkeysLocalRp.build_browser_endpoint(base, route,
signed_request)` builds the URL for `Browser::BROWSER_ROUTE_LOCAL_RP` or
`Browser::BROWSER_ROUTE_AUTHORIZE`.

## Act-as grants

An act-as grant lets this app act as a user at an enrolled application (the
audience). The user approves the grant at the user's home domain. The home
domain signs it. The protocol is in
[`docs/spec/reserved/act-as-grants.md`](../../../docs/spec/reserved/act-as-grants.md).
It is Reserved and can change.

A local RP can be a grantee only. A local RP can be a grantee only after its
home domain approved it. A local RP cannot be an audience, because a peer
cannot find its keys through DNS.

The descriptor signing key signs every request and presentation. The proof
carries the signed descriptor. The act-as types are hand-written in
`types.rb`. The conformance vectors in
`sdks/regular-rp/conformance/act_as_grantee_signing.json` check their bytes.

1. Get the audience's `SignedActAsScopeSet` as CBOR bytes. The format of
   that exchange is between this app and the audience.
2. Call `LinkkeysLocalRp.begin_act_as(ActAs::BeginActAsConfig.new(
   key_material:, user_domain:, scope_set:, callback_url:, now:))`.
   Optional fields: `requested_lifetime_seconds`,
   `requested_renewal_window_seconds`, `dns`, and `request_window_seconds`
   (default 300, maximum 900). It returns `[redirect, pending]`. Keep
   `pending` (`to_h` / `from_h`). Send the browser to
   `redirect.redirect_url`. Browser endpoint discovery and its fallback are
   the same as for `begin_local_login`. The route is `/auth/act-as`.
3. On the callback, call
   `LinkkeysLocalRp.complete_act_as_callback(pending, arrived_url)`. It
   compares the `nonce` in constant time and returns `act_as_grant_id`. Use
   `pending` one time only.
4. Call `LinkkeysLocalRp.refresh_act_as_grant(key_material,
   pending.user_domain, grant_id, now)` to get the grant. It calls
   `ActAs/refresh-grant` over the same pinned TCP path as claim-ticket
   redemption. It returns `grant` and `signed`. Call it again when less than
   half of the grant's life remains.
5. For each call to the audience, call
   `LinkkeysLocalRp.present_act_as(grant, audience, request_digest, now,
   nonce, key_material)`. Send `credential_cbor` with the call. The audience
   defines `request_digest`. Use a new random `nonce` for each call.

The SDK does not verify the grant. The audience verifies it.

## Security notes

- Revoking this local RP identity at the IDP kills future logins **and**
  any outstanding claim tickets immediately — but it does **not** reach
  into sessions the app already minted from a prior successful login.
- Key rotation is not supported as a continuity operation: generating a new
  identity means a new fingerprint and re-approval at every LinkKeys
  domain.
- Domain keys fetched over the network are only ever trusted after DNS
  `fp=` pinning (`Rpc` module) — an unpinned/unauthenticated key can never
  reach the verification chain. TLS to the CSIL-RPC TCP port is pinned by
  SPKI Ed25519-public-key fingerprint only (`Tls` module,
  `OpenSSL::SSL::VERIFY_NONE` + a mandatory manual post-handshake pin
  check) — there is no WebPKI/CA-chain trust involved anywhere in this SDK.
- The default DNS resolver is the OS-configured system resolver via stdlib
  `Resolv::DNS`; LAN resolver spoofing is an accepted, documented tradeoff
  for this mode (design doc, "Decided"). Inject a hardened `dns:` object if
  your deployment needs more.
- `Transport::StdTransport`'s default `AddressPolicy` is **permissive**
  (will dial loopback/private/LAN addresses) — this is deliberate, not a
  bug: connecting from a LAN box to wherever `_linkkeys_apis` points is the
  entire point of this mode. `AddressPolicy::PUBLIC_ONLY` is available as
  an opt-in for integrators who want the stricter posture.
- Error messages never include private key material, nonces, tickets,
  session tokens, or claim values — only lengths, class names, and
  non-sensitive identifiers (domain names, key ids, hostnames).
- Every "current time" is an explicit `now:`/`now` parameter threaded
  through the whole call chain, never read from the system clock inside
  the pure protocol layer (`local_rp.rb`, `claims.rb`) — the one documented
  exception is `Revocation.count_valid_signers`'s sibling-key-validity
  check, which defaults to wall-clock time (with a test-only override)
  because that check is inherently "is this key valid *right now*," not a
  value being verified against a caller-supplied instant.

## Running the tests

```sh
cd sdks/local-rp/ruby
ruby -Ilib -Itest test/run_all.rb
```

Or run an individual conformance/flow file directly, e.g.:

```sh
ruby -Ilib -Itest test/test_flow.rb
```

The test suite loads `sdks/local-rp/conformance/*.json` directly (all eight
files) and additionally spins up a real loopback TCP+TLS "fake IDP" server
(`test/test_flow.rb`, mirroring the Python/Rust reference suites'
`test_flow.py`/`flow.rs`) to exercise `complete_local_login`'s full
verification chain end to end — DNS-pinned TLS handshake, CSIL-RPC framing,
domain-key fetch, revocation fetch/application, and ticket redemption
included — against a throwaway Ed25519 domain identity, not a real
LinkKeys deployment.

No `rake`/`bundler`/gemspec-declared test framework is required: `minitest`
ships with system Ruby (`minitest/autorun` from the standard distribution),
so `ruby -Ilib -Itest test/run_all.rb` is the complete, dependency-free test
command.
