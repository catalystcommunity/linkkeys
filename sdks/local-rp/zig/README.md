# linkkeys_local_rp (Zig)

Zig SDK for LinkKeys' **DNS-less local RP identity** mode — see
`dns-less-local-rp-design.md` at the repo root for the full design; this
module implements its "SDK API Shape" section. It lets a locally installed
app (a LAN jukebox, a desktop tool, a self-hosted service with no public
DNS) use LinkKeys for login without running its own DNS-pinned relying
party. The app's identity is the fingerprint of a locally-generated signing
key (SSH-host-key style), not a domain.

Module name: `linkkeys_local_rp` (see `build.zig`). Like the Go SDK, this is
a standalone package — there is no "liblinkkeys-zig"; this module *is* the
local-RP protocol implementation for Zig, reimplementing the pure
envelope/sealed-box/claims/revocation/DNS logic from
`crates/liblinkkeys/src/{local_rp,crypto,claims,revocation,dns,encoding}.rs`
directly (stdlib `std.crypto` only, zero dependencies), verified byte-for-byte
against the shared conformance vectors in `sdks/local-rp/conformance/`.

## Pinned Zig version

**Zig 0.14.1**, exactly the version `catalyst-tools` provides:

```sh
source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
```

`std.crypto` API names move between Zig versions (design doc, Language
Crypto Matrix, Zig row); this SDK's crypto mappings (`src/crypto.zig`) are
verified against 0.14.1's stdlib source specifically, not just "whatever
`zig` happens to be on `PATH`".

## Test command

```sh
cd sdks/local-rp/zig && zig build test
```

Runs, in one `test` step:

- in-source unit tests across every `src/*.zig` file (CBOR canonicalization,
  crypto primitive mappings, timestamp arithmetic, DNS TXT parsing, claim/
  revocation verification, and TLS SPKI pin-extraction against a real
  openssl-minted fixture)
- `tests/conformance.zig`: every vector in `sdks/local-rp/conformance/`
  (`keys.json`, `envelopes.json`, `callback_box.json`, `url_params.json`,
  `dns.json`, `tickets.json`, `expirations.json`, `revocations.json`),
  positive and negative cases, with the same case-count assertions the Go/
  Rust SDKs enforce (4 positive / 20 negative envelope cases, 2 positive /
  13 negative callback-box cases, 9 revocation-certificate cases, etc.)
- `tests/flow.zig`: `beginLocalLogin`/`completeLocalLogin` end to end
  against a fake IDP — see "TLS evaluation outcome" below for why this runs
  over a plaintext transport rather than real pinned TLS
- `tests/act_as.zig`: act-as grantee support. It checks the exact bytes in
  `sdks/regular-rp/conformance/act_as_grantee_signing.json` (case
  `local_rp_grantee`), `beginActAs` URL discovery and fallback, the
  callback nonce check, and `refreshActAsGrant` against a fake IDP

As of this writing: **108/108 tests pass** (66 in-module unit tests, 18
conformance-vector tests, 15 flow tests, 9 act-as tests) in a clean build. No test
performs a live DNS request: every `beginLocalLogin` call in the suite
injects a fake resolver (`browser.FakeDnsResolver`).

## Browser endpoint discovery

`beginLocalLogin` does one DNS TXT lookup. It reads
`_linkkeys_apis.<identity-domain>` and selects the first valid LinkKeys v1
record with an `https=` endpoint. That endpoint is the browser-facing host
(see `docs/spec/trust-and-anchors.md`). The identity domain is a trust and
discovery domain. It is not always the host that serves the login routes.

The redirect URL is built from three parts:

1. The discovered base, for example `https://login.example.com/linkkeys`.
2. The route `/auth/local-rp` (`browser_route_local_rp`).
3. The `signed_request` query parameter (and `username` for a full login).

A path prefix in the `https=` value is preserved. The base must use `https`,
must have a host, and must not carry userinfo, a query, or a fragment.
Records that fail these checks are skipped. The URL is parsed and emitted
with `std.Uri`.

Fallback rule: when the lookup fails, when no valid record carries `https=`,
or when the discovered base is invalid, the SDK uses
`https://<identity-domain>`. This keeps a domain that serves its browser
routes at the apex working without a `_linkkeys_apis` record.

Inject a resolver with `BeginLocalLoginConfig.dns`. `null` selects the
system resolver (`dns.SystemDnsResolver`). Tests inject a fake resolver so
that no live DNS request happens.

`PendingLogin.user_domain` always stays the identity domain.
`completeLocalLogin` binds verification to that domain, never to the
discovered host.

The helpers are exported for other glue (for example a regular RP building
`/auth/authorize`):

```zig
const base = try lrp.resolveBrowserBase(allocator, my_dns_resolver.resolver(), "example.com");
const url = try lrp.buildBrowserEndpoint(allocator, base, lrp.browser_route_authorize, signed_request_param);
```

## No csilgen Zig target — hand-written wire codec

No csilgen generator targets Zig. Per this repo's `AGENTS.md`, a request
for one has been filed in the csilgen repo's inbox
(`~/repos/catalystcommunity/csilgen/docs/csilgen-requests/zig-target.md`,
`Status: open`). Until it lands, `src/cbor.zig` is a hand-written, minimal
canonical-CBOR value-tree codec (unsigned/negative integers, bool, null,
text/byte strings, definite-length arrays/maps, tag-24 for CSIL-RPC
payloads — no floats, no indefinite-length items, matching the protocol's
actual needs) and `src/types.zig` hand-writes the CSIL struct + encode/
decode pairs the local-RP protocol needs, field-for-field against
`sdks/local-rp/go/generated/{types,codec}.gen.go`. Map keys are encoded
sorted bytewise by their own encoded bytes (RFC 8949 §4.2.1, canonical
CBOR) — decoding is always by key-name lookup, so this SDK stays wire-
compatible with the Go/Rust reference codecs even though their generated
encoders emit a fixed declaration order rather than a strictly sorted one
(both are valid CBOR encodings of the same map).

`src/rpc.zig` likewise hand-builds the CSIL-RPC request/response envelope
(`v`/`service`/`op`/`payload:#6.24(bstr)` and `v`/`status`/`variant`/
`error`/`payload`) and the 4-byte big-endian length-prefix stream framing,
directly against `~/repos/catalystcommunity/csilgen/docs/csil-rpc-transport.md`
and `csil-transport-conventions.md`.

## TLS evaluation outcome — pinned TLS is NOT implemented

The design doc's "SDK endpoint discovery and pinning" section is explicit:
verifying the server certificate's SPKI public-key fingerprint against the
domain's DNS `fp=` set is **mandatory** — WebPKI validity is not the trust
anchor, the pin is. This SDK evaluated `std.crypto.tls.Client` (Zig 0.14.1)
for this and found:

- **(a) Connecting with certificate verification disabled/relaxed: YES.**
  `Options.ca = .self_signed` accepts any self-signed certificate, and
  `Options.host = .no_verification` skips hostname checking. Ed25519 leaf
  certificates are also fully supported — both the TLS 1.3 handshake
  signature scheme (`tls.SignatureScheme.ed25519 = 0x0807`) and the X.509
  signature-algorithm verification path (`Certificate.zig`'s
  `verifyEd25519`) are implemented in the stdlib.
- **(b) Exposing the peer certificate for a manual pin check: NO.**
  `Client.init()` parses and verifies the leaf certificate transiently
  during the handshake and discards it. Nothing on the `Client` struct
  retains it afterward, and there is no verification-callback hook (unlike
  a `rustls::ClientConfig` or a Go `tls.Config.VerifyPeerCertificate`) to
  intercept it before it's dropped.

Because (b) is missing, this SDK cannot implement the mandatory SPKI pin
check on top of `std.crypto.tls.Client` alone. Doing so would require either
forking/vendoring the certificate-handling portion of the stdlib TLS client,
or writing a TLS client from scratch — both out of scope here.

**Consequence, by design, not oversight**: `rpc.defaultSecureDial` always
returns `error.PinnedTlsUnavailable` rather than silently connecting
unpinned (this repo's error-handling philosophy: fail closed at a security
boundary). `CompleteLocalLoginConfig.secure_dial` is injectable — supply a
real pinned-TLS implementation there once one exists (e.g. shelling out to
a system TLS library, or a future vendored/forked TLS client) before this
SDK can reach a real network peer. **What would unblock a real
implementation**: (1) a fork of `std.crypto.tls.Client` that exposes the
parsed leaf certificate (or calls a verification callback before discarding
it), or (2) a separate TLS implementation with that hook.

What IS fully implemented and tested:

- **`src/tls_pin.zig`**: the SPKI pin-extraction logic — given a
  DER-encoded SubjectPublicKeyInfo (or a full certificate DER, in which the
  fixed 12-byte RFC 8410 Ed25519 SPKI prefix is located by search), extract
  the raw 32-byte Ed25519 public key and compute its fingerprint. Unit-
  tested against a **real openssl-CLI-minted Ed25519 self-signed
  certificate fixture** (generation command in that file's comments),
  ready to slot into a real pinned-TLS verification callback once one
  exists.
- **`tests/flow.zig`**: exercises the *entire rest* of the chain — DNS TXT
  parsing/pinning, the CSIL-RPC envelope + stream framing, and the full
  local-RP protocol verification (envelope signatures, sealed-box open,
  header/payload cross-check, audience/issuer/callback-url/nonce-state,
  claim signature verification) — over a fake IDP reached via a plaintext
  `secure_dial` override injected at the `Transport`/`SecureDial` seam. This
  is the design doc's sanctioned fallback for a toolchain that can't do
  pinned TLS (the same shape as the documented Dart fallback), and it is
  real network I/O (a real loopback TCP server, a real background thread,
  real CBOR wire bytes) for everything except the TLS layer itself.

## Quickstart

```zig
const std = @import("std");
const lrp = @import("linkkeys_local_rp");

// Once, at install/setup time — persist the returned bytes with ordinary
// application-secret care (see "Security notes" below).
const identity = try lrp.generateLocalRpIdentity(allocator, .{
    .app_name = "My LAN Jukebox",
    .now = std.time.timestamp(),
});
const stored_bytes = try lrp.localRpIdentityToBytes(allocator, identity);
// ... write stored_bytes to your app's secret/config store ...

// Later, per login attempt:
const identity2 = try lrp.localRpIdentityFromBytes(allocator, stored_bytes);
const result = try lrp.beginLocalLogin(allocator, .{
    .key_material = identity2,
    .callback_url = "http://jukebox.lan:8080/auth/callback",
    .user_domain = "alice@example.com", // a full login prefills alice; a bare domain only selects the IDP
    .now = std.time.timestamp(),
});
// Persist `result.pending` (a plain struct — put it in a server-side
// session tied to the browser), then redirect the user's browser to
// result.redirect.redirect_url. Redirect to it as returned; do not parse
// or rewrite it (see "Browser endpoint discovery" above). Set `.dns` to
// inject a resolver; null selects the system resolver.

// On callback, your app's HTTP handler receives a request whose query
// string carries `encrypted_token=<...>`. Pass the request's full URL and
// that parameter's raw value to completeLocalLogin — see "TLS evaluation
// outcome" above: `secure_dial` must be supplied by you, since this SDK's
// default always fails closed.
const verified = try lrp.completeLocalLogin(allocator, .{
    .key_material = identity2,
    .pending = result.pending,
    .encrypted_token = encrypted_token,
    .arrived_url = arrived_url,
    .now = std.time.timestamp(),
    .transport = lrp.defaultTransport(),
    .secure_dial = my_pinned_tls_dial, // see TLS evaluation outcome above
    .dns = my_dns_resolver.resolver(),
});
// verified.user_id, verified.user_domain, verified.claims, ... — session
// creation, local user records, and authorization are all your app's job.
```

## App responsibilities (this SDK owns none of these)

Per the design doc: *"SDKs must not own application storage, sessions,
database writes, or local user authorization."* Concretely, the app owns:

- **Key material** (`LocalRpKeyMaterial` / the bytes from
  `localRpIdentityToBytes`): persist it wherever the app stores its own
  secrets/configuration, with the care described below.
- **`PendingLogin`**: persist it between `beginLocalLogin` and
  `completeLocalLogin`, and **discard it after one completion attempt**.
  This module owns no storage and cannot enforce single-use itself —
  replay protection at the app boundary is the app's responsibility.
- **A real pinned-TLS `SecureDial`**: see "TLS evaluation outcome" above.
- **Sessions, local user records, authorization decisions**: entirely the
  app's, using the verified facts this SDK returns.
- **Memory**: every public entry point takes an explicit `allocator` and
  returns data owned by it (arena-friendly — pass an
  `std.heap.ArenaAllocator` scoped to one login attempt and free it in one
  shot when done, the idiomatic Zig pattern for this shape of API).

## Security notes

- **Key storage**: the private key fields inside `LocalRpKeyMaterial` don't
  directly identify a user, but they control this app's entire local RP
  identity — anyone holding them can sign login requests and redeem claim
  tickets as this app. Store them with ordinary application-secret care
  (the same tier as a database credential or API key), not merely as
  configuration.
- **Revocation semantics**: revoking this local RP identity at a LinkKeys
  domain stops future logins there and kills that RP's outstanding claim
  tickets immediately (redemption re-checks approval status on every
  call). It does **not** reach into sessions the app already minted from a
  prior successful login — session lifecycle is the app's to manage.
- **No key continuity / rotation**: generating a new identity means a new
  fingerprint and re-approval at every LinkKeys domain that should allow
  the app. There is no "same app, new key" continuity story in this
  protocol version.
- **Network trust anchor**: domain public keys and revocation certificates
  fetched over the network (`rpc.fetchDomainKeys`) are only ever trusted
  after DNS `fp=` pinning (`dns.trustKeys`) — an unpinned/unauthenticated
  key can never reach the verification chain. The default DNS resolver
  (`dns.SystemDnsResolver`) is a hand-rolled, bounded UDP client discovering
  its nameserver from `/etc/resolv.conf` (Linux/POSIX only — inject your own
  `DnsResolver` on other platforms or for hardening, e.g. a DoH client). LAN
  resolver spoofing is an accepted, documented tradeoff for this mode
  (design doc, "Decided").
- **Pinned TLS is not implemented** — see above. `completeLocalLogin`
  cannot reach a real network peer until the caller supplies a real
  `secure_dial`.
- **Address policy**: the default `Transport` (`StdTransport`) dials
  whatever address DNS returns, including private/loopback/LAN addresses —
  that is the entire point of this mode. Set `StdTransport.policy` to
  `.public_only` to opt into a stricter SSRF-guard posture if your
  deployment wants it; nothing in this package applies that restriction by
  default.
- **Expiration**: `checkExpirations(identity, now)` reports `notice` (180
  days remaining), `warning` (90 days), `critical` (30 days), and `expired`
  thresholds as facts — this package never blocks a login or forces
  rotation on its own; that decision is the app's.
- **Claim-signer domain fan-out is bounded**: `completeLocalLogin` caps the
  number of distinct claim-signer domains it will fetch keys for
  (`complete.max_claim_signer_domains = 8`), so a malicious/compromised
  home IDP cannot use an unbounded claim-signature domain list to make this
  SDK perform many outbound DNS/TCP calls to attacker-chosen targets (an
  SSRF/DoS amplification vector) before any signature is actually checked.

## Act-as grants

An act-as grant lets this local RP (the grantee) act as a user at an
enrolled application (the audience). The user approves the grant at the
user's home domain. The home domain signs it. See
`docs/spec/reserved/act-as-grants.md`.

Rules:

- A local RP can be a grantee only after its home domain approved it. The
  home domain refuses a request from a local RP that it did not approve.
- A local RP cannot be an audience. A peer cannot find its keys through DNS.
- The descriptor signing key signs every grantee message. The proof carries
  the signed descriptor.
- A local RP has no enrolling account. A grant request never sends
  `grantee_handle_claim`.
- The SDK copies the audience's `SignedActAsScopeSet` (`scope_set` bytes,
  `signer_instance_id`, and the `signatures` array) into the request
  without a change. It does not verify the audience signatures.

Steps (`src/act_as.zig`):

1. Get the audience's signed scope set (CBOR of `SignedActAsScopeSet`)
   through the audience's own protocol.
2. Call `beginActAs`. It signs an `ActAsGrantRequest` and returns the
   redirect `<browser base>/auth/act-as?signed_request=...` and a
   `PendingActAs`. The browser base comes from `_linkkeys_apis` discovery,
   with a fallback to `https://<domain>`. The request window is 300 seconds
   by default and 900 seconds at most. Keep `PendingActAs` for one callback.
3. When the browser comes back, call `completeActAsCallback` with the
   callback URL or query. It compares the `nonce` with the pending nonce in
   constant time and returns `act_as_grant_id`.
4. Call `refreshActAsGrant` to get the grant (`ActAs/refresh-grant` on the
   user's home domain, through the same discovery and `SecureDial` path as
   claim-ticket redemption). The SDK refuses a returned grant unless its
   `grant_id`, its local-RP grantee fingerprint, and its `subject_domain`
   match the request. The SDK does not verify the home domain's signature;
   the audience does. Call it again when less than half of the grant's life
   remains.
5. For each call to the audience, call `presentActAs`. It signs an
   `ActAsPresentation` and returns the `ActAsCredential` and its CBOR.

`refreshActAsGrant` needs a pinned-TLS `SecureDial`, as
`completeLocalLogin` does. The default fails closed (see "TLS evaluation
outcome").

## Layout

```text
sdks/local-rp/zig/
  build.zig, build.zig.zon    module + test wiring
  src/
    cbor.zig                  canonical CBOR value tree (encode/decode)
    types.zig                 CSIL structs + encode/decode pairs
    crypto.zig                Ed25519/X25519/AES-GCM/ChaCha20-Poly1305/HKDF/SHA-256
    local_rp.zig               envelope sign/verify, sealed box, timestamps
    claims.zig                 claim signature verification (+ test-only signing)
    revocation.zig             sibling-signed revocation certificate verification
    dns.zig                    TXT parsing/pinning + hand-rolled UDP DNS client
    encoding.zig                base64url URL-param helpers
    identity.zig               generateLocalRpIdentity, byte storage helpers
    begin.zig                  beginLocalLogin
    browser.zig                _linkkeys_apis https= discovery + browser URL building
    complete.zig                completeLocalLogin (full verification chain)
    rpc.zig                    CSIL-RPC envelope + stream framing + fetch/redeem
    transport.zig               Transport seam + default TCP dialer
    act_as.zig                  act-as grantee: begin, callback, refresh, present
    tls_pin.zig                 SPKI pin-extraction logic (+ openssl fixture)
    root.zig                   module entry point / flat re-exports
  tests/
    conformance.zig            every sdks/local-rp/conformance/*.json vector
    flow.zig                   end-to-end begin/complete against a fake IDP
    act_as.zig                 act-as grantee vectors, begin, callback, refresh
```
