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

As of this writing: **63/63 tests pass** (41 in-module unit tests, 14
conformance-vector tests, 8 flow tests) in a clean build (~8s).

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
    .user_domain = "example.com", // the LinkKeys domain the user selected/entered
    .now = std.time.timestamp(),
});
// Persist `result.pending` (a plain struct — put it in a server-side
// session tied to the browser), then redirect the user's browser to
// result.redirect.redirect_url.

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
    complete.zig                completeLocalLogin (full verification chain)
    rpc.zig                    CSIL-RPC envelope + stream framing + fetch/redeem
    transport.zig               Transport seam + default TCP dialer
    tls_pin.zig                 SPKI pin-extraction logic (+ openssl fixture)
    root.zig                   module entry point / flat re-exports
  tests/
    conformance.zig            every sdks/local-rp/conformance/*.json vector
    flow.zig                   end-to-end begin/complete against a fake IDP
```
