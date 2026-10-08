# linkkeys_local_rp (Dart)

Dart SDK for LinkKeys' DNS-less local RP identity mode. Read
`dns-less-local-rp-design.md` at the repo root first — this package implements
its "SDK API Shape" section verbatim, Dart-idiomatically adapted, and follows
the same wire construction the Rust/Go/TypeScript/Java reference SDKs use.
Every wire-level claim in this README is verified against the shared
`sdks/local-rp/conformance/` vector suite, not merely asserted.

This mode lets a locally-installed app (a LAN jukebox, a desktop tool, a
self-hosted service with no public DNS) use LinkKeys for login without
running its own DNS-pinned relying party. The app's identity is the
fingerprint of a locally-generated Ed25519 signing key (SSH-host-key style),
not a domain.

## Requirements

- Dart SDK `^3.5.0`, via the shared `catalyst-tools` bundle:

  ```sh
  source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
  cd sdks/local-rp/dart
  dart pub get
  dart test
  ```

- `openssl` on `PATH` — used only to *regenerate* the fixed certificate
  bytes embedded in `test/tls_pinning_test.dart` (see "Known limitations"
  below); never a runtime dependency, and the checked-in test does not
  itself shell out to `openssl`.
- Two runtime dependencies: `cryptography_plus` (crypto primitives) and the
  Dart/Flutter SDK itself. No DNS package (see "DNS TXT lookup" below).

## Quickstart

```dart
import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';

Future<void> main() async {
  // Once, at install/setup time -- persist the returned bytes with ordinary
  // application-secret care (see "Security notes" below).
  final identity = await generateLocalRpIdentity(GenerateLocalRpIdentityConfig(
    appName: 'My LAN Jukebox',
    now: DateTime.now().toUtc(),
  ));
  final storedBytes = localRpIdentityToBytes(identity);

  // Later, per login attempt:
  final reloaded = localRpIdentityFromBytes(storedBytes);
  final begun = await beginLocalLogin(BeginLocalLoginConfig(
    keyMaterial: reloaded,
    callbackUrl: 'http://jukebox.lan:8080/auth/callback',
    userDomain: 'alice@example.com',
    now: DateTime.now().toUtc(),
  ));
  // App: persist begun.pending (e.g. in a server-side session), then
  // redirect the browser to begun.redirect.redirectUrl. This SDK never
  // performs the redirect itself. beginLocalLogin discovers the browser
  // host from `_linkkeys_apis.<domain>` (see "Browser endpoint discovery").

  // On callback (app's HTTP handler received `arrivedUrl`, which carries an
  // `encrypted_token=` query parameter):
  final verified = await completeLocalLogin(CompleteLocalLoginConfig(
    keyMaterial: reloaded,
    pending: begun.pending,
    encryptedToken: extractedEncryptedToken, // from the request query string
    arrivedUrl: arrivedUrl,
    now: DateTime.now().toUtc(),
  ));
  // `verified` carries user id/domain, claims, domain keys used, the local
  // RP fingerprint, and expirations -- session creation, local user
  // records, and authorization are all the app's own responsibility.
}
```

`begin_local_login`'s default claim set matches the design doc exactly:
requested `display_name`, `email`, `handle`; required `handle`. Pass
`requestedClaims`/`requiredClaims` on `BeginLocalLoginConfig` to override.

## Browser endpoint discovery

`beginLocalLogin` does one DNS TXT lookup. It reads
`_linkkeys_apis.<identity domain>` and uses the `https=` value as the
browser-facing base URL (`docs/spec/trust-and-anchors.md`). The identity
domain is a trust domain. It is not always the host that serves the login
routes.

The rules are:

- The first valid `v=lk1` record with an `https=` value wins.
- A base is valid only when it uses `https`, has a host, and has no
  userinfo, query, or fragment. A path prefix is allowed and is kept:
  `https=login.example.com/linkkeys` gives
  `https://login.example.com/linkkeys/auth/local-rp?signed_request=...`.
- If the lookup fails, if no record has a valid `https=` value, or if the
  base is invalid, the redirect falls back to `https://<identity domain>`.
- `PendingLogin.userDomain` is always the identity domain. It is never the
  discovered host. Verification binds to the identity domain.

Inject a resolver with `BeginLocalLoginConfig.dns`. The default is
`defaultDnsResolver()` (the hand-rolled `SystemDnsResolver`). Any
`DnsResolver` works, so tests can supply canned answers:

```dart
class CannedDns implements DnsResolver {
  @override
  Future<List<String>> txtLookup(String name) async {
    if (name == '_linkkeys_apis.example.com') {
      return ['v=lk1 https=login.example.com/linkkeys'];
    }
    throw SdkException(SdkExceptionKind.dns, 'no record for $name');
  }
}

final begun = await beginLocalLogin(BeginLocalLoginConfig(
  keyMaterial: reloaded,
  callbackUrl: 'http://jukebox.lan:8080/auth/callback',
  userDomain: 'alice@example.com',
  now: DateTime.now().toUtc(),
  dns: CannedDns(),
));
```

Redirect the browser to `begun.redirect.redirectUrl` as returned. Do not
parse or rewrite it.

The helpers are public: `resolveBrowserBase`, `buildBrowserEndpoint`,
`browserRouteLocalRp`, and `browserRouteAuthorize` (`lib/src/browser.dart`).
Regular-RP application glue can use them to build `/auth/authorize` URLs
with the same discovery.

## Act-as grants

An act-as grant lets a user give this local RP (the grantee) permission to
act as the user at an enrolled application (the audience). See
`docs/spec/reserved/act-as-grants.md`. The feature is Reserved and can
change.

A local RP can be a grantee only. Its home domain must approve the local RP
first. The home domain refuses an act-as request from a local RP that it did
not approve. A local RP cannot be an audience, because a peer cannot find
its keys through DNS.

The descriptor signing key signs every grantee message. The grantee is
`GranteeRef(localRpDescriptorFingerprint: <fingerprint>)`.

1. Get the signed scope set from the audience. The audience protocol does
   this, not this SDK. Keep the CBOR bytes as you received them.
2. Call `beginActAs`. It signs an `ActAsGrantRequest` and returns
   `redirectUrl` and a `PendingActAs`. Keep the `PendingActAs`. Send the
   browser to `redirectUrl`. The URL host comes from `_linkkeys_apis`
   discovery, with the same fallback as `beginLocalLogin`.
3. The home domain sends the browser to your callback URL with
   `act_as_grant_id` and `nonce`. Call `completeActAsCallback` with the
   `PendingActAs` and the callback URL. It compares the nonce in constant
   time and returns the grant id. Use each `PendingActAs` one time only.
4. Call `refreshActAsGrant` with the home domain and the grant id. It calls
   `ActAs/refresh-grant` over the DNS-pinned TCP CSIL-RPC path. It returns
   the `SignedActAsGrant` and `signed` (true when the home domain signed a
   new grant). Call it again when less than half of the grant life remains.
5. For each call to the audience, call `presentActAsGrant` with the grant,
   the audience `ApplicationRef`, the request digest, the time, and a fresh
   nonce. Send `bytes` (the CBOR `ActAsCredential`) with the call.

```dart
final begun = await beginActAs(BeginActAsConfig(
  keyMaterial: identity,
  userIdentity: 'alice@example.com',
  signedScopeSet: scopeSetBytesFromAudience,
  requestedLifetimeSeconds: 3600,
  callbackUrl: 'http://jukebox.lan:8080/act-as/callback',
  now: DateTime.now().toUtc(),
));
// Keep begun.pending. Send the browser to begun.redirectUrl.

final grantId = completeActAsCallback(begun.pending, arrivedCallbackUrl);
final refreshed = await refreshActAsGrant(RefreshActAsGrantConfig(
  keyMaterial: identity,
  userDomain: begun.pending.userDomain,
  grantId: grantId,
  now: DateTime.now().toUtc(),
));
final presented = await presentActAsGrant(
  grant: refreshed.grant,
  audience: audienceRef,
  requestDigest: digest,
  now: DateTime.now().toUtc(),
  nonce: freshNonce,
  keyMaterial: identity,
);
// Send presented.bytes to the audience.
```

The request window of `beginActAs` is 300 seconds by default. The maximum is
900 seconds. The pure helpers are on `ActAs` (`signGrantRequest`,
`signRefreshRequest`, `grantHash`, and the tags). The wire types and
`ActAsCodec` are in `lib/src/wire/act_as_wire.dart`.
`test/act_as_test.dart` checks the bytes against the `local_rp_grantee`
case of `sdks/regular-rp/conformance/act_as_grantee_signing.json`.

## Package health check: `cryptography_plus` vs `cryptography`

The design doc's Dart matrix row flags a real risk: `package:cryptography`
(the `dint-dev` original) "has had maintenance gaps and community forks
(`cryptography_plus`)." This SDK verified that with data before choosing,
not by reputation:

| | `cryptography` (dint-dev) | `cryptography_plus` (fork) |
|---|---|---|
| Latest version (as of this SDK's implementation) | 2.9.0 | 3.0.0 |
| Latest publish date | 2025-11-21 | 2026-03-02 (**more recent**) |
| Release gap | **2023-09-21 to 2025-11-19: over two years of silence**, then a 3-release burst in 2 days | steady: filled the gap with 2.7.1 (2024-10-24), then 3.0.0 |
| GitHub open issues | 32 | 13 |
| GitHub stars / forks | 184 / 135 (older project, longer history) | 25 / 12 |
| GitHub `pushed_at` | 2025-11-21 | 2026-03-02 |

Both packages are `import 'package:X/cryptography.dart'`-compatible (the
fork keeps the same library name and class surface -- `AesGcm`, `Chacha20`,
`Ed25519`, `X25519`, `Hkdf`, `Sha256`, `SimpleKeyPairData`,
`SimplePublicKey`, etc. -- only the pub.dev package name differs), so the
choice is a pure maintenance-signal decision, not an API tradeoff. Given the
multi-year silent gap in the original and the fork's more recent release,
this SDK depends on `cryptography_plus`. If `dint-dev/cryptography`
re-establishes a visibly maintained cadence, re-evaluating is cheap (one
import prefix and one pubspec line).

### The raw-key-import/export footgun, and what was actually verified

`cryptography_plus` accepts a raw 32-byte seed directly via
`Ed25519()/X25519().newKeyPairFromSeed(seed)` -- no DER/JWK wrapping dance,
unlike Java's JCA or Node's `crypto` module. This is the friendliest
raw-key story of any language in the design doc's matrix, but it hides one
real footgun, documented in detail in `lib/src/crypto/crypto.dart`'s
library docs:

- **X25519 key pairs store the RFC 7748-***clamped*** seed, not the
  original input.** `DartX25519.newKeyPairFromSeed` clamps the low 3 bits /
  bit 254 / bit 255 of the seed *before* storing it as the key pair's
  private-key bytes, so `extractPrivateKeyBytes()` does not round-trip the
  original seed bit-for-bit. This is harmless for every operation this SDK
  performs (clamping is idempotent, and both public-key derivation and
  Diffie-Hellman re-clamp internally, matching RFC 7748 exactly), but it
  would silently break an implementation that assumed round-trip identity.
  Verified empirically against `keys.json`'s fixed seeds before writing any
  other code that depends on this package.
- **HKDF's "no salt" default is NOT usable as RFC 5869's "zero-filled salt
  of hash length."** `Hkdf.deriveKey`'s `nonce` parameter (its name for
  HKDF's salt) defaults to an empty list, which `cryptography_plus`'s HMAC
  implementation rejects outright (`ArgumentError: Secret key must be
  non-empty`) rather than silently zero-padding it the way some other HMAC
  implementations do. This SDK's `hkdfSha256` therefore passes an explicit
  32-byte all-zero salt, which IS the RFC 5869 default. Verified against
  `callback_box.json`'s derived AEAD keys byte-for-byte, not merely
  reasoned about.
- **Low-order X25519 rejection is NOT built in.** Unlike the JDK's XDH
  `KeyAgreement` (which throws for several known low-order inputs during
  `doPhase`), `cryptography_plus`'s pure-Dart X25519 implementation computes
  the RFC 7748 scalar multiplication unconditionally, including for an
  all-zero (or other low-order) input, and returns whatever it computes --
  potentially an all-zero shared secret. This SDK adds an explicit
  all-zero check after every X25519 Diffie-Hellman
  (`Crypto.x25519DiffieHellman`), verified against
  `callback_box.json`'s `low_order_ephemeral_key_rejected` case.

All three findings came from writing a throwaway smoke-test script against
`keys.json`/`envelopes.json`/`callback_box.json` *before* building the rest
of the SDK on top of this package, per the task's "verify EVERY primitive
against the vectors before building on it" requirement.

## DNS TXT lookup: hand-rolled, not a pub package

`dart:io` has **no DNS TXT lookup at all**
(`InternetAddress.lookup` only returns A/AAAA records), unlike Java (JNDI's
built-in DNS provider) or Node (`dns.resolveTxt`). The design doc allows
either a minimal hand-rolled UDP DNS TXT client or a pub package "IF it is
genuinely well-maintained." This SDK health-checked the plausible pub.dev
candidates and none passed:

| Package | Verdict |
|---|---|
| `dns_client` | Its listed GitHub repository **does not resolve at all** (404 from the GitHub API) -- a dead homepage link is disqualifying on its own for a security-relevant dependency. Version history is also a 5+ year silent gap (2021 to 2026) followed by a one-day release burst with nothing since. |
| `dnsolve` | Resolves via native FFI (`res_query`/platform resolver bindings), not a portable DNS client -- adds FFI surface for a need this SDK can meet in ~150 lines of pure Dart. |
| `basic_utils` | DNS lookup is one small corner of a large, general-purpose "kitchen sink" package. Pulling in the whole package for TXT lookups violates AGENTS.md's "every dependency is a liability." |
| `multicast_dns` | mDNS (`.local` LAN discovery), not unicast DNS -- wrong protocol. |

`lib/src/dns/system_dns_resolver.dart` therefore hand-rolls a minimal,
bounded-scope DNS TXT client: one question, UDP first with a TCP fallback
on a truncated response, nameservers read from `/etc/resolv.conf`. This
mirrors the same calculus Go/Rust/Java made for their own protocol-level
gaps in this SDK family (hand-writing CBOR before a generated client
exists; Java hand-rolling HKDF). The `DnsResolver` interface is injectable,
so an app that wants a hardened resolver (e.g. DNS-over-HTTPS) can supply
one instead -- per the design doc's "Decided" section, LAN resolver
spoofing against the default resolver is an accepted, documented tradeoff
for this mode.

## Known limitations

### `dart:io`'s TLS stack cannot serve/negotiate Ed25519 certificates

This protocol's TLS pinning (`crates/linkkeys/src/tcp/tls.rs`'s trust
model, reused here) is defined in terms of a domain's **Ed25519** signing
key: the pinned fingerprint is `sha256(spki_raw_ed25519_public_key)`, and
the peer certificate must carry that exact key. Verified empirically before
writing any flow-test code: `dart:io`'s TLS stack (BoringSSL) refuses the
handshake outright when the server presents an Ed25519 certificate --

```
HandshakeException: Handshake error in server (OS Error:
    NO_COMMON_SIGNATURE_ALGORITHMS(extensions.cc:4823))
```

-- for both `SecureServerSocket` (serving) and, by construction, any client
connecting to it. This is a `dart:io`/BoringSSL platform gap, not a bug in
this SDK: the client-side pin-check logic
(`lib/src/rpc/tls_pinning.dart`) is written exactly like the Rust/Go/Java
reference SDKs' equivalents, and would work against a real LinkKeys IDP
(whose TLS stack, per `crates/linkkeys/src/tcp/tls.rs`, is not `dart:io`).
It simply cannot be exercised through a live in-process TLS handshake in a
Dart test, unlike the Java reference SDK's flow test (JDK's TLS stack does
support Ed25519).

Consequences, and how this SDK covers the gap instead:

- **`test/tls_pinning_test.dart`** unit-tests the actual certificate-parsing
  and fingerprint logic (`extractEd25519PublicKeyFromCertDer`) directly
  against real `openssl`-minted Ed25519 (and, for the negative case, RSA)
  certificate DER bytes -- the exact function `connectPinned` calls
  post-handshake in production, just not reached via a live handshake.
- **`test/flow_test.dart`** exercises the SDK's full verification chain
  end-to-end (CBOR wire codec, envelope signatures, sealed-box open,
  nonce/state/audience/issuer/callback-url checks, claim-ticket redemption,
  per-signer claim verification) over a **real TCP socket** and **real
  CSIL-RPC stream framing** to a real in-process fake IDP, using an
  internal, non-exported test seam (`completeLocalLoginForTesting` +
  `RpcCaller`, see `lib/src/rpc/rpc_client.dart`'s docs) that skips only the
  TLS handshake step. `completeLocalLogin` (the public API) always uses the
  real TLS-pinned path; the test seam exists purely because `dart:io`
  cannot complete that handshake with an Ed25519 certificate in-process.

If a future Dart/BoringSSL release adds Ed25519 TLS support, the flow test
seam can be deleted and `completeLocalLogin` itself driven directly with a
real in-process Ed25519 TLS server, matching the other reference SDKs.

## App responsibilities

This SDK never owns application storage, sessions, or authorization. Per
the design doc's "SDK API Shape":

- **Key material**: persist the bytes from `localRpIdentityToBytes` with
  ordinary application-secret care -- the same care as a database
  credential or API key. The private keys do not directly identify a user,
  but they control the app's entire local RP identity: anyone holding them
  can sign login requests and redeem claim tickets as this app.
- **`PendingLogin`**: persist it between `beginLocalLogin` and
  `completeLocalLogin` (e.g. in a server-side session tied to the browser),
  and discard it after one completion attempt. This SDK owns no storage
  and cannot enforce single-use itself; replay protection at the app
  boundary is the app's job.
- **Sessions, local user records, authorization**: entirely the app's. This
  SDK returns verified protocol facts (`VerifiedLocalLogin`); it never
  creates a session or writes to an app database.
- **Redirecting the browser**: `beginLocalLogin` returns a URL, never
  performs the redirect. The app decides whether to HTTP-redirect, display
  the URL, open a browser, or embed the flow in its own web UI.

## Security notes

- Revoking this local RP identity at the IDP kills future logins AND any
  outstanding claim tickets immediately, but does **not** reach into
  sessions the app already minted from a prior successful login.
- Key rotation is not a continuity operation: generating a new identity
  means a new fingerprint and re-approval at every LinkKeys domain.
- Domain keys and revocations fetched over the network are only ever
  trusted after DNS `fp=` pinning (`lib/src/dns/dns.dart`'s `trustKeys`) --
  an unpinned/unauthenticated key can never reach the verification chain.
- TLS to the domain's CSIL-RPC TCP port bypasses ordinary WebPKI chain
  validation on purpose (there is no CA chain for this trust model to
  begin with) and instead **mandatorily** verifies the peer certificate's
  SPKI fingerprint against the DNS-pinned set before any application data
  is sent or read (`lib/src/rpc/tls_pinning.dart`).
- The default `Transport` (`StdTransport`) is deliberately permissive about
  destination addresses by default (loopback/private/LAN addresses are the
  entire point of this mode); `AddressPolicy.publicOnly` is available
  opt-in for integrators who want the stricter posture the server-side S2S
  client uses for its own outbound calls.
- `beginLocalLogin` uses the `_linkkeys_apis` `https=` endpoint as the
  browser host only. A spoofed value can only change where the browser is
  sent. It cannot change which domain's keys verify the login, because
  `PendingLogin.userDomain` stays the identity domain.
- The default `DnsResolver` reads the OS-configured nameservers from
  `/etc/resolv.conf` with no DNSSEC/DoH validation; LAN resolver spoofing
  is an accepted, documented tradeoff for this mode (design doc,
  "Decided"). Inject a hardened `DnsResolver` if your deployment needs
  more.
- Every signature uses the envelope pattern with a mandatory,
  structure-specific context string; there is no signature versioning.
- The callback claim-signer domain count is capped at 8
  (`maxClaimSignerDomains`) to bound the DNS/TCP calls a malicious or
  compromised home IDP could otherwise induce this SDK to make against
  attacker-chosen targets.
- No key material, nonces, tokens, tickets, or claim values are ever
  included in this SDK's exception messages (`lib/src/errors.dart`) --
  only field names, algorithm ids, key ids, and domain names.

## Test command

```sh
source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
cd sdks/local-rp/dart
dart pub get
dart analyze
dart test
```

`dart analyze` is clean (strict-casts and strict-inference enabled in
`analysis_options.yaml`, on top of `package:lints/recommended.yaml`).
`dart test` runs 8 conformance test files against every one of the eight
`sdks/local-rp/conformance/*.json` vector files (positive and negative
cases alike), plus identity/begin unit tests, the browser endpoint
discovery tests (`test/browser_test.dart`, fake resolver, no live DNS), the
TLS pin-check unit tests described above, and the flow tests. All green
(67 tests as of this writing).

## Package layout

```
lib/
  linkkeys_local_rp.dart      # public API barrel
  src/
    identity.dart              # generate_local_rp_identity, byte helpers
    begin.dart                 # begin_local_login
    act_as.dart                # act-as grants, grantee side
    browser.dart               # _linkkeys_apis https= discovery + browser route URLs
    complete.dart               # complete_local_login (+ internal test seam)
    local_rp.dart               # envelope sign/verify, sealed box, expiry
    claims.dart                  # claim signature verification
    revocation.dart              # sibling-signed revocation certificates
    encoding.dart                 # base64url URL-param helpers
    errors.dart                   # SdkException/LocalRpError/ClaimError/...
    rfc3339.dart
    wire/                          # hand-written CBOR codec + CSIL types
      cbor.dart
      codec.dart
      types.dart
      act_as_wire.dart             # act-as types + codec
    crypto/                        # cryptography_plus-backed primitives
      crypto.dart
      aead_suite.dart
      hex.dart
    dns/                            # DNS TXT lookup seam + hand-rolled resolver
      dns.dart
      dns_resolver.dart
      system_dns_resolver.dart
    rpc/                             # CSIL-RPC over TLS-pinned TCP
      rpc_envelope.dart
      stream_framing.dart
      transport.dart
      std_transport.dart
      address_policy.dart
      tls_pinning.dart
      rpc_client.dart
test/
  conformance/                       # one file per sdks/local-rp/conformance/*.json
  identity_test.dart
  begin_test.dart
  flow_test.dart
  act_as_test.dart
  tls_pinning_test.dart
```

`lib/src/wire/`, `lib/src/crypto/`, and `lib/src/rpc/` are hand-written,
pending a csilgen Dart target (no generated CSIL-RPC client exists for Dart
today); see `~/repos/catalystcommunity/csilgen/docs/csilgen-requests/` for
the filed request. Everything in `wire/` reproduces exactly the CSIL wire
structures this protocol needs, verified byte-for-byte against
`sdks/local-rp/conformance/`, mirroring the approach the Go/TypeScript/Java
reference SDKs took before a generated client existed for them.
