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
    userDomain: 'example.com',
    now: DateTime.now().toUtc(),
  ));
  // App: persist begun.pending (e.g. in a server-side session), then
  // redirect the browser to begun.redirect.redirectUrl. This SDK never
  // performs the redirect itself.

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
cases alike), plus identity/begin unit tests, the TLS pin-check unit tests
described above, and the flow tests. All green.

## Package layout

```
lib/
  linkkeys_local_rp.dart      # public API barrel
  src/
    identity.dart              # generate_local_rp_identity, byte helpers
    begin.dart                 # begin_local_login
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
  tls_pinning_test.dart
```

`lib/src/wire/`, `lib/src/crypto/`, and `lib/src/rpc/` are hand-written,
pending a csilgen Dart target (no generated CSIL-RPC client exists for Dart
today); see `~/repos/catalystcommunity/csilgen/docs/csilgen-requests/` for
the filed request. Everything in `wire/` reproduces exactly the CSIL wire
structures this protocol needs, verified byte-for-byte against
`sdks/local-rp/conformance/`, mirroring the approach the Go/TypeScript/Java
reference SDKs took before a generated client existed for them.
