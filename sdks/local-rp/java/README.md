# linkkeys-local-rp (Java)

Java SDK for LinkKeys' DNS-less local RP identity mode. Read
`dns-less-local-rp-design.md` at the repo root first — this package implements
its "SDK API Shape" section verbatim, Java-idiomatically adapted, and follows
the same wire construction the Rust/Go/TypeScript reference SDKs use.

This mode lets a locally-installed app (a LAN jukebox, a desktop tool, a
self-hosted service with no public DNS) use LinkKeys for login without
running its own DNS-pinned relying party. The app's identity is the
fingerprint of a locally-generated Ed25519 signing key (SSH-host-key style),
not a domain.

## Requirements

- **JDK 17** (uses `java.security.spec.EdECPrivateKeySpec` /
  `XECPrivateKeySpec`, standardized in JDK 15/17; the SunEC provider on 17
  supports Ed25519/X25519 raw key material natively).
- **Gradle 8.10.2**, via the shared `catalyst-tools` bundle:

  ```sh
  source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
  cd sdks/local-rp/java
  gradle test
  ```

- **`openssl` CLI** on `PATH` — test-scope only, used by `FlowTest` to mint a
  self-signed Ed25519 certificate for the fake IDP's TLS listener (JCA on
  JDK 17 has no certificate-*issuing* API, only consuming). Never a runtime
  dependency.
- Zero runtime dependencies otherwise. JUnit 5 is the only test-scope
  dependency (via Gradle's JUnit Platform support).

## Quickstart

```java
import java.time.Instant;
import community.catalyst.linkkeys.localrp.*;

// Once, at install/setup time — persist the returned bytes with ordinary
// application-secret care (see Identity's class docs).
var identity = Identity.generateLocalRpIdentity(
    new Identity.GenerateLocalRpIdentityConfig("My LAN Jukebox", Instant.now()));
byte[] storedBytes = Identity.localRpIdentityToBytes(identity);

// Later, per login attempt:
var reloaded = Identity.localRpIdentityFromBytes(storedBytes);
var begun = Begin.beginLocalLogin(new Begin.BeginLocalLoginConfig(
    reloaded, "http://jukebox.lan:8080/auth/callback", "example.com", Instant.now()));
// App: persist begun.pending() (e.g. in a server-side session), then redirect
// the browser to begun.redirect().redirectUrl().

// On callback (app's HTTP handler received `arrivedUrl` with an
// `encrypted_token=` query parameter):
var config = new Complete.CompleteLocalLoginConfig(
    reloaded, begun.pending(), encryptedToken, arrivedUrl, Instant.now());
var verified = Complete.completeLocalLogin(config);
// `verified` carries user id/domain, claims, domain keys used, the local RP
// fingerprint, and expirations — session creation, local user records, and
// authorization are all the app's own responsibility.
```

## Project layout

```
src/main/java/community/catalyst/linkkeys/localrp/
  crypto/    JCA/JCE crypto adapter: Ed25519, XDH/X25519, AEAD, HKDF, fingerprint
  dns/       DNS TXT parsing (_linkkeys / _linkkeys_apis), key pinning/vouching
  rpc/       CSIL-RPC envelope, TLS pinning, TCP transport seam
  wire/      Hand-written CBOR codec + wire types (see "Hand-written codec" below)
  LocalRp.java       Pure protocol helpers: envelopes, callback sealed box, checks
  Claims.java        Claim signature verification (+ sign helper for test fixtures)
  Revocation.java    Sibling-signed key revocation certificate verification
  Identity.java      generateLocalRpIdentity + byte storage helpers
  Begin.java         beginLocalLogin
  Complete.java      completeLocalLogin (the full verification chain)
  LinkKeysLocalRp.java  Facade: default seams, checkExpirations
  Encoding.java      URL-param (base64url-unpadded) helpers
  *Error.java, SdkException.java   Typed errors
src/test/java/community/catalyst/linkkeys/localrp/
  testutil/          Minimal JSON parser + fixture loader (no JSON dependency either)
  *ConformanceTest.java   One test class per sdks/local-rp/conformance/*.json file
  FlowTest.java      End-to-end test against a real (fake-identity) TLS+CSIL-RPC IDP
  BeginTest.java, IdentityTest.java   SDK-surface unit tests
```

## The EdEC / XDH raw-key helper (the documented pain point)

Every other language's crypto library accepts a raw 32-byte Ed25519/X25519 key
directly. JCA's `KeyFactory` does not — see `crypto/Crypto.java`'s class docs
for the full explanation, summarized here:

- **Ed25519 public key** (32 bytes, RFC 8032): little-endian `y`-coordinate
  with the `x`-coordinate parity bit stashed in the top bit of the last byte.
  `java.security.spec.EdECPoint` models this natively as
  `(boolean xOdd, BigInteger y)`, so the conversion is: reverse the 32 bytes to
  big-endian, peel off (and clear) the top bit as `xOdd`, the rest as `y`.
- **Ed25519 private key** (32-byte seed): `EdECPrivateKeySpec` takes the raw
  seed directly — no PKCS8/DER wrapping needed — and a generated
  `EdECPrivateKey.getBytes()` returns the seed back out.
- **X25519 public key** (32 bytes, RFC 7748): little-endian `u`-coordinate;
  the decoder must mask the top bit of the last byte before treating the rest
  as the coordinate (RFC 7748 §5). `XECPublicKeySpec` takes `u` as a plain
  `BigInteger`.
- **X25519 private key** (32-byte scalar): `XECPrivateKeySpec` takes the raw
  scalar directly; SunEC clamps it internally at agreement time per RFC 7748.

One more wrinkle solved without any hand-rolled elliptic-curve math: deriving
an X25519 **public** key from only a **private** scalar (needed when opening
the callback sealed box, which must feed its own public key into the KDF/AAD)
has no direct JCA primitive. `Crypto.derivePublicFromX25519Private` gets it by
running a `KeyAgreement` against the fixed RFC 7748 base point (`u = 9`) as the
"peer public key" — scalar multiplication by the base point is exactly what
that agreement computes, so it needs zero custom curve arithmetic.

All four raw-bytes directions are verified byte-for-byte against
`conformance/keys.json`, `envelopes.json`, and `callback_box.json`
(`KeysConformanceTest`, `EnvelopesConformanceTest`, `CallbackBoxConformanceTest`).

## HKDF-SHA256 (the documented JCA gap on JDK 17)

The standard `javax.crypto.KDF` API only lands in JDK 24. On JDK 17,
`Crypto.hkdfSha256` hand-rolls RFC 5869 HKDF-Extract + HKDF-Expand over
`Mac.getInstance("HmacSHA256")` — about 30 lines total including both steps
(the design doc's ballpark of "~15 lines" covers Expand alone; Extract is a
single `Mac.doFinal` call). Covered end-to-end by
`CallbackBoxConformanceTest`, which exercises the full seal/open path this KDF
feeds, plus `callback_box.json`'s published `kdf_context_hex` for isolating
the KDF/AAD-prefix construction from the AEAD step.

## Hand-written codec (pending a csilgen Java target)

**No csilgen generator targets Java today** — see the filed request,
`~/repos/catalystcommunity/csilgen/docs/csilgen-requests/java-target-does-not-exist.md`.
Every type and the CSIL-RPC envelope itself in the `wire`/`rpc` packages is
therefore hand-written rather than generated, and clearly marked as such in
each file's docs. Two things make this tractable and safe:

1. **Canonical CBOR map ordering is a sort, not manual bookkeeping.**
   `wire/Cbor.java`'s encoder always sorts map entries by the bytewise
   lexicographic order of their *encoded* keys (RFC 8949 §4.2.1) at encode
   time, rather than requiring each hand-written type's field-declaration
   order to already match canonical order (which is what the Go/Rust
   *generators* do, baking the order in at codegen time). This one sort rule,
   verified once, is what makes ~20 hand-written wire types safe without
   csilgen.
2. **Every wire type and the RPC envelope are byte-verified against the
   checked-in conformance vectors**, not merely internally self-consistent —
   see the `*ConformanceTest` classes.

If csilgen gains a Java target, this SDK's `wire`/`rpc.RpcEnvelope` packages
should be replaced by the generated equivalent; `LocalRp`, `Claims`,
`Revocation`, `Identity`, `Begin`, `Complete` (the actual protocol logic) stay
as hand-written SDK runtime code, matching every other language's split.

## App responsibilities

SDKs must not own application storage, sessions, database writes, or local
user authorization (design doc). Concretely:

- **Key material**: persist the bytes from `Identity.localRpIdentityToBytes`
  with ordinary application-secret care (same tier as a database credential
  or API key) — see `Identity`'s class docs.
- **`Begin.PendingLogin`**: persist it (e.g. in a server-side session tied to
  the browser) between `beginLocalLogin` and `completeLocalLogin`, and discard
  it after one completion attempt. This SDK owns no storage and cannot enforce
  single-use itself.
- **Sessions, local user records, authorization**: entirely the app's. This
  SDK returns verified protocol facts; it never creates a session or writes to
  an app database.

## Security notes

- Revoking this local RP identity at the IDP kills future logins *and* any
  outstanding claim tickets immediately (redemption re-checks approval status
  every time) — but it does **not** reach into sessions the app already
  minted from a prior successful login. Session lifecycle is the app's to
  manage.
- Key rotation is not a continuity operation: generating a new identity means
  a new fingerprint and re-approval at every LinkKeys domain. There is no
  "same app, new key" story in this protocol version.
- Domain keys and revocations fetched over the network are only ever trusted
  after DNS `fp=` pinning (`rpc.RpcClient`, `dns.Dns`) — an
  unpinned/unauthenticated key can never reach the verification chain.
- `rpc.TlsPinning` installs an all-trusting `TrustManager` to get past the
  JDK's WebPKI chain validation (there is no CA chain for a domain's TCP
  service certificate to begin with), then **mandatorily**, before any
  application data is exchanged, recomputes the peer certificate's SPKI
  fingerprint and requires it to be a member of the DNS-pinned set. The pin,
  not the chain, is the trust anchor — see that class's docs for the full
  rationale.
- The default DNS resolver (`dns.SystemDnsResolver`) uses JNDI's built-in DNS
  provider (the OS-configured resolver by default, or explicit servers if
  configured); LAN resolver spoofing is an accepted, documented tradeoff for
  this mode (design doc, "Decided"). Inject a hardened `DnsResolver` if your
  deployment needs more.
- The default `Transport` (`rpc.StdTransport`) is **permissive** by address
  policy (dials private/loopback/LAN addresses) by design — that is the
  entire point of this mode. `AddressPolicy.PUBLIC_ONLY` is available as an
  opt-in for integrators who want a stricter posture.
- None of this SDK's exception types carry key material, nonces, tokens,
  tickets, or claim values in their messages.

## Running tests

```sh
source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
cd sdks/local-rp/java
gradle test
```
