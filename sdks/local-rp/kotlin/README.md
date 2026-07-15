# linkkeys-local-rp-kotlin

Kotlin/JVM SDK for LinkKeys' DNS-less local RP identity mode. Read
`dns-less-local-rp-design.md` at the repo root first -- this package
implements its "SDK API Shape" section verbatim, Kotlin-idiomatically
adapted, and follows the same wire construction the Rust/Go/TypeScript/
Python/Java reference SDKs use.

This mode lets a locally-installed app (a LAN jukebox, a desktop tool, a
self-hosted service with no public DNS) use LinkKeys for login without
running its own DNS-pinned relying party. The app's identity is the
fingerprint of a locally-generated Ed25519 signing key (SSH-host-key style),
not a domain.

## Architecture decision

The design doc offers two options for this SDK: (a) depend on the sibling
Java SDK (`../java`) and wrap it in an idiomatic Kotlin surface, or (b) a
standalone Kotlin implementation with its own hand-written CBOR codec and JCA
crypto adapter. **This project takes option (a).**

Rationale:

- The Java SDK's hardest, most failure-prone code -- the hand-written
  canonical CBOR codec (`wire/Cbor.java`), the CSIL-RPC envelope
  (`rpc/RpcEnvelope.java`), the EdEC/XDH raw-key import/export dance, the
  hand-rolled HKDF-SHA256 (the JDK 17 JCA gap), and TLS `fp=` pinning
  (`rpc/TlsPinning.java`) -- is already written, already byte-verified
  against every conformance vector, and runs on the exact same JVM/JCA
  provider this Kotlin project also targets (JDK 17, `SunEC`). Kotlin and
  Java share a runtime; there is no cross-language FFI tax or packaging
  awkwardness the way there would be wrapping, say, the Rust or Go SDK.
  Re-implementing that code a second time in Kotlin would double the surface
  area for exactly the kind of subtle cross-implementation bug (map key
  ordering, byte-endianness, KDF context construction) the conformance
  vectors exist to catch, for zero behavioral benefit -- it would still be
  "the same JVM crypto/CBOR code," just typed twice.
- The cost of option (a) is packaging independence: this project cannot be
  published as a single, dependency-free artifact the way the Java SDK can;
  it always pulls in `linkkeys-local-rp` (the Java SDK) as a dependency. For
  this SDK's audience -- JVM/Kotlin developers who already accept a Gradle
  dependency graph -- that cost is small and ordinary, not a meaningful
  deployment obstacle. (Contrast with, say, a Kotlin/Native or Kotlin/JS
  target, where pulling in a JVM-only dependency would be a hard blocker;
  this project is Kotlin/JVM only, matching the design doc's language matrix
  row's "Android provider availability needs separate verification" caveat --
  see "Android" below.)
- Consuming the Java SDK via a Gradle **composite build**
  (`settings.gradle`'s `includeBuild('../java')`, matching the pattern
  already used by `csilgen/tests/interop/harness/kotlin` for its own Kotlin
  transport library) rather than a published Maven coordinate means a local
  edit to the Java SDK is picked up immediately, with no separate publish/
  install step -- appropriate for a monorepo where both SDKs move together
  as CSIL/protocol changes land.

What this project actually contributes, then, is **not** a second crypto/CBOR
implementation. It is:

1. An idiomatic Kotlin surface over the five "SDK API Shape" entry points --
   `generateLocalRpIdentity`, `beginLocalLogin`, `completeLocalLogin`,
   `checkExpirations`, and the byte/hex helpers -- using Kotlin data classes,
   named/default arguments in place of Java's config-object pattern (Kotlin's
   named arguments *are* the "big-config, not fluent" idiom the design doc
   asks for), and a sealed exception hierarchy (`LocalRpException`) in place
   of Java's per-kind unchecked exception classes.
2. A `protocol` sub-package (`community.catalyst.linkkeys.localrp.kt.protocol`)
   exposing the lower-level pure verification primitives (envelope signature
   input, the callback sealed box's open half, revocation certificate
   verification, DNS TXT record parsing, URL-param envelope encoding) as this
   package's *own* public API, so this SDK's conformance test suite exercises
   every wire construction through Kotlin -- never by reaching past this
   package into the Java dependency's classes from test code. Most
   applications never need this sub-package; see "App responsibilities"
   below.
3. This SDK's own test suite, written entirely in Kotlin against (1) and (2).

If a csilgen Kotlin target is ever added and the Java SDK's hand-written
`wire`/`rpc` packages get replaced by generated code, this project's
dependency direction and public API are unaffected -- it would simply start
depending on a differently-implemented (but behaviorally identical, per the
same conformance vectors) Java SDK.

## Requirements

- **JDK 17**, same as the Java SDK it depends on.
- **Gradle 8.10.2** with the Kotlin JVM plugin (`org.jetbrains.kotlin.jvm`,
  resolved from Maven Central at build time), via the shared `catalyst-tools`
  bundle:

  ```sh
  source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
  cd sdks/local-rp/kotlin
  gradle test
  ```

- **`openssl` CLI** on `PATH` -- test-scope only, used by `FlowTest` to mint a
  self-signed Ed25519 certificate for the fake IDP's TLS listener (same
  reason as the Java SDK's own `FlowTest`: JCA on JDK 17 has no
  certificate-*issuing* API, only consuming). Never a runtime dependency.
- No JSON library dependency: the conformance-vector loader
  (`src/test/kotlin/.../testutil/MiniJson.kt`) is a small hand-rolled parser,
  ported from the Java SDK's own `testutil.MiniJson`, for the same reason the
  Java SDK avoids one -- keep the test-time dependency surface minimal and
  auditable.

## Quickstart

```kotlin
import java.time.Instant
import community.catalyst.linkkeys.localrp.kt.*

// Once, at install/setup time -- persist the returned bytes with ordinary
// application-secret care (see LocalRpIdentity's class docs).
val identity = generateLocalRpIdentity(appName = "My LAN Jukebox", now = Instant.now())
val storedBytes = identity.toBytes()

// Later, per login attempt:
val reloaded = localRpIdentityFromBytes(storedBytes)
val begun = beginLocalLogin(
    identity = reloaded,
    callbackUrl = "http://jukebox.lan:8080/auth/callback",
    userDomain = "example.com",
    now = Instant.now(),
)
// App: persist begun.pending (e.g. in a server-side session), then redirect
// the browser to begun.redirect.redirectUrl.

// On callback (app's HTTP handler received `arrivedUrl` with an
// `encrypted_token=` query parameter):
val verified = completeLocalLogin(
    identity = reloaded,
    pending = begun.pending,
    encryptedToken = encryptedToken,
    arrivedUrl = arrivedUrl,
    now = Instant.now(),
)
// `verified` carries user id/domain, claims, domain keys used, the local RP
// fingerprint, and expirations -- session creation, local user records, and
// authorization are all the app's own responsibility.
```

Every optional field (`requestedClaims`, `requiredClaims`, `supportedSuites`,
`lifetime`, `clockSkewSeconds`, `transport`, `dns`, ...) is a named/default
Kotlin parameter with the design doc's documented default -- there is no
builder, and no fluent `request.requestClaim(...).requestClaim(...)` chain
(design doc: "Avoid fluent examples as the primary docs").

## Project layout

```
src/main/kotlin/community/catalyst/linkkeys/localrp/kt/
  LocalRpIdentity.kt   generateLocalRpIdentity + byte/hex storage helpers
  Login.kt             beginLocalLogin, PendingLogin, LocalLoginRedirect
  CompleteLogin.kt      completeLocalLogin, VerifiedLocalLogin (the full verification chain)
  Expiration.kt         checkExpirations, ExpirationStatus, ExpirationLevel
  Seams.kt              Transport / DnsResolver seams, AddressPolicy, defaults
  Errors.kt              LocalRpException sealed hierarchy + the Java-exception translation boundary
  WireMapping.kt         Claim / ClaimSignature / DomainPublicKey idiomatic data classes + RFC3339 <-> Instant mapping
  protocol/Protocol.kt   lower-level pure helpers (envelope sig input, callback-box open,
                          revocation verification, DNS TXT parsing, URL-param codec) --
                          this package's own conformance-testing / advanced-interop surface
src/test/kotlin/community/catalyst/linkkeys/localrp/kt/
  testutil/              hand-rolled JSON parser + fixture loader (no JSON dependency)
  *ConformanceTest.kt    one test class per sdks/local-rp/conformance/*.json file
  FlowTest.kt             end-to-end test against a real (fake-identity) TLS+CSIL-RPC IDP
  BeginTest.kt, IdentityTest.kt   SDK-surface unit tests
```

## Error handling

Every public function in this package throws a subtype of the sealed
`LocalRpException` (never a Java exception type from the underlying
dependency) -- exhaustive `when` matching is available on the sealed
hierarchy:

```kotlin
try {
    completeLocalLogin(identity, pending, encryptedToken, arrivedUrl, Instant.now())
} catch (e: LocalRpException.Protocol) {
    // e.kind: ProtocolErrorKind -- signature/timestamp/nonce/audience/... failure
} catch (e: LocalRpException.ClaimVerification) {
    // e.kind: ClaimErrorKind
} catch (e: LocalRpException.Revocation) {
    // sibling-signed revocation certificate did not meet quorum
} catch (e: LocalRpException.Server) {
    // e.status: the peer's non-Ok RPC transport status
} catch (e: LocalRpException.Network) {
    // e.kind: NetworkErrorKind -- DNS/transport/TLS/protocol-framing/no-trusted-keys
} catch (e: LocalRpException.InvalidInput) {
    // a field the caller supplied was structurally invalid
}
```

As required by AGENTS.md ("Never log sensitive information"), no exception
message ever carries key material, nonces, tokens, tickets, or claim values --
only field names, algorithm ids, key ids, and domain names.

## App responsibilities

SDKs must not own application storage, sessions, database writes, or local
user authorization (design doc). Concretely:

- **Key material**: persist the bytes from `LocalRpIdentity.toBytes()` with
  ordinary application-secret care (same tier as a database credential or API
  key) -- see `LocalRpIdentity`'s class docs.
- **`PendingLogin`**: persist it (e.g. in a server-side session tied to the
  browser) between `beginLocalLogin` and `completeLocalLogin`, and discard it
  after one completion attempt. This SDK owns no storage and cannot enforce
  single-use itself.
- **Sessions, local user records, authorization**: entirely the app's. This
  SDK returns verified protocol facts; it never creates a session or writes
  to an app database.
- **The `protocol` sub-package**: almost no application needs it. It exists
  so this SDK's own conformance/interop tests don't have to reach past this
  package's boundary; the only realistic app-level use is pre-fetching/
  caching domain keys and revocations outside the `completeLocalLogin` call
  (e.g. `protocol.DnsRecords`), which remains an advanced, opt-in path.

## Security notes

- Revoking this local RP identity at the IDP kills future logins *and* any
  outstanding claim tickets immediately (redemption re-checks approval status
  every time) -- but it does **not** reach into sessions the app already
  minted from a prior successful login. Session lifecycle is the app's to
  manage.
- Key rotation is not a continuity operation: generating a new identity means
  a new fingerprint and re-approval at every LinkKeys domain. There is no
  "same app, new key" story in this protocol version.
- Domain keys and revocations fetched over the network are only ever trusted
  after DNS `fp=` pinning (inside the Java SDK's `rpc.RpcClient`/`dns.Dns`) --
  an unpinned/unauthenticated key can never reach the verification chain.
  This Kotlin project does not re-implement that pinning logic; it delegates
  to it (see "Architecture decision" above).
- The default `Transport` (`stdTransport()` / `defaultTransport()`) is
  **permissive** by address policy (dials private/loopback/LAN addresses) by
  design -- that is the entire point of this mode. `AddressPolicy.PUBLIC_ONLY`
  (re-exported as `PUBLIC_ONLY` in this package) is available as an opt-in
  for integrators who want a stricter posture.
- The default `DnsResolver` (`systemDnsResolver()` / `defaultDnsResolver()`)
  uses the OS-configured system resolver by default; LAN resolver spoofing is
  an accepted, documented tradeoff for this mode (design doc, "Decided").
  Inject a hardened `DnsResolver` (a Kotlin lambda SAM-converts to the
  underlying Java functional interface) if your deployment needs more.
- `LocalRpException` messages never carry key material, nonces, tokens,
  tickets, or claim values (see "Error handling" above).
- `RevocationCertificate.revokedAt` (in the `protocol` sub-package) is
  deliberately kept as a raw RFC3339 wire string rather than parsed to
  `Instant`: it is one of the exact bytes a sibling's signature covers, and
  parsing-then-reformatting it (`+00:00` -> `Z`, a real difference between
  this SDK's own RFC3339 output and the conformance vectors' RFC3339 input)
  would silently break every signature in the certificate. See that type's
  class docs for the full rationale -- this is the one place in this
  package's public surface where an `Instant` would have been more
  "idiomatic" but actively wrong.

## Android

Out of scope for this project, per the design doc's language matrix row for
Kotlin/JVM: "Android provider availability needs separate verification."
This SDK targets JDK 17's `SunEC`/`SunJCE` providers directly (via the Java
SDK it depends on); Android's own crypto provider stack (Conscrypt/BoringSSL,
a different minimum API level per Android version, no guaranteed raw
Ed25519/X25519 key import) has not been verified and would need its own
investigation before this SDK could be recommended on Android. Do not assume
this project works unmodified in an Android build.

## Running tests

```sh
source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
cd sdks/local-rp/kotlin
gradle test
```

This exercises, through this package's own public API only:

- all four `envelopes.json` positive cases and all twenty negative cases
- both `callback_box.json` suite positive cases and all thirteen negative cases
- every `dns.json` valid/invalid TXT-record case for both record types
- both `expirations.json` sections (`check_expirations`' eleven threshold
  cases via a real generated identity, and `check_timestamps`' four
  skew-boundary cases)
- both `keys.json` fingerprint/X25519-derivation checks
- all nine `revocations.json` certificate cases plus its application case
  (a revocation certificate must be *applied* to the fetched key set, not
  merely verified)
- the single `tickets.json` hash-pair case (times however many fixture
  tickets are present)
- both `url_params.json` round-trip cases and both negative cases
- an end-to-end fake-IDP flow test (`FlowTest`) covering the happy path plus
  seven rejection scenarios (wrong audience, wrong issuer, nonce mismatch,
  expired payload, DNS pin mismatch, revoked signing key, tampered claim
  signature)
- `Begin`/`Identity` surface-level unit tests

Nothing outside `sdks/local-rp/kotlin/` is modified by this project; the
dependency on `../java` (via `settings.gradle`'s `includeBuild`) is read-only.
