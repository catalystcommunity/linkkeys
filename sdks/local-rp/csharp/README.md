# linkkeys-local-rp (C#/.NET)

C#/.NET SDK for LinkKeys' DNS-less local RP identity mode. Read
`dns-less-local-rp-design.md` at the repo root first — this package implements its "SDK
API Shape" section verbatim, C#-idiomatically adapted, and follows the same wire
construction the Rust/Go/TypeScript/Java reference SDKs use.

This mode lets a locally-installed app (a LAN jukebox, a desktop tool, a self-hosted
service with no public DNS) use LinkKeys for login without running its own DNS-pinned
relying party. The app's identity is the fingerprint of a locally-generated Ed25519
signing key (SSH-host-key style), not a domain.

## Requirements

- **.NET 8 SDK**, via the shared `catalyst-tools` bundle:

  ```sh
  source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
  cd sdks/local-rp/csharp
  dotnet test
  ```

- **`openssl` CLI** on `PATH` — test-scope only, used by `FlowTests` to mint a
  self-signed Ed25519 certificate for the fake IDP's TLS listener, and to actually
  *run* that TLS listener as an external process (see "Why an external `openssl
  s_server` instead of an in-process TLS server" below). Never a runtime dependency.
- One runtime NuGet dependency: `NSec.Cryptography`. Everything else is BCL or
  hand-rolled — see "Dependency justifications" below.

## Quickstart

```csharp
using LinkKeys.LocalRp;

// Once, at install/setup time — persist the returned bytes with ordinary
// application-secret care (see Identity's class docs).
var identity = Identity.GenerateLocalRpIdentity(
    new Identity.GenerateLocalRpIdentityConfig("My LAN Jukebox", DateTimeOffset.UtcNow));
byte[] storedBytes = Identity.LocalRpIdentityToBytes(identity);

// Later, per login attempt:
var reloaded = Identity.LocalRpIdentityFromBytes(storedBytes);
var begun = Begin.BeginLocalLogin(new Begin.BeginLocalLoginConfig(
    reloaded, "http://jukebox.lan:8080/auth/callback", "example.com", DateTimeOffset.UtcNow));
// App: persist begun.Pending (e.g. in a server-side session), then redirect the
// browser to begun.Redirect.RedirectUrl.

// On callback (app's HTTP handler received `arrivedUrl` with an `encrypted_token=`
// query parameter):
var config = new Complete.CompleteLocalLoginConfig(
    reloaded, begun.Pending, encryptedToken, arrivedUrl, DateTimeOffset.UtcNow);
var verified = Complete.CompleteLocalLogin(config);
// `verified` carries user id/domain, claims, domain keys used, the local RP
// fingerprint, and expirations — session creation, local user records, and
// authorization are all the app's own responsibility.
```

## Project layout

```text
src/LinkKeys.LocalRp/
  Crypto/      NSec.Cryptography (Ed25519, X25519) + BCL (AES-GCM, ChaCha20-Poly1305,
               HKDF, SHA-256, CSPRNG) crypto adapter
  Dns/         Hand-rolled DNS TXT client (_linkkeys / _linkkeys_apis), key pinning/vouching
  Rpc/         CSIL-RPC envelope, TLS pinning, TCP transport seam
  Wire/        Hand-written CBOR codec + wire types (see "Hand-written codec" below)
  LocalRp.cs         Pure protocol helpers: envelopes, callback sealed box, checks
  Claims.cs          Claim signature verification (+ sign helper for test fixtures)
  Revocation.cs      Sibling-signed key revocation certificate verification
  Identity.cs        GenerateLocalRpIdentity + byte storage helpers
  Begin.cs           BeginLocalLogin
  Complete.cs        CompleteLocalLogin (the full verification chain)
  LinkKeysLocalRp.cs Facade: default seams, CheckExpirations
  UrlEncoding.cs     URL-param (base64url-unpadded) helpers
  *Error.cs, SdkException.cs   Typed errors
tests/LinkKeys.LocalRp.Tests/
  TestUtil/          Fixture loader (System.Text.Json), openssl cert minting, fake-IDP harness
  *ConformanceTests.cs   One test class per sdks/local-rp/conformance/*.json file
  FlowTests.cs       End-to-end tests against a real (fake-identity) TLS+CSIL-RPC IDP
  BeginTests.cs, IdentityTests.cs   SDK-surface unit tests
```

## Dependency justifications

Per `AGENTS.md`: "every dependency is a liability... prefer standard library where
reasonable."

- **`NSec.Cryptography`** (runtime dependency): the BCL has *no* Ed25519 or X25519
  support at all — `System.Security.Cryptography.ECDiffieHellman`/`ECDsa` are
  NIST-curves-only (P-256/P-384/P-521), and there is no Ed25519/X25519 type anywhere in
  the BCL as of .NET 8. NSec wraps libsodium and is the design doc's own recommendation
  for this row of the Language Crypto Matrix. This is the SDK's only runtime NuGet
  dependency.
- **BCL `AesGcm` / `ChaCha20Poly1305` (NOT NSec's AEAD)**: NSec's own AES-256-GCM
  binding is gated on hardware AES-NI support and throws/reports unavailable without it
  (per the design doc's language matrix note). The BCL's `AesGcm`/`ChaCha20Poly1305` go
  through OpenSSL on Linux (`System.Security.Cryptography.Native.OpenSsl`) with no such
  gate. `ChaCha20Poly1305.IsSupported` is checked at runtime before use
  (`Crypto.IsSuiteSupported`); **on this development box it reports `true`** (OpenSSL
  3.6.3-backed), so the optional suite's conformance vectors (`callback_box.json`'s
  `chacha20-poly1305` positive case) are fully exercised, not skipped. If a target
  runtime reports `false`, `Crypto.AeadEncrypt`/`AeadDecrypt` throw a clear
  `CryptoException` naming the unsupported suite rather than silently miscoding.
- **BCL `HKDF`**: `System.Security.Cryptography.HKDF.DeriveKey` implements RFC 5869
  directly; no gap to fill (unlike Java on JDK 17, which had to hand-roll it). Verified
  against NSec's own `HkdfSha256` algorithm (both implementations of the same RFC) and
  against the checked-in conformance vectors' `kdf_context_hex`.
- **BCL `SHA256`, `RandomNumberGenerator`**: no gap.
- **DNS TXT resolution: hand-rolled UDP/TCP client, not a NuGet package.** The BCL's
  `System.Net.Dns` resolves only A/AAAA/PTR — there is no TXT lookup in the BCL at all.
  The design doc offers two options for C#: the `DnsClient` NuGet package, or a
  hand-rolled minimal UDP DNS TXT query reading `/etc/resolv.conf`. This SDK already
  carries exactly one justified runtime dependency (NSec, for a curve the BCL genuinely
  cannot do); a DNS TXT query is a small, stable, 1980s-vintage wire format (RFC 1035
  §4) — build a query, parse a header plus one answer section, handle name-compression
  pointers and the truncation-then-TCP-retry case. `Dns/SystemDnsResolver.cs` is ~300
  lines total including RFC1035 comments. Taking a general-purpose DNS client library
  dependency for exactly one record type did not clear AGENTS.md's bar; hand-rolling
  did. It supports EDNS0 (advertising a 4096-byte UDP payload) and falls back to TCP on
  a truncated UDP response, matching real resolver behavior.

## Zero-dependency test tooling

`System.Text.Json` (BCL, shipped in the `net8.0` shared framework — no package
reference needed) reads the conformance JSON fixtures directly, unlike the Java SDK
(which had to hand-write a JSON parser because JCA has none and a JSON library would
have been an unjustified test dependency). xUnit is the only test-scope package
(standard for `dotnet new xunit`).

## NSec / BCL split and the low-order X25519 case

- **Ed25519 sign/verify, X25519 key agreement**: NSec.Cryptography, raw key
  import/export via `KeyBlobFormat.RawPrivateKey`/`RawPublicKey` — NSec accepts raw
  32-byte keys directly (no EdEC/XDH point-decoding footgun the way JCA on Java 17
  requires; see the Java SDK's README for that pain point, which C# simply does not
  have).
- **AEAD/HKDF**: BCL (`AesGcm`, `ChaCha20Poly1305`, `HKDF`) as justified above.
- **Deriving an X25519 public key from only a private scalar** (needed when opening the
  callback sealed box, which must feed its own public key into the KDF/AAD from only its
  private key): NSec has no direct "scalar → point" primitive, so
  `Crypto.DerivePublicFromX25519Private` runs a key agreement against the fixed RFC 7748
  base point (`u = 9`) as the "peer public key" — scalar multiplication by the base
  point is exactly what that agreement computes. The same trick the Java SDK uses via
  JCA; verified byte-for-byte against `keys.json`'s `private_key_hex`/`public_key_hex`
  pairs.
- **Low-order X25519 rejection**: a runtime spike (see the design-doc-mandated
  investigation before implementing) confirmed NSec's libsodium-backed
  `KeyAgreementAlgorithm.Agree` rejects an all-zero/low-order public key *itself*, at the
  C layer, by returning `null` rather than an all-zero `SharedSecret` — it never even
  hands back bytes to inspect. `Crypto.X25519DiffieHellman` treats a `null` result
  identically to an explicit all-zero-bytes check (kept as defense in depth in case a
  future NSec version changes that behavior), so rejection is uniform either way. This
  matches `callback_box.json`'s `low_order_ephemeral_key_rejected` negative case, which
  passes.

## Hand-written codec (pending a csilgen C# target)

**No csilgen generator targets C# today** — see the filed request,
`~/repos/catalystcommunity/csilgen/docs/csilgen-requests/csharp-target-does-not-exist.md`.
Every type and the CSIL-RPC envelope itself in the `Wire`/`Rpc` namespaces is therefore
hand-written rather than generated, and clearly marked as such in each file's docs. Two
things make this tractable and safe, exactly mirroring the Java SDK's approach:

1. **Canonical CBOR map ordering is a sort, not manual bookkeeping.** `Wire/Cbor.cs`'s
   encoder always sorts map entries by the bytewise lexicographic order of their
   *encoded* keys (RFC 8949 §4.2.1) at encode time, rather than requiring each
   hand-written type's field-declaration order to already match canonical order. This
   one sort rule, verified once, is what makes ~20 hand-written wire types safe without
   csilgen.
2. **Every wire type and the RPC envelope are byte-verified against the checked-in
   conformance vectors**, not merely internally self-consistent — see the
   `*ConformanceTests` classes.

If csilgen gains a C# target, this SDK's `Wire`/`Rpc.RpcEnvelope` namespaces should be
replaced by the generated equivalent; `LocalRp`, `Claims`, `Revocation`, `Identity`,
`Begin`, `Complete` (the actual protocol logic) stay as hand-written SDK runtime code,
matching every other language's split.

## TLS pinning and the Ed25519-SPKI extraction on .NET

`Rpc/TlsPinning.cs` installs an all-accepting `RemoteCertificateValidationCallback` to
get past .NET's WebPKI chain validation (there is no CA chain for a domain's TCP-service
certificate to begin with), then **mandatorily**, before any application data is
exchanged, recomputes the peer certificate's raw Ed25519 public-key fingerprint and
requires it to be a member of the DNS-pinned set. The pin, not the chain, is the trust
anchor.

Per the design doc: "System.Security.Cryptography.X509Certificates may not parse
Ed25519 public keys into key objects — work at the DER byte level like the Java SDK
does." A runtime spike found the practical shape of that gap on .NET 8: `X509Certificate2.PublicKey.Oid`
*does* recognize the Ed25519 OID (`1.3.101.112`), but
`PublicKey.ExportSubjectPublicKeyInfo()` throws `CryptographicException: ASN1 corrupted
data` for an Ed25519 key on this runtime. The legacy `X509Certificate.GetPublicKey()`
API does **not** hit that bug — for an Ed25519 certificate it returns exactly the 32 raw
public-key bytes (RFC 8410's SubjectPublicKey BIT STRING content has no further DER
wrapping, unlike RSA/DSA), the same bytes the Java SDK recovers by manually stripping a
fixed 12-byte SPKI DER prefix. `TlsPinning.CertFingerprint` therefore calls
`GetPublicKey()` directly and requires exactly 32 bytes, rather than hand-parsing SPKI
DER — .NET already hands back the post-prefix bytes through that older API.

## Why an external `openssl s_server` instead of an in-process TLS server (FlowTests)

Every other reference SDK's flow test runs an in-process TLS server presenting a real
Ed25519 certificate. A runtime spike found that .NET 8 cannot do this **at all**, not
merely awkwardly: `X509Certificate2.CreateFromPemFile` throws
`CryptographicException: '1.3.101.112' is not a known key algorithm` when given an
Ed25519 private key — there is no BCL type that can hold an Ed25519 private key for TLS
signing purposes, so `SslStream` has no way to present one as a server certificate. (The
*client* side is unaffected and is this SDK's actual production code path: a .NET
`SslStream` client completes a real TLS 1.3 handshake against an
`openssl s_server`-terminated Ed25519 certificate without issue, confirmed separately —
`TlsPinning`/`RpcClient`/`StreamFraming` all run for real, unmodified, in every
`FlowTests` scenario.)

`tests/LinkKeys.LocalRp.Tests/TestUtil/FakeIdp.cs` documents the resulting design in
full: single-shot `openssl s_server -naccept 1` processes (one per expected RPC call,
since this SDK's own `RpcClient` opens a fresh TLS connection per call anyway), each
preloaded via stdin with its exact framed CSIL-RPC response, on its own loopback port; a
call-order-aware fake `IDnsResolver` advertises the next port on each successive
`_linkkeys_apis` TXT lookup. This is a test-harness artifact (a real domain has one
stable `tcp=` endpoint), not a protocol concept — documented at the one place it matters
so it's never mistaken for one.

## App responsibilities

SDKs must not own application storage, sessions, database writes, or local user
authorization (design doc). Concretely:

- **Key material**: persist the bytes from `Identity.LocalRpIdentityToBytes` with
  ordinary application-secret care (same tier as a database credential or API key) —
  see `Identity`'s class docs.
- **`Begin.PendingLogin`**: persist it (e.g. in a server-side session tied to the
  browser) between `BeginLocalLogin` and `CompleteLocalLogin`, and discard it after one
  completion attempt. This SDK owns no storage and cannot enforce single-use itself.
- **Sessions, local user records, authorization**: entirely the app's. This SDK returns
  verified protocol facts; it never creates a session or writes to an app database.

## Security notes

- Revoking this local RP identity at the IDP kills future logins *and* any outstanding
  claim tickets immediately (redemption re-checks approval status every time) — but it
  does **not** reach into sessions the app already minted from a prior successful login.
  Session lifecycle is the app's to manage.
- Key rotation is not a continuity operation: generating a new identity means a new
  fingerprint and re-approval at every LinkKeys domain. There is no "same app, new key"
  story in this protocol version.
- Domain keys and revocations fetched over the network are only ever trusted after DNS
  `fp=` pinning (`Rpc/RpcClient.cs`, `Dns/Dns.cs`) — an unpinned/unauthenticated key can
  never reach the verification chain.
- `Rpc/TlsPinning.cs` installs an all-accepting TLS validation callback to get past
  .NET's WebPKI chain validation (there is no CA chain for a domain's TCP service
  certificate to begin with), then **mandatorily**, before any application data is
  exchanged, recomputes the peer certificate's SPKI fingerprint and requires it to be a
  member of the DNS-pinned set. The pin, not the chain, is the trust anchor — see that
  class's docs for the full rationale.
- The default DNS resolver (`Dns/SystemDnsResolver.cs`) reads `/etc/resolv.conf` (the
  OS-configured resolver by default, or explicit servers if configured); LAN resolver
  spoofing is an accepted, documented tradeoff for this mode (design doc, "Decided").
  Inject a hardened `IDnsResolver` if your deployment needs more.
- The default `ITransport` (`Rpc/StdTransport.cs`) is **permissive** by address policy
  (dials private/loopback/LAN addresses) by design — that is the entire point of this
  mode. `AddressPolicy.PublicOnly` is available as an opt-in for integrators who want a
  stricter posture.
- None of this SDK's exception types carry key material, nonces, tokens, tickets, or
  claim values in their messages.

## Running tests

```sh
source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
cd sdks/local-rp/csharp
dotnet test
```
