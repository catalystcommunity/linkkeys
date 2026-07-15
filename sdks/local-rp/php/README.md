# linkkeys-local-rp (PHP)

PHP SDK for LinkKeys' **DNS-less local RP identity** mode — see
`dns-less-local-rp-design.md` at the repo root for the full design; this
package implements its "SDK API Shape" section. It lets a locally installed
app (a LAN jukebox, a desktop tool, a self-hosted PHP web app — the
archetypal local RP, per the design doc's language matrix) use LinkKeys for
login without running its own DNS-pinned relying party. The app's identity
is the fingerprint of a locally-generated signing key (SSH-host-key style),
not a domain.

Mirrors the Rust reference SDK (`sdks/local-rp/rust/`) and the Python SDK
(`sdks/local-rp/python/`) module-for-module — read those first if you want
the fullest picture; this README notes only where PHP differs.

## Package layout

```
sdks/local-rp/php/
  composer.json
  run-tests.sh          # the test command — see "Running the tests"
  src/
    Generated/
      types.php          # csilgen-generated CSIL value classes (checked in,
      codec.php           # never hand-edited) -- codec.php has a confirmed
                          # generator bug (see "Code generation" below) and
                          # is NOT used by this SDK's runtime; kept checked
                          # in only for reproducibility/record.
    Cbor.php              # hand-written, correct CBOR encode/decode (works
                          # around the codec.php bug -- see its docblock)
    Wire.php               # hand-written CSIL wire-type (de)serialization,
                          # built on Cbor.php + the Generated/types.php
                          # classes (which ARE fine -- only the generated
                          # codec is broken)
    Crypto.php              # Ed25519/X25519/AEAD/HKDF/fingerprint over
                          # ext-sodium + ext-openssl + hash_hkdf()
    Time.php                 # RFC3339 parse/format shared by every module
    LocalRp.php                # pure protocol helpers (envelope sign/verify,
                          # callback seal/open, timestamp/expiration checks)
                          # -- mirrors crates/liblinkkeys/src/local_rp.rs
    Claims.php                  # claim signature/revocation/expiry
                          # verification -- mirrors
                          # crates/liblinkkeys/src/claims.rs
    Revocation.php                # sibling-signed key revocation
                          # certificate verification -- mirrors
                          # crates/liblinkkeys/src/revocation.rs
    Dns.php                        # _linkkeys/_linkkeys_apis TXT parsing,
                          # key pinning, the DnsResolver seam +
                          # SystemDnsResolver (dns_get_record)
    Tls.php                         # SPKI-fingerprint TLS pinning (the
                          # trust anchor for every TCP peer this SDK talks
                          # to)
    Transport.php                    # the TCP dial seam + AddressPolicy
    Rpc.php                           # CSIL-RPC framing + fetchDomainKeys /
                          # redeemClaimTicket
    Encoding.php                       # base64url-unpadded URL-parameter
                          # helpers
    Identity.php                       # generateLocalRpIdentity + byte
                          # storage helpers + checkExpirations
    Begin.php                           # beginLocalLogin
    Complete.php                        # completeLocalLogin (the full
                          # verification chain)
  tests/
    bootstrap.php          # dependency-free autoloader + require of TestKit
    TestKit.php             # tiny assertion/test-registration harness (no
                          # PHPUnit -- see "Running the tests")
    conformance/            # one file per conformance vector JSON file
    fixtures/               # fake-IDP test doubles (FakeRpc.php,
                          # tls_server.php)
    FlowTest.php             # fake-IDP end-to-end flow tests
    TlsPinningTest.php        # real-certificate SPKI pin-check tests
    CborTest.php, IdentityTest.php, BeginTest.php
```

## Environment / extension requirements

- PHP **>= 8.1** (uses typed properties, enums-adjacent `const`-based
  registries, `str_starts_with`/`str_contains`, constructor property
  promotion is NOT required so 8.1 is the floor, not 8.0).
- `ext-sodium` — Ed25519 sign/verify, X25519 ECDH, ChaCha20-Poly1305 AEAD.
  Bundled with PHP since 7.2; essentially always present.
- `ext-openssl` — AES-256-GCM AEAD (deliberately NOT via sodium — see
  `src/Crypto.php`'s class docblock for why) and TLS pin verification.
- `ext-hash` — `hash_hkdf()` (HKDF-SHA256) and SHA-256 fingerprinting.
- The `openssl` **CLI** binary on `PATH` — only needed to run
  `tests/TlsPinningTest.php`, which mints a real Ed25519 X.509 certificate
  (PHP's `openssl` extension has no certificate-*issuing* API). Not required
  to use the SDK itself.

Composer is optional. `composer.json` is provided (classmap autoload, since
several files declare more than one class — see its comment) for projects
that already use Composer, but nothing in this package or its tests
requires it: `tests/bootstrap.php` is a small dependency-free autoloader
used by every test file, and app code can `require` the files under `src/`
directly (respecting load order: `Cbor.php` and `Generated/types.php`
before anything that uses them — or just `require` every file, as
`bootstrap.php` does; there are no circular requires).

## Running the tests

No PHPUnit dependency (Composer may not be installed on the target system —
design doc, "SDK Layout and Tooling" — and this package targets plain
system PHP first). `tests/TestKit.php` is a ~70-line assertion/registration
harness; every test file is a plain, directly-executable PHP script.

```sh
cd sdks/local-rp/php
./run-tests.sh
```

If system PHP isn't available, run the same script inside a container
(verified working with the official `php:8.3-cli` image, which already
bundles `ext-sodium`/`ext-openssl`/`ext-hash` and the `openssl` CLI):

```sh
cd sdks/local-rp
sudo nerdctl run --rm -v "$(pwd)":/repo -w /repo/php php:8.3-cli ./run-tests.sh
```

This is the command to wire into `tools.sh test-local-rp-php` — per this
task's instructions, `tools.sh` itself is not edited here.

`run-tests.sh` runs, in order: every `tests/conformance/*Test.php` (one per
`sdks/local-rp/conformance/*.json` vector file — the shared, language-agnostic
correctness oracle, positive AND negative cases), `CborTest.php`,
`IdentityTest.php`, `BeginTest.php`, `FlowTest.php` (a fake-IDP end-to-end
happy-path + failure-mode suite, including a hostile-IDP subsection that
proves the security-review fixes below fail closed), and `TlsPinningTest.php`
(a real X.509 certificate + a real, separate-process TLS handshake — see
below). All 147 cases across 14 files pass.

### Security-review hardening (identity binding, `required_claims`, revocation)

A review of the verification chain in `completeLocalLogin` found five gaps,
all now closed (mirrored across every local-RP SDK; see
`dns-less-local-rp-design.md`, "Post-implementation security review"):

1. **Identity source.** The verified identity `completeLocalLogin` returns is
   always `payload.user_id`/`payload.user_domain` from the signed,
   envelope-verified, issuer-bound callback payload — never the unsigned
   ticket-redemption response. The redemption response's `user_id`/
   `user_domain` are asserted equal to the payload's (fatal on mismatch,
   `LocalRpError::REDEMPTION_IDENTITY_MISMATCH`); the verified
   `payload.user_domain` (never the redemption's) is the subject-domain used
   for every downstream per-claim signature check.
2. **Claim ownership.** Every returned claim's `user_id` is asserted equal
   to the verified payload's `user_id` (fatal on mismatch,
   `LocalRpError::CLAIM_OWNERSHIP_MISMATCH`).
3. **`required_claims` enforcement.** `PendingLogin` now retains
   `required_claims` from `beginLocalLogin` (`toArray()`/`fromArray()`
   round-trip it too). `completeLocalLogin` verifies every required claim
   type is present among the *signature-verified* redemption claims — an
   empty or insufficient claim set is fatal
   (`LocalRpError::REQUIRED_CLAIMS_NOT_SATISFIED`), never a silent partial
   success.
4. **Unconditional revocation fetch.** `Rpc::fetchDomainKeys` always fetches
   `get-revocations` for every domain whose keys it uses — never gated on
   the server-advertised `recent_revocations_available` flag — and a
   `get-revocations` RPC/decode error is now fatal (`RevocationFetchError`):
   fail closed rather than verifying against a possibly-stale key set.
5. **Constant-time nonce/state comparison.** `LocalRp::verifyNonceState`
   compares both fields with `hash_equals()`.

### Test-only TLS-pinning bypass is no longer a public static

An earlier revision exposed `Rpc::$tlsDialerOverrideForTesting`, a `public
static` property any code could flip at runtime to globally disable TLS
pinning for the rest of the process. It's gone. In its place,
`src/Transport.php` defines `OpaqueTransport` (a marker interface extending
`Transport`); `Rpc::dialTls()` skips its pinning wrap only for a `Transport`
instance that explicitly implements it. `tests/fixtures/FakeRpc.php`'s
`FakeTransport` is the only implementation, so opting out of pinning now
requires writing and injecting a whole `Transport` — a type-checked,
call-site-visible, per-instance decision instead of a hidden process-global
switch with no audit trail.

### Why `FlowTest.php` fakes the Transport seam but `TlsPinningTest.php` doesn't

PHP's CLI SAPI has no threads, and this environment has no `pcntl`
extension, so a single PHP process cannot run a concurrent background TLS
server the way the Rust/TypeScript reference SDKs' flow tests do. Per the
design doc's conformance section, faking at the `Transport` seam for flow
tests is an accepted simplification *provided the pin-check logic itself is
still unit-tested against a real cert fixture*:

- `FlowTest.php` uses `tests/fixtures/FakeRpc.php` — a custom PHP stream
  wrapper (`fakerpc://`) that decodes a real length-prefixed CSIL-RPC
  request frame synchronously inside `stream_write()` and hands back a real
  encoded response frame for the next `stream_read()`. This exercises the
  SDK's actual CBOR/CSIL-RPC framing and the entire verification chain
  end-to-end; only the TLS handshake and real sockets are skipped, because
  `FakeTransport` implements `OpaqueTransport` (see "Test-only TLS-pinning
  bypass is no longer a public static" above).
- `TlsPinningTest.php` mints a real self-signed Ed25519 certificate with the
  system `openssl` CLI (PKCS8 DER wrapping of a raw 32-byte seed, same
  technique the TypeScript reference SDK uses, since neither language's
  `openssl` bindings can *issue* a certificate) and spawns a genuinely
  separate OS process (`proc_open`, not a thread) running
  `tests/fixtures/tls_server.php` as the real TLS peer. `Tls::dialTlsPinned`
  then performs a real client-side TLS handshake and a real SPKI-fingerprint
  pin check against it — both the accept (correct pin) and reject (wrong
  pin) paths.

## Code generation

Types are generated via:

```sh
csilgen generate --input csil/linkkeys.csil --target php-typesonly \
  --output sdks/local-rp/php/src/Generated/
```

**`php-typesonly` was the right sub-target** to generate from (the other
three — bare `php`, `php-client`, `php-server` — additionally emit a
generated `client.php`/router this SDK doesn't use; see below). When this
SDK was written, the generated `codec.php` had a confirmed bug — every
`[* T]` (list-typed) field's closure referenced an undefined variable,
silently round-tripping every list field as an empty array on both encode
and decode. That csilgen defect has since been fixed upstream and the
checked-in `codec.php` regenerated with the fix.

Per `AGENTS.md` ("Never hand-edit generated files — fix the generator or the
CSIL instead"), `src/Generated/codec.php` is checked in **exactly as
csilgen emits it**, and this SDK's runtime continues to use `src/Cbor.php`
+ `src/Wire.php`'s hand-written CBOR (de)serialization for the ~19 wire
structures it needs (written while the generated codec was broken;
byte-compatible with it now, and pinned by the conformance vectors either
way), reusing the generated `src/Generated/types.php` classes as plain
data holders. Migrating the runtime onto the fixed generated codec is now
possible but optional.

The `php-client` sub-target's generated `client.php` was evaluated too, and
not used, for a second, independent reason: at the time, its per-service
wrapper classes collapsed the verbatim CSIL `service`/`op` names into a
single pre-mangled route string before handing it to the injected
`Transport::call()` seam (the same defect class as the since-fixed
`python-client`/`go-client` issues — the PHP fix landed upstream alongside
them). `src/Rpc.php` hand-builds the two real `CsilRpcRequest`s this SDK needs
directly against `csil-rpc-transport.md`'s wire spec instead, mirroring what
the Rust/Python/Go reference SDKs' own `rpc.rs`/`rpc.py`/`revocation.go`
siblings independently arrived at. (Filed as a csilgen request at the time;
handled upstream since.)

A third, smaller finding at the time: the hand-maintained `csilgen/transport`
Composer package's `Rpc` helper class shipped an envelope shape that didn't
match `csil-rpc-transport.md` v1. (Filed as a csilgen request; handled
upstream since. This SDK's `Cbor.php`/`Rpc.php` remain independent of that
package regardless.)

Regenerate with the command above; the output is fully reproducible and must
never be hand-edited — fix the generator or file a request instead.

## sodium / openssl crypto mapping notes

See `src/Crypto.php`'s class docblock for the full writeup; summary:

- **Ed25519.** This protocol's canonical stored private key is the 32-byte
  seed, but libsodium's own "secret key" is 64 bytes (`seed || public`).
  Every sign/verify operation here expands the seed via
  `sodium_crypto_sign_seed_keypair()` first and always stores/returns only
  the 32-byte seed as "the private key" — the 64-byte libsodium form never
  leaves `Crypto.php`.
- **X25519.** `sodium_crypto_scalarmult_base()` derives the public key from
  a raw 32-byte private scalar; `sodium_crypto_scalarmult()` does ECDH.
  libsodium's `crypto_scalarmult` already rejects an all-zero (low-order)
  result internally (throws `SodiumException`), but `Crypto::rejectLowOrder()`
  also checks explicitly, so behavior does not silently depend on a specific
  libsodium version's internal check alone.
- **AES-256-GCM** is deliberately `ext-openssl`, NOT sodium — sodium's
  AES-256-GCM is AES-NI-hardware-gated and not portable (design doc,
  "Language Crypto Matrix" preamble); OpenSSL's software fallback is
  portable on every build.
- **ChaCha20-Poly1305** uses sodium's IETF variant
  (`sodium_crypto_aead_chacha20poly1305_ietf_*`, 12-byte nonce), which
  matches the conformance vectors and the Rust `chacha20poly1305` crate's
  wire format (`ciphertext || 16-byte tag`) directly.
- **HKDF-SHA256** is `hash_hkdf()`; an empty-string salt is treated as a
  zero-filled block per RFC 5869, matching the Rust `hkdf` crate's
  `Hkdf::new(None, ikm)`.
- **Fingerprint** is `hash('sha256', $bytes)` (lowercase hex by default).
- **TLS SPKI pinning** (`src/Tls.php`): PHP's `openssl_x509_parse()` doesn't
  expose Ed25519 SPKI raw bytes. Per RFC 8410, an Ed25519 SPKI is a fixed
  44-byte DER structure (a constant 12-byte prefix
  `302a300506032b6570032100` followed by exactly the 32 raw public key
  bytes), so `Tls::leafPublicKeyFingerprint()` locates that fixed prefix
  directly in the certificate's DER bytes rather than parsing full ASN.1 —
  this SDK only ever needs to handle Ed25519 leaf certificates, since that
  is the only key type in the LinkKeys TLS trust model.

## App responsibilities (this SDK does NOT do these)

- **Key material storage.** Persist the bytes from
  `Identity::localRpIdentityToBytes()` with ordinary application-secret
  care (same tier as a database credential or API key) — see
  `src/Identity.php`'s class docblock.
- **`PendingLogin` storage and single-use enforcement.** Persist it (e.g. a
  PHP session) between `Begin::beginLocalLogin()` and
  `Complete::completeLocalLogin()`, and discard it after one completion
  attempt. This package owns no storage and cannot enforce single-use
  itself.
- **Sessions, local user records, authorization, database writes.** This
  package returns verified protocol facts (`VerifiedLocalLogin`); it never
  creates a session or writes to an app database.
- **Opening a browser / performing the HTTP redirect.** `Begin::beginLocalLogin()`
  returns a redirect URL; redirecting the actual HTTP response is the app's
  job (e.g. a Symfony/Laravel/plain-PHP `Location:` header).

## Security notes

- Revoking this local RP identity at the IDP kills future logins AND any
  outstanding claim tickets immediately — but does **not** reach into
  sessions the app already minted from a prior successful login.
- Key rotation is not a continuity operation: generating a new identity
  means a new fingerprint and re-approval at every LinkKeys domain.
- Domain keys and revocations fetched over the network are only ever
  trusted after DNS `fp=` pinning (`src/Dns.php`, `src/Rpc.php`) — an
  unpinned/unauthenticated key can never reach the verification chain.
- The default DNS resolver is PHP's own resolver via `dns_get_record()`
  (the OS-configured resolver on most systems); LAN resolver spoofing is an
  accepted, documented tradeoff for this mode (design doc, "Decided"
  section). Inject a hardened `DnsResolver` implementation if your
  deployment needs more.
- The default `Transport` (`StdTransport`) is deliberately **permissive**
  about destination addresses (loopback/private/LAN addresses are exactly
  where `_linkkeys_apis` is expected to point in this mode) — this is a
  documented, intentional difference from the server-side S2S path's SSRF
  guard. Pass `AddressPolicy::PUBLIC_ONLY` to `StdTransport`'s constructor
  if your deployment specifically wants that stricter posture.
