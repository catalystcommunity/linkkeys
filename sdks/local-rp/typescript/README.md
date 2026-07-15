# @linkkeys/local-rp (TypeScript / Node)

TypeScript/Node SDK for LinkKeys' **DNS-less local RP identity** mode — see
`dns-less-local-rp-design.md` at the repo root for the full design; this
package implements its "SDK API Shape" section. It lets a locally installed
app (a LAN jukebox, a desktop tool, a self-hosted service with no public DNS)
use LinkKeys for login without running its own DNS-pinned relying party. The
app's identity is the fingerprint of a locally-generated signing key
(SSH-host-key style), not a domain.

## Node only — the browser is explicitly NOT a target

Quoting the design doc's own language matrix directly, because it should not
be softened:

> Node `crypto` covers Ed25519, X25519, AES-GCM, HKDF, and randomness. **The
> browser is not a target.** Browser-based RP identities are an incredibly
> stupid idea and you should never do them: it would mean the RP private key
> lives in browser storage. Anyone who insists can compile liblinkkeys to
> WASM in a real language and own the consequences.

This package targets Node's `node:crypto`, `node:net`, `node:tls`, and
`node:dns` directly. It does not run in a browser, is not bundled for one,
and there is no supported path to make it do so. If your app is itself a
browser-facing web app, this SDK still runs on your **server**; the browser
only ever carries opaque signed/encrypted blobs through redirects (see the
design doc's "The Browser Is Only a Carrier").

## Quickstart

```ts
import {
  generateLocalRpIdentity,
  beginLocalLogin,
  completeLocalLogin,
  localRpIdentityToBytes,
  localRpIdentityFromBytes,
} from "@linkkeys/local-rp";

// Once, at install/setup time — persist the returned bytes with ordinary
// application-secret care (see "Security notes" below).
const identity = generateLocalRpIdentity({
  appName: "My LAN Jukebox",
  now: new Date(),
});
const storedBytes = localRpIdentityToBytes(identity);
// ... write `storedBytes` to your app's secret/config store ...

// Later, per login attempt:
const restored = localRpIdentityFromBytes(storedBytes);
const { redirect, pending } = beginLocalLogin({
  keyMaterial: restored,
  callbackUrl: "http://jukebox.lan:8080/auth/callback",
  userDomain: "example.com", // the LinkKeys domain the user selected/entered
  now: new Date(),
});
// Persist `pending` (it's plain JSON-serializable data — put it in a
// server-side session tied to the browser), then redirect the user's
// browser to `redirect.redirectUrl`.

// On callback, your app's HTTP handler receives a request whose query
// string carries `encrypted_token=<...>`. Pass the request's full URL and
// that parameter's raw value to completeLocalLogin:
const verified = await completeLocalLogin({
  keyMaterial: restored,
  pending,
  encryptedToken, // the encrypted_token query-parameter's value
  arrivedUrl, // the full URL the request actually arrived at
  now: new Date(),
});
// verified.userId, verified.userDomain, verified.claims, ... — session
// creation, local user records, and authorization are all your app's job.
```

## App responsibilities (what this SDK deliberately does NOT do)

Per the design doc: *"SDKs must not own application storage, sessions,
database writes, or local user authorization."* Concretely, the app owns:

- **Key material** (`LocalRpKeyMaterial` / the bytes from
  `localRpIdentityToBytes`): persist it wherever the app stores its own
  secrets/configuration, with the care described below.
- **`PendingLogin`**: persist it between `beginLocalLogin` and
  `completeLocalLogin` (it's a plain object of strings, so any
  session/serialization format works — `JSON.stringify` needs no special
  handling), and **discard it after one completion attempt**. This package
  owns no storage and cannot enforce single-use itself — replay protection
  at the app boundary is the app's responsibility.
- **Sessions, local user records, authorization decisions**: entirely the
  app's, using the verified facts this SDK returns.
- **Redirecting the browser**: `beginLocalLogin` returns a URL; it never
  performs an HTTP redirect, opens a browser, or otherwise assumes how your
  app is shaped (server-rendered web app, LAN web UI, desktop app driving an
  embedded browser view, etc.).

## Security notes

- **Key storage**: the private key fields inside `LocalRpKeyMaterial` don't
  directly identify a user, but they control this app's entire local RP
  identity — anyone holding them can sign login requests and redeem claim
  tickets as this app. Store them with ordinary application-secret care (the
  same tier as a database credential or API key), not merely as
  configuration.
- **The raw-key-import footgun, and how this package avoids it**: Node's
  `crypto` module does not accept raw 32-byte Ed25519/X25519 keys directly.
  This package wraps a raw private key (seed) in the fixed, well-known PKCS8
  DER prefix for that curve (RFC 8410) before calling
  `crypto.createPrivateKey` — critically, PKCS8 import needs only the
  private scalar, so a bare 32-byte seed loaded back from storage (this
  package's own "Byte Storage Helpers" format) imports cleanly without also
  needing a bundled public key. The equivalent JWK-import path was evaluated
  and rejected: Node's JWK private-key import for OKP curves requires both
  `d` and `x`, which doesn't fit "just a stored seed." See `src/crypto.ts`'s
  module docs for the full writeup and the conformance-vector verification
  this approach was checked against before the rest of the SDK was written.
- **TLS pinning, and why `rejectUnauthorized: false` is safe here**:
  LinkKeys domain certificates are self-signed by design — there is no CA to
  validate against. The trust anchor is the DNS `_linkkeys` TXT record's
  `fp=` set: SHA-256 hex over the certificate's SubjectPublicKeyInfo
  `subject_public_key` BIT STRING contents (the raw Ed25519 public key),
  exactly as `crates/linkkeys/src/tcp/tls.rs` pins the existing
  server-to-server path. WebPKI chain-of-trust validity is simply not the
  question this protocol asks; **the pin IS the trust anchor**. This package
  connects with `rejectUnauthorized: false` (there being no CA to check) and
  replaces that check with a **mandatory manual pin verification**
  (`src/rpc.ts`'s `verifyPeerCertificatePin`) performed immediately after the
  TLS handshake and before any RPC bytes are sent: it also checks the
  certificate's own validity window (`notBefore`/`notAfter`), mirroring
  `crates/linkkeys-rpc-client/src/tls.rs`'s client-side verifier. The public
  key is extracted via `crypto.X509Certificate` (not
  `TLSSocket#getPeerCertificate().pubkey`, which is empirically `undefined`
  for Ed25519 certificates in Node) — see `src/rpc.ts`'s module docs.
- **Revocation semantics**: revoking this local RP identity at a LinkKeys
  domain stops future logins there and kills that RP's outstanding claim
  tickets immediately (redemption re-checks approval status on every call).
  It does **not** reach into sessions the app already minted from a prior
  successful login — session lifecycle is the app's to manage.
- **No key continuity / rotation**: generating a new identity means a new
  fingerprint and re-approval at every LinkKeys domain that should allow the
  app. There is no "same app, new key" continuity story in this protocol
  version — see the design doc's "One Signing Key and One Encryption Key".
- **Network trust anchor**: domain public keys and revocation certificates
  fetched over the network (`src/rpc.ts`) are only ever trusted after DNS
  `fp=` pinning — an unpinned/unauthenticated key can never reach the
  verification chain. The default DNS resolver is Node's stdlib
  `dns.promises` (the OS-configured system resolver); LAN resolver spoofing
  is an accepted, documented tradeoff for this mode (the design doc's
  "Decided" section). Inject a hardened `DnsResolver` (e.g. a DoH client) if
  your deployment needs more.
- **Address policy**: the default `Transport` (`NodeTransport`) dials
  whatever address DNS returns, including private/loopback/LAN addresses —
  that is the entire point of this mode (a LAN box talking to wherever
  `_linkkeys_apis` points). Construct `new NodeTransport({ policy:
  "public-only" })` to opt into a stricter SSRF-guard posture if your
  deployment wants it; nothing in this package applies that restriction by
  default.
- **Expiration**: `checkExpirations(identity, now)` reports `"notice"` (180
  days remaining), `"warning"` (90 days), `"critical"` (30 days), and
  `"expired"` thresholds as facts — this package never blocks a login or
  forces rotation on its own; that decision is the app's.
- **Claim-signer fan-out cap**: `completeLocalLogin` bounds the number of
  distinct claim-signer domains it will fetch keys for per completion
  (`MAX_CLAIM_SIGNER_DOMAINS` in `src/complete.ts`) — a compromised home IDP
  cannot use an unbounded claim-signature domain list to drive this SDK into
  making arbitrary outbound DNS/TCP calls before a single signature is
  checked.

## Zero runtime dependencies

Crypto is `node:crypto` only (Ed25519, X25519, AES-256-GCM,
ChaCha20-Poly1305, HKDF-SHA256, SHA-256, CSPRNG bytes). Networking is
`node:net`/`node:tls`/`node:dns`. The CSIL-RPC envelope codec is a small,
hand-maintained, zero-dependency reference implementation vendored from
`catalystcommunity/csilgen`'s `transports/typescript` (see
`src/vendor/csilgen-transport/`) — the same pattern the Rust SDK uses for
its own `csilgen-transport` dependency, just vendored as source instead of a
crate. `typescript`/`@types/node` are devDependencies only (typechecking),
never a runtime dependency.

## Generated code

`src/generated/{types.gen.ts,codec.gen.ts}` are generated by csilgen:

```sh
csilgen generate --input csil/linkkeys.csil --target typescript-typesonly \
  --output sdks/local-rp/typescript/src/generated
```

`typescript-typesonly` was chosen over the bare `typescript` target (which
also emits a server router and an RPC client wrapper) because, like the Rust
SDK, this package hand-rolls its own CSIL-RPC calls over an injectable
`Transport`/`DnsResolver` seam rather than using a generated client — the
generated client would otherwise need to embed a transport-level default
this SDK must not have (see Wire Precision's "SDK endpoint discovery and
pinning": the generated CSIL-RPC client pattern is right for HTTP typed
clients, but this mode's TCP path needs address-policy control the
generated client doesn't expose). Never hand-edit these two files — fix the
generator or the CSIL instead, and file a request in
`~/repos/catalystcommunity/csilgen/docs/csilgen-requests/` for anything
that's wrong or missing.

## Testing

```sh
cd sdks/local-rp/typescript
npm install   # once, for the typescript/@types/node devDependencies
npm test      # node --test test/*.test.ts
npm run typecheck   # tsc --noEmit
```

- `test/conformance.test.ts` consumes every file under
  `sdks/local-rp/conformance/` (keys, envelopes, callback_box, url_params,
  dns, tickets, expirations, revocations), positive and negative cases,
  exercising this package's own wrappers — including all nine
  revocation-certificate cases with exact counted-signer assertions and the
  application case proving a valid certificate flips the target key's
  envelope from verifying to failing.
- `test/flow.test.ts` runs `completeLocalLogin`'s full verification chain
  end-to-end against a real (but locally spun up) TLS+TCP+CSIL-RPC fake IDP,
  with fake `Transport`/`DnsResolver` implementations injected — a happy
  path plus one test per verification-chain failure (wrong audience, wrong
  issuer, nonce mismatch, expired callback, DNS pin mismatch, revoked
  signing key, tampered claim signature). Its fake IDP's TLS certificate is
  minted with the system `openssl` CLI (Node's stdlib has no
  certificate-issuing API) from a fixed test seed.

Requires the `catalyst-tools` Node (v26+; the package's stated minimum is
Node >=22.18 for native TypeScript execution):

```sh
source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
```

**Wiring into `tools.sh`** (not modified by this change — report only): a
`test-local-rp-typescript` subcommand should `cd sdks/local-rp/typescript &&
npm install && npm test`.
