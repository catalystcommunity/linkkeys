# linkkeys_local_rp (Elixir)

Elixir SDK for LinkKeys' **DNS-less local RP identity** mode — see
`dns-less-local-rp-design.md` at the repo root for the full design; this
package implements its "SDK API Shape" section. It lets a locally installed
app (a LAN jukebox, a desktop tool, a self-hosted service with no public DNS)
use LinkKeys for login without running its own DNS-pinned relying party. The
app's identity is the fingerprint of a locally-generated signing key
(SSH-host-key style), not a domain.

Mirrors the Rust reference SDK (`sdks/local-rp/rust/`) and the Python SDK
(`sdks/local-rp/python/`) module-for-module — read those first if you want
the fullest picture; this one notes only where Elixir differs.

## Requirements

- **Elixir 1.17+** (developed/tested against Elixir 1.20.2)
- **Erlang/OTP 29** — specifically requires:
  - `:crypto` with `:eddsa`/`:ed25519`, `:ecdh`/`:x25519`, and
    `:crypto_one_time_aead` support for `:aes_256_gcm` and
    `:chacha20_poly1305` (all standard since OTP 24+; nothing unusual here)
  - `:ssl` for TLS client (and, in the flow tests only, TLS server) sockets
  - `:inet_res` for DNS TXT lookups
  - OTP 27+'s built-in `:json` module (test-support only — see "Testing"
    below)
- **Zero hex dependencies.** Everything above ships in the Erlang/OTP
  standard distribution; `mix.exs` declares no runtime deps.

## Package layout

```
sdks/local-rp/elixir/
  mix.exs
  lib/
    linkkeys_local_rp.ex       # public API surface (delegates)
    linkkeys_local_rp/
      cbor.ex          # hand-written canonical CBOR codec (RFC 8949 §4.2.1)
      types.ex          # hand-written CSIL wire types + to_cbor/from_cbor
      crypto.ex           # Ed25519/X25519/AEAD/HKDF/fingerprint over :crypto
      local_rp.ex           # pure protocol helpers (envelope sign/verify,
                            # callback seal/open, timestamp/expiration checks)
                            # -- mirrors crates/liblinkkeys/src/local_rp.rs
      claims.ex               # claim signature/revocation/expiry verification
                            # -- mirrors crates/liblinkkeys/src/claims.rs
      revocation.ex            # sibling-signed key revocation certificate
                            # verification + application to the trusted set
                            # -- mirrors crates/liblinkkeys/src/revocation.rs
      dns.ex                     # _linkkeys/_linkkeys_apis TXT parsing, key
                            # pinning, the DNS resolver seam + system default
      tls.ex                      # SPKI-fingerprint TLS pinning
      transport.ex                  # the TCP dial seam + address policy
      rpc.ex                          # CSIL-RPC framing + fetch_domain_keys /
                            # redeem_claim_ticket
      encoding.ex                      # base64url-unpadded URL-parameter
                            # helpers
      timeutil.ex                        # RFC3339 parse/format
      identity.ex                          # generate_local_rp_identity +
                            # byte storage helpers
      begin.ex                              # begin_local_login
      complete.ex                            # complete_local_login (the full
                            # verification chain)
  test/
    support/vectors.ex        # conformance-vector JSON loader (uses :json)
    conformance_*_test.exs    # one file per conformance vector JSON file
    flow_test.exs              # fake-IDP end-to-end flow tests
```

## No csilgen Elixir target (yet)

There is no `csilgen` target for Elixir, unlike Rust/Go/TypeScript/Python.
`lib/linkkeys_local_rp/cbor.ex` and `lib/linkkeys_local_rp/types.ex` are
therefore hand-written where every sibling SDK gets the equivalent code
generated. Both are clearly marked as such in their module docs and are
verified byte-for-byte against `sdks/local-rp/conformance/` (every struct's
canonical field encoding, every envelope signature input, and the callback
sealed-box KDF/AAD construction were checked against the fixed conformance
vectors before being relied on — see "Crypto and CBOR verification" below).

A request for an `elixir`/`elixir-client` csilgen target has been filed at
`~/repos/catalystcommunity/csilgen/docs/csilgen-requests/elixir-target-does-not-exist.md`.
Once available, `cbor.ex`/`types.ex` (and the CSIL-RPC envelope framing
portion of `rpc.ex`) can be dropped in favor of generated output.

## Running the tests

```sh
cd sdks/local-rp/elixir
mix test
```

That's the exact command — no setup step, no dependency install, no
environment variables required (`mix.exs` declares zero deps, and OTP's
`:ssl` application is started automatically by `test/test_helper.exs`).

Test counts as of this writing: **54 passed** — 29 conformance-vector tests
(one file per `sdks/local-rp/conformance/*.json`, positive and negative
cases) + 16 flow tests (happy path + 8 single-step failure modes + 7
hostile-IDP identity/revocation-binding tests) + 9 TLS pin-extraction tests
(`test/tls_test.exs`, fixture-based, `openssl`-independent). No skips, no
`@tag :skip` triggered, as long as `openssl` is on `PATH` (see "Flow tests
and openssl" below) — and even without it, only the 16 flow tests skip;
everything else (including TLS pin extraction) still runs.

## Crypto and CBOR verification

Every non-trivial cryptographic and wire-format claim in this SDK was
verified directly against fixed test vectors *before* being relied on, per
this task's own instructions — not assumed from documentation:

- **Ed25519 sign/verify**: `:crypto.generate_key(:eddsa, :ed25519, seed)` and
  `:crypto.sign(:eddsa, :none, msg, [seed, :ed25519])` /
  `:crypto.verify(:eddsa, :none, msg, sig, [pub, :ed25519])` were checked
  against `conformance/keys.json`'s fixed seed and `conformance/envelopes.json`'s
  real descriptor-envelope signature — byte-exact match.
- **X25519 ECDH**: `:crypto.generate_key(:ecdh, :x25519, priv)` (derive
  public from private) and `:crypto.compute_key(:ecdh, peer_pub, priv,
  :x25519)` were checked against `keys.json`'s `local_rp.encryption`
  fixture and cross-verified both directions (A's shared secret == B's).
  **Important OTP-specific finding**: calling `compute_key` with an
  all-zero (low-order) public key does **not** return an all-zero shared
  secret on OTP 29 — it *raises* an `ErlangError` from the underlying
  `EVP_PKEY_derive` call (`{:error, {~c"evp.c", 189}, ~c"Can't
  EVP_PKEY_derive"}`). `LinkkeysLocalRp.Crypto.x25519_dh/2` normalizes this
  (and, defensively, an actual all-zero result, in case some other
  non-contributory point isn't rejected at the EVP layer) into a single
  `{:error, :low_order_key}` return — verified against
  `callback_box.json`'s `low_order_ephemeral_key_rejected` case.
- **HKDF-SHA256**: the hand-rolled extract/expand over
  `:crypto.mac(:hmac, :sha256, ...)` was checked end-to-end (ECDH -> HKDF ->
  AES-256-GCM decrypt) against `callback_box.json`'s first `aes-256-gcm`
  positive case, reproducing the published `plaintext_cbor_hex` byte-for-byte.
- **AEAD**: `:crypto.crypto_one_time_aead(:aes_256_gcm | :chacha20_poly1305,
  key, iv, plaintext, aad, true)` for encrypt (returns `{ciphertext, tag}`)
  and the 6-arity form with `false` for decrypt (returns the plaintext, or
  the atom `:error` on tag mismatch — not an exception) were both exercised
  directly before use.
- **Canonical CBOR map-key ordering**: `LinkkeysLocalRp.Cbor`'s map encoder
  sorts entries by the bytewise lexicographic order of each key's own
  encoded bytes (RFC 8949 §4.2.1), implemented with an explicit
  byte-by-byte comparator (`compare_bytes/2`) rather than any assumption
  about Erlang/Elixir binary term ordering. Constructing a
  `LocalRpDescriptor` from the raw field values in `envelopes.json`'s
  `descriptor` case and encoding it with this codec reproduces the
  published `payload_cbor_hex` byte-for-byte.
- **OTP's `:json` module**: probed directly (`:json.decode/1`) and used for
  all conformance-vector/test-fixture JSON parsing — no hex dependency, no
  hand-rolled JSON parser needed. One nuance recorded and normalized in
  `test/support/vectors.ex`: `:json.decode/1` maps JSON `null` to the atom
  `:null`, **not** Elixir's `nil`; `Vectors.load/1` recursively normalizes
  `:null` -> `nil` across the decoded tree so ordinary `nil`-based Elixir
  pattern matching works in every test.

## Flow tests and `openssl`

`test/flow_test.exs` spins up a real fake IDP: a loopback TCP+TLS+CSIL-RPC
server presenting a certificate derived from a fixed Ed25519 domain-signing
seed, so the SDK's real `LinkkeysLocalRp.Tls` pin-checking code (not a
stand-in) verifies it against the test's DNS answer. **Confirmed working**:
OTP's `:ssl` accepts and correctly serves/consumes an Ed25519 leaf
certificate on both the server and client sides — verified directly with a
hand-built loopback `:ssl.listen`/`:ssl.connect` pair before writing the
full flow-test harness.

The one piece OTP's `:public_key` doesn't provide as a single call is
"build and self-sign an X.509 certificate" the way `openssl req -x509`
does, so — matching what the task instructions note the TypeScript and Java
SDKs did — this test suite shells out to the `openssl` CLI to mint the
fake IDP's certificate deterministically from a fixed 32-byte seed (via a
hand-built, RFC 8410, 16-byte-fixed-prefix PKCS8 DER wrapper around the raw
seed — verified byte-for-byte against `openssl genpkey -algorithm
ed25519`'s own DER output before relying on it). If `openssl` is not on
`PATH`, every test in `flow_test.exs` is skipped (via `@moduletag skip:
"..."`, computed once at compile time) with a clear reason rather than
failing — the conformance-vector suite (29 tests, including
`LinkkeysLocalRp.LocalRp.open_local_rp_callback/3`'s full sealed-box
decrypt path) and `test/tls_test.exs`'s 9 tests do not depend on `openssl`
at all. `test/tls_test.exs` exercises
`LinkkeysLocalRp.Tls.leaf_public_key_fingerprint/1` (the pin-extraction
logic) directly against real, `openssl`-minted certificate DER bytes
captured once and hardcoded as fixtures in that file — so the ASN.1 walk
and SPKI-fingerprint logic stay covered by real certificate bytes on any
box, with zero `openssl`/live-TLS dependency at test time. This closes what
would otherwise be a real gap: without it, a box lacking `openssl` would
have **zero** coverage of the single most pitfall-prone check in this SDK
(a wrong TLS pin silently accepting an attacker's certificate).

## Code generation

None — see "No csilgen Elixir target (yet)" above.

## App developer responsibilities

Same division of labor as every other LinkKeys SDK — this package returns
verified protocol facts; it never creates a session, writes to an app
database, or manages local user authorization:

- **Key material** (`LinkkeysLocalRp.Identity.LocalRpKeyMaterial` / the
  bytes from `local_rp_identity_to_bytes/1`): persist wherever your app
  stores its own secrets/configuration, with the same care as a database
  credential or API key — anyone holding these bytes can sign login
  requests and redeem claim tickets as your app.
- **`PendingLogin`**: persist it between `begin_local_login/1` and
  `complete_local_login/1` (`LinkkeysLocalRp.Begin.PendingLogin.to_map/1` /
  `from_map/1` give you a JSON-safe round trip for an ordinary session
  store), and **discard it after one completion attempt**. This package
  owns no storage and cannot enforce single-use itself — replay protection
  at the app boundary is your job.
- **Sessions, local user records, authorization decisions**: entirely
  yours, using the verified facts `complete_local_login/1` returns.
- **The redirect itself**: `begin_local_login/1` returns a URL; this
  package never issues an HTTP redirect or opens a browser (a UX decision
  outside its scope — see the design doc's "Browser-only Flow").

### Quickstart

```elixir
alias LinkkeysLocalRp, as: LocalRp

# Once, at install/setup time -- persist the returned bytes with ordinary
# application-secret care.
identity =
  LocalRp.generate_local_rp_identity(app_name: "My LAN Jukebox", now: DateTime.utc_now())

stored_bytes = LocalRp.local_rp_identity_to_bytes(identity)
# ... write stored_bytes to your app's secret/config store ...

# Later, per login attempt:
identity = LocalRp.local_rp_identity_from_bytes(stored_bytes)

{redirect, pending} =
  LocalRp.begin_local_login(
    key_material: identity,
    callback_url: "http://jukebox.lan:8080/auth/callback",
    user_domain: "example.com",
    now: DateTime.utc_now()
  )

# Persist LinkkeysLocalRp.Begin.PendingLogin.to_map(pending) (e.g. in a
# server-side session tied to the browser), then redirect the user's
# browser to redirect.redirect_url.

# On callback, your app's HTTP handler receives a request whose query
# string carries `encrypted_token=<...>`. Pass the request's full URL and
# that parameter's raw value to complete_local_login:
{:ok, verified} =
  LocalRp.complete_local_login(
    key_material: identity,
    pending: pending,
    encrypted_token: encrypted_token,
    arrived_url: arrived_url,
    now: DateTime.utc_now()
  )

# verified.user_id, verified.user_domain, verified.claims, ... -- session
# creation, local user records, and authorization are all your app's job.
```

## API return-value convention

Fallible protocol operations return `{:ok, result}` / `{:error, reason}`
(never raise for ordinary protocol failures — a tampered signature or an
expired timestamp is an expected outcome the app must branch on, not an
exceptional program state): `complete_local_login/1` is the main example.
Pure input-shape violations (a caller passing a 31-byte "32-byte" key, an
empty `app_name`, a `callback_url` with a non-http(s) scheme) raise a typed
exception (`LinkkeysLocalRp.Identity.IdentityError`,
`LinkkeysLocalRp.Begin.BeginLoginError`, etc.), because those indicate an
integration bug in the calling app rather than a protocol-verification
failure. This mirrors ordinary Elixir/OTP convention (`File.read/1` vs.
`File.read!/1`-style reasoning) rather than forcing one uniform scheme
across genuinely different situations.

Transport/DNS seams are plain 1-arity functions (`(host_port -> {:ok,
socket} | {:error, term})` and `(name -> {:ok, [String.t()]} | {:error,
term})` respectively) — the idiomatic Elixir shape for a swappable
capability — rather than behaviours or protocols. Any function of the
right arity/shape can be injected via the `:transport` / `:dns` keys in
`complete_local_login/1`'s config; `LinkkeysLocalRp.Transport.dial/1` and
`LinkkeysLocalRp.Dns.system_resolver/1` are the OTP-backed defaults.

## Security notes

- **Key storage**: see "App developer responsibilities" above.
- **Revocation semantics**: revoking this local RP identity at a LinkKeys
  domain stops future logins there and kills that RP's outstanding claim
  tickets immediately (redemption re-checks approval status on every
  call). It does **not** reach into sessions the app already minted from a
  prior successful login — session lifecycle is the app's to manage.
- **No key continuity / rotation**: generating a new identity means a new
  fingerprint and re-approval at every LinkKeys domain that should allow
  the app. There is no "same app, new key" continuity story in this
  protocol version.
- **Network trust anchor**: domain public keys fetched over the network
  (`LinkkeysLocalRp.Rpc`) are only ever trusted after DNS `fp=` pinning —
  an unpinned/unauthenticated key can never reach the verification chain.
  TLS pinning (`LinkkeysLocalRp.Tls`) verifies the peer certificate's SPKI
  public-key SHA-256 fingerprint against that pinned set — **not** WebPKI
  validity — exactly mirroring `crates/linkkeys/src/tcp/tls.rs`. Every
  LinkKeys domain TLS certificate is generated from an Ed25519 domain
  signing key, so this SDK only ever needs to accept Ed25519 leaf
  certificates; an unexpected key type is rejected outright
  (`LinkkeysLocalRp.Tls.UnsupportedCertificateKeyType`) rather than
  silently trusted.
- **No client TLS certificate**: this SDK never presents a client
  certificate — public domain-key fetch and ticket redemption must not
  require mutual TLS (the redemption request's own signature is the
  possession proof instead).
- **Default DNS resolver**: the OS-configured system resolver via OTP's
  `:inet_res`. LAN resolver spoofing is an accepted, documented tradeoff
  for this mode (the design doc's "Decided" section). Inject a hardened
  resolver function (e.g. a DoH client) if your deployment needs more.
- **Address policy**: the default transport (`LinkkeysLocalRp.Transport.dial/1`)
  dials whatever address DNS returns, including private/loopback/LAN
  addresses — that is the entire point of this mode. Pass `opts:
  [policy: :public_only]` (via a wrapper closure passed as `:transport`)
  to opt into a stricter SSRF-guard posture; nothing in this package
  applies that restriction by default.
- **Expiration**: `check_expirations/2` reports `:notice` (180 days
  remaining), `:warning` (90 days), `:critical` (30 days), and `:expired`
  thresholds as facts — this package never blocks a login or forces
  rotation on its own; that decision is the app's.
- **Claim-signer domain fan-out cap**: `complete_local_login/1` caps the
  number of distinct claim-signer domains it will fetch keys for per
  completion (8) — a malicious/compromised home IDP cannot use an
  attacker-chosen claim set to make this SDK perform unbounded outbound
  DNS/TCP calls (an SSRF/DoS amplification vector).
- **Redemption/claim identity binding**: the ticket-redemption response and
  every returned claim carry no signature of their own — they are trusted
  only because they were fetched over the DNS-pinned TLS channel for the
  domain the SIGNED callback payload named. `complete_local_login/1`
  cross-checks the redemption's `user_id`/`user_domain` and each claim's
  `user_id` against the signature-verified payload's, unconditionally, and
  treats any mismatch as fatal — never a success return. The identity
  `complete_local_login/1` ultimately returns is always sourced from that
  signed payload, never from the redemption response.
- **`required_claims` enforcement**: `PendingLogin` carries the
  `required_claims` set the login was begun with, and
  `complete_local_login/1` re-checks it against only the claims that
  passed full verification (subject binding + signature quorum +
  revocation/expiry) — an empty or insufficient claim set against a
  non-empty requirement is fatal.
- **Constant-time nonce/state comparison**: `LocalRp.verify_nonce_state/4`
  compares the pending login's nonce/state against the callback payload's
  via `Crypto.constant_time_equal?/2` (hand-rolled over `Bitwise`, since
  this package has zero hex dependencies and `Plug.Crypto.secure_compare/2`
  isn't available) rather than binary `==`.

## Revocation certificates

Sibling-signed key revocation certificates
(`crates/liblinkkeys/src/revocation.rs`; conformance authority:
`sdks/local-rp/conformance/revocations.json` + its README section) are
fully supported: `LinkkeysLocalRp.Rpc.fetch_domain_keys/3` **always**
fetches `DomainKeys/get-revocations` — regardless of `get-domain-keys`'s
`recent_revocations_available` flag, which is merely a server-side
optimization hint and never a trust decision this client relies on (a
compromised/malicious IDP could otherwise simply omit or clear that flag to
suppress delivery of a revocation targeting one of its own keys) — and
**applies** every quorum-verified certificate to the trusted key set: the
target key is dropped no matter what its own fetched entry says (its
`revoked_at` may well be unset; that is the whole point of the sibling
channel). Verification semantics (`LinkkeysLocalRp.Revocation`): quorum of
2 distinct, currently-valid sibling signing keys; the target's
self-signature never counts; each signature covers the five-element
`CBOR([tag, target_key_id, target_fingerprint, revoked_at,
signing_domain])` tuple (the older house tuple pattern — NOT the local-RP
two-element envelope framing) recomputed from that signature's own wire
`domain` field; sibling validity is a wall-clock check (`DateTime.utc_now/0`
default, override accepted for tests). Delivery is **fail-closed**: a
`get-revocations` fetch or decode failure fails the whole
`fetch_domain_keys/3` call (and therefore the whole login) — an empty
*list* is a legitimate, successful "nothing revoked" answer, but a failure
to even ask is not, since revocation delivery is exactly the mechanism that
lets a verifier learn a key it would otherwise trust has been compromised.

## Known scope limits / follow-ups

- **Suite negotiation** only supports what the conformance vectors and
  Rust reference SDK exercise (`aes-256-gcm`, `chacha20-poly1305`); no
  other registry entries exist to add.
- No csilgen Elixir target exists yet; see "No csilgen Elixir target
  (yet)" above and the filed request.
- `LinkkeysLocalRp.Transport`'s `:public_only` address policy and
  `LinkkeysLocalRp.Rpc.NoTrustedDomainKeys` are implemented and reachable
  but not independently unit-tested in this pass (the flow tests exercise
  the default `:permissive` policy and the DNS-pin-mismatch path, which
  fails earlier at the TLS layer before that particular error path is
  reached); the underlying protocol properties they exist to enforce are
  covered.
