# linkkeys-local-rp (Rust)

Rust SDK for LinkKeys' **DNS-less local RP identity** mode — see
`dns-less-local-rp-design.md` at the repo root for the full design; this
crate implements its "SDK API Shape" section. It lets a locally installed app
(a LAN jukebox, a desktop tool, a self-hosted service with no public DNS) use
LinkKeys for login without running its own DNS-pinned relying party. The
app's identity is the fingerprint of a locally-generated signing key
(SSH-host-key style), not a domain.

## Layout: why this crate is a workspace member

Unlike the other SDKs under `sdks/local-rp/` (which will stand alone with
their own toolchains, per csilgen's `transports/README.md` precedent), the
Rust SDK joins the main LinkKeys Cargo workspace (`../../../Cargo.toml`).
Reasons, spelled out in this crate's `Cargo.toml`:

- The design doc's own Language Crypto Matrix says it plainly: *"Rust:
  Already liblinkkeys' dependencies; the SDK is largely a wrapper over
  liblinkkeys itself."* There's no cross-language toolchain-isolation reason
  to keep it out of the workspace the way there is for Go/Python/etc.
- It path-depends on `liblinkkeys`, `linkkeys-rpc-client`, and
  `csilgen-transport`, all already workspace members — one `Cargo.lock` keeps
  their versions in lockstep instead of drifting against a second lockfile.
- `cargo test` works identically from this directory or from the repo root
  (`cargo test --workspace`) either way — a workspace member is not a
  standalone-crate tradeoff here.
- This mirrors csilgen's own `transports/rust/` (`csilgen-transport`), which
  its `transports/README.md` explicitly places "in cargo workspace" while
  every other language transport library stands alone.

Run tests either way:

```sh
cd sdks/local-rp/rust && cargo test          # from the crate directory
cargo test -p linkkeys-local-rp              # from the repo root
./tools.sh test-local-rp-rust                # via tools.sh
```

`./tools.sh generate-local-rp-sdks` also exists (layout/tooling parity with
the design doc's proposed command set) but is currently a no-op for Rust —
there is no separate codegen step; this crate consumes `liblinkkeys` (and its
CSIL-generated types) directly as a normal Cargo dependency.

## Quickstart

```rust
use chrono::Utc;
use linkkeys_local_rp::{
    generate_local_rp_identity, begin_local_login, complete_local_login,
    GenerateLocalRpIdentityConfig, BeginLocalLoginConfig, CompleteLocalLoginConfig,
    local_rp_identity_to_bytes, local_rp_identity_from_bytes,
};

// Once, at install/setup time — persist the returned bytes with ordinary
// application-secret care (see "Security notes" below).
let identity = generate_local_rp_identity(
    GenerateLocalRpIdentityConfig::new("My LAN Jukebox", Utc::now()),
)?;
let stored_bytes = local_rp_identity_to_bytes(&identity);
// ... write `stored_bytes` to your app's secret/config store ...

// Later, per login attempt:
let identity = local_rp_identity_from_bytes(&stored_bytes)?;
let (redirect, pending) = begin_local_login(BeginLocalLoginConfig::new(
    &identity,
    "http://jukebox.lan:8080/auth/callback",
    "example.com",   // the LinkKeys domain the user selected/entered
    Utc::now(),
))?;
// Persist `pending` (it derives Serialize/Deserialize — e.g. put it in a
// server-side session tied to the browser), then redirect the user's
// browser to `redirect.redirect_url`.

// On callback, your app's HTTP handler receives a request whose query
// string carries `encrypted_token=<...>`. Pass the request's full URL and
// that parameter's raw value to complete_local_login:
let verified = complete_local_login(CompleteLocalLoginConfig::new(
    &identity,
    &pending,
    &encrypted_token,   // the encrypted_token query-parameter's value
    &arrived_url,        // the full URL the request actually arrived at
    Utc::now(),
))?;
// verified.user_id, verified.user_domain, verified.claims, ... — session
// creation, local user records, and authorization are all your app's job.
```

## Storage and single-use responsibilities this SDK assigns to the app

This SDK returns verified protocol facts. It never creates a session, writes
to an app database, or manages local user authorization — per the design
doc: *"SDKs must not own application storage, sessions, database writes, or
local user authorization."* Concretely, the app owns:

- **Key material** (`LocalRpKeyMaterial` / the bytes from
  `local_rp_identity_to_bytes`): persist it wherever the app stores its own
  secrets/configuration, with the care described below.
- **`PendingLogin`**: persist it between `begin_local_login` and
  `complete_local_login` (it derives `Serialize`/`Deserialize`, so any
  session/serialization format works), and **discard it after one completion
  attempt**. This crate owns no storage and cannot enforce single-use itself
  — replay protection at the app boundary is the app's responsibility.
- **Sessions, local user records, authorization decisions**: entirely the
  app's, using the verified facts this SDK returns.

## Security notes

- **Key storage**: the private key fields inside `LocalRpKeyMaterial` don't
  directly identify a user, but they control this app's entire local RP
  identity — anyone holding them can sign login requests and redeem claim
  tickets as this app. Store them with ordinary application-secret care (the
  same tier as a database credential or API key), not merely as
  configuration.
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
  fetched over the network (`linkkeys_local_rp::rpc`) are only ever trusted
  after DNS `fp=` pinning — an unpinned/unauthenticated key can never reach
  the verification chain. The default DNS resolver is the OS-configured
  system resolver; LAN resolver spoofing is an accepted, documented tradeoff
  for this mode (the design doc's "Decided" section). Inject a hardened
  `DnsResolver` (e.g. a DoH client) if your deployment needs more.
- **Address policy**: the default `Transport` (`StdTransport`) dials whatever
  address DNS returns, including private/loopback/LAN addresses — that is
  the entire point of this mode (a LAN box talking to wherever
  `_linkkeys_apis` points). Set `StdTransport::policy` to
  `AddressPolicy::PublicOnly` to opt into a stricter SSRF-guard posture if
  your deployment wants it; nothing in this crate applies that restriction by
  default.
- **Expiration**: `check_expirations(identity, now)` reports `notice` (180
  days remaining), `warning` (90 days), `critical` (30 days), and `expired`
  thresholds as facts — this crate never blocks a login or forces rotation on
  its own; that decision is the app's.

## Testing

- `tests/conformance.rs` consumes the conformance vectors under
  `sdks/local-rp/conformance/` (envelopes, callback_box, url_params, dns,
  tickets, expirations, keys), positive and negative cases, exercising this
  SDK's own wrappers where it has one and the underlying `liblinkkeys` calls
  it wraps otherwise.
- `tests/revocations_conformance.rs` consumes `revocations.json`: all nine
  sibling-signed revocation-certificate cases (outcome AND counted-signer
  assertions), CBOR wire round-trips, and the application case run through
  the SDK's own `rpc::fetch_domain_keys` path against a fake IDP — proving a
  valid certificate actually drops its target key from the trusted set and
  flips the fixture's callback envelope from verifying to failing.
- `tests/flow.rs` runs `complete_local_login`'s full verification chain
  end-to-end against a real (but locally spun up) TLS+TCP+CSIL-RPC fake IDP,
  with fake `Transport`/`DnsResolver` implementations injected — a happy path
  plus one test per verification-chain failure (wrong audience, wrong
  issuer, nonce mismatch, expired callback, DNS pin mismatch, revoked signing
  key, tampered claim signature).
