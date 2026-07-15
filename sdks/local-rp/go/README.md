# linkkeys-local-rp (Go)

Go SDK for LinkKeys' **DNS-less local RP identity** mode — see
`dns-less-local-rp-design.md` at the repo root for the full design; this
package implements its "SDK API Shape" section. It lets a locally installed
app (a LAN jukebox, a desktop tool, a self-hosted service with no public
DNS) use LinkKeys for login without running its own DNS-pinned relying
party. The app's identity is the fingerprint of a locally-generated signing
key (SSH-host-key style), not a domain.

Module path: `github.com/catalystcommunity/linkkeys/sdks/local-rp/go`
(package name `localrp`; the generated CSIL types live in the `generated`
subpackage, package name `api`).

## Layout: why this is a standalone Go module

Unlike the Rust SDK (a workspace member that path-depends on `liblinkkeys`
directly), this package stands alone with its own `go.mod` and toolchain —
the pattern csilgen's `transports/README.md` documents for every
non-Rust transport library. There is no separate "liblinkkeys-go": this
package *is* the local-RP protocol implementation for Go, reimplementing the
pure envelope/sealed-box/claims/revocation/DNS logic from
`crates/liblinkkeys/src/{local_rp,crypto,claims,revocation,dns,encoding}.rs`
directly in Go (stdlib crypto + `golang.org/x/crypto/chacha20poly1305`), and
verified byte-for-byte against the shared conformance vectors in
`sdks/local-rp/conformance/`.

Run tests:

```sh
cd sdks/local-rp/go && go test ./...          # from the crate directory
./tools.sh test-local-rp-go                    # via tools.sh (see below)
```

Requires the catalyst-tools Go (1.26.x):

```sh
source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
```

## Generation

CSIL types and the CBOR codec are generated with:

```sh
csilgen generate --input csil/linkkeys.csil --target go-typesonly --output sdks/local-rp/go/generated/
```

`go-typesonly` (rather than `go-client`/`go-server`/bare `go`) was chosen
when the `go-client` sub-target's generated `Transport.Call(ctx, service,
op, payload)` invocations still used a lowercased/re-cased name pair
(e.g. `"domainkeys"`/`"GetDomainKeys"`) instead of the verbatim CSIL names
the linkkeys TCP dispatch matches on. That csilgen defect has since been
fixed (the regenerated client emits `"DomainKeys"`/`"get-domain-keys"`
verbatim), so adopting `go-client` is now possible but optional; this SDK
continues to consume only the generated **types + codec**
(`Encode*`/`Decode*` functions) and builds its own CSIL-RPC calls directly
against `github.com/catalystcommunity/csilgen/transports/go`'s
`RpcRequest`/`RpcResponse`/`StreamCarrier`, with literal, correct service/op
strings — see `rpc.go`'s doc comment. This mirrors the Rust reference SDK's
`src/rpc.rs`, which also bypasses the generated client (for a different
reason: permissive address policy) and hand-builds requests over the
generated types + a shared transport library.

Generated files are checked in but must be reproducible: `gofmt -w
generated/` after regenerating (a separate, still-open csilgen defect —
`go-gofmt-clean-output.md` in the same inbox — means the raw generator
output isn't gofmt-clean on its own, the same situation the Rust generator
has for `rustfmt`).

## Quickstart

```go
import (
	"time"

	localrp "github.com/catalystcommunity/linkkeys/sdks/local-rp/go"
)

// Once, at install/setup time — persist the returned bytes with ordinary
// application-secret care (see "Security notes" below).
identity, err := localrp.GenerateLocalRpIdentity(localrp.GenerateLocalRpIdentityConfig{
	AppName: "My LAN Jukebox",
	Now:     time.Now(),
})
storedBytes := localrp.LocalRpIdentityToBytes(identity)
// ... write storedBytes to your app's secret/config store ...

// Later, per login attempt:
identity, err = localrp.LocalRpIdentityFromBytes(storedBytes)
redirect, pending, err := localrp.BeginLocalLogin(localrp.BeginLocalLoginConfig{
	KeyMaterial: identity,
	CallbackURL: "http://jukebox.lan:8080/auth/callback",
	UserDomain:  "example.com", // the LinkKeys domain the user selected/entered
	Now:         time.Now(),
})
// Persist `pending` (a plain, JSON-taggable struct — put it in a
// server-side session tied to the browser), then redirect the user's
// browser to redirect.RedirectURL.

// On callback, your app's HTTP handler receives a request whose query
// string carries `encrypted_token=<...>`. Pass the request's full URL and
// that parameter's raw value to CompleteLocalLogin:
verified, err := localrp.CompleteLocalLogin(localrp.CompleteLocalLoginConfig{
	KeyMaterial:    identity,
	Pending:        pending,
	EncryptedToken: encryptedToken, // the encrypted_token query-parameter's value
	ArrivedURL:     arrivedURL,     // the full URL the request actually arrived at
	Now:            time.Now(),
})
// verified.UserID, verified.UserDomain, verified.Claims, ... — session
// creation, local user records, and authorization are all your app's job.
```

## Storage and single-use responsibilities this SDK assigns to the app

This SDK returns verified protocol facts. It never creates a session,
writes to an app database, or manages local user authorization — per the
design doc: *"SDKs must not own application storage, sessions, database
writes, or local user authorization."* Concretely, the app owns:

- **Key material** (`LocalRpKeyMaterial` / the bytes from
  `LocalRpIdentityToBytes`): persist it wherever the app stores its own
  secrets/configuration, with the care described below.
- **`PendingLogin`**: persist it between `BeginLocalLogin` and
  `CompleteLocalLogin` (it's a plain struct with JSON tags, so any
  session/serialization format works), and **discard it after one
  completion attempt**. This package owns no storage and cannot enforce
  single-use itself — replay protection at the app boundary is the app's
  responsibility.
- **Sessions, local user records, authorization decisions**: entirely the
  app's, using the verified facts this SDK returns.

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
  fetched over the network (`FetchDomainKeys`) are only ever trusted after
  DNS `fp=` pinning — an unpinned/unauthenticated key can never reach the
  verification chain. The default DNS resolver is the OS-configured system
  resolver; LAN resolver spoofing is an accepted, documented tradeoff for
  this mode. Inject a hardened `DnsResolver` if your deployment needs more.
- **Address policy**: the default `Transport` (`StdTransport`) dials
  whatever address DNS returns, including private/loopback/LAN addresses —
  that is the entire point of this mode (a LAN box talking to wherever
  `_linkkeys_apis` points). Set `StdTransport.Policy` to
  `AddressPolicyPublicOnly` to opt into a stricter SSRF-guard posture if
  your deployment wants it; nothing in this package applies that
  restriction by default.
- **Expiration**: `CheckExpirations(identity, now)` reports `notice` (180
  days remaining), `warning` (90 days), `critical` (30 days), and `expired`
  thresholds as facts — this package never blocks a login or forces
  rotation on its own; that decision is the app's.
- **TLS pinning**: outbound TCP CSIL-RPC connections use `crypto/tls` with
  `InsecureSkipVerify` + a custom `VerifyPeerCertificate` callback that
  checks the peer certificate's validity window and its SubjectPublicKeyInfo
  SHA-256 fingerprint against the DNS `fp=` pinned set — there is no CA
  chain in this protocol; the pin is the entire trust anchor, exactly as
  `crates/linkkeys/src/tcp/tls.rs` / `linkkeys-rpc-client`'s
  `FingerprintVerifier` do on the Rust side.

## Testing

- `conformance_test.go` consumes `sdks/local-rp/conformance/`'s `keys.json`,
  `envelopes.json`, `callback_box.json`, `url_params.json`, `dns.json`,
  `tickets.json`, and `expirations.json`, positive and negative cases,
  exercising this package's public API.
- `revocations_conformance_test.go` consumes `revocations.json`: all nine
  sibling-signed revocation-certificate cases with exact counted-signer
  assertions (`CountRevocationSigners`), plus the application case proving
  that a valid certificate, once applied, flips a callback-payload envelope
  signed by the targeted key from verifying to failing (tested both by
  marking the key revoked, per the vector's semantics, and by removing it
  from the trusted set, this SDK's actual `FetchDomainKeys` apply behavior).
- `flow_test.go` runs `CompleteLocalLogin`'s full verification chain
  end-to-end against a real (but locally spun up) TLS+TCP+CSIL-RPC fake
  IDP, with fake `Transport`/`DnsResolver` implementations injected — a
  happy path plus one test per verification-chain failure (wrong audience,
  wrong issuer, nonce mismatch, expired callback, DNS pin mismatch, revoked
  signing key, tampered claim signature).

Run with `go test ./...` (or `go test ./... -race` — the fake-IDP tests are
race-clean). `go vet ./...` is also clean.

## `tools.sh` wiring

This package does not modify `tools.sh` (per this repo's convention, the
maintainer wires new subcommands). The command a `test-local-rp-go`
subcommand should run:

```sh
cd sdks/local-rp/go && go test ./...
```

with the catalyst-tools Go on `PATH`
(`source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"` first).
