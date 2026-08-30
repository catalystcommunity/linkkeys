# linkkeys application keys (Go)

This package gives a Go regular-RP application the ability to verify and
cache LinkKeys application keys. Read `docs/application-keys.md` at the
repo root first. That document explains the protocol. This file explains
how to use the Go package.

Application keys let an application, such as Tinku, sign its own messages.
The application keeps its own private keys. The application's home domain
only attests that a public key belongs to one account, one application, and
one application instance. The home domain never sees or signs with an
application private key.

Module path: `github.com/catalystcommunity/linkkeys/sdks/regular-rp/go`
(package name `regularrp`). The generated CSIL types and client live in the
`generated` subpackage (package name `api`).

## Layout

This package is a standalone Go module, with its own `go.mod`. It
reimplements the pure application-key logic from
`crates/liblinkkeys/src/application_keys.rs` directly in Go. It uses the
generated CBOR codec and typed `Rp` client from `generated/` for every CSIL
wire type. It hand-builds only the few structures that are not CSIL wire
types: the envelope signature input and the sealed-challenge tuple (see
`cbor.go`).

Do not hand-edit any file under `generated/`. That directory is `csilgen`
output. Regenerate it with:

```sh
./tools.sh generate-regular-rp-bindings
```

## Install

Requires the catalyst-tools Go (1.26.x) or a Go toolchain of the same
version or later:

```sh
source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
```

## Quickstart: verify and cache a peer's application keys

Build a `PinnedRpcTransport` for your own RP server, then wrap it in a
`CachedResolver`:

```go
transport, err := regularrp.NewPinnedRpcTransport(regularrp.PinnedRpcTransportOptions{
	TCPAddress:   "rp.example.internal:8443",
	Fingerprints: []string{"…sha256 hex of the RP's pinned TLS key…"},
	APIKey:       os.Getenv("LINKKEYS_RP_API_KEY"),
})
if err != nil {
	// handle err
}
resolver := regularrp.NewCachedResolver(transport, regularrp.CachedResolverOptions{})
```

Resolve a peer's keys before you verify a message from that peer:

```go
result, err := resolver.Resolve(ctx, regularrp.InstanceRef{
	SubjectUserID: peerUserID,
	SubjectDomain: peerDomain,
	ApplicationID: "tinku",
	InstanceID:    peerInstanceID,
}, nil)
if err != nil {
	// The RP is unreachable and this SDK has no prior verified material
	// for this instance. Do not proceed.
}
```

Check `result.Freshness` before you trust `result.Keys`. A stale result is
never an error, but it is also never a fresh answer:

```go
if result.Freshness == regularrp.FreshnessStale {
	log.Warn("using stale application keys for %s", peerUserID)
}
```

Look up the specific key that signed the message. `KeyForUse` fails closed
on an unknown, expired, unattested, mismatched, or revoked key:

```go
attestation, err := result.Keys.KeyForUse(signedByKeyID, regularrp.KeyUsageSign, "ed25519")
if err != nil {
	// refuse the message
}
// verify the message signature against attestation.PublicKey
```

`InstanceRef` is the cache key. It is the full canonical tuple: subject
user id, subject domain, application id, and instance id. Never use a
handle as a cache key. A handle can move to a different account.

## Quickstart: the local signing keyring

An application generates its own key pairs and signs its own requests. No
function in this package sends a private key anywhere.

Generate a signing key pair and a key-agreement key pair:

```go
signPub, signSeed, signFp, err := regularrp.NewSigningKeyPair()
agreePub, agreePriv, agreeFp, err := regularrp.NewAgreementKeyPair()
```

Build and sign an addition request. Two distinct, currently valid signing
keys authorize the new key. The new key proves it holds its own private
key with a separate possession proof:

```go
addition := api.ApplicationKeyAddition{ /* fill in the fields the home domain asks for */ }
signed, err := regularrp.SignAddition(addition,
	[]regularrp.ApplicationSigner{signerA, signerB},
	&newKeySigner,
)
```

Submit `signed` to `ApplicationKeys/add-key` with the generated
`api.ApplicationKeysClient`. This op carries no API key. The signed request
is the authentication.

Build and sign a renewal. An Ed25519 key renews itself. An X25519
(key-agreement) key cannot sign, so a sibling signing key vouches for it:

```go
// Ed25519 target: it signs for itself.
signed, err := regularrp.SignRenewal(renewal, nil, &targetSigner)

// X25519 target: a sibling signs instead.
signed, err := regularrp.SignRenewal(renewal, []regularrp.ApplicationSigner{siblingA}, nil)
```

Build and sign a revocation. Two distinct sibling signing keys authorize
it. The target key never signs its own revocation:

```go
revocation, err := regularrp.SignRevocation(instance, targetKeyID, targetFingerprint, revokedAt,
	[]regularrp.ApplicationSigner{siblingA, siblingB},
)
```

Open a sealed X25519 proof-of-possession challenge. The home domain sends
this when you add or renew a key-agreement key. Return the opened bytes
inside the addition or renewal request:

```go
challenge, err := regularrp.OpenChallenge(sealedChallengeBytes, agreePriv)
```

## What this package does not do

It never submits an addition, renewal, or revocation request over the
network. It only builds and signs the request. Submit the request with the
generated `api.ApplicationKeysClient`.

It never verifies an incoming addition, renewal, or revocation request as
a home domain would. `VerifyAddition` and `VerifyRenewal` exist for the
application's own sanity checks and for the conformance test. A home
domain runs its own admission checks server-side.

It never holds or sends a private key on the application's behalf beyond
the calling process. Every signing function takes key material in and
returns signed bytes out.

## Testing

```sh
go build ./...
go vet ./...
go test ./...
gofmt -l .
```

- `conformance_test.go` replays every vector in `sdks/regular-rp/conformance/`
  against this package's `Verify*` and `OpenChallenge` functions: 4
  attestation cases, 6 addition cases, 3 renewal cases, 4 revocation cases,
  and 3 sealed-challenge cases — 20 cases total, positive and negative. See
  that directory's `README.md` for what each case proves.
- `keyring_test.go` builds and signs an addition, a renewal, and a
  revocation with this package's own `Sign*` functions, then verifies each
  with this package's own `Verify*` functions. The conformance suite proves
  this package agrees with the Rust reference. This test additionally
  proves the signing side and the verifying side agree with each other.
- `resolver_test.go` tests `CachedResolver` against a fake transport: the
  three freshness states (fresh, refreshed, stale) across TTL expiry and a
  simulated RP outage, bounded eviction under a low `MaxEntries`, cache
  isolation between instances that differ in only one identifier field, and
  singleflight coalescing of concurrent resolves for one instance.

Run `go test ./... -race` for the concurrency-sensitive resolver tests. It
passes clean.

## `tools.sh` wiring

`tools.sh` has no Go SDK test target for `sdks/regular-rp/go` today (only
`test-regular-rp-typescript` exists for this SDK family). This package does
not add one. Per this repo's convention, the maintainer wires new `tools.sh`
subcommands. The command a future `test-regular-rp-go` subcommand should
run:

```sh
cd sdks/regular-rp/go && go build ./... && go vet ./... && go test ./...
```

with the catalyst-tools Go on `PATH` first.
