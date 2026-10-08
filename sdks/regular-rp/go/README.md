# linkkeys application keys and act-as grants (Go)

This package gives a Go regular-RP application the ability to verify and
cache LinkKeys application keys. It also gives the grantee and audience
sides of act-as grants (see "Act-as grants" below). Read
`docs/application-keys.md` at the repo root first. That document explains
the protocol. This file explains how to use the Go package.

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

## Act-as grants

An act-as grant lets application C (the grantee) act as a user at
application D (the audience). The user approves the grant. The user's home
domain signs it. C and D enforce the scope. Read
`docs/act-as-grants.md` and `docs/spec/reserved/act-as-grants.md` first.
This package ports `crates/liblinkkeys/src/act_as.rs` (`actas.go`) and adds
the RP calls (`actas_rp.go`).

Use `FormatActAsTime` for every timestamp that you put in a request. It
gives whole-second RFC3339 UTC with a trailing `Z`.

### Grantee flow (application C)

1. Get a signed scope set from D. Your protocol with D sets how. Do not
   change it. A change breaks D's signature.
2. Make a signer. An enrolled application instance uses
   `NewApplicationGranteeSigner(instanceID, signer)`. A local RP uses
   `NewLocalRpGranteeSigner(descriptor, fingerprint, seed)`.
3. Sign the grant request and send the user's browser to the home domain:

   ```go
   signed, err := regularrp.SignGrantRequest(api.ActAsGrantRequest{
   	Grantee:            grantee,
   	ScopeSet:           scopeSetFromD,
   	GranteeHandleClaim: handleClaim, // optional; nil when you have none
   	CallbackUrl:        "https://c.example/act-as/callback",
   	Nonce:              nonce, // single use; check it on the callback
   	RequestedAt:        regularrp.FormatActAsTime(now),
   	ExpiresAt:          regularrp.FormatActAsTime(now.Add(5 * time.Minute)),
   }, signer)
   link, err := regularrp.GrantRequestURL("https://home.example", signed)
   ```

   `GranteeHandleClaim` is optional. It is a signed `handle` claim from your
   home domain about the account that enrolled your application. The consent
   screen then shows the handle. A local RP has no account, so it cannot
   send a handle claim.

   This package has no discovery of the home domain's browser endpoint. You
   supply the browser base URL. The URL must use https. Only a loopback
   host can use http.
4. The callback gets `act_as_grant_id` and `nonce`. Make sure the nonce is
   yours. Then fetch the grant through your own RP:

   ```go
   refresh, err := regularrp.SignRefreshRequest(api.ActAsRefreshRequest{
   	GrantId:     grantID,
   	Grantee:     grantee,
   	RequestedAt: regularrp.FormatActAsTime(now),
   	ExpiresAt:   regularrp.FormatActAsTime(now.Add(5 * time.Minute)),
   	Nonce:       freshNonce,
   }, signer)
   got, err := regularrp.RefreshGrant(ctx, transport, userHomeDomain, refresh)
   ```

5. For each call to D, make a credential and send it with the call:

   ```go
   credential, err := regularrp.Present(got.Grant, audienceRef, requestDigest, now, callNonce, signer)
   ```

   Use a new nonce for each call. D defines `requestDigest`.
6. Call `RefreshGrant` again when less than half of the grant's life
   remains. `DecideRefresh` tells you what the home domain will do. A
   refresh that cannot renew yet returns the stored grant, with
   `Signed == false`. An expired grant cannot be renewed. Ask the user
   again.

### Audience scope sets (application D)

Sign each scope set with ALL current signing keys of your instance:

```go
scopeSet, err := regularrp.SignScopeSet(set, myInstanceID, []regularrp.ApplicationSigner{key1, key2})
```

A verifier needs one signature by a key that was valid at the set's
`IssuedAt`. Thus the set stays valid when one key expires or is revoked.
The list must not be empty, and a key id must not occur two times.

`set.AudienceHandleClaim` is optional. It is a signed `handle` claim from
your home domain about the account that enrolled your application. It must
be about `set.Audience.SubjectUserId`.

### Audience verification flow (application D)

1. Find the keys that the credential needs:
   - `CredentialSignerInstance` gives the grantee instance. Resolve its
     keys with `CachedResolver`, then use `UsableKeyRefs()`. A local-RP
     grantee needs no instance keys.
   - `CredentialScopeSetSigner` gives your own instance that signed the
     scope set. Resolve its keys with `CachedResolver`, then use
     `AttestedKeyRefs()`. Do NOT use `UsableKeyRefs()` here.
     `AttestedKeyRefs()` keeps the keys that expired or were revoked
     since, each with its `RevokedAt`. Without them, every grant whose
     scope set was signed before a key rotation fails.
   - Get the signing keys of the grant's home domain from your RP
     (`Rp/resolve-domain-keys`). Apply its revocations.
2. Get the revocations that you hold for the grant with
   `ResolveGrantRevocations`. It returns only revocations that verify
   against the home domain's keys.
3. Run the checklist:

   ```go
   verified, err := regularrp.VerifyCredential(credential, regularrp.AudienceContext{
   	OwnApplication:            myApplicationRef, // from configuration, never from the request
   	OwnScopeSetKeys:           myScopeSetKeys,
   	IssuerDomainKeys:          homeDomainKeys,
   	GranteeInstanceKeys:       granteeKeys,
   	ExpectedRequestDigest:     digestOfThisRequest,
   	RevokedGrantIDs:           revokedIDs,
   	MaxPresentationAgeSeconds: 300,
   	Now:                       time.Now(),
   	SkewSeconds:               60,
   	RevokedKeyPolicy:          regularrp.AcceptBeforeRevocation, // the default
   })
   ```

   `VerifyCredential` runs the seven checks of the specification in the
   same order as the Rust reference.

   `RevokedKeyPolicy` tells how to treat a scope-set signature by a key
   that was revoked after it signed. `AcceptBeforeRevocation` (the zero
   value) accepts it. `RefuseRevoked` refuses it. When no signature is
   acceptable, the error kind is `ErrActAsNoValidSignature`. Its detail
   names each key and why it was refused.
4. Use only `verified.ApprovedScope` in your policy. Never use the full
   scope set.

D owns replay protection. `VerifyCredential` does not remember nonces.
Record `verified.Nonce` until `MaxPresentationAgeSeconds` plus the skew
has passed, and refuse a nonce that you already hold.

### Handle claims

`VerifyHandleClaim(claim, party, domainKeys)` returns the handle when the
claim counts:

- Its type is `handle` and it is about `party.SubjectUserId`.
- A signature by `party.SubjectDomain` verifies against `domainKeys`, the
  signing keys of that domain. Signatures by other domains are ignored.
- It is not revoked and not expired.

A claim that does not count must not block consent. Do not show its handle.

### Revocation data

D also owns the freshness of its revocation data. It decides how often to
call `ResolveGrantRevocations`. A short grant lifetime decreases the risk
of old revocation data.

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
- `actas_conformance_test.go` replays the four `act_as_*.json` files:
  every positive, negative, and policy case of scope sets (with per-case
  audience keys and revoked-key policy), handle claims, grant requests,
  refresh requests, grants, revocations, and credentials; the terms
  arithmetic; and the exact bytes that a grantee signs, for an application
  grantee and for a local-RP grantee.
- `actas_test.go` signs and then verifies with this package only. It tests
  multi-signature scope sets, the refusal text, both revoked-key policies,
  `AttestedKeyRefs`, handle claims, and `RefreshGrant` and
  `ResolveGrantRevocations` against a fake transport.
  No test opens a network connection.

Run `go test ./... -race` for the concurrency-sensitive resolver tests. It
passes clean.

## `tools.sh` wiring

From the repository root:

```sh
./tools.sh test-regular-rp-go
```
