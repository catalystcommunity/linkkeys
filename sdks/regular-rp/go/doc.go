// Package regularrp gives a Go regular-RP application the ability to verify
// and cache LinkKeys application keys — see docs/application-keys.md at the
// repo root for the protocol in plain language, and
// crates/liblinkkeys/src/application_keys.rs for the normative rules this
// package ports (its module doc explains the reasoning behind each one).
//
// Application keys let an application (Tinku is the first) generate and
// hold its own signing/key-agreement key pairs and sign its own federation
// messages, while the application's home domain only attests that a public
// key belongs to one canonical account, application, and application
// instance — never seeing or signing with an application private key.
//
// This package covers three things:
//
//   - Verification (applicationkeys.go, domainkeys.go): the five
//     domain-separation tags and canonical signature inputs,
//     [VerifyAttestationSignature], [VerifyApplicationKeySet] (the
//     whole-response verifier: attestations first, then revocations against
//     those attested siblings, then classification), and
//     [VerifiedApplicationKeySet.KeyForUse], which fails closed on an
//     unknown, expired, unattested, mismatched, or revoked key.
//   - A local signing keyring (keyring.go): generate signing
//     ([NewSigningKeyPair]) and key-agreement ([NewAgreementKeyPair]) key
//     pairs, build and sign an addition ([SignAddition]), a renewal
//     ([SignRenewal]), a revocation ([SignRevocation]), and open a sealed
//     X25519 proof-of-possession challenge ([OpenChallenge]). Private keys
//     never leave the calling process.
//   - A cached resolver (resolver.go): [CachedResolver] asks the
//     application's own RP (`Rp/resolve-application-keys`, API-key
//     authenticated via [PinnedRpcTransport]), verifies the signed records
//     itself, and caches the result — bounded, keyed on the canonical
//     [InstanceRef] tuple (never a bare handle), with concurrent refreshes
//     for one instance coalesced and freshness ([Freshness]) always carried
//     alongside the result.
//
// # Quickstart: resolving a peer's application keys
//
//	transport, err := regularrp.NewPinnedRpcTransport(regularrp.PinnedRpcTransportOptions{
//		TCPAddress:   "rp.example.internal:8443",
//		Fingerprints: []string{"…sha256 hex of the RP's pinned TLS key…"},
//		APIKey:       os.Getenv("LINKKEYS_RP_API_KEY"),
//	})
//	resolver := regularrp.NewCachedResolver(transport, regularrp.CachedResolverOptions{})
//
//	result, err := resolver.Resolve(ctx, regularrp.InstanceRef{
//		SubjectUserID: peerUserID,
//		SubjectDomain: peerDomain,
//		ApplicationID: "tinku",
//		InstanceID:    peerInstanceID,
//	}, nil)
//	// result.Freshness is fresh / refreshed / stale — never discard it.
//	key, err := result.Keys.KeyForUse(signedByKeyID, regularrp.KeyUsageSign, "ed25519")
//	// verify the peer's message signature against key.PublicKey.
//
// # What this package does NOT do
//
// It never submits an addition/renewal/revocation request to a home
// domain — that is `ApplicationKeys/add-key` etc. on the CSIL-RPC service
// the generated client (sdks/regular-rp/go/generated) already exposes
// unauthenticated (the signed request itself is the authentication, per
// docs/application-keys.md's Operations table); this package only builds
// and signs the request. It never verifies an incoming
// addition/renewal/revocation REQUEST (that is the home domain server's own
// admission check, not a peer/SDK concern). And it never holds or transmits
// a private key on the application's behalf beyond the process that calls
// it — signing always happens in-process, against key material the caller
// supplies.
package regularrp
