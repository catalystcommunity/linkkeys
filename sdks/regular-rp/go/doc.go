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
// For application keys, this package covers three things:
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
// # Act-as grants
//
// An act-as grant lets application C (the grantee) act as a user at
// application D (the audience). The user approves the grant. The user's
// home domain signs it. C and D enforce the scope. actas.go ports
// crates/liblinkkeys/src/act_as.rs. actas_rp.go adds the RP calls. See
// docs/act-as-grants.md and docs/spec/reserved/act-as-grants.md.
//
// Grantee flow:
//
//  1. Get a signed scope set from D.
//  2. Make a signer with [NewApplicationGranteeSigner] or
//     [NewLocalRpGranteeSigner].
//  3. Sign the request with [SignGrantRequest]. Send the user's browser to
//     the URL from [GrantRequestURL]. You supply the home domain's browser
//     base URL. This package has no discovery for it.
//  4. On the callback, make sure the nonce is yours. Fetch the grant with
//     [SignRefreshRequest] and [RefreshGrant].
//  5. For each call to D, send the credential from [Present]. Use a new
//     nonce for each call.
//  6. Call [RefreshGrant] again when less than half of the grant's life
//     remains. [DecideRefresh] predicts the result.
//
// Use [FormatActAsTime] for every timestamp in a request.
//
// Audience flow:
//
//  1. Resolve the grantee instance's keys ([CredentialSignerInstance],
//     [CachedResolver], [VerifiedApplicationKeySet.UsableKeyRefs]), your own
//     scope-set keys ([CredentialScopeSetSigner], [CachedResolver],
//     [VerifiedApplicationKeySet.AttestedKeyRefs]), and the home domain's
//     signing keys. For your own scope-set keys, use AttestedKeyRefs, not
//     UsableKeyRefs: it keeps expired and revoked keys, so a grant signed
//     before a key rotation stays valid.
//  2. Get verified revocations with [ResolveGrantRevocations].
//  3. Call [VerifyCredential] with an [AudienceContext]. It runs the seven
//     checks of the specification in the reference order. Set
//     OwnApplication from your configuration, never from the request. Set
//     RevokedKeyPolicy to [AcceptBeforeRevocation] (the zero value) or
//     [RefuseRevoked].
//  4. Use only [VerifiedActAs].ApprovedScope in your policy.
//
// D signs each scope set with all current signing keys of its instance
// ([SignScopeSet] takes a list). One valid signature is enough. When no
// signature is acceptable, the error kind is [ErrActAsNoValidSignature], and
// its detail names each key and why it was refused.
//
// A scope set and a grant request can carry an optional signed handle claim
// about the account that enrolled the party. [VerifyHandleClaim] counts only
// a signature by the party's own domain. A claim that does not count must not
// block consent.
//
// D owns replay protection: [VerifyCredential] does not remember nonces.
// Record [VerifiedActAs].Nonce until the accepted presentation age has
// passed, and refuse a nonce that you already hold. D also owns the
// freshness of its revocation data: it decides how often to call
// [ResolveGrantRevocations].
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
