package localrp

import (
	"crypto/ed25519"
	"sort"
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

// Claim signature verification — mirrors crates/liblinkkeys/src/claims.rs.
// Only the verification half is ported: claims are always signed by an IDP
// (server-side, Rust liblinkkeys); this SDK only ever needs to verify claims
// returned from a ticket redemption. `claimSignPayload` is reproduced exactly
// (same tag, same tuple field order/CBOR shape) so this SDK can verify
// claims signed by the real Rust implementation — this is a genuine wire
// interop requirement, not merely internal self-consistency.

// claimPayloadTag is the domain-separation tag + version for the claim
// signature payload.
const claimPayloadTag = "linkkeys-claim-v1alpha"

// claimSignPayload builds the canonical bytes a single signature covers for
// a claim. The subject is the single full identity `user_id@subject_domain`
// (not the bare user_id), so a claim about a user_id at one domain can't be
// replayed as the same user_id at another. signingDomain is bound
// per-signature so a signature from domain A cannot satisfy a claim
// presented as signed by B.
//
// Timestamps are signed as whole Unix seconds (CBOR integers); a time with a
// fraction of a second cannot be signed and yields an error.
func claimSignPayload(claimID, claimType string, claimValue []byte, userID, subjectDomain, signingDomain string, expiresAt *time.Time, attestedAt time.Time) ([]byte, error) {
	subject := userID + "@" + subjectDomain
	expires, err := signedOptTime(expiresAt)
	if err != nil {
		return nil, &ClaimError{Kind: ClaimErrKindBadTimestamp}
	}
	attested, err := signedTime(attestedAt)
	if err != nil {
		return nil, &ClaimError{Kind: ClaimErrKindBadTimestamp}
	}
	return cborTuple(
		cborText(claimPayloadTag),
		cborText(claimID),
		cborText(claimType),
		cborBytesVal(claimValue),
		cborText(subject),
		cborText(signingDomain),
		expires,
		attested,
	), nil
}

// ClaimSpec is what is being claimed: the pieces that go into a Claim
// independent of who is signing it. Mirrors liblinkkeys::claims::ClaimSpec.
type ClaimSpec struct {
	ClaimID       string
	ClaimType     string
	ClaimValue    []byte
	UserID        string
	SubjectDomain string
	// ExpiresAt must be whole seconds.
	ExpiresAt *time.Time
	// AttestedAt is when the claim is signed. Must be whole seconds.
	AttestedAt time.Time
}

// ClaimSigner is one signer of a claim: a single key, owned by Domain, used
// to produce one api.ClaimSignature.
type ClaimSigner struct {
	Domain         string
	KeyID          string
	PrivateKeySeed [32]byte
}

// SignClaim signs a claim with one or more keys, producing an api.Claim
// carrying one api.ClaimSignature per signer. This is a server-side (IDP)
// operation exposed here as a pure protocol helper (mirroring
// liblinkkeys::claims::sign_claim) so that it reproduces the exact same
// wire bytes a real IDP would; the local-RP SDK itself never calls it in
// production — an app only ever verifies claims returned from ticket
// redemption. Test fixtures (fake IDPs) use it to build realistic claims.
//
// Returns a *ClaimError of kind ClaimErrKindBadTimestamp when ExpiresAt or
// AttestedAt has a fraction of a second.
func SignClaim(spec ClaimSpec, signers []ClaimSigner) (api.Claim, error) {
	signatures := make([]api.ClaimSignature, 0, len(signers))
	for _, signer := range signers {
		payload, err := claimSignPayload(spec.ClaimID, spec.ClaimType, spec.ClaimValue, spec.UserID, spec.SubjectDomain, signer.Domain, spec.ExpiresAt, spec.AttestedAt)
		if err != nil {
			return api.Claim{}, err
		}
		sig := signEd25519(signer.PrivateKeySeed, payload)
		signatures = append(signatures, api.ClaimSignature{
			Domain:        signer.Domain,
			SignedByKeyId: signer.KeyID,
			Signature:     sig,
		})
	}
	return api.Claim{
		ClaimId:    spec.ClaimID,
		UserId:     spec.UserID,
		ClaimType:  spec.ClaimType,
		ClaimValue: spec.ClaimValue,
		Signatures: signatures,
		AttestedAt: spec.AttestedAt,
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  spec.ExpiresAt,
		RevokedAt:  nil,
	}, nil
}

// DomainKeySet is a domain and the set of its currently-known public keys,
// as supplied to VerifyClaim. The caller resolves these before verifying
// (via FetchDomainKeys) so verification stays pure and performs no I/O.
type DomainKeySet struct {
	Domain string
	Keys   []api.DomainPublicKey
}

// verifyOneClaimSignature verifies one signature against a set of candidate
// keys for its domain: the referenced key must exist, be a currently-valid
// signing key, and the signature must check out over payload.
func verifyOneClaimSignature(sig api.ClaimSignature, payload []byte, keys []api.DomainPublicKey) error {
	var key *api.DomainPublicKey
	for i := range keys {
		if keys[i].KeyId == sig.SignedByKeyId {
			key = &keys[i]
			break
		}
	}
	if key == nil {
		return &ClaimError{Kind: ClaimErrKindKeyNotFound, Detail: sig.SignedByKeyId}
	}

	// A claim signature must come from a signing key, never an encryption
	// key sharing the same id.
	if key.KeyUsage != api.KeyUsageSign {
		return &ClaimError{Kind: ClaimErrKindSignatureInvalid}
	}

	switch signingKeyValidity(key.ExpiresAt, key.RevokedAt) {
	case keyValidityValid:
	case keyValidityRevoked:
		return &ClaimError{Kind: ClaimErrKindKeyRevoked, Detail: key.KeyId}
	default:
		return &ClaimError{Kind: ClaimErrKindKeyExpired, Detail: key.KeyId}
	}

	if key.Algorithm != api.KeyAlgorithmEd25519 {
		return &ClaimError{Kind: ClaimErrKindUnsupportedAlgorithm, Detail: keyAlgorithmLabel(key.Algorithm)}
	}
	if len(key.PublicKey) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(key.PublicKey), payload, sig.Signature) {
		return &ClaimError{Kind: ClaimErrKindSignatureInvalid}
	}
	return nil
}

// verifySignatureQuorum verifies only the cryptographic per-domain quorum:
// every domain that signed must contribute at least one signature from a
// currently-valid key of that domain, over the payload payloadFor(domain)
// produces for it. Does NOT check the claim's own revocation/expiry.
func verifySignatureQuorum(signatures []api.ClaimSignature, domainKeys []DomainKeySet, payloadFor func(signingDomain string) ([]byte, error)) error {
	if len(signatures) == 0 {
		return &ClaimError{Kind: ClaimErrKindUnsigned}
	}

	seen := make(map[string]bool)
	var domains []string
	for _, s := range signatures {
		if !seen[s.Domain] {
			seen[s.Domain] = true
			domains = append(domains, s.Domain)
		}
	}
	sort.Strings(domains) // stable order for deterministic errors

	for _, signingDomain := range domains {
		var set *DomainKeySet
		for i := range domainKeys {
			if domainKeys[i].Domain == signingDomain {
				set = &domainKeys[i]
				break
			}
		}
		if set == nil {
			return &ClaimError{Kind: ClaimErrKindDomainKeysUnavailable, Detail: signingDomain}
		}

		payload, err := payloadFor(signingDomain)
		if err != nil {
			return err
		}

		var lastErr error = &ClaimError{Kind: ClaimErrKindDomainUnverified, Detail: signingDomain}
		satisfied := false
		for _, sig := range signatures {
			if sig.Domain != signingDomain {
				continue
			}
			if err := verifyOneClaimSignature(sig, payload, set.Keys); err == nil {
				satisfied = true
				break
			} else {
				lastErr = err
			}
		}
		if !satisfied {
			return lastErr
		}
	}
	return nil
}

// VerifyClaimSignatures verifies only the cryptographic per-domain quorum
// for claim (see verifySignatureQuorum); subjectDomain is the subject's home
// domain, supplied from authoritative context (never attacker-controlled
// input), binding a claim about user@A from being replayed as one about
// user@B.
func VerifyClaimSignatures(claim api.Claim, subjectDomain string, domainKeys []DomainKeySet) error {
	return verifySignatureQuorum(claim.Signatures, domainKeys, func(signingDomain string) ([]byte, error) {
		return claimSignPayload(claim.ClaimId, claim.ClaimType, claim.ClaimValue, claim.UserId, subjectDomain, signingDomain, claim.ExpiresAt, claim.AttestedAt)
	})
}

// VerifyClaim performs full claim verification: the cryptographic
// per-domain quorum plus the claim's own revocation and expiry (both
// tamper-evident, being bound into each signed payload).
func VerifyClaim(claim api.Claim, subjectDomain string, domainKeys []DomainKeySet) error {
	if err := VerifyClaimSignatures(claim, subjectDomain, domainKeys); err != nil {
		return err
	}

	if claim.RevokedAt != nil {
		return &ClaimError{Kind: ClaimErrKindRevoked}
	}
	if claim.ExpiresAt != nil {
		if time.Now().UTC().After(claim.ExpiresAt.UTC()) {
			return &ClaimError{Kind: ClaimErrKindExpired}
		}
	}

	return nil
}
