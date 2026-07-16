package localrp

import (
	"crypto/ed25519"

	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

// Sibling-signed key revocation certificate verification — mirrors
// crates/liblinkkeys/src/revocation.rs. Only verification is ported here
// (building/signing a revocation certificate is a domain-admin/server-side
// operation, out of scope for a local-RP SDK); this SDK verifies revocation
// certificates fetched alongside domain keys (FetchDomainKeys) so it can
// drop a key a quorum-verified sibling revocation targets.

// RevocationQuorum is the minimum number of distinct sibling signatures
// required to revoke a key.
const RevocationQuorum = 2

// revocationTag is the domain-separation tag / version for the signed
// revocation payload.
const revocationTag = "linkkeys-key-revocation-v1alpha"

// revocationPayload builds the canonical signed bytes: the tag, the target
// key id + fingerprint, the revocation instant, and the signing sibling's
// domain (bound per-signature to stop cross-domain reuse of a signature).
func revocationPayload(targetKeyID, targetFingerprint, revokedAt, signingDomain string) []byte {
	return cborTuple(
		cborText(revocationTag),
		cborText(targetKeyID),
		cborText(targetFingerprint),
		cborText(revokedAt),
		cborText(signingDomain),
	)
}

// CountRevocationSigners walks a revocation certificate's signatures against
// a domain's public key set and returns how many DISTINCT signer key ids
// survive the full filtering rules (conformance README, "Verification
// rules"):
//
//  1. Skip any signature whose signed_by_key_id equals the certificate's
//     target_key_id (a key never authorizes its own revocation), any whose
//     domain field differs from the domain being verified (the domain
//     parameter only FILTERS — see rule 2), and any whose signer key is
//     absent from domainKeys or is not a currently-valid signing key (wrong
//     key_usage, expired, or itself revoked — wall-clock validity, like
//     checkSigningKeyValid everywhere else).
//  2. For the rest, recompute the payload from the signature's WIRE domain
//     field (never from the verify-domain parameter — this is what makes a
//     signature computed over another domain's payload fail even when its
//     wire domain claims this one) and Ed25519-verify.
//  3. Count distinct signed_by_key_id values that verified.
func CountRevocationSigners(cert api.RevocationCertificate, domainKeys []api.DomainPublicKey, domain string) int {
	validSigners := make(map[string]bool)

	for _, sig := range cert.Signatures {
		// A key can never authorize its own revocation.
		if sig.SignedByKeyId == cert.TargetKeyId {
			continue
		}
		// The signature must be bound to this domain.
		if sig.Domain != domain {
			continue
		}
		var key *api.DomainPublicKey
		for i := range domainKeys {
			if domainKeys[i].KeyId == sig.SignedByKeyId {
				key = &domainKeys[i]
				break
			}
		}
		if key == nil {
			continue
		}
		// Only a currently-valid signing key counts toward the quorum.
		if checkSigningKeyValid(*key) != nil {
			continue
		}
		payload := revocationPayload(cert.TargetKeyId, cert.TargetFingerprint, cert.RevokedAt, sig.Domain)
		if key.Algorithm == "ed25519" && len(key.PublicKey) == ed25519.PublicKeySize &&
			ed25519.Verify(ed25519.PublicKey(key.PublicKey), payload, sig.Signature) {
			validSigners[sig.SignedByKeyId] = true
		}
	}

	return len(validSigners)
}

// RevocationSigner is one sibling signer of a revocation certificate: a
// single key, owned by Domain, used to produce one signature.
type RevocationSigner struct {
	Domain         string
	KeyID          string
	PrivateKeySeed [32]byte
}

// SignRevocationCertificate signs a revocation certificate with one or more
// sibling keys, producing an api.RevocationCertificate carrying one
// signature per signer. This is a server-side (domain-admin) operation
// exposed here as a pure protocol helper, reproducing the exact canonical
// payload bytes (revocationPayload) a real IDP's admin tooling would sign;
// the local-RP SDK itself never calls it in production — only test fixtures
// (fake IDPs) use it to build realistic revocation certificates for
// exercising FetchDomainKeys' quorum-verified revocation-drop behavior.
func SignRevocationCertificate(targetKeyID, targetFingerprint, revokedAt string, signers []RevocationSigner) api.RevocationCertificate {
	signatures := make([]api.ClaimSignature, 0, len(signers))
	for _, signer := range signers {
		payload := revocationPayload(targetKeyID, targetFingerprint, revokedAt, signer.Domain)
		sig := signEd25519(signer.PrivateKeySeed, payload)
		signatures = append(signatures, api.ClaimSignature{
			Domain:        signer.Domain,
			SignedByKeyId: signer.KeyID,
			Signature:     sig,
		})
	}
	return api.RevocationCertificate{
		TargetKeyId:       targetKeyID,
		TargetFingerprint: targetFingerprint,
		RevokedAt:         revokedAt,
		Signatures:        signatures,
	}
}

// VerifyRevocationCertificate verifies a revocation certificate against a
// domain's public key set. Requires at least RevocationQuorum DISTINCT
// signing keys of domain, each currently valid and NOT the target key, to
// have signed the canonical payload (see CountRevocationSigners for the
// exact per-signature filtering rules).
func VerifyRevocationCertificate(cert api.RevocationCertificate, domainKeys []api.DomainPublicKey, domain string) error {
	got := CountRevocationSigners(cert, domainKeys, domain)
	if got >= RevocationQuorum {
		return nil
	}
	return &RevocationError{Got: got, Need: RevocationQuorum}
}
