package regularrp

import (
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

// Domain signing key validity and sibling-signed domain-key revocation
// certificates — mirrors crates/liblinkkeys/src/assertions.rs's
// `check_signing_key_valid` and crates/liblinkkeys/src/revocation.rs.
//
// This SDK needs both: `verifyAttestationSignature` (applicationkeys.go)
// requires a currently-valid domain SIGNING key, checked against
// wall-clock time exactly like the Rust reference (NOT an injected `now` —
// see crates/liblinkkeys/src/crypto.rs's `signing_key_validity`, which has
// no override); and the cached resolver (resolver.go) must apply
// `home_domain_key_revocations` to `home_domain_keys` before trusting any of
// them, the same way sdks/local-rp/go's `FetchDomainKeys` applies
// `DomainKeys/get-revocations` to `DomainKeys/get-domain-keys` — one RP call
// carries both pieces so the SDK can verify for itself rather than trusting
// the RP's own verification.

type domainKeyValidity int

const (
	domainKeyValidityValid domainKeyValidity = iota
	domainKeyValidityRevoked
	domainKeyValidityExpired
	domainKeyValidityBadExpiry
)

func signingKeyValidity(expiresAt string, revokedAt *string) domainKeyValidity {
	if revokedAt != nil {
		return domainKeyValidityRevoked
	}
	t, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return domainKeyValidityBadExpiry
	}
	if time.Now().UTC().After(t.UTC()) {
		return domainKeyValidityExpired
	}
	return domainKeyValidityValid
}

// checkSigningKeyValid rejects a domain key that is not usable as a
// signer: wrong key_usage, revoked, or expired (checked against wall-clock
// time — see the file doc comment). Mirrors
// `liblinkkeys::assertions::check_signing_key_valid`.
func checkSigningKeyValid(key api.DomainPublicKey) error {
	if key.KeyUsage != "sign" {
		return &ApplicationKeyError{Kind: ErrCrypto, Detail: "signature verification failed"}
	}
	switch signingKeyValidity(key.ExpiresAt, key.RevokedAt) {
	case domainKeyValidityValid:
		return nil
	case domainKeyValidityRevoked:
		return &ApplicationKeyError{Kind: ErrKeyRevoked, Detail: key.KeyId}
	default:
		return &ApplicationKeyError{Kind: ErrKeyExpired, Detail: key.KeyId}
	}
}

// revocationCertTag is REVOCATION_TAG from
// crates/liblinkkeys/src/revocation.rs — the domain-key sibling-revocation
// payload's own tag, distinct from the application-key REVOCATION_TAG.
const revocationCertTag = "linkkeys-key-revocation-v1alpha"

// revocationCertPayload builds the canonical signed bytes: the tag, the
// target key id + fingerprint, the revocation instant, and the signing
// sibling's domain (bound per-signature to stop cross-domain reuse of a
// signature). Mirrors `liblinkkeys::revocation::revocation_payload`.
func revocationCertPayload(targetKeyID, targetFingerprint, revokedAt, signingDomain string) []byte {
	return cborTuple(
		cborText(revocationCertTag),
		cborText(targetKeyID),
		cborText(targetFingerprint),
		cborText(revokedAt),
		cborText(signingDomain),
	)
}

// revocationCertQuorum is REVOCATION_QUORUM from
// crates/liblinkkeys/src/revocation.rs.
const revocationCertQuorum = 2

// countRevocationCertSigners walks a domain-key revocation certificate's
// signatures against a domain's public key set and returns how many
// DISTINCT signer key ids survive the full filtering rules: a key can never
// authorize its own revocation, the signature's wire domain must match
// `domain`, the signer key must be a currently-valid signing key (wall-clock
// checked), and the signature must verify over the payload rebuilt from the
// signature's own wire domain field.
func countRevocationCertSigners(cert api.RevocationCertificate, domainKeys []api.DomainPublicKey, domain string) int {
	validSigners := make(map[string]bool)
	for _, sig := range cert.Signatures {
		if sig.SignedByKeyId == cert.TargetKeyId {
			continue
		}
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
		if key == nil || checkSigningKeyValid(*key) != nil {
			continue
		}
		payload := revocationCertPayload(cert.TargetKeyId, cert.TargetFingerprint, cert.RevokedAt, sig.Domain)
		if resolveAndVerify(key.Algorithm, payload, sig.Signature, key.PublicKey) == nil {
			validSigners[sig.SignedByKeyId] = true
		}
	}
	return len(validSigners)
}

// verifyRevocationCertificate verifies a domain-key revocation certificate
// against a domain's public key set. Requires at least
// revocationCertQuorum DISTINCT signing keys of domain, each currently
// valid and NOT the target key, to have signed the canonical payload.
func verifyRevocationCertificate(cert api.RevocationCertificate, domainKeys []api.DomainPublicKey, domain string) error {
	got := countRevocationCertSigners(cert, domainKeys, domain)
	if got >= revocationCertQuorum {
		return nil
	}
	return &RevocationError{Got: got, Need: revocationCertQuorum}
}

// applyDomainKeyRevocations returns domainKeys with RevokedAt set for any
// key a quorum-verified sibling revocation certificate targets. A key
// already carrying its own RevokedAt from the domain's own record is left
// unchanged. Never mutates its input.
func applyDomainKeyRevocations(domainKeys []api.DomainPublicKey, certs []api.RevocationCertificate, domain string) []api.DomainPublicKey {
	out := make([]api.DomainPublicKey, len(domainKeys))
	copy(out, domainKeys)
	for _, cert := range certs {
		if verifyRevocationCertificate(cert, domainKeys, domain) != nil {
			continue
		}
		for i := range out {
			if out[i].KeyId == cert.TargetKeyId && out[i].RevokedAt == nil {
				revokedAt := cert.RevokedAt
				out[i].RevokedAt = &revokedAt
			}
		}
	}
	return out
}
