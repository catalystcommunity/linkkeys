package regularrp

import (
	"errors"
	"fmt"
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

// Claim signature verification for ONE signing domain. This is the part of
// crates/liblinkkeys/src/claims.rs that VerifyHandleClaim needs: the signed
// payload (`claim_sign_payload`), the per-signature key check
// (`verify_one_signature` with a stored attestation time), and the claim's own
// revocation and expiry (`verify_claim`). It is not a general claim verifier:
// it does not do the multi-domain quorum.

// claimPayloadTag is CLAIM_PAYLOAD_TAG from crates/liblinkkeys/src/claims.rs.
const claimPayloadTag = "linkkeys-claim-v1alpha"

// claimSignPayload builds the bytes that one claim signature covers. Mirrors
// `liblinkkeys::claims::claim_sign_payload`: the CBOR array
// [tag, claim_id, claim_type, claim_value (bstr), "user_id@subject_domain",
// signing_domain, expires_at (text or null), attested_at].
func claimSignPayload(claimID, claimType string, claimValue []byte, userID, subjectDomain, signingDomain string, expiresAt *string, attestedAt string) []byte {
	expires := cborNull
	if expiresAt != nil {
		expires = cborText(*expiresAt)
	}
	return cborTuple(
		cborText(claimPayloadTag),
		cborText(claimID),
		cborText(claimType),
		cborBytesVal(claimValue),
		cborText(userID+"@"+subjectDomain),
		cborText(signingDomain),
		expires,
		cborText(attestedAt),
	)
}

// claimKeyValidAt mirrors `liblinkkeys::claims::key_valid_at`: the domain key
// was not revoked and not expired at the claim's attestation time. Neither
// revocation nor expiry is retroactive (invariant I-7).
func claimKeyValidAt(key api.DomainPublicKey, at string) error {
	atTime, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return fmt.Errorf("signing key has expired: %s", key.KeyId)
	}
	if key.RevokedAt != nil {
		revoked, err := time.Parse(time.RFC3339, *key.RevokedAt)
		if err != nil || !atTime.Before(revoked) {
			return fmt.Errorf("signing key has been revoked: %s", key.KeyId)
		}
	}
	expires, err := time.Parse(time.RFC3339, key.ExpiresAt)
	if err != nil || !atTime.Before(expires) {
		return fmt.Errorf("signing key has expired: %s", key.KeyId)
	}
	return nil
}

// verifyOneClaimSignature mirrors `liblinkkeys::claims::verify_one_signature`
// for a stored attestation (attested_at given).
func verifyOneClaimSignature(sig api.ClaimSignature, payload []byte, keys []api.DomainPublicKey, attestedAt string) error {
	var key *api.DomainPublicKey
	for i := range keys {
		if keys[i].KeyId == sig.SignedByKeyId {
			key = &keys[i]
			break
		}
	}
	if key == nil {
		return fmt.Errorf("signing key not found: %s", sig.SignedByKeyId)
	}
	if key.KeyUsage != KeyUsageSign {
		return errors.New("claim signature verification failed")
	}
	if err := claimKeyValidAt(*key, attestedAt); err != nil {
		return err
	}
	if key.Algorithm != algorithmEd25519 {
		return fmt.Errorf("unsupported signing algorithm: %s", key.Algorithm)
	}
	if resolveAndVerify(key.Algorithm, payload, sig.Signature, key.PublicKey) != nil {
		return errors.New("claim signature verification failed")
	}
	return nil
}

// verifySingleDomainClaim verifies a claim whose signatures are all by
// domain, which is also the subject's home domain. One signature by a key
// that was valid at the claim's attested_at is enough. Then the claim must
// not be revoked, and not expired at now. The error text matches
// `liblinkkeys::claims::ClaimError`.
func verifySingleDomainClaim(claim api.Claim, signatures []api.ClaimSignature, domain string, domainKeys []api.DomainPublicKey, now time.Time) error {
	if len(signatures) == 0 {
		return errors.New("claim has no signatures")
	}
	payload := claimSignPayload(claim.ClaimId, claim.ClaimType, claim.ClaimValue, claim.UserId, domain, domain, claim.ExpiresAt, claim.AttestedAt)
	lastErr := fmt.Errorf("no valid signature for signing domain: %s", domain)
	verified := false
	for _, sig := range signatures {
		if err := verifyOneClaimSignature(sig, payload, domainKeys, claim.AttestedAt); err != nil {
			lastErr = err
			continue
		}
		verified = true
		break
	}
	if !verified {
		return lastErr
	}
	if claim.RevokedAt != nil {
		return errors.New("claim has been revoked")
	}
	if claim.ExpiresAt != nil {
		expires, err := time.Parse(time.RFC3339, *claim.ExpiresAt)
		if err != nil {
			return errors.New("claim has an invalid expires_at")
		}
		if now.After(expires) {
			return errors.New("claim has expired")
		}
	}
	return nil
}
