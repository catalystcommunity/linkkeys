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
// signing_domain, expires_at (int or null), attested_at (int)]. Both times
// are whole Unix seconds. A time with a fraction of a second was never
// signed, so it is an error, not a rounded value.
func claimSignPayload(claimID, claimType string, claimValue []byte, userID, subjectDomain, signingDomain string, expiresAt *time.Time, attestedAt time.Time) ([]byte, error) {
	expires := cborNull
	if expiresAt != nil {
		e, err := cborSignedTime(*expiresAt)
		if err != nil {
			return nil, errClaimBadTimestamp
		}
		expires = e
	}
	attested, err := cborSignedTime(attestedAt)
	if err != nil {
		return nil, errClaimBadTimestamp
	}
	return cborTuple(
		cborText(claimPayloadTag),
		cborText(claimID),
		cborText(claimType),
		cborBytesVal(claimValue),
		cborText(userID+"@"+subjectDomain),
		cborText(signingDomain),
		expires,
		attested,
	), nil
}

// errClaimBadTimestamp matches `liblinkkeys::claims::ClaimError::BadTimestamp`.
var errClaimBadTimestamp = errors.New("claim has a timestamp that cannot be signed")

// claimKeyValidAt mirrors `liblinkkeys::claims::key_valid_at`: the domain key
// was not revoked and not expired at the claim's attestation time. Neither
// revocation nor expiry is retroactive (invariant I-7).
func claimKeyValidAt(key api.DomainPublicKey, at time.Time) error {
	if key.RevokedAt != nil && !at.Before(*key.RevokedAt) {
		return fmt.Errorf("signing key has been revoked: %s", key.KeyId)
	}
	if !at.Before(key.ExpiresAt) {
		return fmt.Errorf("signing key has expired: %s", key.KeyId)
	}
	return nil
}

// verifyOneClaimSignature mirrors `liblinkkeys::claims::verify_one_signature`
// for a stored attestation (attested_at given).
func verifyOneClaimSignature(sig api.ClaimSignature, payload []byte, keys []api.DomainPublicKey, attestedAt time.Time) error {
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
		return fmt.Errorf("unsupported signing algorithm: %s", enumLabel(key.Algorithm))
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
	payload, err := claimSignPayload(claim.ClaimId, claim.ClaimType, claim.ClaimValue, claim.UserId, domain, domain, claim.ExpiresAt, claim.AttestedAt)
	if err != nil {
		return err
	}
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
	if claim.ExpiresAt != nil && now.After(*claim.ExpiresAt) {
		return errors.New("claim has expired")
	}
	return nil
}
