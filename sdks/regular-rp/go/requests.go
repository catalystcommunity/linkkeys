package regularrp

import (
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

// Verification of addition and renewal requests — the quorum-signed
// requests keyring.go builds and signs. Mirrors
// `liblinkkeys::application_keys::verify_addition` /
// `verify_renewal`.
//
// This is normally a HOME DOMAIN server operation (the request's admission
// check), not something a peer or a resolving application needs — which is
// why it is a separate file from applicationkeys.go's peer-facing verifier.
// It is ported here because sdks/regular-rp/conformance/'s addition and
// renewal vector files exist specifically so every LinkKeys SDK can prove
// its construction AND verification of these requests agree with the Rust
// reference, and because an application built on this SDK may want to
// sanity-check a request it just built (or received, if it implements a
// home-domain-like role) before submitting it over the wire.

// checkWindow checks a `(requestedAt, expiresAt)` pair against now, tolerant
// of skewSeconds of clock skew in either direction. Mirrors
// `application_keys::check_window`.
func checkWindow(requestedAt, expiresAt string, now time.Time, skewSeconds int64) error {
	start, err := parseAppKeyTime(requestedAt)
	if err != nil {
		return &ApplicationKeyError{Kind: ErrBadTimestamp, Detail: err.Error()}
	}
	end, err := parseAppKeyTime(expiresAt)
	if err != nil {
		return &ApplicationKeyError{Kind: ErrBadTimestamp, Detail: err.Error()}
	}
	if !end.After(start) {
		return &ApplicationKeyError{Kind: ErrRequestExpired}
	}
	skew := time.Duration(skewSeconds) * time.Second
	if now.Add(skew).Before(start) || now.Add(-skew).After(end) {
		return &ApplicationKeyError{Kind: ErrRequestExpired}
	}
	return nil
}

func decodeAddition(signed api.SignedApplicationKeyAddition, instance InstanceRef, now time.Time, skewSeconds int64) (api.ApplicationKeyAddition, error) {
	addition, err := api.DecodeApplicationKeyAddition(signed.Addition)
	if err != nil {
		return api.ApplicationKeyAddition{}, &ApplicationKeyError{Kind: ErrDecode, Detail: err.Error()}
	}
	if err := checkIdentity(instance, addition.SubjectUserId, addition.SubjectDomain, addition.ApplicationId, addition.InstanceId); err != nil {
		return api.ApplicationKeyAddition{}, err
	}
	if err := CheckKeyShape(addition.KeyUsage, addition.Algorithm, addition.PublicKey, addition.Fingerprint); err != nil {
		return api.ApplicationKeyAddition{}, err
	}
	if err := checkWindow(addition.RequestedAt, addition.ExpiresAt, now, skewSeconds); err != nil {
		return api.ApplicationKeyAddition{}, err
	}
	if addition.RequestedKeyLifetimeSeconds <= 0 {
		return api.ApplicationKeyAddition{}, &ApplicationKeyError{Kind: ErrBadConfiguration, Detail: "requested key lifetime must be positive"}
	}
	return addition, nil
}

func checkAdditionPossession(signed api.SignedApplicationKeyAddition, addition api.ApplicationKeyAddition) error {
	switch addition.KeyUsage {
	case KeyUsageSign:
		if signed.PossessionProof == nil {
			return &ApplicationKeyError{Kind: ErrMissingPossessionProof}
		}
		message := PossessionSignatureInput(signed.Addition)
		if resolveAndVerify(addition.Algorithm, message, *signed.PossessionProof, addition.PublicKey) != nil {
			return &ApplicationKeyError{Kind: ErrBadPossessionProof}
		}
		return nil
	case KeyUsageAgree:
		// An X25519 key cannot sign, so a signature here proves nothing
		// about it and must not be accepted as if it did. Possession is
		// proven by the sealed-challenge plaintext the server checks
		// separately.
		if signed.PossessionProof != nil {
			return &ApplicationKeyError{Kind: ErrBadPossessionProof}
		}
		return nil
	default:
		return &ApplicationKeyError{Kind: ErrUsageMismatch, Detail: "expected sign or agree, got " + addition.KeyUsage}
	}
}

// VerifyAddition verifies an addition request against the instance's
// current key set. Requires AdditionQuorum DISTINCT currently-valid signing
// keys of existingKeys (excluding the new key, which never counts toward
// its own authorization) to have signed, and the new key to have proven
// possession of its own private key.
//
// The caller still owns two things this function cannot know: that
// addition.Challenge matches the single-use nonce the home domain issued
// under addition.ChallengeId, and that addition.KeyId is not already taken.
// Both need server state.
func VerifyAddition(signed api.SignedApplicationKeyAddition, existingKeys []ApplicationKeyRef, instance InstanceRef, now time.Time, skewSeconds int64) (api.ApplicationKeyAddition, error) {
	addition, err := decodeAddition(signed, instance, now, skewSeconds)
	if err != nil {
		return api.ApplicationKeyAddition{}, err
	}
	if err := checkAdditionPossession(signed, addition); err != nil {
		return api.ApplicationKeyAddition{}, err
	}

	message := AdditionSignatureInput(signed.Addition)
	accepted := countDistinctAppKeySigners(signed.Signatures, existingKeys, message, addition.KeyId, func(k ApplicationKeyRef) bool {
		return k.IsValidSigningKey(now)
	})
	if len(accepted) < AdditionQuorum {
		return api.ApplicationKeyAddition{}, &ApplicationKeyError{Kind: ErrInsufficientSignatures, Got: len(accepted), Need: AdditionQuorum}
	}
	return addition, nil
}

// VerifyRenewal verifies a renewal request for target.
//
// Renewal creates a new attestation for the SAME key. It never creates a
// key and never changes key equality. A revoked key can never be renewed,
// and revocation is permanent, so this is checked before anything else.
//
// As with additions, the caller must separately confirm that
// renewal.Challenge matches the single-use nonce it issued.
func VerifyRenewal(signed api.SignedApplicationKeyRenewal, target ApplicationKeyRef, siblingKeys []ApplicationKeyRef, instance InstanceRef, now time.Time, skewSeconds int64) (api.ApplicationKeyRenewal, error) {
	renewal, err := api.DecodeApplicationKeyRenewal(signed.Renewal)
	if err != nil {
		return api.ApplicationKeyRenewal{}, &ApplicationKeyError{Kind: ErrDecode, Detail: err.Error()}
	}
	if err := checkIdentity(instance, renewal.SubjectUserId, renewal.SubjectDomain, renewal.ApplicationId, renewal.InstanceId); err != nil {
		return api.ApplicationKeyRenewal{}, err
	}
	if err := checkWindow(renewal.RequestedAt, renewal.ExpiresAt, now, skewSeconds); err != nil {
		return api.ApplicationKeyRenewal{}, err
	}

	if renewal.KeyId != target.KeyID {
		return api.ApplicationKeyRenewal{}, &ApplicationKeyError{Kind: ErrIdentityMismatch, Field: "key_id"}
	}
	if target.RevokedAt != nil {
		return api.ApplicationKeyRenewal{}, &ApplicationKeyError{Kind: ErrKeyRevoked, Detail: target.KeyID}
	}
	if !target.IsValid(now) {
		return api.ApplicationKeyRenewal{}, &ApplicationKeyError{Kind: ErrKeyExpired, Detail: target.KeyID}
	}

	switch target.KeyUsage {
	case KeyUsageSign:
		if signed.PossessionProof == nil {
			return api.ApplicationKeyRenewal{}, &ApplicationKeyError{Kind: ErrMissingPossessionProof}
		}
		if resolveAndVerify(target.Algorithm, PossessionSignatureInput(signed.Renewal), *signed.PossessionProof, target.PublicKey) != nil {
			return api.ApplicationKeyRenewal{}, &ApplicationKeyError{Kind: ErrBadPossessionProof}
		}
	case KeyUsageAgree:
		if signed.PossessionProof != nil {
			return api.ApplicationKeyRenewal{}, &ApplicationKeyError{Kind: ErrBadPossessionProof}
		}
		// The key cannot sign, so a sibling must say who is asking. The
		// proof of possession itself is the sealed-challenge plaintext
		// the server checks against the nonce it issued.
		message := RenewalSignatureInput(signed.Renewal)
		accepted := countDistinctAppKeySigners(signed.Signatures, siblingKeys, message, target.KeyID, func(k ApplicationKeyRef) bool {
			return k.IsValidSigningKey(now)
		})
		if len(accepted) < RenewalQuorum {
			return api.ApplicationKeyRenewal{}, &ApplicationKeyError{Kind: ErrInsufficientSignatures, Got: len(accepted), Need: RenewalQuorum}
		}
	default:
		return api.ApplicationKeyRenewal{}, &ApplicationKeyError{Kind: ErrUsageMismatch, Detail: "expected sign or agree, got " + target.KeyUsage}
	}
	return renewal, nil
}
