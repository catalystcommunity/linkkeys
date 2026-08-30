package regularrp

import (
	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

// The local signing keyring: everything the APPLICATION side needs to
// generate its own key pairs and build/sign the requests that authorize
// adding, renewing, and revoking application keys. Mirrors the signing half
// of crates/liblinkkeys/src/application_keys.rs (`sign_addition`,
// `sign_renewal`, `sign_revocation`) plus the SDK side of the sealed
// challenge (`open_challenge`).
//
// Private keys never leave this process: every function here takes key
// material in and returns signed wire structures out. Submitting a signed
// request to a home domain (ApplicationKeys/add-key, /renew-attestation,
// /revoke-key — all unauthenticated at the transport layer, per
// docs/application-keys.md's Operations table: the signed request IS the
// authentication) is the caller's job, using the generated
// api.ApplicationKeysClient directly; this package only builds and signs.

// NewSigningKeyPair generates a fresh Ed25519 application signing key pair
// and its fingerprint.
func NewSigningKeyPair() (publicKey [32]byte, seed [32]byte, fingerprint string, err error) {
	publicKey, seed, err = GenerateEd25519KeyPair()
	if err != nil {
		return publicKey, seed, "", err
	}
	return publicKey, seed, Fingerprint(publicKey[:]), nil
}

// NewAgreementKeyPair generates a fresh X25519 application key-agreement key
// pair and its fingerprint.
func NewAgreementKeyPair() (publicKey [32]byte, privateKey [32]byte, fingerprint string, err error) {
	publicKey, privateKey, err = GenerateX25519KeyPair()
	if err != nil {
		return publicKey, privateKey, "", err
	}
	return publicKey, privateKey, Fingerprint(publicKey[:]), nil
}

// SignAddition builds and signs an addition request. quorumSigners must be
// two DISTINCT currently-valid signing keys of the instance (AdditionQuorum),
// and must not include the new key. newKeySigner is the new key itself for a
// signing key, and nil for a key-agreement key (which cannot sign — it
// proves possession by returning the sealed-challenge plaintext in
// addition.Challenge instead).
func SignAddition(addition api.ApplicationKeyAddition, quorumSigners []ApplicationSigner, newKeySigner *ApplicationSigner) (api.SignedApplicationKeyAddition, error) {
	bytes := api.EncodeApplicationKeyAddition(addition)
	quorumMessage := AdditionSignatureInput(bytes)

	signatures := make([]api.ApplicationKeySignature, 0, len(quorumSigners))
	for _, signer := range quorumSigners {
		sig, err := signWithAlgorithm(signer.Algorithm, quorumMessage, signer.PrivateKeyBytes)
		if err != nil {
			return api.SignedApplicationKeyAddition{}, err
		}
		signatures = append(signatures, api.ApplicationKeySignature{SignedByKeyId: signer.KeyID, Signature: sig})
	}

	var possessionProof *[]byte
	if newKeySigner != nil {
		proof, err := signWithAlgorithm(newKeySigner.Algorithm, PossessionSignatureInput(bytes), newKeySigner.PrivateKeyBytes)
		if err != nil {
			return api.SignedApplicationKeyAddition{}, err
		}
		possessionProof = &proof
	}

	return api.SignedApplicationKeyAddition{
		Addition:        bytes,
		Signatures:      signatures,
		PossessionProof: possessionProof,
	}, nil
}

// SignRenewal builds and signs a renewal request. For an Ed25519 target the
// key signs for itself in the returned PossessionProof, which is both the
// proof and the authentication (pass targetSigner, leave siblingSigners
// empty). For an X25519 target, pass sibling siblingSigners — it cannot sign
// for itself (leave targetSigner nil).
func SignRenewal(renewal api.ApplicationKeyRenewal, siblingSigners []ApplicationSigner, targetSigner *ApplicationSigner) (api.SignedApplicationKeyRenewal, error) {
	bytes := api.EncodeApplicationKeyRenewal(renewal)
	message := RenewalSignatureInput(bytes)

	signatures := make([]api.ApplicationKeySignature, 0, len(siblingSigners))
	for _, signer := range siblingSigners {
		sig, err := signWithAlgorithm(signer.Algorithm, message, signer.PrivateKeyBytes)
		if err != nil {
			return api.SignedApplicationKeyRenewal{}, err
		}
		signatures = append(signatures, api.ApplicationKeySignature{SignedByKeyId: signer.KeyID, Signature: sig})
	}

	var possessionProof *[]byte
	if targetSigner != nil {
		proof, err := signWithAlgorithm(targetSigner.Algorithm, PossessionSignatureInput(bytes), targetSigner.PrivateKeyBytes)
		if err != nil {
			return api.SignedApplicationKeyRenewal{}, err
		}
		possessionProof = &proof
	}

	return api.SignedApplicationKeyRenewal{
		Renewal:         bytes,
		Signatures:      signatures,
		PossessionProof: possessionProof,
	}, nil
}

// SignRevocation builds a revocation co-signed by sibling keys. The caller
// must not include the target among signers — the target never signs its
// own revocation, and the home domain rejects it regardless.
func SignRevocation(instance InstanceRef, targetKeyID, targetFingerprint, revokedAt string, signers []ApplicationSigner) (api.ApplicationKeyRevocation, error) {
	message := RevocationPayload(instance.SubjectUserID, instance.SubjectDomain, instance.ApplicationID, instance.InstanceID, targetKeyID, targetFingerprint, revokedAt)

	signatures := make([]api.ApplicationKeySignature, 0, len(signers))
	for _, signer := range signers {
		sig, err := signWithAlgorithm(signer.Algorithm, message, signer.PrivateKeyBytes)
		if err != nil {
			return api.ApplicationKeyRevocation{}, err
		}
		signatures = append(signatures, api.ApplicationKeySignature{SignedByKeyId: signer.KeyID, Signature: sig})
	}

	return api.ApplicationKeyRevocation{
		SubjectUserId:     instance.SubjectUserID,
		SubjectDomain:     instance.SubjectDomain,
		ApplicationId:     instance.ApplicationID,
		InstanceId:        instance.InstanceID,
		TargetKeyId:       targetKeyID,
		TargetFingerprint: targetFingerprint,
		RevokedAt:         revokedAt,
		Signatures:        signatures,
	}, nil
}

// OpenChallenge opens a sealed X25519 proof-of-possession challenge with the
// application's own X25519 private key — the SDK side of the home domain's
// `seal_challenge`. The recovered bytes ARE the proof-of-possession secret
// for the key-agreement key: return them verbatim inside the addition or
// renewal request's Challenge field, never log them.
func OpenChallenge(sealed []byte, recipientX25519Private [32]byte) ([]byte, error) {
	count, rest, err := cborReadArray(sealed)
	if err != nil {
		return nil, &ApplicationKeyError{Kind: ErrDecode, Detail: err.Error()}
	}
	if count != 4 {
		return nil, &ApplicationKeyError{Kind: ErrDecode, Detail: "sealed challenge is not a 4-element array"}
	}
	suiteID, rest, err := cborReadText(rest)
	if err != nil {
		return nil, &ApplicationKeyError{Kind: ErrDecode, Detail: err.Error()}
	}
	ephemeral, rest, err := cborReadBytes(rest)
	if err != nil {
		return nil, &ApplicationKeyError{Kind: ErrDecode, Detail: err.Error()}
	}
	nonce, rest, err := cborReadBytes(rest)
	if err != nil {
		return nil, &ApplicationKeyError{Kind: ErrDecode, Detail: err.Error()}
	}
	ciphertext, _, err := cborReadBytes(rest)
	if err != nil {
		return nil, &ApplicationKeyError{Kind: ErrDecode, Detail: err.Error()}
	}

	return sealedBoxDecrypt(ephemeral, nonce, ciphertext, recipientX25519Private, suiteID)
}
