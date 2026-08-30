package regularrp

import (
	"sort"
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

// Application-key verification: attestations, revocations, and the
// whole-response verifier a peer or SDK must run. Ports the pure logic of
// crates/liblinkkeys/src/application_keys.rs — read that file's module doc
// first; it explains the reasoning behind every rule, and this file must
// agree with it exactly (verified byte-for-byte against
// sdks/regular-rp/conformance/ in conformance_test.go).
//
// VerifyAddition and VerifyRenewal (the request-admission checks a home
// domain runs before accepting a quorum-signed request) live in
// requests.go, not here — this file is the PEER-facing verifier: what an
// application or its RP checks about a home domain's already-accepted,
// already-attested keys. This file deliberately does NOT port
// `verify_initial_enrollment`: that path is reachable only after the
// account owner authenticates directly with the home domain, which is
// outside any SDK's role.

// ---------------------------------------------------------------------------
// Domain-separation tags (docs/application-keys.md, "Domain-separation tags")
// ---------------------------------------------------------------------------

// The `-v1alpha` suffix on every tag below is an EPOCH marker, not a version
// counter: it marks the pre-alpha protocol epoch and changes only when the
// protocol leaves alpha. Within an epoch these MUST NOT change.
const (
	AttestationTag = "linkkeys-application-key-attestation-v1alpha"
	AdditionTag    = "linkkeys-application-key-addition-v1alpha"
	PossessionTag  = "linkkeys-application-key-possession-v1alpha"
	RenewalTag     = "linkkeys-application-key-renewal-v1alpha"
	RevocationTag  = "linkkeys-application-key-revocation-v1alpha"
)

// Protocol constants (crates/liblinkkeys/src/application_keys.rs).
const (
	// AdditionQuorum: distinct valid signing keys that must authorize
	// adding a key.
	AdditionQuorum = 2
	// RevocationQuorum: distinct valid sibling signing keys that must
	// authorize a revocation.
	RevocationQuorum = 2
	// RenewalQuorum: distinct valid sibling signing keys that must
	// authorize renewing the attestation of a key that cannot sign for
	// itself.
	RenewalQuorum = 1
	// MinSigningKeys: an instance MUST hold at least this many valid
	// signing keys after initial enrollment.
	MinSigningKeys = 2
	// RecommendedSigningKeys: an instance SHOULD hold at least this
	// many, so an ordinary sibling revocation is possible (the target
	// may not sign its own revocation).
	RecommendedSigningKeys = 3
)

// Key use strings (wire values of `key_usage`).
const (
	KeyUsageSign  = "sign"
	KeyUsageAgree = "agree"
)

// Challenge purpose strings (wire values of `purpose`).
const (
	PurposeAdd   = "add"
	PurposeRenew = "renew"
)

// ---------------------------------------------------------------------------
// Identity and key references
// ---------------------------------------------------------------------------

// InstanceRef is the canonical identity an application key is bound to.
// SubjectUserID is always the account's one canonical UUID — a profile is a
// presentation persona, never a second identity, so it never appears here.
// This is also the SDK's application-key CACHE KEY (resolver.go): never a
// bare handle, which can move or be reused.
type InstanceRef struct {
	SubjectUserID string
	SubjectDomain string
	ApplicationID string
	InstanceID    string
}

// ApplicationKeyRef is one application public key as the verifying side
// knows it: no private key here, and never will be.
type ApplicationKeyRef struct {
	KeyID       string
	KeyUsage    string
	Algorithm   string
	PublicKey   []byte
	Fingerprint string
	CreatedAt   string
	ExpiresAt   string
	RevokedAt   *string
}

// IsValidSigningKey reports whether this key can currently make a quorum
// signature: a signing key, not revoked, and inside its own validity window.
func (k ApplicationKeyRef) IsValidSigningKey(now time.Time) bool {
	return k.KeyUsage == KeyUsageSign && k.IsValid(now)
}

// IsValid reports whether this key is not revoked and inside its own
// validity window at now.
func (k ApplicationKeyRef) IsValid(now time.Time) bool {
	if k.RevokedAt != nil {
		t, err := parseAppKeyTime(*k.RevokedAt)
		if err != nil || !t.After(now) {
			return false
		}
	}
	exp, err := parseAppKeyTime(k.ExpiresAt)
	if err != nil {
		return false
	}
	return exp.After(now)
}

// WasValidAt reports whether this key was able to authorize something at
// `at` — used when checking a revocation long after the fact: a signer that
// was valid when it signed authorized the revocation, and a verifier must
// still be able to confirm that after the signer itself expires.
func (k ApplicationKeyRef) WasValidAt(at time.Time) bool {
	if created, err := parseAppKeyTime(k.CreatedAt); err == nil && created.After(at) {
		return false
	}
	exp, err := parseAppKeyTime(k.ExpiresAt)
	if err != nil || !exp.After(at) {
		return false
	}
	if k.RevokedAt != nil {
		rev, err := parseAppKeyTime(*k.RevokedAt)
		if err != nil || !rev.After(at) {
			return false
		}
	}
	return true
}

// ApplicationSigner is one of the application's OWN signing keys (the
// mirror of `liblinkkeys::claims::ClaimSigner` for keys the APPLICATION
// holds). Used only for signing (keyring.go) — this package never sends a
// private key anywhere.
type ApplicationSigner struct {
	KeyID           string
	Algorithm       string // "ed25519"
	PrivateKeyBytes []byte
}

func parseAppKeyTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// ---------------------------------------------------------------------------
// Canonical signature inputs
// ---------------------------------------------------------------------------

// AttestationSignatureInput builds the bytes a home-domain signature over an
// attestation covers: `CBOR([AttestationTag, attestationBytes])`.
func AttestationSignatureInput(attestationBytes []byte) []byte {
	return envelopeSignatureInput(AttestationTag, attestationBytes)
}

// AdditionSignatureInput builds the bytes a quorum signature over an
// addition request covers.
func AdditionSignatureInput(additionBytes []byte) []byte {
	return envelopeSignatureInput(AdditionTag, additionBytes)
}

// PossessionSignatureInput builds the bytes a key's own proof of possession
// covers: the same payload bytes as the addition or renewal, under a
// DIFFERENT tag, so a possession proof can never be replayed as a quorum
// signature or the reverse.
func PossessionSignatureInput(payloadBytes []byte) []byte {
	return envelopeSignatureInput(PossessionTag, payloadBytes)
}

// RenewalSignatureInput builds the bytes a sibling signature over a renewal
// request covers.
func RenewalSignatureInput(renewalBytes []byte) []byte {
	return envelopeSignatureInput(RenewalTag, renewalBytes)
}

// envelopeSignatureInput mirrors `liblinkkeys::local_rp::envelope_signature_input`:
// `CBOR([tag, payload])` — a two-element array, NOT a concatenation.
func envelopeSignatureInput(tag string, payloadBytes []byte) []byte {
	return cborTuple(cborText(tag), cborBytesVal(payloadBytes))
}

// RevocationPayload builds the bytes a sibling signature over a revocation
// covers. Unlike the attestation and the requests, a revocation is verified
// from its FIELDS rather than from a stored byte string: a tagged
// eight-element tuple. Every identifier is bound, so a revocation cannot
// move between subjects, applications, or instances.
func RevocationPayload(subjectUserID, subjectDomain, applicationID, instanceID, targetKeyID, targetFingerprint, revokedAt string) []byte {
	return cborTuple(
		cborText(RevocationTag),
		cborText(subjectUserID),
		cborText(subjectDomain),
		cborText(applicationID),
		cborText(instanceID),
		cborText(targetKeyID),
		cborText(targetFingerprint),
		cborText(revokedAt),
	)
}

func revocationPayloadOf(rev api.ApplicationKeyRevocation) []byte {
	return RevocationPayload(
		rev.SubjectUserId, rev.SubjectDomain, rev.ApplicationId, rev.InstanceId,
		rev.TargetKeyId, rev.TargetFingerprint, rev.RevokedAt,
	)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func checkIdentity(expected InstanceRef, subjectUserID, subjectDomain, applicationID, instanceID string) error {
	switch {
	case subjectUserID != expected.SubjectUserID:
		return &ApplicationKeyError{Kind: ErrIdentityMismatch, Field: "subject_user_id"}
	case subjectDomain != expected.SubjectDomain:
		return &ApplicationKeyError{Kind: ErrIdentityMismatch, Field: "subject_domain"}
	case applicationID != expected.ApplicationID:
		return &ApplicationKeyError{Kind: ErrIdentityMismatch, Field: "application_id"}
	case instanceID != expected.InstanceID:
		return &ApplicationKeyError{Kind: ErrIdentityMismatch, Field: "instance_id"}
	}
	return nil
}

func expectedAlgorithm(keyUsage string) (string, bool) {
	switch keyUsage {
	case KeyUsageSign:
		return algorithmEd25519, true
	case KeyUsageAgree:
		return algorithmX25519, true
	default:
		return "", false
	}
}

// CheckKeyShape checks that a key's stated use, algorithm, and fingerprint
// are internally consistent before anything trusts them.
func CheckKeyShape(keyUsage, algorithm string, publicKey []byte, fingerprint string) error {
	expected, ok := expectedAlgorithm(keyUsage)
	if !ok {
		return &ApplicationKeyError{Kind: ErrUsageMismatch, Detail: "expected sign or agree, got " + keyUsage}
	}
	if algorithm != expected {
		return &ApplicationKeyError{Kind: ErrUsageMismatch, Detail: "expected " + expected + ", got " + algorithm}
	}
	if len(publicKey) != 32 {
		return &ApplicationKeyError{Kind: ErrCrypto, Detail: "public key must be 32 bytes"}
	}
	if Fingerprint(publicKey) != fingerprint {
		return &ApplicationKeyError{Kind: ErrFingerprintMismatch}
	}
	return nil
}

// countDistinctAppKeySigners counts DISTINCT valid application signing keys
// that signed message. A key never counts twice, excludedKeyID never counts
// at all (the new key in an addition, the target in a revocation), and only
// a key validAt accepts is eligible.
func countDistinctAppKeySigners(signatures []api.ApplicationKeySignature, keys []ApplicationKeyRef, message []byte, excludedKeyID string, validAt func(ApplicationKeyRef) bool) map[string]bool {
	accepted := make(map[string]bool)
	for _, sig := range signatures {
		if sig.SignedByKeyId == excludedKeyID {
			continue
		}
		if accepted[sig.SignedByKeyId] {
			continue
		}
		var key *ApplicationKeyRef
		for i := range keys {
			if keys[i].KeyID == sig.SignedByKeyId {
				key = &keys[i]
				break
			}
		}
		if key == nil || key.KeyUsage != KeyUsageSign || !validAt(*key) {
			continue
		}
		if resolveAndVerify(key.Algorithm, message, sig.Signature, key.PublicKey) == nil {
			accepted[sig.SignedByKeyId] = true
		}
	}
	return accepted
}

// ---------------------------------------------------------------------------
// Attestations: verify
// ---------------------------------------------------------------------------

// VerifyAttestationSignature verifies a home-domain attestation and returns
// what it says. Requires at least one signature from a currently valid
// signing key of expectedDomain — a domain assertion, not a peer quorum: the
// domain's own key set is already pinned, so one valid signature over the
// exact stored bytes is the proof.
//
// Checking that the attestation is CURRENT is a separate step (see
// ClassifyKey) — an expired attestation is a missing proof, not a
// revocation.
func VerifyAttestationSignature(signed api.SignedApplicationKeyAttestation, domainKeys []api.DomainPublicKey, expectedDomain string) (api.ApplicationKeyAttestation, error) {
	attestation, err := api.DecodeApplicationKeyAttestation(signed.Attestation)
	if err != nil {
		return api.ApplicationKeyAttestation{}, &ApplicationKeyError{Kind: ErrDecode, Detail: err.Error()}
	}
	if attestation.SubjectDomain != expectedDomain {
		return api.ApplicationKeyAttestation{}, &ApplicationKeyError{Kind: ErrIdentityMismatch, Field: "subject_domain"}
	}
	if err := CheckKeyShape(attestation.KeyUsage, attestation.Algorithm, attestation.PublicKey, attestation.Fingerprint); err != nil {
		return api.ApplicationKeyAttestation{}, err
	}

	message := AttestationSignatureInput(signed.Attestation)
	for _, sig := range signed.Signatures {
		if sig.Domain != expectedDomain {
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
		if resolveAndVerify(key.Algorithm, message, sig.Signature, key.PublicKey) == nil {
			return attestation, nil
		}
	}
	return api.ApplicationKeyAttestation{}, &ApplicationKeyError{Kind: ErrUntrustedAttestation}
}

// ---------------------------------------------------------------------------
// The verifier's view of a key set
// ---------------------------------------------------------------------------

// KeyStatusKind is why a key is or is not acceptable for current use. A
// dedicated enum, not a boolean: AttestationExpired and Revoked are
// deliberately distinct — an expired attestation is a MISSING PROOF, not a
// revocation, and a renewed attestation can make the same unrevoked key
// acceptable again.
type KeyStatusKind int

const (
	// KeyStatusUsable: every condition holds — the attestation verifies
	// and is current, the key is inside its own window, no accepted
	// revocation applies.
	KeyStatusUsable KeyStatusKind = iota
	// KeyStatusAttestationExpired: the key is fine but the proof is
	// stale. A renewed attestation can make the same unrevoked key
	// acceptable again.
	KeyStatusAttestationExpired
	// KeyStatusKeyExpired: the key's own lifetime has passed. Renewal
	// cannot help.
	KeyStatusKeyExpired
	// KeyStatusRevoked: permanently revoked as of RevokedAt.
	KeyStatusRevoked
)

func (k KeyStatusKind) String() string {
	switch k {
	case KeyStatusUsable:
		return "usable"
	case KeyStatusAttestationExpired:
		return "attestation_expired"
	case KeyStatusKeyExpired:
		return "key_expired"
	case KeyStatusRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// KeyStatus carries KeyStatusKind plus the revocation instant when Kind is
// KeyStatusRevoked.
type KeyStatus struct {
	Kind      KeyStatusKind
	RevokedAt string // only meaningful when Kind == KeyStatusRevoked
}

// VerifiedApplicationKey is one attestation-verified key, with the reason it
// is or is not usable.
type VerifiedApplicationKey struct {
	Attestation api.ApplicationKeyAttestation
	Status      KeyStatus
}

// IsUsable reports whether this key is currently usable.
func (k VerifiedApplicationKey) IsUsable() bool { return k.Status.Kind == KeyStatusUsable }

// RejectedRecord is a record that did not survive verification, and why.
// Kept rather than silently dropped so a caller can see a real problem
// instead of an unexplained empty set.
type RejectedRecord struct {
	What   string
	Reason string
}

// VerifiedApplicationKeySet is the verified result of one
// resolve-application-keys (or RP-cached) response.
type VerifiedApplicationKeySet struct {
	// Keys are attestation-verified keys, in no meaningful order. A key
	// id identifies one key; there is no preferred key.
	Keys []VerifiedApplicationKey
	// RevokedKeyIDs are key ids with an accepted revocation that applies
	// at the evaluated time.
	RevokedKeyIDs map[string]bool
	// Rejected are records that failed verification, with the reason.
	Rejected []RejectedRecord
}

// KeyForUse looks up one key by id and confirms it is acceptable for a
// specific operation. This is the call a peer makes before it verifies a
// message: it fails closed on an unknown, expired, unattested, mismatched,
// or revoked key.
func (s VerifiedApplicationKeySet) KeyForUse(keyID, keyUsage, algorithm string) (api.ApplicationKeyAttestation, error) {
	if s.RevokedKeyIDs[keyID] {
		return api.ApplicationKeyAttestation{}, &ApplicationKeyError{Kind: ErrKeyRevoked, Detail: keyID}
	}
	var found *VerifiedApplicationKey
	for i := range s.Keys {
		if s.Keys[i].Attestation.KeyId == keyID {
			found = &s.Keys[i]
			break
		}
	}
	if found == nil {
		return api.ApplicationKeyAttestation{}, &ApplicationKeyError{Kind: ErrUnknownKey, Detail: keyID}
	}
	switch found.Status.Kind {
	case KeyStatusUsable:
	case KeyStatusAttestationExpired:
		return api.ApplicationKeyAttestation{}, &ApplicationKeyError{Kind: ErrAttestationExpired}
	case KeyStatusKeyExpired:
		return api.ApplicationKeyAttestation{}, &ApplicationKeyError{Kind: ErrKeyExpired, Detail: keyID}
	case KeyStatusRevoked:
		return api.ApplicationKeyAttestation{}, &ApplicationKeyError{Kind: ErrKeyRevoked, Detail: keyID}
	}
	if found.Attestation.KeyUsage != keyUsage {
		return api.ApplicationKeyAttestation{}, &ApplicationKeyError{Kind: ErrUsageMismatch, Detail: "expected " + keyUsage + ", got " + found.Attestation.KeyUsage}
	}
	if found.Attestation.Algorithm != algorithm {
		return api.ApplicationKeyAttestation{}, &ApplicationKeyError{Kind: ErrUsageMismatch, Detail: "expected " + algorithm + ", got " + found.Attestation.Algorithm}
	}
	return found.Attestation, nil
}

// UsableKeys returns every currently usable key of one use. All such keys
// are equal: a caller may pick any of them, and the returned order carries
// no meaning (sorted by key id only for deterministic test output).
func (s VerifiedApplicationKeySet) UsableKeys(keyUsage string) []api.ApplicationKeyAttestation {
	var out []api.ApplicationKeyAttestation
	for _, k := range s.Keys {
		if k.IsUsable() && k.Attestation.KeyUsage == keyUsage {
			out = append(out, k.Attestation)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyId < out[j].KeyId })
	return out
}

// ClassifyKey decides the status of one verified attestation at now.
func ClassifyKey(attestation api.ApplicationKeyAttestation, revokedAt *string, now time.Time, skewSeconds int64) (KeyStatus, error) {
	skew := time.Duration(skewSeconds) * time.Second
	if revokedAt != nil {
		effective, err := parseAppKeyTime(*revokedAt)
		if err != nil {
			return KeyStatus{}, &ApplicationKeyError{Kind: ErrBadTimestamp, Detail: err.Error()}
		}
		if !effective.After(now.Add(skew)) {
			return KeyStatus{Kind: KeyStatusRevoked, RevokedAt: *revokedAt}, nil
		}
	}
	keyExpires, err := parseAppKeyTime(attestation.KeyExpiresAt)
	if err != nil {
		return KeyStatus{}, &ApplicationKeyError{Kind: ErrBadTimestamp, Detail: err.Error()}
	}
	if !keyExpires.Add(skew).After(now) {
		return KeyStatus{Kind: KeyStatusKeyExpired}, nil
	}
	attestationExpires, err := parseAppKeyTime(attestation.AttestationExpiresAt)
	if err != nil {
		return KeyStatus{}, &ApplicationKeyError{Kind: ErrBadTimestamp, Detail: err.Error()}
	}
	if !attestationExpires.Add(skew).After(now) {
		return KeyStatus{Kind: KeyStatusAttestationExpired}, nil
	}
	return KeyStatus{Kind: KeyStatusUsable}, nil
}

// VerifyRevocation verifies a revocation against the instance's attested
// SIBLING keys. Requires RevocationQuorum distinct signing keys that were
// valid AT THE REVOCATION TIME. Judging signers at revokedAt rather than at
// "now" is deliberate: revocation is permanent, so the record must stay
// verifiable long after its signers have themselves expired or been rotated
// out. The target never signs and never counts.
func VerifyRevocation(rev api.ApplicationKeyRevocation, keys []ApplicationKeyRef, instance InstanceRef) error {
	if err := checkIdentity(instance, rev.SubjectUserId, rev.SubjectDomain, rev.ApplicationId, rev.InstanceId); err != nil {
		return err
	}
	effective, err := parseAppKeyTime(rev.RevokedAt)
	if err != nil {
		return &ApplicationKeyError{Kind: ErrBadTimestamp, Detail: err.Error()}
	}

	var target *ApplicationKeyRef
	for i := range keys {
		if keys[i].KeyID == rev.TargetKeyId {
			target = &keys[i]
			break
		}
	}
	if target == nil {
		return &ApplicationKeyError{Kind: ErrUnknownKey, Detail: rev.TargetKeyId}
	}
	if target.Fingerprint != rev.TargetFingerprint {
		return &ApplicationKeyError{Kind: ErrFingerprintMismatch}
	}

	message := revocationPayloadOf(rev)
	accepted := countDistinctAppKeySigners(rev.Signatures, keys, message, rev.TargetKeyId, func(k ApplicationKeyRef) bool {
		return k.WasValidAt(effective)
	})
	if len(accepted) < RevocationQuorum {
		return &ApplicationKeyError{Kind: ErrInsufficientSignatures, Got: len(accepted), Need: RevocationQuorum}
	}
	return nil
}

func attestedKeyRef(a api.ApplicationKeyAttestation) ApplicationKeyRef {
	return ApplicationKeyRef{
		KeyID:       a.KeyId,
		KeyUsage:    a.KeyUsage,
		Algorithm:   a.Algorithm,
		PublicKey:   a.PublicKey,
		Fingerprint: a.Fingerprint,
		CreatedAt:   a.KeyCreatedAt,
		ExpiresAt:   a.KeyExpiresAt,
		RevokedAt:   nil,
	}
}

// VerifyApplicationKeySet verifies a whole application-key response the way
// a peer or an SDK must. Order of work matters and is deliberate:
//
//  1. Verify every attestation against the home domain's pinned key set.
//     Only attested keys exist as far as this function is concerned.
//  2. Verify every revocation against those attested SIBLING keys,
//     requiring the quorum, excluding the target, and judging each signer
//     by whether it was valid AT THE REVOCATION TIME.
//  3. Classify each key against the accepted revocations and now.
//
// Nothing here fails the whole set because one record is bad: a rejected
// record is recorded with its reason. A caller that requires completeness
// must check Rejected is empty.
func VerifyApplicationKeySet(
	signedAttestations []api.SignedApplicationKeyAttestation,
	revocations []api.ApplicationKeyRevocation,
	domainKeys []api.DomainPublicKey,
	instance InstanceRef,
	now time.Time,
	skewSeconds int64,
) VerifiedApplicationKeySet {
	set := VerifiedApplicationKeySet{RevokedKeyIDs: make(map[string]bool)}
	var attested []api.ApplicationKeyAttestation

	for _, signed := range signedAttestations {
		a, err := VerifyAttestationSignature(signed, domainKeys, instance.SubjectDomain)
		if err != nil {
			set.Rejected = append(set.Rejected, RejectedRecord{What: "attestation", Reason: err.Error()})
			continue
		}
		if err := checkIdentity(instance, a.SubjectUserId, a.SubjectDomain, a.ApplicationId, a.InstanceId); err != nil {
			set.Rejected = append(set.Rejected, RejectedRecord{What: "attestation " + a.KeyId, Reason: err.Error()})
			continue
		}
		duplicate := false
		for _, x := range attested {
			if x.KeyId == a.KeyId {
				duplicate = true
				break
			}
		}
		if duplicate {
			set.Rejected = append(set.Rejected, RejectedRecord{
				What:   "attestation " + a.KeyId,
				Reason: (&ApplicationKeyError{Kind: ErrDuplicateKey, Detail: a.KeyId}).Error(),
			})
			continue
		}
		attested = append(attested, a)
	}

	// The attested keys are the only sibling authority a revocation can
	// draw on, so this set is built first and used as-is below.
	keyRefs := make([]ApplicationKeyRef, len(attested))
	for i, a := range attested {
		keyRefs[i] = attestedKeyRef(a)
	}

	revoked := make(map[string]string) // key id -> earliest accepted revoked_at
	for _, rev := range revocations {
		if err := VerifyRevocation(rev, keyRefs, instance); err != nil {
			set.Rejected = append(set.Rejected, RejectedRecord{What: "revocation of " + rev.TargetKeyId, Reason: err.Error()})
			continue
		}
		// Revocation is permanent, so the earliest accepted effective
		// time wins if several records name the same key.
		if existing, ok := revoked[rev.TargetKeyId]; !ok || rev.RevokedAt < existing {
			revoked[rev.TargetKeyId] = rev.RevokedAt
		}
	}

	for _, a := range attested {
		var revokedAt *string
		if r, ok := revoked[a.KeyId]; ok {
			r := r
			revokedAt = &r
		}
		status, err := ClassifyKey(a, revokedAt, now, skewSeconds)
		if err != nil {
			set.Rejected = append(set.Rejected, RejectedRecord{What: "attestation " + a.KeyId, Reason: err.Error()})
			continue
		}
		if status.Kind == KeyStatusRevoked {
			set.RevokedKeyIDs[a.KeyId] = true
		}
		set.Keys = append(set.Keys, VerifiedApplicationKey{Attestation: a, Status: status})
	}

	return set
}
