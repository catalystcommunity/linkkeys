package regularrp

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

// Act-as grants: a user lets one application (the grantee) act as the user at
// a second application (the audience). The user's home domain signs the
// user's decision. The audience defines the scope strings, signs the set it
// offers, and enforces them in its own policy.
//
// This file ports the pure half of crates/liblinkkeys/src/act_as.rs:
// signature construction and verification, the issued-terms calculation, the
// refresh decision, and the audience's seven-step verification checklist. It
// must agree with that file exactly (verified against
// sdks/regular-rp/conformance/act_as_*.json in actas_conformance_test.go).
// Every temporal function takes `now`. The one exception, shared with the
// application-key code, is a DOMAIN signing key's validity, which
// checkSigningKeyValid checks against wall-clock time, like the Rust
// reference.
//
// The network half (Rp/act-as-refresh-grant, Rp/resolve-act-as-revocations,
// and the browser URL of a grant request) is in actas_rp.go. The protocol is
// docs/spec/reserved/act-as-grants.md.

// ---------------------------------------------------------------------------
// Domain-separation tags
// ---------------------------------------------------------------------------

// The `-v1alpha` suffix is an EPOCH marker, not a version counter (see the
// application-key tags in applicationkeys.go).
const (
	// ScopeSetTag: the audience's signature over the scope set it offers one
	// grantee.
	ScopeSetTag = "linkkeys-act-as-scope-set-v1alpha"
	// GrantTag: the home domain's signature over a grant.
	GrantTag = "linkkeys-act-as-grant-v1alpha"
	// GrantRequestTag: the grantee's signature over a grant request.
	GrantRequestTag = "linkkeys-act-as-grant-request-v1alpha"
	// RefreshRequestTag: the grantee's signature over a refresh request.
	RefreshRequestTag = "linkkeys-act-as-refresh-request-v1alpha"
	// PresentationTag: the grantee's signature over one presentation to the
	// audience.
	PresentationTag = "linkkeys-act-as-presentation-v1alpha"
	// GrantRevocationTag: the home domain's signature over a grant
	// revocation.
	GrantRevocationTag = "linkkeys-act-as-grant-revocation-v1alpha"
)

// localRpDescriptorTag is CTX_LOCAL_RP_DESCRIPTOR from
// crates/liblinkkeys/src/local_rp.rs: the tag a local RP's descriptor
// self-signature covers.
const localRpDescriptorTag = "linkkeys-local-rp-descriptor-v1alpha"

// ---------------------------------------------------------------------------
// Defaults and bounds
// ---------------------------------------------------------------------------

const (
	// DefaultActAsLifetimeSeconds is the default grant lifetime: one hour.
	DefaultActAsLifetimeSeconds int64 = 3_600
	// DefaultActAsMaxLifetimeSeconds is the default largest lifetime a user
	// can choose: one day.
	DefaultActAsMaxLifetimeSeconds int64 = 86_400
	// DefaultActAsRenewalWindowSeconds is the default renewal window: no
	// renewal.
	DefaultActAsRenewalWindowSeconds int64 = 0
	// DefaultActAsMaxRenewalWindowSeconds is the default largest renewal
	// window a user can choose: 30 days.
	DefaultActAsMaxRenewalWindowSeconds int64 = 30 * 86_400
	// MaxRevocationLookupIDs is the most grant ids one revocation read
	// accepts.
	MaxRevocationLookupIDs = 100
	// MaxScopeEntries is the most entries one scope set can carry. The
	// consent screen must show every entry, so the set stays bounded.
	MaxScopeEntries = 64
	// MaxScopeBytes is the longest scope string, in bytes.
	MaxScopeBytes = 256
	// MaxDescriptionBytes is the longest scope description, in bytes.
	MaxDescriptionBytes = 1_024
)

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func actAsErr(kind ActAsErrorKind, detail string) *ActAsError {
	return &ActAsError{Kind: kind, Detail: detail}
}

func actAsMismatch(field string) *ActAsError {
	return &ActAsError{Kind: ErrActAsMismatch, Field: field}
}

func parseActAsTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, actAsErr(ErrActAsBadTimestamp, err.Error())
	}
	return t, nil
}

// FormatActAsTime formats t as whole-second RFC3339 in UTC with a trailing
// "Z", so a timestamp survives storage unchanged. Sub-second precision is
// truncated. Mirrors `liblinkkeys::act_as::format_time`. Use it for every
// timestamp you put in an act-as request.
func FormatActAsTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}

// maxDurationSeconds is the largest whole-second count a time.Duration can
// hold.
const maxDurationSeconds = math.MaxInt64 / int64(time.Second)

// addSeconds adds s seconds to t, clamped so a huge value cannot overflow
// time.Duration.
func addSeconds(t time.Time, s int64) time.Time {
	s = max(min(s, maxDurationSeconds), -maxDurationSeconds)
	return t.Add(time.Duration(s) * time.Second)
}

func skewDuration(skewSeconds int64) time.Duration {
	return time.Duration(max(min(skewSeconds, maxDurationSeconds), -maxDurationSeconds)) * time.Second
}

func checkActAsWindow(startsAt, endsAt string, now time.Time, skewSeconds int64) error {
	start, err := parseActAsTime(startsAt)
	if err != nil {
		return err
	}
	end, err := parseActAsTime(endsAt)
	if err != nil {
		return err
	}
	if !end.After(start) {
		return actAsErr(ErrActAsRequestExpired, "")
	}
	skew := skewDuration(skewSeconds)
	if now.Add(skew).Before(start) || now.Add(-skew).After(end) {
		return actAsErr(ErrActAsRequestExpired, "")
	}
	return nil
}

// GrantHash is the SHA-256 of a grant's signed bytes
// (SignedActAsGrant.Grant). A presentation binds this value.
func GrantHash(grantBytes []byte) []byte {
	sum := sha256.Sum256(grantBytes)
	return sum[:]
}

// SameApplication reports whether two application references name the same
// application.
func SameApplication(a, b api.ApplicationRef) bool {
	return a.SubjectUserId == b.SubjectUserId &&
		a.SubjectDomain == b.SubjectDomain &&
		a.ApplicationId == b.ApplicationId
}

// SameGrantee reports whether two grantee references name the same grantee.
// A reference that does not carry exactly one form never matches.
func SameGrantee(a, b api.GranteeRef) bool {
	switch {
	case a.Application != nil && a.LocalRpDescriptorFingerprint == nil &&
		b.Application != nil && b.LocalRpDescriptorFingerprint == nil:
		return SameApplication(*a.Application, *b.Application)
	case a.Application == nil && a.LocalRpDescriptorFingerprint != nil &&
		b.Application == nil && b.LocalRpDescriptorFingerprint != nil:
		return *a.LocalRpDescriptorFingerprint == *b.LocalRpDescriptorFingerprint
	default:
		return false
	}
}

// CheckGrantee checks that a GranteeRef carries exactly one non-empty form.
func CheckGrantee(grantee api.GranteeRef) error {
	switch {
	case grantee.Application != nil && grantee.LocalRpDescriptorFingerprint == nil:
		app := grantee.Application
		if app.SubjectUserId == "" || app.SubjectDomain == "" || app.ApplicationId == "" {
			return actAsErr(ErrActAsMalformedGrantee, "")
		}
		return nil
	case grantee.Application == nil && grantee.LocalRpDescriptorFingerprint != nil &&
		*grantee.LocalRpDescriptorFingerprint != "":
		return nil
	default:
		return actAsErr(ErrActAsMalformedGrantee, "")
	}
}

// ---------------------------------------------------------------------------
// Grantee keys and proofs
// ---------------------------------------------------------------------------

// GranteeSigner is the grantee's signing material, as the grantee holds it.
// Build one with NewApplicationGranteeSigner or NewLocalRpGranteeSigner. The
// private key never leaves the process.
type GranteeSigner struct {
	localRp bool

	// Application grantee.
	instanceID string
	app        ApplicationSigner

	// Local-RP grantee.
	descriptor  api.SignedLocalRpDescriptor
	fingerprint string
	localKey    []byte
}

// NewApplicationGranteeSigner returns a signer for an enrolled application
// instance. signer must be one of the instance's attested signing keys.
func NewApplicationGranteeSigner(instanceID string, signer ApplicationSigner) GranteeSigner {
	return GranteeSigner{instanceID: instanceID, app: signer}
}

// NewLocalRpGranteeSigner returns a signer for a local RP. descriptor is the
// local RP's signed descriptor, fingerprint its descriptor fingerprint, and
// signingPrivateKey the 32-byte Ed25519 seed of the descriptor signing key.
func NewLocalRpGranteeSigner(descriptor api.SignedLocalRpDescriptor, fingerprint string, signingPrivateKey []byte) GranteeSigner {
	return GranteeSigner{localRp: true, descriptor: descriptor, fingerprint: fingerprint, localKey: signingPrivateKey}
}

// Prove signs message and wraps the signature in a GranteeProof.
func (s GranteeSigner) Prove(message []byte) (api.GranteeProof, error) {
	if s.localRp {
		sig, err := signWithAlgorithm(algorithmEd25519, message, s.localKey)
		if err != nil {
			return api.GranteeProof{}, actAsErr(ErrActAsCrypto, err.Error())
		}
		descriptor := s.descriptor
		return api.GranteeProof{
			LocalRpDescriptor: &descriptor,
			Signature:         api.ApplicationKeySignature{SignedByKeyId: s.fingerprint, Signature: sig},
		}, nil
	}
	sig, err := signWithAlgorithm(s.app.Algorithm, message, s.app.PrivateKeyBytes)
	if err != nil {
		return api.GranteeProof{}, actAsErr(ErrActAsCrypto, err.Error())
	}
	instanceID := s.instanceID
	return api.GranteeProof{
		ApplicationInstanceId: &instanceID,
		Signature:             api.ApplicationKeySignature{SignedByKeyId: s.app.KeyID, Signature: sig},
	}, nil
}

// VerifiedGranteeSigner says who signed a proof, once the proof is verified.
type VerifiedGranteeSigner struct {
	// InstanceID is the application instance, for an application grantee.
	// It is empty for a local-RP grantee.
	InstanceID string
	// KeyID is the key id or descriptor fingerprint that signed.
	KeyID string
}

// verifyLocalRpDescriptor mirrors `liblinkkeys::local_rp::verify_local_rp_descriptor`:
// decode, key lengths, fingerprint == sha256(signing key), the descriptor's
// own Ed25519 signature over CBOR([localRpDescriptorTag, descriptor_bytes]),
// then the validity window with skew (both boundaries inclusive).
func verifyLocalRpDescriptor(signed api.SignedLocalRpDescriptor, now time.Time, skewSeconds int64) (api.LocalRpDescriptor, error) {
	descriptor, err := api.DecodeLocalRpDescriptor(signed.Descriptor)
	if err != nil {
		return api.LocalRpDescriptor{}, actAsErr(ErrActAsDecode, err.Error())
	}
	if len(descriptor.SigningPublicKey) != 32 || len(descriptor.EncryptionPublicKey) != 32 {
		return api.LocalRpDescriptor{}, actAsErr(ErrActAsCrypto, "invalid local RP key length")
	}
	if descriptor.Fingerprint != Fingerprint(descriptor.SigningPublicKey) {
		return api.LocalRpDescriptor{}, actAsMismatch("local_rp_descriptor.fingerprint")
	}
	if !verifyEd25519(descriptor.SigningPublicKey, envelopeSignatureInput(localRpDescriptorTag, signed.Descriptor), signed.Signature) {
		return api.LocalRpDescriptor{}, actAsErr(ErrActAsBadSignature, "local RP descriptor")
	}
	created, err := parseActAsTime(descriptor.CreatedAt)
	if err != nil {
		return api.LocalRpDescriptor{}, err
	}
	expires, err := parseActAsTime(descriptor.ExpiresAt)
	if err != nil {
		return api.LocalRpDescriptor{}, err
	}
	skew := skewDuration(skewSeconds)
	if now.Add(skew).Before(created) || now.Add(-skew).After(expires) {
		return api.LocalRpDescriptor{}, actAsErr(ErrActAsRequestExpired, "local RP descriptor")
	}
	return descriptor, nil
}

func findAppKey(keys []ApplicationKeyRef, keyID string) *ApplicationKeyRef {
	for i := range keys {
		if keys[i].KeyID == keyID {
			return &keys[i]
		}
	}
	return nil
}

// VerifyGranteeProof verifies that a grantee key signed message.
//
// For an application grantee, instanceKeys are the attested keys of the
// instance that the proof names (proof.ApplicationInstanceId). The caller
// MUST have verified those attestations against the grantee's home domain,
// for the grantee's ApplicationRef (for example with CachedResolver and
// VerifiedApplicationKeySet.UsableKeyRefs). The signing key must be a signing
// key that is valid at now.
//
// For a local-RP grantee, instanceKeys is ignored. The descriptor in the
// proof must verify, its fingerprint must equal the grantee's, and its
// signing key must have signed.
func VerifyGranteeProof(proof api.GranteeProof, message []byte, grantee api.GranteeRef, instanceKeys []ApplicationKeyRef, now time.Time, skewSeconds int64) (VerifiedGranteeSigner, error) {
	if err := CheckGrantee(grantee); err != nil {
		return VerifiedGranteeSigner{}, err
	}
	switch {
	case grantee.Application != nil && proof.ApplicationInstanceId != nil && proof.LocalRpDescriptor == nil:
		key := findAppKey(instanceKeys, proof.Signature.SignedByKeyId)
		if key == nil || key.KeyUsage != KeyUsageSign || !key.IsValidSigningKey(now) {
			return VerifiedGranteeSigner{}, actAsErr(ErrActAsUntrustedSigner, "")
		}
		if resolveAndVerify(key.Algorithm, message, proof.Signature.Signature, key.PublicKey) != nil {
			return VerifiedGranteeSigner{}, actAsErr(ErrActAsBadSignature, "")
		}
		return VerifiedGranteeSigner{InstanceID: *proof.ApplicationInstanceId, KeyID: key.KeyID}, nil
	case grantee.LocalRpDescriptorFingerprint != nil && proof.ApplicationInstanceId == nil && proof.LocalRpDescriptor != nil:
		descriptor, err := verifyLocalRpDescriptor(*proof.LocalRpDescriptor, now, skewSeconds)
		if err != nil {
			return VerifiedGranteeSigner{}, actAsErr(ErrActAsUntrustedSigner, "")
		}
		if descriptor.Fingerprint != *grantee.LocalRpDescriptorFingerprint ||
			proof.Signature.SignedByKeyId != descriptor.Fingerprint {
			return VerifiedGranteeSigner{}, actAsMismatch("local_rp_descriptor_fingerprint")
		}
		if !verifyEd25519(descriptor.SigningPublicKey, message, proof.Signature.Signature) {
			return VerifiedGranteeSigner{}, actAsErr(ErrActAsBadSignature, "")
		}
		return VerifiedGranteeSigner{KeyID: descriptor.Fingerprint}, nil
	default:
		return VerifiedGranteeSigner{}, actAsErr(ErrActAsProofDoesNotMatchGrantee, "")
	}
}

// UsableKeyRefs returns the usable keys of a verified set, in the form the
// act-as verifiers take. Mirrors the reference server's `usable_key_refs`.
// Use it for a GRANTEE's keys (VerifyGranteeProof needs a key that is valid
// now). Do not use it for an audience's own scope-set keys: use
// AttestedKeyRefs.
func (s VerifiedApplicationKeySet) UsableKeyRefs() []ApplicationKeyRef {
	var out []ApplicationKeyRef
	for _, k := range s.Keys {
		if k.IsUsable() {
			out = append(out, attestedKeyRef(k.Attestation))
		}
	}
	return out
}

// AttestedKeyRefs returns every attestation-verified key of a verified set,
// in the form the act-as verifiers take. It includes keys that expired, and
// keys that were revoked, each with its RevokedAt. Mirrors the reference
// server's `attested_key_refs`.
//
// An audience that verifies its own scope set (VerifyScopeSet, and
// AudienceContext.OwnScopeSetKeys) MUST use this list. A list of usable keys
// only refuses every set signed before a key rotation.
func (s VerifiedApplicationKeySet) AttestedKeyRefs() []ApplicationKeyRef {
	out := make([]ApplicationKeyRef, 0, len(s.Keys))
	for _, k := range s.Keys {
		ref := attestedKeyRef(k.Attestation)
		if k.Status.Kind == KeyStatusRevoked {
			revokedAt := k.Status.RevokedAt
			ref.RevokedAt = &revokedAt
		}
		out = append(out, ref)
	}
	return out
}

// ---------------------------------------------------------------------------
// Revoked-key policy
// ---------------------------------------------------------------------------

// RevokedKeyPolicy tells a verifier how to treat a signature by a key that
// was revoked after it signed. Mirrors `liblinkkeys::act_as::RevokedKeyPolicy`.
//
// Revocation invalidates one key, never the other keys. The protocol does not
// require a verifier to trust the earlier signatures of a revoked key, so each
// verifier chooses. The zero value is AcceptBeforeRevocation.
type RevokedKeyPolicy int

const (
	// AcceptBeforeRevocation accepts a signature by a revoked key when the
	// signature was made before the revocation time (invariant I-7). This is
	// the default.
	AcceptBeforeRevocation RevokedKeyPolicy = iota
	// RefuseRevoked refuses every signature by a key that is now revoked.
	RefuseRevoked
)

func (p RevokedKeyPolicy) String() string {
	switch p {
	case AcceptBeforeRevocation:
		return "accept_before_revocation"
	case RefuseRevoked:
		return "refuse_revoked"
	default:
		return "unknown"
	}
}

// keyRefusal returns why key cannot vouch for something signed at signedAt,
// or "" when it can. Mirrors `liblinkkeys::act_as::key_refusal`.
func keyRefusal(key ApplicationKeyRef, signedAt time.Time, policy RevokedKeyPolicy) string {
	if key.KeyUsage != KeyUsageSign {
		return "not a signing key"
	}
	if policy == RefuseRevoked && key.RevokedAt != nil {
		return fmt.Sprintf("revoked at %s; this verifier refuses revoked keys", *key.RevokedAt)
	}
	if !key.WasValidAt(signedAt) {
		if key.RevokedAt != nil {
			return fmt.Sprintf("revoked at %s, before it signed", *key.RevokedAt)
		}
		return "not inside its validity window when it signed"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Scope sets
// ---------------------------------------------------------------------------

// CheckScopeSetShape checks a scope set's shape: a valid grantee, 1 to
// MaxScopeEntries entries, bounded strings, no repeated scope, a handle claim
// (when present) about the audience's own account, and RFC3339 times.
func CheckScopeSetShape(set api.ActAsScopeSet) error {
	if err := CheckGrantee(set.Grantee); err != nil {
		return err
	}
	if len(set.Entries) == 0 {
		return actAsErr(ErrActAsBadScopeSet, "no entries")
	}
	if len(set.Entries) > MaxScopeEntries {
		return actAsErr(ErrActAsBadScopeSet, "too many entries")
	}
	seen := make(map[string]bool, len(set.Entries))
	for _, entry := range set.Entries {
		if entry.Scope == "" || len(entry.Scope) > MaxScopeBytes {
			return actAsErr(ErrActAsBadScopeSet, "scope length out of range")
		}
		if entry.Description != nil && len(*entry.Description) > MaxDescriptionBytes {
			return actAsErr(ErrActAsBadScopeSet, "description too long")
		}
		if seen[entry.Scope] {
			return actAsErr(ErrActAsBadScopeSet, "a scope repeats")
		}
		seen[entry.Scope] = true
	}
	if set.AudienceHandleClaim != nil {
		if err := checkHandleClaimSubject(*set.AudienceHandleClaim, set.Audience); err != nil {
			return err
		}
	}
	if _, err := parseActAsTime(set.IssuedAt); err != nil {
		return err
	}
	if _, err := parseActAsTime(set.ExpiresAt); err != nil {
		return err
	}
	return nil
}

// SignScopeSet is the audience's signature over the scope set it offers one
// grantee. signerInstanceID names the audience instance that owns signers.
// Give every current signing key of that instance: a verifier needs one
// signature by a valid key, so one expired or revoked key does not break the
// set. signers must not be empty, and no key id can occur twice.
func SignScopeSet(set api.ActAsScopeSet, signerInstanceID string, signers []ApplicationSigner) (api.SignedActAsScopeSet, error) {
	if err := CheckScopeSetShape(set); err != nil {
		return api.SignedActAsScopeSet{}, err
	}
	if len(signers) == 0 {
		return api.SignedActAsScopeSet{}, actAsErr(ErrActAsNoValidSignature, "no signing key given")
	}
	seen := make(map[string]bool, len(signers))
	for _, signer := range signers {
		if seen[signer.KeyID] {
			return api.SignedActAsScopeSet{}, actAsErr(ErrActAsNoValidSignature, "a key is listed twice")
		}
		seen[signer.KeyID] = true
	}
	setBytes := api.EncodeActAsScopeSet(set)
	message := envelopeSignatureInput(ScopeSetTag, setBytes)
	signatures := make([]api.ApplicationKeySignature, 0, len(signers))
	for _, signer := range signers {
		sig, err := signWithAlgorithm(signer.Algorithm, message, signer.PrivateKeyBytes)
		if err != nil {
			return api.SignedActAsScopeSet{}, actAsErr(ErrActAsCrypto, err.Error())
		}
		signatures = append(signatures, api.ApplicationKeySignature{SignedByKeyId: signer.KeyID, Signature: sig})
	}
	return api.SignedActAsScopeSet{
		ScopeSet:         setBytes,
		SignerInstanceId: signerInstanceID,
		Signatures:       signatures,
	}, nil
}

// VerifyScopeSet verifies a scope set's signatures and shape. Mirrors
// `liblinkkeys::act_as::verify_scope_set`.
//
// audienceKeys are the attested keys of the instance that
// signed.SignerInstanceId names, INCLUDING keys that expired or were revoked
// since, each with its RevokedAt (VerifiedApplicationKeySet.AttestedKeyRefs).
// The caller MUST have verified them for expectedAudience. One signature by a
// key that was valid when the set was issued, and that policy accepts, is
// enough. A later key rotation does not invalidate a set that the user
// already approved.
//
// When no signature is acceptable, the error has kind
// ErrActAsNoValidSignature. Its detail names each signing key and why it was
// refused.
//
// This does not check the set's expiry. Only approval does that, with
// CheckScopeSetCurrent.
func VerifyScopeSet(signed api.SignedActAsScopeSet, expectedAudience api.ApplicationRef, audienceKeys []ApplicationKeyRef, policy RevokedKeyPolicy) (api.ActAsScopeSet, error) {
	set, err := api.DecodeActAsScopeSet(signed.ScopeSet)
	if err != nil {
		return api.ActAsScopeSet{}, actAsErr(ErrActAsDecode, err.Error())
	}
	if !SameApplication(set.Audience, expectedAudience) {
		return api.ActAsScopeSet{}, actAsMismatch("scope_set.audience")
	}
	if err := CheckScopeSetShape(set); err != nil {
		return api.ActAsScopeSet{}, err
	}
	if len(signed.Signatures) == 0 {
		return api.ActAsScopeSet{}, actAsErr(ErrActAsNoValidSignature, "the scope set is unsigned")
	}
	issuedAt, err := parseActAsTime(set.IssuedAt)
	if err != nil {
		return api.ActAsScopeSet{}, err
	}
	message := envelopeSignatureInput(ScopeSetTag, signed.ScopeSet)
	refusals := make([]string, 0, len(signed.Signatures))
	for _, sig := range signed.Signatures {
		key := findAppKey(audienceKeys, sig.SignedByKeyId)
		if key == nil {
			refusals = append(refusals, sig.SignedByKeyId+": not a key of the audience")
			continue
		}
		if reason := keyRefusal(*key, issuedAt, policy); reason != "" {
			refusals = append(refusals, key.KeyID+": "+reason)
			continue
		}
		if resolveAndVerify(key.Algorithm, message, sig.Signature, key.PublicKey) == nil {
			return set, nil
		}
		refusals = append(refusals, key.KeyID+": signature did not verify")
	}
	return api.ActAsScopeSet{}, actAsErr(ErrActAsNoValidSignature, strings.Join(refusals, "; "))
}

// ---------------------------------------------------------------------------
// Handle claims
// ---------------------------------------------------------------------------

// HandleClaimType is the claim type that a handle claim carries.
const HandleClaimType = "handle"

// checkHandleClaimSubject checks that a handle claim is a handle claim about
// the party's own account. Mirrors `liblinkkeys::act_as::check_handle_claim_subject`.
func checkHandleClaimSubject(claim api.Claim, party api.ApplicationRef) error {
	if claim.ClaimType != HandleClaimType {
		return actAsErr(ErrActAsBadHandleClaim, fmt.Sprintf("claim type is %q, not %q", claim.ClaimType, HandleClaimType))
	}
	if claim.UserId != party.SubjectUserId {
		return actAsErr(ErrActAsBadHandleClaim, "the claim is about another account")
	}
	return nil
}

// VerifyHandleClaim verifies a handle claim about the account that enrolled
// party, and returns the handle. Mirrors
// `liblinkkeys::act_as::verify_handle_claim`.
//
// Only signatures by party.SubjectDomain count: a handle is the statement of
// that domain. Signatures by other domains are ignored. domainKeys are the
// signing keys of party.SubjectDomain, from that domain's anchor, with its
// revocations applied. The claim must not be revoked or expired. Like the
// reference, the claim's expiry is checked against wall-clock time.
//
// A claim that fails does not block consent. Do not show its handle.
func VerifyHandleClaim(claim api.Claim, party api.ApplicationRef, domainKeys []api.DomainPublicKey) (string, error) {
	if err := checkHandleClaimSubject(claim, party); err != nil {
		return "", err
	}
	own := make([]api.ClaimSignature, 0, len(claim.Signatures))
	for _, sig := range claim.Signatures {
		if sig.Domain == party.SubjectDomain {
			own = append(own, sig)
		}
	}
	if err := verifySingleDomainClaim(claim, own, party.SubjectDomain, domainKeys, time.Now()); err != nil {
		return "", actAsErr(ErrActAsBadHandleClaim, err.Error())
	}
	if !utf8.Valid(claim.ClaimValue) {
		return "", actAsErr(ErrActAsBadHandleClaim, "the handle is not UTF-8")
	}
	return string(claim.ClaimValue), nil
}

// CheckScopeSetCurrent reports, at approval only, whether the scope set has
// not expired.
func CheckScopeSetCurrent(set api.ActAsScopeSet, now time.Time, skewSeconds int64) error {
	if checkActAsWindow(set.IssuedAt, set.ExpiresAt, now, skewSeconds) != nil {
		return actAsErr(ErrActAsScopeSetExpired, "")
	}
	return nil
}

// CheckApprovedScope checks that the approved scope is a non-empty subset of
// the set, with no repeats.
func CheckApprovedScope(set api.ActAsScopeSet, approved []string) error {
	if len(approved) == 0 {
		return actAsErr(ErrActAsBadApprovedScope, "no scope approved")
	}
	offered := make(map[string]bool, len(set.Entries))
	for _, e := range set.Entries {
		offered[e.Scope] = true
	}
	seen := make(map[string]bool, len(approved))
	for _, scope := range approved {
		if !offered[scope] {
			return actAsErr(ErrActAsBadApprovedScope, "a scope is not in the scope set")
		}
		if seen[scope] {
			return actAsErr(ErrActAsBadApprovedScope, "a scope repeats")
		}
		seen[scope] = true
	}
	return nil
}

// ---------------------------------------------------------------------------
// Grant requests
// ---------------------------------------------------------------------------

// SignGrantRequest is the grantee's signature over a grant request. Use
// FormatActAsTime for RequestedAt and ExpiresAt. Send the result to the
// user's browser with GrantRequestURL.
//
// request.GranteeHandleClaim is optional. Set it to a signed `handle` claim,
// from your home domain, about the account that enrolled your application.
// The consent screen then shows the handle. A local-RP grantee has no
// account, so it cannot carry a handle claim. SignGrantRequest refuses a
// handle claim that the home domain would refuse for its shape (another
// claim type, another account, or a local-RP grantee). It does not verify
// the claim's signatures.
func SignGrantRequest(request api.ActAsGrantRequest, signer GranteeSigner) (api.SignedActAsGrantRequest, error) {
	if err := CheckGrantee(request.Grantee); err != nil {
		return api.SignedActAsGrantRequest{}, err
	}
	if err := checkGranteeHandleClaim(request); err != nil {
		return api.SignedActAsGrantRequest{}, err
	}
	requestBytes := api.EncodeActAsGrantRequest(request)
	proof, err := signer.Prove(envelopeSignatureInput(GrantRequestTag, requestBytes))
	if err != nil {
		return api.SignedActAsGrantRequest{}, err
	}
	return api.SignedActAsGrantRequest{Request: requestBytes, Proof: proof}, nil
}

// checkGranteeHandleClaim checks the shape of a request's optional handle
// claim. A local-RP grantee may not carry one.
func checkGranteeHandleClaim(request api.ActAsGrantRequest) error {
	if request.GranteeHandleClaim == nil {
		return nil
	}
	if request.Grantee.Application == nil {
		return actAsErr(ErrActAsBadHandleClaim, "a local-RP grantee has no account to name")
	}
	return checkHandleClaimSubject(*request.GranteeHandleClaim, *request.Grantee.Application)
}

// VerifyGrantRequest is the home domain's check of a grant request's
// signature, window, and shape. It is here for conformance and for
// diagnostics; an application does not normally need it.
//
// It checks the shape of an optional grantee handle claim, but not its
// signatures. Use VerifyHandleClaim for that.
//
// The caller still owns three checks that need state or the network: that
// the scope set verifies against the audience's keys (VerifyScopeSet), that
// the set is current (CheckScopeSetCurrent), and that the nonce is
// single-use.
func VerifyGrantRequest(signed api.SignedActAsGrantRequest, granteeInstanceKeys []ApplicationKeyRef, now time.Time, skewSeconds int64) (api.ActAsGrantRequest, error) {
	request, err := api.DecodeActAsGrantRequest(signed.Request)
	if err != nil {
		return api.ActAsGrantRequest{}, actAsErr(ErrActAsDecode, err.Error())
	}
	if err := CheckGrantee(request.Grantee); err != nil {
		return api.ActAsGrantRequest{}, err
	}
	if err := checkActAsWindow(request.RequestedAt, request.ExpiresAt, now, skewSeconds); err != nil {
		return api.ActAsGrantRequest{}, err
	}
	if request.RequestedLifetimeSeconds != nil && *request.RequestedLifetimeSeconds <= 0 {
		return api.ActAsGrantRequest{}, actAsErr(ErrActAsBadTerms, "requested lifetime must be positive")
	}
	if request.RequestedRenewalWindowSeconds != nil && *request.RequestedRenewalWindowSeconds < 0 {
		return api.ActAsGrantRequest{}, actAsErr(ErrActAsBadTerms, "requested renewal window must not be negative")
	}
	if err := checkGranteeHandleClaim(request); err != nil {
		return api.ActAsGrantRequest{}, err
	}
	if request.Nonce == "" || request.CallbackUrl == "" {
		return api.ActAsGrantRequest{}, actAsErr(ErrActAsDecode, "nonce and callback_url are required")
	}
	if _, err := VerifyGranteeProof(signed.Proof, envelopeSignatureInput(GrantRequestTag, signed.Request), request.Grantee, granteeInstanceKeys, now, skewSeconds); err != nil {
		return api.ActAsGrantRequest{}, err
	}
	return request, nil
}

// ---------------------------------------------------------------------------
// Terms
// ---------------------------------------------------------------------------

// DomainTermBounds are the home domain's bounds for one grant.
type DomainTermBounds struct {
	DefaultLifetimeSeconds  int64
	MaxLifetimeSeconds      int64
	MaxRenewalWindowSeconds int64
}

// DefaultDomainTermBounds returns the reference server's default bounds.
func DefaultDomainTermBounds() DomainTermBounds {
	return DomainTermBounds{
		DefaultLifetimeSeconds:  DefaultActAsLifetimeSeconds,
		MaxLifetimeSeconds:      DefaultActAsMaxLifetimeSeconds,
		MaxRenewalWindowSeconds: DefaultActAsMaxRenewalWindowSeconds,
	}
}

// OfferedTerms is what the consent screen offers: starting values and the
// most the user can choose.
type OfferedTerms struct {
	DefaultLifetimeSeconds      int64
	MaxLifetimeSeconds          int64
	DefaultRenewalWindowSeconds int64
	MaxRenewalWindowSeconds     int64
}

// OfferTerms returns the consent screen's starting values and limits.
// Mirrors `liblinkkeys::act_as::offered_terms`.
//
// The grantee's request is a ceiling, never a floor. A nil requested
// lifetime sets no ceiling, and the screen starts at the domain default. A
// nil renewal window means 0.
func OfferTerms(requestedLifetimeSeconds, requestedRenewalWindowSeconds *int64, bounds DomainTermBounds) OfferedTerms {
	maxLifetime := bounds.MaxLifetimeSeconds
	defaultLifetime := bounds.DefaultLifetimeSeconds
	if requestedLifetimeSeconds != nil {
		maxLifetime = min(*requestedLifetimeSeconds, bounds.MaxLifetimeSeconds)
		defaultLifetime = *requestedLifetimeSeconds
	}
	maxLifetime = max(maxLifetime, 1)
	defaultLifetime = max(min(defaultLifetime, maxLifetime), 1)
	var window int64
	if requestedRenewalWindowSeconds != nil {
		window = *requestedRenewalWindowSeconds
	}
	window = max(min(window, bounds.MaxRenewalWindowSeconds), 0)
	return OfferedTerms{
		DefaultLifetimeSeconds:      defaultLifetime,
		MaxLifetimeSeconds:          maxLifetime,
		DefaultRenewalWindowSeconds: window,
		MaxRenewalWindowSeconds:     window,
	}
}

// IssuedTerms returns the issued lifetime and renewal window: the user's
// choice, never above the offered maximum. A choice above the maximum is an
// error, not a silent cap. Mirrors `liblinkkeys::act_as::issued_terms`.
func IssuedTerms(offered OfferedTerms, chosenLifetimeSeconds, chosenRenewalWindowSeconds int64) (lifetimeSeconds, renewalWindowSeconds int64, err error) {
	if chosenLifetimeSeconds <= 0 || chosenLifetimeSeconds > offered.MaxLifetimeSeconds {
		return 0, 0, actAsErr(ErrActAsBadTerms, "lifetime is outside the offered range")
	}
	if chosenRenewalWindowSeconds < 0 || chosenRenewalWindowSeconds > offered.MaxRenewalWindowSeconds {
		return 0, 0, actAsErr(ErrActAsBadTerms, "renewal window is outside the offered range")
	}
	return chosenLifetimeSeconds, chosenRenewalWindowSeconds, nil
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

// DecodeGrant decodes a grant WITHOUT verifying it. A grantee can use it to
// read its own grant's times. An audience must use VerifyCredential.
func DecodeGrant(signed api.SignedActAsGrant) (api.ActAsGrant, error) {
	grant, err := api.DecodeActAsGrant(signed.Grant)
	if err != nil {
		return api.ActAsGrant{}, actAsErr(ErrActAsDecode, err.Error())
	}
	return grant, nil
}

// verifyActAsDomainSignature accepts the first signature, from domain, by a
// currently valid signing key in domainKeys, that verifies over message.
func verifyActAsDomainSignature(message []byte, signatures []api.ClaimSignature, domainKeys []api.DomainPublicKey, domain string) error {
	for _, sig := range signatures {
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
		if resolveAndVerify(key.Algorithm, message, sig.Signature, key.PublicKey) == nil {
			return nil
		}
	}
	return actAsErr(ErrActAsUntrustedSigner, "")
}

// VerifyGrantSignature verifies a grant's home-domain signature and internal
// consistency. It refuses a grant that carries a device_fingerprint.
//
// domainKeys are the keys of the grant's subject_domain, from that domain's
// anchor (for example Rp/resolve-domain-keys, with its revocations applied).
// This does not check expiry, revocation, the audience, or the scope set's
// signature. VerifyCredential does all of those.
func VerifyGrantSignature(signed api.SignedActAsGrant, domainKeys []api.DomainPublicKey) (api.ActAsGrant, error) {
	grant, err := DecodeGrant(signed)
	if err != nil {
		return api.ActAsGrant{}, err
	}
	if err := CheckGrantee(grant.Grantee); err != nil {
		return api.ActAsGrant{}, err
	}
	if grant.DeviceFingerprint != nil {
		return api.ActAsGrant{}, actAsErr(ErrActAsDeviceBindingUnsupported, "")
	}
	if err := verifyActAsDomainSignature(envelopeSignatureInput(GrantTag, signed.Grant), signed.Signatures, domainKeys, grant.SubjectDomain); err != nil {
		return api.ActAsGrant{}, err
	}
	return grant, nil
}

// ---------------------------------------------------------------------------
// Refresh and renewal
// ---------------------------------------------------------------------------

// RefreshDecision is what a refresh returns. When Renew is false, the home
// domain returns the stored grant bytes with no new signature. When Renew is
// true, it signs a renewed grant with IssuedAt and ExpiresAt.
type RefreshDecision struct {
	Renew     bool
	IssuedAt  string
	ExpiresAt string
}

// DecideRefresh decides whether a refresh renews the grant. Mirrors
// `liblinkkeys::act_as::refresh_decision`. A grantee can use it to predict
// what Rp/act-as-refresh-grant will do; pass the series lifetime
// (expires_at - issued_at of the first grant) as lifetimeSeconds.
//
// The current grant must not have expired: an expired grant cannot be
// renewed (ErrActAsGrantExpired), and the grantee must ask the user again.
// While the grant keeps more than one half of its life, the stored bytes are
// returned. A renewal happens only before renewable_until, and only when it
// would extend the expiry. A renewed grant expires at
// min(now + lifetime, renewable_until).
func DecideRefresh(grant api.ActAsGrant, lifetimeSeconds int64, now time.Time) (RefreshDecision, error) {
	issued, err := parseActAsTime(grant.IssuedAt)
	if err != nil {
		return RefreshDecision{}, err
	}
	expires, err := parseActAsTime(grant.ExpiresAt)
	if err != nil {
		return RefreshDecision{}, err
	}
	renewableUntil, err := parseActAsTime(grant.RenewableUntil)
	if err != nil {
		return RefreshDecision{}, err
	}
	if !now.Before(expires) {
		return RefreshDecision{}, actAsErr(ErrActAsGrantExpired, "")
	}
	if !expires.After(issued) {
		return RefreshDecision{}, nil
	}
	half := issued.Add(expires.Sub(issued) / 2)
	if now.Before(half) || !now.Before(renewableUntil) {
		return RefreshDecision{}, nil
	}
	newExpires := addSeconds(now, lifetimeSeconds)
	if newExpires.After(renewableUntil) {
		newExpires = renewableUntil
	}
	if !newExpires.After(expires) {
		return RefreshDecision{}, nil
	}
	return RefreshDecision{Renew: true, IssuedAt: FormatActAsTime(now), ExpiresAt: FormatActAsTime(newExpires)}, nil
}

// SignRefreshRequest is the grantee's signature over a refresh request. Use
// FormatActAsTime for RequestedAt and ExpiresAt. Send the result with
// RefreshGrant.
func SignRefreshRequest(request api.ActAsRefreshRequest, signer GranteeSigner) (api.SignedActAsRefreshRequest, error) {
	if err := CheckGrantee(request.Grantee); err != nil {
		return api.SignedActAsRefreshRequest{}, err
	}
	requestBytes := api.EncodeActAsRefreshRequest(request)
	proof, err := signer.Prove(envelopeSignatureInput(RefreshRequestTag, requestBytes))
	if err != nil {
		return api.SignedActAsRefreshRequest{}, err
	}
	return api.SignedActAsRefreshRequest{Request: requestBytes, Proof: proof}, nil
}

// VerifyRefreshRequest is the home domain's check of a refresh request
// against the stored grant's grantee. It is here for conformance; an
// application does not normally need it.
func VerifyRefreshRequest(signed api.SignedActAsRefreshRequest, grantGrantee api.GranteeRef, granteeInstanceKeys []ApplicationKeyRef, now time.Time, skewSeconds int64) (api.ActAsRefreshRequest, error) {
	request, err := api.DecodeActAsRefreshRequest(signed.Request)
	if err != nil {
		return api.ActAsRefreshRequest{}, actAsErr(ErrActAsDecode, err.Error())
	}
	if !SameGrantee(request.Grantee, grantGrantee) {
		return api.ActAsRefreshRequest{}, actAsMismatch("grantee")
	}
	if err := checkActAsWindow(request.RequestedAt, request.ExpiresAt, now, skewSeconds); err != nil {
		return api.ActAsRefreshRequest{}, err
	}
	if _, err := VerifyGranteeProof(signed.Proof, envelopeSignatureInput(RefreshRequestTag, signed.Request), grantGrantee, granteeInstanceKeys, now, skewSeconds); err != nil {
		return api.ActAsRefreshRequest{}, err
	}
	return request, nil
}

// ---------------------------------------------------------------------------
// Presentations and audience verification
// ---------------------------------------------------------------------------

// Present builds the credential for one call to the audience. requestDigest
// is the digest of this call, as the audience's protocol defines it. nonce
// must be fresh for each call: the audience uses it for replay protection.
func Present(grant api.SignedActAsGrant, audience api.ApplicationRef, requestDigest []byte, presentedAt time.Time, nonce []byte, signer GranteeSigner) (api.ActAsCredential, error) {
	presentation := api.ActAsPresentation{
		GrantHash:     GrantHash(grant.Grant),
		Audience:      audience,
		RequestDigest: requestDigest,
		PresentedAt:   FormatActAsTime(presentedAt),
		Nonce:         nonce,
	}
	presentationBytes := api.EncodeActAsPresentation(presentation)
	proof, err := signer.Prove(envelopeSignatureInput(PresentationTag, presentationBytes))
	if err != nil {
		return api.ActAsCredential{}, err
	}
	return api.ActAsCredential{
		Grant:        grant,
		Presentation: api.SignedActAsPresentation{Presentation: presentationBytes, Proof: proof},
	}, nil
}

// AudienceContext is what the audience supplies to verify a credential.
// Every key list is already verified by the caller: domain keys from the
// issuer's anchor, and application keys from verified attestations.
type AudienceContext struct {
	// OwnApplication is the verifier's own application. Never read it from
	// the request.
	OwnApplication api.ApplicationRef
	// OwnScopeSetKeys are the verifier's own attested keys, for the instance
	// that signed the scope set. Resolve the instance with
	// CredentialScopeSetSigner. Give ALL its attested keys, including expired
	// and revoked keys with their RevokedAt
	// (VerifiedApplicationKeySet.AttestedKeyRefs). Usable keys only refuse
	// every grant whose scope set was signed before a key rotation.
	OwnScopeSetKeys []ApplicationKeyRef
	// IssuerDomainKeys are the signing keys of the grant's subject_domain.
	IssuerDomainKeys []api.DomainPublicKey
	// GranteeInstanceKeys are the attested keys of the grantee instance that
	// signed the presentation. Resolve with CredentialSignerInstance.
	// Ignored for a local-RP grantee.
	GranteeInstanceKeys []ApplicationKeyRef
	// ExpectedRequestDigest is the digest of this request, as the audience's
	// protocol defines it.
	ExpectedRequestDigest []byte
	// RevokedGrantIDs are grant ids the verifier holds a valid revocation
	// for (see ResolveGrantRevocations and RevokedGrantIDs).
	RevokedGrantIDs []string
	// MaxPresentationAgeSeconds is the largest accepted age of a
	// presentation.
	MaxPresentationAgeSeconds int64
	Now                       time.Time
	SkewSeconds               int64
	// RevokedKeyPolicy tells how to treat a scope-set signature by a key that
	// was revoked after it signed. The zero value is AcceptBeforeRevocation.
	RevokedKeyPolicy RevokedKeyPolicy
}

// VerifiedActAs is a credential the audience accepted.
type VerifiedActAs struct {
	GrantID string
	// UserID is `user_id@subject_domain`.
	UserID        string
	SubjectDomain string
	Grantee       api.GranteeRef
	Signer        VerifiedGranteeSigner
	// ApprovedScope is the only scope the audience's policy may act on.
	// Never use the full scope set.
	ApprovedScope []string
	ExpiresAt     string
	// Nonce is the presentation nonce. The audience owns replay protection:
	// record it until MaxPresentationAgeSeconds (plus skew) has passed, and
	// refuse a nonce it already holds.
	Nonce []byte
}

// CredentialSignerInstance returns the grantee instance whose key signed a
// credential's presentation, so the audience can resolve its attested keys
// before VerifyCredential. ok is false for a local-RP grantee.
func CredentialSignerInstance(credential api.ActAsCredential) (instanceID string, ok bool) {
	if id := credential.Presentation.Proof.ApplicationInstanceId; id != nil {
		return *id, true
	}
	return "", false
}

// CredentialScopeSetSigner returns the audience instance whose key signed
// the embedded scope set. The grant is decoded, not verified.
func CredentialScopeSetSigner(credential api.ActAsCredential) (string, error) {
	grant, err := DecodeGrant(credential.Grant)
	if err != nil {
		return "", err
	}
	return grant.ScopeSet.SignerInstanceId, nil
}

// VerifyCredential is the audience's verification checklist. Mirrors
// `liblinkkeys::act_as::verify_credential`. Every step must pass, in this
// order:
//
//  1. The grant's home-domain signature verifies.
//  2. The grant's audience is the verifier.
//  3. The grant is inside its validity window.
//  4. The presentation was signed by a key of the grantee.
//  5. The presentation binds this grant, this audience, and this request,
//     and is fresh.
//  6. The embedded scope set was signed by the verifier, names the same
//     grantee, and contains every approved scope. Its expiry is NOT checked.
//  7. The verifier holds no revocation for the grant.
//
// It does not check nonce reuse. The audience owns replay protection.
func VerifyCredential(credential api.ActAsCredential, ctx AudienceContext) (VerifiedActAs, error) {
	// 1
	grant, err := VerifyGrantSignature(credential.Grant, ctx.IssuerDomainKeys)
	if err != nil {
		return VerifiedActAs{}, err
	}
	// 2
	if !SameApplication(grant.Audience, ctx.OwnApplication) {
		return VerifiedActAs{}, actAsMismatch("audience")
	}
	// 3
	issued, err := parseActAsTime(grant.IssuedAt)
	if err != nil {
		return VerifiedActAs{}, err
	}
	expires, err := parseActAsTime(grant.ExpiresAt)
	if err != nil {
		return VerifiedActAs{}, err
	}
	skew := skewDuration(ctx.SkewSeconds)
	if ctx.Now.Add(skew).Before(issued) {
		return VerifiedActAs{}, actAsErr(ErrActAsRequestExpired, "grant is not yet valid")
	}
	if !ctx.Now.Add(-skew).Before(expires) {
		return VerifiedActAs{}, actAsErr(ErrActAsGrantExpired, "")
	}
	// 4
	signed := credential.Presentation
	signer, err := VerifyGranteeProof(signed.Proof, envelopeSignatureInput(PresentationTag, signed.Presentation), grant.Grantee, ctx.GranteeInstanceKeys, ctx.Now, ctx.SkewSeconds)
	if err != nil {
		return VerifiedActAs{}, err
	}
	// 5
	presentation, err := api.DecodeActAsPresentation(signed.Presentation)
	if err != nil {
		return VerifiedActAs{}, actAsErr(ErrActAsDecode, err.Error())
	}
	if !bytes.Equal(presentation.GrantHash, GrantHash(credential.Grant.Grant)) {
		return VerifiedActAs{}, actAsMismatch("grant_hash")
	}
	if !SameApplication(presentation.Audience, ctx.OwnApplication) {
		return VerifiedActAs{}, actAsMismatch("presentation.audience")
	}
	if !bytes.Equal(presentation.RequestDigest, ctx.ExpectedRequestDigest) {
		return VerifiedActAs{}, actAsMismatch("request_digest")
	}
	presentedAt, err := parseActAsTime(presentation.PresentedAt)
	if err != nil {
		return VerifiedActAs{}, err
	}
	if presentedAt.After(ctx.Now.Add(skew)) ||
		addSeconds(presentedAt, ctx.MaxPresentationAgeSeconds).Add(skew).Before(ctx.Now) {
		return VerifiedActAs{}, actAsErr(ErrActAsRequestExpired, "presentation")
	}
	// 6
	set, err := VerifyScopeSet(grant.ScopeSet, ctx.OwnApplication, ctx.OwnScopeSetKeys, ctx.RevokedKeyPolicy)
	if err != nil {
		return VerifiedActAs{}, err
	}
	if !SameGrantee(set.Grantee, grant.Grantee) {
		return VerifiedActAs{}, actAsMismatch("scope_set.grantee")
	}
	if err := CheckApprovedScope(set, grant.ApprovedScope); err != nil {
		return VerifiedActAs{}, err
	}
	// 7
	for _, id := range ctx.RevokedGrantIDs {
		if id == grant.GrantId {
			return VerifiedActAs{}, actAsErr(ErrActAsGrantRevoked, "")
		}
	}
	return VerifiedActAs{
		GrantID:       grant.GrantId,
		UserID:        grant.UserId + "@" + grant.SubjectDomain,
		SubjectDomain: grant.SubjectDomain,
		Grantee:       grant.Grantee,
		Signer:        signer,
		ApprovedScope: grant.ApprovedScope,
		ExpiresAt:     grant.ExpiresAt,
		Nonce:         presentation.Nonce,
	}, nil
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

// VerifyGrantRevocation verifies a grant revocation against the issuing
// domain's keys. expectedDomain is the grant's subject_domain.
func VerifyGrantRevocation(signed api.SignedActAsGrantRevocation, domainKeys []api.DomainPublicKey, expectedDomain string) (api.ActAsGrantRevocation, error) {
	revocation, err := api.DecodeActAsGrantRevocation(signed.Revocation)
	if err != nil {
		return api.ActAsGrantRevocation{}, actAsErr(ErrActAsDecode, err.Error())
	}
	if revocation.SubjectDomain != expectedDomain {
		return api.ActAsGrantRevocation{}, actAsMismatch("subject_domain")
	}
	if _, err := parseActAsTime(revocation.RevokedAt); err != nil {
		return api.ActAsGrantRevocation{}, err
	}
	if err := verifyActAsDomainSignature(envelopeSignatureInput(GrantRevocationTag, signed.Revocation), signed.Signatures, domainKeys, expectedDomain); err != nil {
		return api.ActAsGrantRevocation{}, err
	}
	return revocation, nil
}

// RevokedGrantIDs returns the grant ids that a set of revocations validly
// revokes. Records that fail verification are ignored.
func RevokedGrantIDs(revocations []api.SignedActAsGrantRevocation, domainKeys []api.DomainPublicKey, expectedDomain string) []string {
	var out []string
	for _, r := range revocations {
		if rev, err := VerifyGrantRevocation(r, domainKeys, expectedDomain); err == nil {
			out = append(out, rev.GrantId)
		}
	}
	return out
}
