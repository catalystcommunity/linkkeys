package regularrp

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

// Replays every vector in sdks/regular-rp/conformance/ against this
// package's implementation — the proof that this Go SDK's wire
// constructions and verification rules agree with the Rust reference
// (crates/liblinkkeys/src/application_keys.rs). See that directory's
// README.md for the vector schema and the meaning of each case.
//
// Convention shared by every file: every case expected to fail carries
// `"expected_valid": false` and lives under `negative_cases[]`. This test's
// assertion is simply: attempt the operation, and require success/failure to
// match `expected_valid` — exact error TYPES are not part of the portable
// contract, only pass/fail.

func conformanceDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "conformance"))
	if err != nil {
		t.Fatalf("resolve conformance dir: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("conformance dir not found at %s: %v", dir, err)
	}
	return dir
}

func loadVectorFile(t *testing.T, dir, name string, out any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// ---------------------------------------------------------------------------
// Shared vector shapes
// ---------------------------------------------------------------------------

type appKeyRefVec struct {
	Algorithm    string  `json:"algorithm"`
	CreatedAt    string  `json:"created_at"`
	ExpiresAt    string  `json:"expires_at"`
	Fingerprint  string  `json:"fingerprint"`
	KeyID        string  `json:"key_id"`
	KeyUsage     string  `json:"key_usage"`
	PublicKeyHex string  `json:"public_key_hex"`
	RevokedAt    *string `json:"revoked_at"`
}

func (v appKeyRefVec) toRef(t *testing.T) ApplicationKeyRef {
	t.Helper()
	return ApplicationKeyRef{
		KeyID:       v.KeyID,
		KeyUsage:    v.KeyUsage,
		Algorithm:   v.Algorithm,
		PublicKey:   mustHex(t, v.PublicKeyHex),
		Fingerprint: v.Fingerprint,
		CreatedAt:   v.CreatedAt,
		ExpiresAt:   v.ExpiresAt,
		RevokedAt:   v.RevokedAt,
	}
}

type domainKeyVec struct {
	Algorithm    string  `json:"algorithm"`
	CreatedAt    string  `json:"created_at"`
	ExpiresAt    string  `json:"expires_at"`
	Fingerprint  string  `json:"fingerprint"`
	KeyID        string  `json:"key_id"`
	KeyUsage     string  `json:"key_usage"`
	PublicKeyHex string  `json:"public_key_hex"`
	RevokedAt    *string `json:"revoked_at"`
}

func (v domainKeyVec) toDomainKey(t *testing.T) api.DomainPublicKey {
	t.Helper()
	return api.DomainPublicKey{
		KeyId:       v.KeyID,
		PublicKey:   mustHex(t, v.PublicKeyHex),
		Fingerprint: v.Fingerprint,
		Algorithm:   v.Algorithm,
		KeyUsage:    v.KeyUsage,
		CreatedAt:   v.CreatedAt,
		ExpiresAt:   v.ExpiresAt,
		RevokedAt:   v.RevokedAt,
	}
}

type claimSigVec struct {
	Domain        string `json:"domain"`
	SignedByKeyID string `json:"signed_by_key_id"`
	SignatureHex  string `json:"signature_hex"`
}

func (v claimSigVec) toSig(t *testing.T) api.ClaimSignature {
	t.Helper()
	return api.ClaimSignature{Domain: v.Domain, SignedByKeyId: v.SignedByKeyID, Signature: mustHex(t, v.SignatureHex)}
}

type appKeySigVec struct {
	SignedByKeyID string `json:"signed_by_key_id"`
	SignatureHex  string `json:"signature_hex"`
}

func (v appKeySigVec) toSig(t *testing.T) api.ApplicationKeySignature {
	t.Helper()
	return api.ApplicationKeySignature{SignedByKeyId: v.SignedByKeyID, Signature: mustHex(t, v.SignatureHex)}
}

func toAppKeySigs(t *testing.T, vs []appKeySigVec) []api.ApplicationKeySignature {
	t.Helper()
	out := make([]api.ApplicationKeySignature, len(vs))
	for i, v := range vs {
		out[i] = v.toSig(t)
	}
	return out
}

func checkExpected(t *testing.T, name string, expectedValid bool, err error) {
	t.Helper()
	if expectedValid && err != nil {
		t.Errorf("%s: expected valid, got error: %v", name, err)
	}
	if !expectedValid && err == nil {
		t.Errorf("%s: expected invalid, got success", name)
	}
}

// ---------------------------------------------------------------------------
// application_key_attestation.json
// ---------------------------------------------------------------------------

type attestationCaseVec struct {
	Name           string         `json:"name"`
	ExpectedValid  bool           `json:"expected_valid"`
	DomainKeys     []domainKeyVec `json:"domain_keys"`
	ExpectedDomain string         `json:"expected_domain"`
	Signed         struct {
		AttestationCborHex string        `json:"attestation_cbor_hex"`
		Signatures         []claimSigVec `json:"signatures"`
	} `json:"signed"`
}

type attestationVectorFile struct {
	Cases         []attestationCaseVec `json:"cases"`
	NegativeCases []attestationCaseVec `json:"negative_cases"`
}

func TestConformanceAttestation(t *testing.T) {
	var f attestationVectorFile
	loadVectorFile(t, conformanceDir(t), "application_key_attestation.json", &f)

	run := func(c attestationCaseVec) {
		domainKeys := make([]api.DomainPublicKey, len(c.DomainKeys))
		for i, dk := range c.DomainKeys {
			domainKeys[i] = dk.toDomainKey(t)
		}
		signed := api.SignedApplicationKeyAttestation{
			Attestation: mustHex(t, c.Signed.AttestationCborHex),
			Signatures:  make([]api.ClaimSignature, len(c.Signed.Signatures)),
		}
		for i, s := range c.Signed.Signatures {
			signed.Signatures[i] = s.toSig(t)
		}
		_, err := VerifyAttestationSignature(signed, domainKeys, c.ExpectedDomain)
		checkExpected(t, c.Name, c.ExpectedValid, err)
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) { run(c) })
	}
	for _, c := range f.NegativeCases {
		t.Run(c.Name, func(t *testing.T) { run(c) })
	}
}

// ---------------------------------------------------------------------------
// application_key_addition.json
// ---------------------------------------------------------------------------

type additionCaseVec struct {
	Name          string         `json:"name"`
	ExpectedValid bool           `json:"expected_valid"`
	ExistingKeys  []appKeyRefVec `json:"existing_keys"`
	Signed        struct {
		AdditionCborHex    string         `json:"addition_cbor_hex"`
		Signatures         []appKeySigVec `json:"signatures"`
		PossessionProofHex *string        `json:"possession_proof_hex"`
	} `json:"signed"`
}

type additionVectorFile struct {
	Instance struct {
		SubjectUserID string `json:"subject_user_id"`
		SubjectDomain string `json:"subject_domain"`
		ApplicationID string `json:"application_id"`
		InstanceID    string `json:"instance_id"`
	} `json:"instance"`
	Now           string            `json:"now"`
	SkewSeconds   int64             `json:"skew_seconds"`
	Cases         []additionCaseVec `json:"cases"`
	NegativeCases []additionCaseVec `json:"negative_cases"`
}

func TestConformanceAddition(t *testing.T) {
	var f additionVectorFile
	loadVectorFile(t, conformanceDir(t), "application_key_addition.json", &f)

	instance := InstanceRef{
		SubjectUserID: f.Instance.SubjectUserID,
		SubjectDomain: f.Instance.SubjectDomain,
		ApplicationID: f.Instance.ApplicationID,
		InstanceID:    f.Instance.InstanceID,
	}
	now, err := time.Parse(time.RFC3339, f.Now)
	if err != nil {
		t.Fatalf("bad now: %v", err)
	}

	run := func(c additionCaseVec) {
		existing := make([]ApplicationKeyRef, len(c.ExistingKeys))
		for i, k := range c.ExistingKeys {
			existing[i] = k.toRef(t)
		}
		signed := api.SignedApplicationKeyAddition{
			Addition:   mustHex(t, c.Signed.AdditionCborHex),
			Signatures: toAppKeySigs(t, c.Signed.Signatures),
		}
		if c.Signed.PossessionProofHex != nil {
			proof := mustHex(t, *c.Signed.PossessionProofHex)
			signed.PossessionProof = &proof
		}
		_, err := VerifyAddition(signed, existing, instance, now, f.SkewSeconds)
		checkExpected(t, c.Name, c.ExpectedValid, err)
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) { run(c) })
	}
	for _, c := range f.NegativeCases {
		t.Run(c.Name, func(t *testing.T) { run(c) })
	}
}

// ---------------------------------------------------------------------------
// application_key_renewal.json
// ---------------------------------------------------------------------------

type renewalCaseVec struct {
	Name          string         `json:"name"`
	ExpectedValid bool           `json:"expected_valid"`
	Now           string         `json:"now"`
	SkewSeconds   int64          `json:"skew_seconds"`
	Target        appKeyRefVec   `json:"target"`
	SiblingKeys   []appKeyRefVec `json:"sibling_keys"`
	Signed        struct {
		RenewalCborHex     string         `json:"renewal_cbor_hex"`
		Signatures         []appKeySigVec `json:"signatures"`
		PossessionProofHex *string        `json:"possession_proof_hex"`
	} `json:"signed"`
}

type renewalVectorFile struct {
	Instance struct {
		SubjectUserID string `json:"subject_user_id"`
		SubjectDomain string `json:"subject_domain"`
		ApplicationID string `json:"application_id"`
		InstanceID    string `json:"instance_id"`
	} `json:"instance"`
	Cases         []renewalCaseVec `json:"cases"`
	NegativeCases []renewalCaseVec `json:"negative_cases"`
}

func TestConformanceRenewal(t *testing.T) {
	var f renewalVectorFile
	loadVectorFile(t, conformanceDir(t), "application_key_renewal.json", &f)

	instance := InstanceRef{
		SubjectUserID: f.Instance.SubjectUserID,
		SubjectDomain: f.Instance.SubjectDomain,
		ApplicationID: f.Instance.ApplicationID,
		InstanceID:    f.Instance.InstanceID,
	}

	run := func(c renewalCaseVec) {
		now, err := time.Parse(time.RFC3339, c.Now)
		if err != nil {
			t.Fatalf("bad now: %v", err)
		}
		siblings := make([]ApplicationKeyRef, len(c.SiblingKeys))
		for i, k := range c.SiblingKeys {
			siblings[i] = k.toRef(t)
		}
		signed := api.SignedApplicationKeyRenewal{
			Renewal:    mustHex(t, c.Signed.RenewalCborHex),
			Signatures: toAppKeySigs(t, c.Signed.Signatures),
		}
		if c.Signed.PossessionProofHex != nil {
			proof := mustHex(t, *c.Signed.PossessionProofHex)
			signed.PossessionProof = &proof
		}
		_, err = VerifyRenewal(signed, c.Target.toRef(t), siblings, instance, now, c.SkewSeconds)
		checkExpected(t, c.Name, c.ExpectedValid, err)
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) { run(c) })
	}
	for _, c := range f.NegativeCases {
		t.Run(c.Name, func(t *testing.T) { run(c) })
	}
}

// ---------------------------------------------------------------------------
// application_key_revocation.json
// ---------------------------------------------------------------------------

type revocationVec struct {
	SubjectUserID     string         `json:"subject_user_id"`
	SubjectDomain     string         `json:"subject_domain"`
	ApplicationID     string         `json:"application_id"`
	InstanceID        string         `json:"instance_id"`
	TargetKeyID       string         `json:"target_key_id"`
	TargetFingerprint string         `json:"target_fingerprint"`
	RevokedAt         string         `json:"revoked_at"`
	Signatures        []appKeySigVec `json:"signatures"`
}

type revocationCaseVec struct {
	Name          string        `json:"name"`
	ExpectedValid bool          `json:"expected_valid"`
	Revocation    revocationVec `json:"revocation"`
}

type revocationVectorFile struct {
	Keys          []appKeyRefVec      `json:"keys"`
	Cases         []revocationCaseVec `json:"cases"`
	NegativeCases []revocationCaseVec `json:"negative_cases"`
}

func TestConformanceRevocation(t *testing.T) {
	var f revocationVectorFile
	loadVectorFile(t, conformanceDir(t), "application_key_revocation.json", &f)

	keys := make([]ApplicationKeyRef, len(f.Keys))
	for i, k := range f.Keys {
		keys[i] = k.toRef(t)
	}

	run := func(c revocationCaseVec) {
		rev := api.ApplicationKeyRevocation{
			SubjectUserId:     c.Revocation.SubjectUserID,
			SubjectDomain:     c.Revocation.SubjectDomain,
			ApplicationId:     c.Revocation.ApplicationID,
			InstanceId:        c.Revocation.InstanceID,
			TargetKeyId:       c.Revocation.TargetKeyID,
			TargetFingerprint: c.Revocation.TargetFingerprint,
			RevokedAt:         c.Revocation.RevokedAt,
			Signatures:        toAppKeySigs(t, c.Revocation.Signatures),
		}
		instance := InstanceRef{
			SubjectUserID: c.Revocation.SubjectUserID,
			SubjectDomain: c.Revocation.SubjectDomain,
			ApplicationID: c.Revocation.ApplicationID,
			InstanceID:    c.Revocation.InstanceID,
		}
		err := VerifyRevocation(rev, keys, instance)
		checkExpected(t, c.Name, c.ExpectedValid, err)
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) { run(c) })
	}
	for _, c := range f.NegativeCases {
		t.Run(c.Name, func(t *testing.T) { run(c) })
	}
}

// ---------------------------------------------------------------------------
// application_key_sealed_challenge.json
// ---------------------------------------------------------------------------

type sealedChallengeKeyVec struct {
	KeyID         string `json:"key_id"`
	PrivateKeyHex string `json:"private_key_hex"`
	PublicKeyHex  string `json:"public_key_hex"`
	SeedHex       string `json:"seed_hex"`
}

type sealedChallengeCaseVec struct {
	Name                   string  `json:"name"`
	ExpectedValid          bool    `json:"expected_valid"`
	RecipientPrivateKeyHex string  `json:"recipient_private_key_hex"`
	ExpectedPlaintextHex   *string `json:"expected_plaintext_hex"`
	SealedCborHex          *string `json:"sealed_cbor_hex"`
}

type sealedChallengeVectorFile struct {
	Recipient     sealedChallengeKeyVec    `json:"recipient"`
	SealedCborHex string                   `json:"sealed_cbor_hex"`
	Cases         []sealedChallengeCaseVec `json:"cases"`
	NegativeCases []sealedChallengeCaseVec `json:"negative_cases"`
}

func TestConformanceSealedChallenge(t *testing.T) {
	var f sealedChallengeVectorFile
	loadVectorFile(t, conformanceDir(t), "application_key_sealed_challenge.json", &f)

	run := func(c sealedChallengeCaseVec) {
		var recipientPriv [32]byte
		copy(recipientPriv[:], mustHex(t, c.RecipientPrivateKeyHex))

		sealedHex := f.SealedCborHex
		if c.SealedCborHex != nil {
			sealedHex = *c.SealedCborHex
		}
		plaintext, err := OpenChallenge(mustHex(t, sealedHex), recipientPriv)
		checkExpected(t, c.Name, c.ExpectedValid, err)
		if c.ExpectedValid && c.ExpectedPlaintextHex != nil {
			want := mustHex(t, *c.ExpectedPlaintextHex)
			if hex.EncodeToString(plaintext) != hex.EncodeToString(want) {
				t.Errorf("%s: plaintext mismatch: got %x want %x", c.Name, plaintext, want)
			}
		}
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) { run(c) })
	}
	for _, c := range f.NegativeCases {
		t.Run(c.Name, func(t *testing.T) { run(c) })
	}
}
