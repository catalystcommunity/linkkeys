package regularrp

import (
	"bytes"
	"errors"
	"testing"
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

// Round-trip tests: build and sign a request with keyring.go, then verify
// it with applicationkeys.go/requests.go. The conformance suite proves this
// package's Verify* functions agree with Rust-PRODUCED signatures; these
// tests additionally prove this package's OWN Sign* functions produce
// something its OWN Verify* functions accept — catching an asymmetric bug
// (e.g. a mismatched field order) the conformance vectors alone would not.

func testSigner(t *testing.T, keyID string) (ApplicationSigner, ApplicationKeyRef, time.Time) {
	t.Helper()
	pub, seed, fp, err := NewSigningKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	ref := ApplicationKeyRef{
		KeyID:       keyID,
		KeyUsage:    KeyUsageSign,
		Algorithm:   AlgorithmEd25519,
		PublicKey:   pub[:],
		Fingerprint: fp,
		CreatedAt:   now.Add(-time.Hour).Truncate(time.Second),
		ExpiresAt:   now.Add(24 * time.Hour).Truncate(time.Second),
	}
	signer := ApplicationSigner{KeyID: keyID, Algorithm: AlgorithmEd25519, PrivateKeyBytes: seed[:]}
	return signer, ref, now
}

func TestKeyringAdditionRoundTrip(t *testing.T) {
	instance := InstanceRef{SubjectUserID: "018f0000-0000-7000-8000-000000000001", SubjectDomain: "app-conformance.example", ApplicationID: "tinku", InstanceID: "instance-a"}
	signerA, refA, now := testSigner(t, "app-key-a")
	signerB, refB, _ := testSigner(t, "app-key-b")

	newPub, newSeed, newFp, err := NewSigningKeyPair()
	if err != nil {
		t.Fatalf("generate new key: %v", err)
	}
	newSigner := ApplicationSigner{KeyID: "app-key-new", Algorithm: AlgorithmEd25519, PrivateKeyBytes: newSeed[:]}

	addition := api.ApplicationKeyAddition{
		SubjectUserId:               instance.SubjectUserID,
		SubjectDomain:               instance.SubjectDomain,
		ApplicationId:               instance.ApplicationID,
		InstanceId:                  instance.InstanceID,
		KeyId:                       "app-key-new",
		KeyUsage:                    KeyUsageSign,
		Algorithm:                   AlgorithmEd25519,
		PublicKey:                   newPub[:],
		Fingerprint:                 newFp,
		RequestedKeyLifetimeSeconds: 86400,
		ChallengeId:                 "challenge-1",
		Challenge:                   []byte("nonce-bytes-from-start-key-challenge"),
		RequestedAt:                 now.Truncate(time.Second),
		ExpiresAt:                   now.Add(5 * time.Minute).Truncate(time.Second),
	}

	signed, err := SignAddition(addition, []ApplicationSigner{signerA, signerB}, &newSigner)
	if err != nil {
		t.Fatalf("SignAddition: %v", err)
	}

	got, err := VerifyAddition(signed, []ApplicationKeyRef{refA, refB}, instance, now, 300)
	if err != nil {
		t.Fatalf("VerifyAddition: %v", err)
	}
	if got.KeyId != "app-key-new" {
		t.Errorf("verified addition key id = %q, want app-key-new", got.KeyId)
	}

	// One signer alone must not meet the quorum.
	if _, err := VerifyAddition(signed, []ApplicationKeyRef{refA}, instance, now, 300); err == nil {
		t.Error("VerifyAddition unexpectedly succeeded with only one of the two quorum keys visible")
	}
}

func TestKeyringRenewalRoundTrip(t *testing.T) {
	instance := InstanceRef{SubjectUserID: "018f0000-0000-7000-8000-000000000001", SubjectDomain: "app-conformance.example", ApplicationID: "tinku", InstanceID: "instance-a"}
	signerA, refA, now := testSigner(t, "app-key-a")

	renewal := api.ApplicationKeyRenewal{
		SubjectUserId: instance.SubjectUserID,
		SubjectDomain: instance.SubjectDomain,
		ApplicationId: instance.ApplicationID,
		InstanceId:    instance.InstanceID,
		KeyId:         "app-key-a",
		ChallengeId:   "renew-challenge-1",
		Challenge:     []byte("renew-nonce-bytes"),
		RequestedAt:   now.Truncate(time.Second),
		ExpiresAt:     now.Add(5 * time.Minute).Truncate(time.Second),
	}

	// Ed25519 self-renewal: the key signs for itself, no siblings.
	signed, err := SignRenewal(renewal, nil, &signerA)
	if err != nil {
		t.Fatalf("SignRenewal: %v", err)
	}
	if _, err := VerifyRenewal(signed, refA, nil, instance, now, 300); err != nil {
		t.Fatalf("VerifyRenewal (self-renewal): %v", err)
	}

	// X25519 sibling renewal: the agreement key cannot sign, a sibling vouches.
	agreePub, _, agreeFp, err := NewAgreementKeyPair()
	if err != nil {
		t.Fatalf("generate agreement key: %v", err)
	}
	agreeRef := ApplicationKeyRef{
		KeyID: "app-key-agree", KeyUsage: KeyUsageAgree, Algorithm: AlgorithmX25519,
		PublicKey: agreePub[:], Fingerprint: agreeFp,
		CreatedAt: now.Add(-time.Hour).Truncate(time.Second), ExpiresAt: now.Add(24 * time.Hour).Truncate(time.Second),
	}
	agreeRenewal := renewal
	agreeRenewal.KeyId = "app-key-agree"
	signedAgree, err := SignRenewal(agreeRenewal, []ApplicationSigner{signerA}, nil)
	if err != nil {
		t.Fatalf("SignRenewal (sibling): %v", err)
	}
	if _, err := VerifyRenewal(signedAgree, agreeRef, []ApplicationKeyRef{refA}, instance, now, 300); err != nil {
		t.Fatalf("VerifyRenewal (sibling): %v", err)
	}
}

func TestKeyringRevocationRoundTrip(t *testing.T) {
	instance := InstanceRef{SubjectUserID: "018f0000-0000-7000-8000-000000000001", SubjectDomain: "app-conformance.example", ApplicationID: "tinku", InstanceID: "instance-a"}
	signerA, refA, now := testSigner(t, "app-key-a")
	signerB, refB, _ := testSigner(t, "app-key-b")
	_, refC, _ := testSigner(t, "app-key-c")

	rev, err := SignRevocation(instance, refC.KeyID, refC.Fingerprint, now.Truncate(time.Second), []ApplicationSigner{signerA, signerB})
	if err != nil {
		t.Fatalf("SignRevocation: %v", err)
	}

	if err := VerifyRevocation(rev, []ApplicationKeyRef{refA, refB, refC}, instance); err != nil {
		t.Fatalf("VerifyRevocation: %v", err)
	}
}

// A signed revoked_at with a fraction of a second was never signed. The
// verifier must refuse it, not round it.
func TestRevocationFractionalRevokedAtRefused(t *testing.T) {
	instance := InstanceRef{SubjectUserID: "018f0000-0000-7000-8000-000000000001", SubjectDomain: "app-conformance.example", ApplicationID: "tinku", InstanceID: "instance-a"}
	signerA, refA, now := testSigner(t, "app-key-a")
	signerB, refB, _ := testSigner(t, "app-key-b")
	_, refC, _ := testSigner(t, "app-key-c")

	if _, err := RevocationPayload(instance.SubjectUserID, instance.SubjectDomain, instance.ApplicationID, instance.InstanceID, refC.KeyID, refC.Fingerprint, now.Truncate(time.Second).Add(time.Millisecond)); err == nil {
		t.Fatal("RevocationPayload accepted a fractional revoked_at")
	}

	if _, err := SignRevocation(instance, refC.KeyID, refC.Fingerprint, now.Truncate(time.Second).Add(time.Millisecond), []ApplicationSigner{signerA, signerB}); err == nil {
		t.Fatal("SignRevocation signed a fractional revoked_at")
	}
	rev, err := SignRevocation(instance, refC.KeyID, refC.Fingerprint, now.Truncate(time.Second), []ApplicationSigner{signerA, signerB})
	if err != nil {
		t.Fatalf("SignRevocation: %v", err)
	}
	rev.RevokedAt = rev.RevokedAt.Add(500 * time.Millisecond)
	err = VerifyRevocation(rev, []ApplicationKeyRef{refA, refB, refC}, instance)
	var ake *ApplicationKeyError
	if !errors.As(err, &ake) || ake.Kind != ErrBadTimestamp {
		t.Fatalf("want ErrBadTimestamp, got %v", err)
	}
}

func TestSignedTimeIsUnixSecondsInteger(t *testing.T) {
	got, err := cborSignedTime(time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x1a, 0x65, 0x53, 0xf1, 0x00}; !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
	if got, _ := cborSignedTime(time.Unix(-1, 0)); !bytes.Equal(got, []byte{0x20}) {
		t.Errorf("negative: got %x", got)
	}
}
