package localrp_test

// Conformance tests for sdks/local-rp/conformance/revocations.json —
// sibling-signed key revocation certificates (see that README's
// "revocations.json" section for the schema and the four gotchas its
// verification rules encode):
//
//   - each signature's payload is recomputed from the signature's WIRE
//     domain field; the verify-domain parameter only filters (this is what
//     distinguishes cross_domain_signature_reuse, where the wire domain
//     lies, from verified_under_wrong_domain, where the filter drops
//     everything)
//   - a key never authorizes its own revocation
//   - expired/revoked siblings never count toward quorum (wall-clock key
//     validity — which is why the fixture keys expire in 2126)
//   - distinctness is by signer key id
//
// Every certificate case asserts the exact expected_counted_signers via
// CountRevocationSigners plus the overall outcome via
// VerifyRevocationCertificate; the application case proves a valid
// certificate, once applied, flips a callback-payload envelope signed by
// the target key from verifying to failing.

import (
	"errors"
	"testing"

	localrp "github.com/catalystcommunity/linkkeys/sdks/local-rp/go"
	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

type revocationDomainKey struct {
	KeyID        string  `json:"key_id"`
	PublicKeyHex string  `json:"public_key_hex"`
	Fingerprint  string  `json:"fingerprint_hex"`
	Algorithm    string  `json:"algorithm"`
	KeyUsage     string  `json:"key_usage"`
	CreatedAt    string  `json:"created_at"`
	ExpiresAt    string  `json:"expires_at"`
	RevokedAt    *string `json:"revoked_at"`
}

type revocationSignature struct {
	Domain        string `json:"domain"`
	SignedByKeyID string `json:"signed_by_key_id"`
	SignatureHex  string `json:"signature_hex"`
}

type revocationCertificate struct {
	TargetKeyID       string                `json:"target_key_id"`
	TargetFingerprint string                `json:"target_fingerprint"`
	RevokedAt         string                `json:"revoked_at"`
	Signatures        []revocationSignature `json:"signatures"`
}

type revocationCertCase struct {
	Name                   string                `json:"name"`
	VerifyDomain           string                `json:"verify_domain"`
	Certificate            revocationCertificate `json:"certificate"`
	CertificateCborHex     string                `json:"certificate_cbor_hex"`
	ExpectedValid          bool                  `json:"expected_valid"`
	ExpectedCountedSigners int                   `json:"expected_counted_signers"`
}

type revocationApplicationCase struct {
	Envelope struct {
		PayloadCborHex string `json:"payload_cbor_hex"`
		SigningKeyID   string `json:"signing_key_id"`
		SignatureHex   string `json:"signature_hex"`
		Context        string `json:"context"`
	} `json:"envelope"`
	VerifyNow                     string `json:"verify_now"`
	ClockSkewSeconds              int64  `json:"clock_skew_seconds"`
	ExpectedValidBeforeRevocation bool   `json:"expected_valid_before_revocation"`
	ExpectedValidAfterRevocation  bool   `json:"expected_valid_after_revocation"`
}

type revocationsFile struct {
	Tag              string                    `json:"tag"`
	Quorum           int                       `json:"quorum"`
	Domain           string                    `json:"domain"`
	DomainKeys       []revocationDomainKey     `json:"domain_keys"`
	CertificateCases []revocationCertCase      `json:"certificate_cases"`
	ApplicationCase  revocationApplicationCase `json:"application_case"`
}

func revocationFixtureKeys(t *testing.T, d *revocationsFile) []api.DomainPublicKey {
	t.Helper()
	keys := make([]api.DomainPublicKey, 0, len(d.DomainKeys))
	for _, k := range d.DomainKeys {
		keys = append(keys, api.DomainPublicKey{
			KeyId:       k.KeyID,
			PublicKey:   mustHex(t, k.PublicKeyHex),
			Fingerprint: k.Fingerprint,
			Algorithm:   k.Algorithm,
			KeyUsage:    k.KeyUsage,
			CreatedAt:   k.CreatedAt,
			ExpiresAt:   k.ExpiresAt,
			RevokedAt:   k.RevokedAt,
		})
	}
	return keys
}

func TestRevocationsCertificateCases(t *testing.T) {
	var d revocationsFile
	loadJSON(t, "revocations.json", &d)

	if d.Quorum != localrp.RevocationQuorum {
		t.Fatalf("quorum mismatch: vectors say %d, SDK constant is %d", d.Quorum, localrp.RevocationQuorum)
	}
	if len(d.CertificateCases) != 9 {
		t.Fatalf("expected 9 certificate cases, got %d", len(d.CertificateCases))
	}
	keys := revocationFixtureKeys(t, &d)

	for _, c := range d.CertificateCases {
		t.Run(c.Name, func(t *testing.T) {
			// Decode the certificate from its CSIL CBOR wire form (the shape
			// FetchDomainKeys actually receives from get-revocations), and
			// cross-check it against the case's expanded fields so the wire
			// encoding and the JSON expansion can never drift apart silently.
			cert, err := api.DecodeRevocationCertificate(mustHex(t, c.CertificateCborHex))
			if err != nil {
				t.Fatalf("decode certificate_cbor_hex: %v", err)
			}
			if cert.TargetKeyId != c.Certificate.TargetKeyID ||
				cert.TargetFingerprint != c.Certificate.TargetFingerprint ||
				cert.RevokedAt != c.Certificate.RevokedAt ||
				len(cert.Signatures) != len(c.Certificate.Signatures) {
				t.Fatalf("decoded certificate does not match the case's expanded fields")
			}
			for i, sig := range c.Certificate.Signatures {
				if cert.Signatures[i].Domain != sig.Domain ||
					cert.Signatures[i].SignedByKeyId != sig.SignedByKeyID ||
					hexEncode(cert.Signatures[i].Signature) != sig.SignatureHex {
					t.Fatalf("decoded signature[%d] does not match the case's expanded fields", i)
				}
			}

			counted := localrp.CountRevocationSigners(cert, keys, c.VerifyDomain)
			if counted != c.ExpectedCountedSigners {
				t.Errorf("counted signers = %d, want %d", counted, c.ExpectedCountedSigners)
			}

			err = localrp.VerifyRevocationCertificate(cert, keys, c.VerifyDomain)
			if valid := err == nil; valid != c.ExpectedValid {
				t.Errorf("verify outcome = %v, want %v (err: %v)", valid, c.ExpectedValid, err)
			}
			if err != nil {
				var revErr *localrp.RevocationError
				if !errors.As(err, &revErr) {
					t.Fatalf("expected *localrp.RevocationError, got %T: %v", err, err)
				}
				if revErr.Got != c.ExpectedCountedSigners || revErr.Need != localrp.RevocationQuorum {
					t.Errorf("RevocationError{Got: %d, Need: %d}, want Got=%d Need=%d",
						revErr.Got, revErr.Need, c.ExpectedCountedSigners, localrp.RevocationQuorum)
				}
			}
		})
	}
}

func TestRevocationsApplicationCase(t *testing.T) {
	var d revocationsFile
	loadJSON(t, "revocations.json", &d)
	keys := revocationFixtureKeys(t, &d)
	ac := d.ApplicationCase

	if ac.Envelope.Context != "linkkeys-local-rp-callback" {
		t.Fatalf("unexpected envelope context %q", ac.Envelope.Context)
	}

	signed := api.SignedLocalRpCallbackPayload{
		Payload:      mustHex(t, ac.Envelope.PayloadCborHex),
		SigningKeyId: ac.Envelope.SigningKeyID,
		Signature:    mustHex(t, ac.Envelope.SignatureHex),
	}
	now := parseRFC3339(t, ac.VerifyNow)

	// Before revocation: the fetched key list shows the target key with no
	// revoked_at, so the envelope verifies.
	_, err := localrp.VerifyLocalRpCallbackPayload(signed, keys, now, ac.ClockSkewSeconds)
	if valid := err == nil; valid != ac.ExpectedValidBeforeRevocation {
		t.Fatalf("before revocation: valid=%v, want %v (err: %v)", valid, ac.ExpectedValidBeforeRevocation, err)
	}

	// The referenced certificate (valid_quorum_two_siblings) must verify
	// against the same key set.
	var certCase *revocationCertCase
	for i := range d.CertificateCases {
		if d.CertificateCases[i].Name == "valid_quorum_two_siblings" {
			certCase = &d.CertificateCases[i]
			break
		}
	}
	if certCase == nil {
		t.Fatal("certificate_ref target valid_quorum_two_siblings not found")
	}
	cert, err := api.DecodeRevocationCertificate(mustHex(t, certCase.CertificateCborHex))
	if err != nil {
		t.Fatalf("decode referenced certificate: %v", err)
	}
	if err := localrp.VerifyRevocationCertificate(cert, keys, d.Domain); err != nil {
		t.Fatalf("referenced certificate must verify: %v", err)
	}

	// Apply the revocation the way the vector's note describes: treat the
	// target as revoked from cert.revoked_at onward. The same envelope must
	// now fail even though the fetched key entry looked valid on its own.
	markedKeys := make([]api.DomainPublicKey, len(keys))
	copy(markedKeys, keys)
	for i := range markedKeys {
		if markedKeys[i].KeyId == cert.TargetKeyId {
			revokedAt := cert.RevokedAt
			markedKeys[i].RevokedAt = &revokedAt
		}
	}
	_, err = localrp.VerifyLocalRpCallbackPayload(signed, markedKeys, now, ac.ClockSkewSeconds)
	if valid := err == nil; valid != ac.ExpectedValidAfterRevocation {
		t.Fatalf("after revocation (marked): valid=%v, want %v (err: %v)", valid, ac.ExpectedValidAfterRevocation, err)
	}

	// This SDK's production apply path (FetchDomainKeys) removes the
	// targeted key from the trusted set entirely rather than marking it —
	// verify that stricter application also flips the envelope to failing.
	var removedKeys []api.DomainPublicKey
	for _, k := range keys {
		if k.KeyId != cert.TargetKeyId {
			removedKeys = append(removedKeys, k)
		}
	}
	if _, err := localrp.VerifyLocalRpCallbackPayload(signed, removedKeys, now, ac.ClockSkewSeconds); err == nil {
		t.Fatal("after revocation (removed): envelope unexpectedly verified")
	}
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, hexdigits[x>>4], hexdigits[x&0x0f])
	}
	return string(out)
}
