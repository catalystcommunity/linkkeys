package localrp_test

// Conformance tests for sdks/local-rp/conformance/claims.json — Claim wire
// encoding and claim-signature verification (see that README's "claims.json"
// section for the schema and, especially, "THE TRAP THIS FILE EXISTS TO
// CATCH").
//
// The trap: Claim.claim_value is CBOR bytes (bstr, major type 2), never a
// text string, both on the wire and inside the signed payload. An SDK that
// wires it as text passes its own self-tests perfectly (its sign path and
// verify path agree with each other, just not with the real Rust
// implementation) — only vectors containing real signatures produced by the
// Rust implementation expose the bug. That is why every test below decodes
// claim_cbor_hex (bytes this SDK did not produce) and verifies the embedded
// signatures through this SDK's own VerifyClaimSignatures/VerifyClaim (which
// internally rebuild the exact same 8-element CBOR array these vectors
// pin), rather than round-tripping through this SDK's own SignClaim — a
// sign/verify self-comparison would hide exactly the bug these vectors were
// written to catch.
//
// Covers every case in claims.json: the 3 positive cases (wire round-trip +
// verification), the 4 verification negatives (with expected_error kinds),
// the 1 decode-negative case (claim_value wired as tstr must be rejected),
// and the LocalRpTicketRedemptionResponse round-trip + embedded-claim
// verification.

import (
	"encoding/hex"
	"errors"
	"testing"

	localrp "github.com/catalystcommunity/linkkeys/sdks/local-rp/go"
	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

type claimSignatureFixture struct {
	Domain        string `json:"domain"`
	SignedByKeyID string `json:"signed_by_key_id"`
	SignatureHex  string `json:"signature_hex"`
}

type claimFixture struct {
	AttestedAt string                  `json:"attested_at"`
	ClaimID    string                  `json:"claim_id"`
	ClaimType  string                  `json:"claim_type"`
	ClaimValue string                  `json:"claim_value_hex"`
	CreatedAt  string                  `json:"created_at"`
	ExpiresAt  *string                 `json:"expires_at"`
	RevokedAt  *string                 `json:"revoked_at"`
	Signatures []claimSignatureFixture `json:"signatures"`
	UserID     string                  `json:"user_id"`
}

type claimPositiveCase struct {
	Claim         claimFixture `json:"claim"`
	ClaimCborHex  string       `json:"claim_cbor_hex"`
	Description   string       `json:"description"`
	ExpectedValid bool         `json:"expected_valid"`
	Name          string       `json:"name"`
	SubjectDomain string       `json:"subject_domain"`
}

type claimDecodeNegativeCase struct {
	ClaimCborHex     string `json:"claim_cbor_hex"`
	Description      string `json:"description"`
	ExpectedDecodeOk bool   `json:"expected_decode_ok"`
	Name             string `json:"name"`
}

type claimDomainKeyFixture struct {
	Algorithm   string  `json:"algorithm"`
	CreatedAt   string  `json:"created_at"`
	Domain      string  `json:"domain"`
	ExpiresAt   string  `json:"expires_at"`
	Fingerprint string  `json:"fingerprint_hex"`
	KeyID       string  `json:"key_id"`
	KeyUsage    string  `json:"key_usage"`
	PublicKey   string  `json:"public_key_hex"`
	RevokedAt   *string `json:"revoked_at"`
}

type claimNegativeCase struct {
	ClaimCborHex  string                  `json:"claim_cbor_hex"`
	Description   string                  `json:"description"`
	DomainKeys    []claimDomainKeyFixture `json:"domain_keys"`
	ExpectedError string                  `json:"expected_error"`
	Name          string                  `json:"name"`
	SubjectDomain string                  `json:"subject_domain"`
}

type claimTicketRedemptionResponseFixture struct {
	ResponseCborHex string `json:"response_cbor_hex"`
	TicketExpiresAt string `json:"ticket_expires_at"`
	UserDomain      string `json:"user_domain"`
	UserID          string `json:"user_id"`
}

type claimsFile struct {
	Cases                    []claimPositiveCase                  `json:"cases"`
	DecodeNegativeCases      []claimDecodeNegativeCase            `json:"decode_negative_cases"`
	DomainKeys               []claimDomainKeyFixture              `json:"domain_keys"`
	NegativeCases            []claimNegativeCase                  `json:"negative_cases"`
	SubjectDomain            string                               `json:"subject_domain"`
	TicketRedemptionResponse claimTicketRedemptionResponseFixture `json:"ticket_redemption_response"`
}

// claimDomainKeySets groups fixture domain keys by their own "domain" field
// into the []localrp.DomainKeySet shape VerifyClaimSignatures/VerifyClaim
// expect. This is keyed by the SIGNING domain (the domain that produced a
// given ClaimSignature), which is independent of — and, in the
// subject_domain_replay negative case, deliberately different from — the
// subject_domain passed to verification.
func claimDomainKeySets(t *testing.T, keys []claimDomainKeyFixture) []localrp.DomainKeySet {
	t.Helper()
	byDomain := make(map[string][]api.DomainPublicKey)
	var order []string
	for _, k := range keys {
		if _, ok := byDomain[k.Domain]; !ok {
			order = append(order, k.Domain)
		}
		byDomain[k.Domain] = append(byDomain[k.Domain], api.DomainPublicKey{
			KeyId:       k.KeyID,
			PublicKey:   mustHex(t, k.PublicKey),
			Fingerprint: k.Fingerprint,
			Algorithm:   k.Algorithm,
			KeyUsage:    k.KeyUsage,
			CreatedAt:   k.CreatedAt,
			ExpiresAt:   k.ExpiresAt,
			RevokedAt:   k.RevokedAt,
		})
	}
	out := make([]localrp.DomainKeySet, 0, len(order))
	for _, domain := range order {
		out = append(out, localrp.DomainKeySet{Domain: domain, Keys: byDomain[domain]})
	}
	return out
}

func TestClaimsPositiveCasesRoundTripAndVerify(t *testing.T) {
	var d claimsFile
	loadJSON(t, "claims.json", &d)
	if len(d.Cases) != 3 {
		t.Fatalf("expected 3 positive claim cases, got %d", len(d.Cases))
	}
	defaultKeySets := claimDomainKeySets(t, d.DomainKeys)

	for _, c := range d.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if !c.ExpectedValid {
				t.Fatalf("case %s should be expected_valid=true", c.Name)
			}

			claimBytes := mustHex(t, c.ClaimCborHex)
			claim, err := api.DecodeClaim(claimBytes)
			if err != nil {
				t.Fatalf("decode claim_cbor_hex: %v", err)
			}

			// Cross-check decoded scalar fields against the case's expanded
			// claim. claim_value is the field the whole file exists to pin:
			// it must decode as raw bytes, matching claim_value_hex exactly
			// — a codec that wired it as tstr would either fail to decode
			// claim_non_utf8_binary_value at all, or would produce a
			// different byte sequence here.
			if claim.ClaimId != c.Claim.ClaimID ||
				claim.UserId != c.Claim.UserID ||
				claim.ClaimType != c.Claim.ClaimType ||
				claim.AttestedAt != c.Claim.AttestedAt ||
				claim.CreatedAt != c.Claim.CreatedAt {
				t.Fatalf("decoded claim scalar fields do not match the case's expanded fields")
			}
			if hex.EncodeToString(claim.ClaimValue) != c.Claim.ClaimValue {
				t.Fatalf("claim_value mismatch: got %x want %s (must be wired as bstr, not tstr)",
					claim.ClaimValue, c.Claim.ClaimValue)
			}
			if !strPtrEqual(claim.ExpiresAt, c.Claim.ExpiresAt) {
				t.Fatalf("expires_at mismatch")
			}
			if !strPtrEqual(claim.RevokedAt, c.Claim.RevokedAt) {
				t.Fatalf("revoked_at mismatch")
			}
			if len(claim.Signatures) != len(c.Claim.Signatures) {
				t.Fatalf("signature count mismatch: got %d want %d", len(claim.Signatures), len(c.Claim.Signatures))
			}
			for i, sig := range c.Claim.Signatures {
				if claim.Signatures[i].Domain != sig.Domain ||
					claim.Signatures[i].SignedByKeyId != sig.SignedByKeyID ||
					hexEncode(claim.Signatures[i].Signature) != sig.SignatureHex {
					t.Fatalf("signature[%d] does not match the case's expanded fields", i)
				}
			}

			// Byte-exact round trip through the generated codec.
			reencoded := api.EncodeClaim(claim)
			if hex.EncodeToString(reencoded) != c.ClaimCborHex {
				t.Fatalf("re-encoded claim does not match claim_cbor_hex byte-exactly")
			}

			// Verify through the SDK's own claim verification path. The
			// signature bytes decoded above were produced by the real Rust
			// implementation, not by this SDK, so this is a genuine
			// cross-implementation check — exactly what catches a
			// self-consistent sign/verify bug like the OCaml SDK's.
			if err := localrp.VerifyClaimSignatures(claim, c.SubjectDomain, defaultKeySets); err != nil {
				t.Fatalf("VerifyClaimSignatures: %v", err)
			}
			if err := localrp.VerifyClaim(claim, c.SubjectDomain, defaultKeySets); err != nil {
				t.Fatalf("VerifyClaim: %v", err)
			}
		})
	}
}

func TestClaimsDecodeNegativeCaseRejectsTstrClaimValue(t *testing.T) {
	var d claimsFile
	loadJSON(t, "claims.json", &d)
	if len(d.DecodeNegativeCases) != 1 {
		t.Fatalf("expected 1 decode negative case, got %d", len(d.DecodeNegativeCases))
	}

	for _, c := range d.DecodeNegativeCases {
		t.Run(c.Name, func(t *testing.T) {
			if c.ExpectedDecodeOk {
				t.Fatalf("case %s should be expected_decode_ok=false", c.Name)
			}
			_, err := api.DecodeClaim(mustHex(t, c.ClaimCborHex))
			if err == nil {
				t.Fatalf("expected decode failure for claim_value encoded as CBOR text (major type 3); a " +
					"strict bstr codec must reject it, not silently accept a tstr claim_value")
			}
		})
	}
}

func TestClaimsVerificationNegativeCasesFail(t *testing.T) {
	var d claimsFile
	loadJSON(t, "claims.json", &d)
	if len(d.NegativeCases) != 4 {
		t.Fatalf("expected 4 verification negative cases, got %d", len(d.NegativeCases))
	}
	defaultKeySets := claimDomainKeySets(t, d.DomainKeys)

	for _, c := range d.NegativeCases {
		t.Run(c.Name, func(t *testing.T) {
			claim, err := api.DecodeClaim(mustHex(t, c.ClaimCborHex))
			if err != nil {
				t.Fatalf("decode claim_cbor_hex: %v", err)
			}

			keySets := defaultKeySets
			if c.DomainKeys != nil {
				keySets = claimDomainKeySets(t, c.DomainKeys)
			}

			err = localrp.VerifyClaimSignatures(claim, c.SubjectDomain, keySets)
			if err == nil {
				t.Fatalf("expected VerifyClaimSignatures failure, got nil")
			}
			var claimErr *localrp.ClaimError
			if !errors.As(err, &claimErr) {
				t.Fatalf("expected *localrp.ClaimError, got %T: %v", err, err)
			}
			if string(claimErr.Kind) != c.ExpectedError {
				t.Errorf("error kind = %s, want %s", claimErr.Kind, c.ExpectedError)
			}

			// VerifyClaim must fail for the same underlying reason (it
			// checks signatures first, before revocation/expiry).
			if err := localrp.VerifyClaim(claim, c.SubjectDomain, keySets); err == nil {
				t.Fatalf("VerifyClaim unexpectedly succeeded")
			}
		})
	}
}

func TestClaimsTicketRedemptionResponseRoundTripAndVerify(t *testing.T) {
	var d claimsFile
	loadJSON(t, "claims.json", &d)
	rr := d.TicketRedemptionResponse

	respBytes := mustHex(t, rr.ResponseCborHex)
	resp, err := api.DecodeLocalRpTicketRedemptionResponse(respBytes)
	if err != nil {
		t.Fatalf("decode ticket_redemption_response: %v", err)
	}
	if resp.UserId != rr.UserID || resp.UserDomain != rr.UserDomain || resp.TicketExpiresAt != rr.TicketExpiresAt {
		t.Fatalf("ticket redemption response scalar fields mismatch: got %+v", resp)
	}
	if len(resp.Claims) != len(d.Cases) {
		t.Fatalf("expected %d claims in ticket_redemption_response, got %d", len(d.Cases), len(resp.Claims))
	}

	// Byte-exact round trip through the generated codec — this is the wire
	// message CompleteLocalLogin actually consumes Claims from.
	reencoded := api.EncodeLocalRpTicketRedemptionResponse(resp)
	if hex.EncodeToString(reencoded) != rr.ResponseCborHex {
		t.Fatalf("re-encoded ticket redemption response does not match response_cbor_hex byte-exactly")
	}

	// claims_ref documents the order: claim_utf8_text_value,
	// claim_non_utf8_binary_value, claim_multiple_signatures — i.e. d.Cases
	// in file order. Each embedded claim must reproduce its standalone
	// case's wire bytes AND verify its signatures through the SDK's own
	// path: decoding without verifying misses the point of this fixture.
	keySets := claimDomainKeySets(t, d.DomainKeys)
	for i, claim := range resp.Claims {
		want := d.Cases[i]
		if hex.EncodeToString(api.EncodeClaim(claim)) != want.ClaimCborHex {
			t.Fatalf("embedded claim[%d] does not round-trip to case %s's claim_cbor_hex", i, want.Name)
		}
		if err := localrp.VerifyClaim(claim, rr.UserDomain, keySets); err != nil {
			t.Fatalf("embedded claim[%d] (%s) failed verification: %v", i, want.Name, err)
		}
	}
}
