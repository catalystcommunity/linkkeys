package regularrp

import (
	"context"
	"errors"
	"fmt"
	"testing"

	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

// verifyClaimsTransport answers Rp/verify-claims with checks from answer.
type verifyClaimsTransport struct {
	answer func(api.RpVerifyClaimsRequest) api.RpVerifyClaimsResponse
	got    *api.RpVerifyClaimsRequest
}

func (f *verifyClaimsTransport) Call(_ context.Context, service, op string, payload []byte) ([]byte, error) {
	if service != "Rp" || op != "verify-claims" {
		return nil, fmt.Errorf("unexpected call %s/%s", service, op)
	}
	req, err := api.DecodeRpVerifyClaimsRequest(payload)
	if err != nil {
		return nil, err
	}
	f.got = &req
	return api.EncodeRpVerifyClaimsResponse(f.answer(req))
}

func (f *verifyClaimsTransport) CallReply(_ context.Context, service, op string, _ []byte) (api.WireReply, error) {
	return api.WireReply{}, fmt.Errorf("unexpected CallReply %s/%s", service, op)
}

func testClaim(id, claimType string) api.Claim {
	return api.Claim{ClaimId: id, ClaimType: claimType, UserId: "user-1", ClaimValue: []byte("v")}
}

func check(c api.Claim, claimStatus api.ClaimCheckStatus, domains ...api.DomainSignatureCheck) api.ClaimCheck {
	verified := claimStatus == api.ClaimCheckStatusValid && len(domains) > 0
	for _, d := range domains {
		verified = verified && d.Status == api.ClaimCheckStatusValid
	}
	return api.ClaimCheck{ClaimId: c.ClaimId, ClaimType: c.ClaimType, ClaimStatus: claimStatus, SigningDomains: domains, Verified: verified}
}

func signedBy(domain string, status api.ClaimCheckStatus) api.DomainSignatureCheck {
	return api.DomainSignatureCheck{Domain: domain, Status: status}
}

// homeValid answers every claim as valid and signed by home.example.
func homeValid(req api.RpVerifyClaimsRequest) api.RpVerifyClaimsResponse {
	var out api.RpVerifyClaimsResponse
	for _, c := range req.Claims {
		out.Checks = append(out.Checks, check(c, api.ClaimCheckStatusValid, signedBy("home.example", api.ClaimCheckStatusValid)))
	}
	return out
}

func TestVerifiedBy(t *testing.T) {
	c := testClaim("c1", "email")
	cases := []struct {
		name  string
		check api.ClaimCheck
		want  bool
	}{
		{"home valid", check(c, api.ClaimCheckStatusValid, signedBy("home.example", api.ClaimCheckStatusValid)), true},
		{"case of domain", check(c, api.ClaimCheckStatusValid, signedBy("Home.Example", api.ClaimCheckStatusValid)), true},
		{"other domain fails too", check(c, api.ClaimCheckStatusValid, signedBy("home.example", api.ClaimCheckStatusValid), signedBy("x.example", api.ClaimCheckStatusBadSignature)), true},
		{"only another domain", check(c, api.ClaimCheckStatusValid, signedBy("x.example", api.ClaimCheckStatusValid)), false},
		{"bad home signature", check(c, api.ClaimCheckStatusValid, signedBy("home.example", api.ClaimCheckStatusBadSignature)), false},
		{"revoked", check(c, api.ClaimCheckStatusRevoked, signedBy("home.example", api.ClaimCheckStatusValid)), false},
		{"wrong subject", check(c, api.ClaimCheckStatusWrongSubject, signedBy("home.example", api.ClaimCheckStatusValid)), false},
	}
	for _, tc := range cases {
		if got := VerifiedBy(tc.check, "home.example"); got != tc.want {
			t.Errorf("%s: VerifiedBy = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestVerifyClaimsSendsTheSubjectAndChecksTheAnswer(t *testing.T) {
	claims := []api.Claim{testClaim("c1", "email"), testClaim("c2", "handle")}
	tr := &verifyClaimsTransport{answer: homeValid}
	checks, err := VerifyClaims(context.Background(), tr, "home.example", "user-1", claims)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 2 || tr.got.SubjectDomain != "home.example" || tr.got.UserId != "user-1" || len(tr.got.Claims) != 2 {
		t.Fatalf("unexpected request %+v or checks %+v", tr.got, checks)
	}

	short := &verifyClaimsTransport{answer: func(req api.RpVerifyClaimsRequest) api.RpVerifyClaimsResponse {
		out := homeValid(req)
		out.Checks = out.Checks[:1]
		return out
	}}
	var pe *ProtocolError
	if _, err := VerifyClaims(context.Background(), short, "home.example", "user-1", claims); !errors.As(err, &pe) {
		t.Fatalf("a short answer must be a ProtocolError, got %v", err)
	}

	swapped := &verifyClaimsTransport{answer: func(req api.RpVerifyClaimsRequest) api.RpVerifyClaimsResponse {
		out := homeValid(req)
		out.Checks[0], out.Checks[1] = out.Checks[1], out.Checks[0]
		return out
	}}
	if _, err := VerifyClaims(context.Background(), swapped, "home.example", "user-1", claims); !errors.As(err, &pe) {
		t.Fatalf("a reordered answer must be a ProtocolError, got %v", err)
	}

	if _, err := VerifyClaims(context.Background(), tr, " ", "user-1", claims); !errors.As(err, &pe) {
		t.Fatalf("an empty subject domain must be refused, got %v", err)
	}
}

func TestRequireClaimsVerifiedBy(t *testing.T) {
	email := testClaim("c-email", "email")
	verified := testClaim("c-verified", "email_verified")
	other := testClaim("c-name", "display_name")
	ctx := context.Background()

	tr := &verifyClaimsTransport{answer: homeValid}
	got, err := RequireClaimsVerifiedBy(ctx, tr, "home.example", "user-1", []api.Claim{other, email, verified}, "email", "email_verified")
	if err != nil {
		t.Fatal(err)
	}
	if got["email"].ClaimId != "c-email" || got["email_verified"].ClaimId != "c-verified" {
		t.Fatalf("unexpected result %+v", got)
	}
	if len(tr.got.Claims) != 2 {
		t.Fatalf("only the required types are sent, got %d claims", len(tr.got.Claims))
	}

	var ce *ClaimCheckError
	_, err = RequireClaimsVerifiedBy(ctx, tr, "home.example", "user-1", []api.Claim{email}, "email", "email_verified")
	if !errors.As(err, &ce) || !ce.Missing || ce.ClaimType != "email_verified" {
		t.Fatalf("a missing type must be a Missing ClaimCheckError, got %v", err)
	}

	foreign := &verifyClaimsTransport{answer: func(req api.RpVerifyClaimsRequest) api.RpVerifyClaimsResponse {
		var out api.RpVerifyClaimsResponse
		for _, c := range req.Claims {
			out.Checks = append(out.Checks, check(c, api.ClaimCheckStatusValid, signedBy("x.example", api.ClaimCheckStatusValid)))
		}
		return out
	}}
	_, err = RequireClaimsVerifiedBy(ctx, foreign, "home.example", "user-1", []api.Claim{email}, "email")
	if !errors.As(err, &ce) || ce.Missing || ce.DomainStatus != 0 {
		t.Fatalf("a claim the home domain did not sign must be refused, got %v", err)
	}

	// One bad and one good claim of the same type: the good one is used.
	second := testClaim("c-email-2", "email")
	mixed := &verifyClaimsTransport{answer: func(req api.RpVerifyClaimsRequest) api.RpVerifyClaimsResponse {
		return api.RpVerifyClaimsResponse{Checks: []api.ClaimCheck{
			check(req.Claims[0], api.ClaimCheckStatusExpired, signedBy("home.example", api.ClaimCheckStatusValid)),
			check(req.Claims[1], api.ClaimCheckStatusValid, signedBy("home.example", api.ClaimCheckStatusValid)),
		}}
	}}
	got, err = RequireClaimsVerifiedBy(ctx, mixed, "home.example", "user-1", []api.Claim{email, second}, "email")
	if err != nil || got["email"].ClaimId != "c-email-2" {
		t.Fatalf("expected the verified claim, got %+v, %v", got, err)
	}

	expired := &verifyClaimsTransport{answer: func(req api.RpVerifyClaimsRequest) api.RpVerifyClaimsResponse {
		return api.RpVerifyClaimsResponse{Checks: []api.ClaimCheck{
			check(req.Claims[0], api.ClaimCheckStatusExpired, signedBy("home.example", api.ClaimCheckStatusValid)),
		}}
	}}
	_, err = RequireClaimsVerifiedBy(ctx, expired, "home.example", "user-1", []api.Claim{email}, "email")
	if !errors.As(err, &ce) || ce.ClaimStatus != api.ClaimCheckStatusExpired {
		t.Fatalf("an expired claim must be refused with its status, got %v", err)
	}
	if msg := err.Error(); msg == "" {
		t.Fatal("empty error text")
	}
}
