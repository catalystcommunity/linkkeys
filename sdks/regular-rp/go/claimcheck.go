package regularrp

import (
	"context"
	"fmt"
	"strings"

	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

// Claim verification through the application's own RP.
//
// The RP server verifies the claims (Rp/verify-claims): it gets the keys of
// each signing domain from DNS-pinned discovery and its cache, applies the
// domain-key revocations, and runs the LinkKeys reference verifier
// (liblinkkeys::claims::check_claim). The application applies only its own
// trust policy to the result, for example "the user's home domain signed
// this claim".
//
// Use the claims of Rp/userinfo-fetch, and the subject of the verified
// assertion (Rp/verify-assertion), never a subject from the claims.

// ClaimCheckError tells why RequireClaimsVerifiedBy refused a required claim
// type. It names the claim type and the signing domain, never the value.
type ClaimCheckError struct {
	ClaimType string
	Domain    string
	// Missing is true when no claim of ClaimType was given.
	Missing bool
	// ClaimStatus is the claim_status of the best claim of ClaimType.
	ClaimStatus api.ClaimCheckStatus
	// DomainStatus is the status of Domain's signatures on that claim.
	// It is zero when Domain did not sign the claim.
	DomainStatus api.ClaimCheckStatus
}

func (e *ClaimCheckError) Error() string {
	if e.Missing {
		return fmt.Sprintf("claim check: no %s claim", e.ClaimType)
	}
	if e.DomainStatus == 0 {
		return fmt.Sprintf("claim check: %s is not signed by %s", e.ClaimType, e.Domain)
	}
	return fmt.Sprintf("claim check: %s is not verified by %s (claim %s, signatures %s)",
		e.ClaimType, e.Domain, statusText(e.ClaimStatus), statusText(e.DomainStatus))
}

func statusText(s api.ClaimCheckStatus) string {
	text, err := s.MarshalText()
	if err != nil {
		return fmt.Sprintf("status %d", s)
	}
	return string(text)
}

// VerifyClaims asks the application's own RP to verify claims about
// userID@subjectDomain (Rp/verify-claims). It returns one ClaimCheck for each
// claim, in the same order. It refuses an answer that does not match the
// request.
//
// A claim is verified by a domain when VerifiedBy is true for that domain.
// ClaimCheck.Verified is the stricter full check: every signing domain
// verified.
func VerifyClaims(ctx context.Context, transport api.Transport, subjectDomain, userID string, claims []api.Claim) ([]api.ClaimCheck, error) {
	if strings.TrimSpace(subjectDomain) == "" {
		return nil, &ProtocolError{Detail: "subject domain must not be empty"}
	}
	if strings.TrimSpace(userID) == "" {
		return nil, &ProtocolError{Detail: "user id must not be empty"}
	}
	resp, err := api.NewRpClient(transport).VerifyClaims(ctx, api.RpVerifyClaimsRequest{
		SubjectDomain: subjectDomain,
		UserId:        userID,
		Claims:        claims,
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Checks) != len(claims) {
		return nil, &ProtocolError{Detail: fmt.Sprintf("verify-claims returned %d checks for %d claims", len(resp.Checks), len(claims))}
	}
	for i, check := range resp.Checks {
		if check.ClaimId != claims[i].ClaimId || check.ClaimType != claims[i].ClaimType {
			return nil, &ProtocolError{Detail: fmt.Sprintf("verify-claims check %d names another claim", i)}
		}
	}
	return resp.Checks, nil
}

// VerifiedBy reports whether check shows a current claim that domain
// signed: the claim_status is valid and domain's signatures are valid. The
// signatures of other domains do not change the result. The domain
// comparison ignores ASCII case.
func VerifiedBy(check api.ClaimCheck, domain string) bool {
	if check.ClaimStatus != api.ClaimCheckStatusValid {
		return false
	}
	for _, d := range check.SigningDomains {
		if asciiEqualFold(d.Domain, domain) && d.Status == api.ClaimCheckStatusValid {
			return true
		}
	}
	return false
}

// RequireClaimsVerifiedBy verifies the claims of claimTypes through the RP
// and returns, for each type, a claim that domain verified (VerifiedBy).
// Claims of other types are not sent. It fails with a *ClaimCheckError for
// the first type that has no such claim.
//
// To require an email address that the user's home domain confirmed, pass
// the assertion's domain as domain, and the types "email" and
// "email_verified". Then check that the email_verified value is "true".
// The LinkKeys reference server signs both claims only after the user opens
// the confirmation link it sent to the address.
func RequireClaimsVerifiedBy(ctx context.Context, transport api.Transport, domain, userID string, claims []api.Claim, claimTypes ...string) (map[string]api.Claim, error) {
	if len(claimTypes) == 0 {
		return nil, &ProtocolError{Detail: "no claim types to require"}
	}
	wanted := make(map[string]bool, len(claimTypes))
	for _, t := range claimTypes {
		wanted[t] = true
	}
	var send []api.Claim
	for _, c := range claims {
		if wanted[c.ClaimType] {
			send = append(send, c)
		}
	}
	for _, t := range claimTypes {
		if !hasClaimType(send, t) {
			return nil, &ClaimCheckError{ClaimType: t, Domain: domain, Missing: true}
		}
	}
	checks, err := VerifyClaims(ctx, transport, domain, userID, send)
	if err != nil {
		return nil, err
	}

	out := make(map[string]api.Claim, len(claimTypes))
	for _, t := range claimTypes {
		var refusal *ClaimCheckError
		for i, check := range checks {
			if check.ClaimType != t {
				continue
			}
			if VerifiedBy(check, domain) {
				out[t] = send[i]
				refusal = nil
				break
			}
			if refusal == nil {
				refusal = &ClaimCheckError{ClaimType: t, Domain: domain, ClaimStatus: check.ClaimStatus, DomainStatus: domainStatus(check, domain)}
			}
		}
		if refusal != nil {
			return nil, refusal
		}
	}
	return out, nil
}

func hasClaimType(claims []api.Claim, claimType string) bool {
	for _, c := range claims {
		if c.ClaimType == claimType {
			return true
		}
	}
	return false
}

func domainStatus(check api.ClaimCheck, domain string) api.ClaimCheckStatus {
	for _, d := range check.SigningDomains {
		if asciiEqualFold(d.Domain, domain) {
			return d.Status
		}
	}
	return 0
}
