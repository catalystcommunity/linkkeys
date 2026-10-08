package regularrp

import (
	"context"
	"encoding/base64"
	"net"
	"net/url"
	"strings"

	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

// The network half of act-as grants. Like CachedResolver, an application
// talks only to its OWN RP (API-key authenticated, typically through
// PinnedRpcTransport). The RP forwards each call to the user's home domain
// over pinned TCP:
//
//   - Rp/act-as-refresh-grant fetches a new grant, or renews a current one,
//     for the grantee (RefreshGrant).
//   - Rp/resolve-act-as-revocations fetches signed grant revocations for the
//     audience (ResolveGrantRevocations). This SDK verifies them itself,
//     against the home domain's keys from Rp/resolve-domain-keys, before it
//     returns them.
//
// The browser step of a grant request does not go through the RP. The
// grantee sends the user's browser to the home domain (GrantRequestURL).

// RefreshedGrant is the result of RefreshGrant.
type RefreshedGrant struct {
	// Grant is the signed grant, as the home domain returned it. Present
	// it with Present.
	Grant api.SignedActAsGrant
	// Decoded is the decoded grant. It is NOT signature-verified: the
	// audience verifies it. Use it to read ExpiresAt and RenewableUntil.
	Decoded api.ActAsGrant
	// Signed is true when the home domain signed a new grant for this
	// call, and false when it returned the stored grant bytes.
	Signed bool
}

// RefreshGrant sends a signed refresh request (SignRefreshRequest) to the
// user's home domain through the application's own RP
// (Rp/act-as-refresh-grant). subjectDomain is the user's home domain. The
// same call fetches a new grant after the user approves it, and renews a
// current grant.
//
// A refresh that cannot renew yet is not an error: the home domain returns
// the stored grant, and Signed is false. A refresh of an expired grant
// fails; ask the user again.
//
// RefreshGrant checks that the returned grant decodes and names the
// requested grant_id, the requested grantee, and subjectDomain. It does not
// verify the grant signature. The audience does that.
func RefreshGrant(ctx context.Context, transport api.Transport, subjectDomain string, request api.SignedActAsRefreshRequest) (RefreshedGrant, error) {
	if strings.TrimSpace(subjectDomain) == "" {
		return RefreshedGrant{}, &ProtocolError{Detail: "subject domain must not be empty"}
	}
	sent, err := api.DecodeActAsRefreshRequest(request.Request)
	if err != nil {
		return RefreshedGrant{}, actAsErr(ErrActAsDecode, err.Error())
	}
	resp, err := api.NewRpClient(transport).ActAsRefreshGrant(ctx, api.RpActAsRefreshRequest{
		SubjectDomain: subjectDomain,
		Request:       request,
	})
	if err != nil {
		return RefreshedGrant{}, err
	}
	grant, err := DecodeGrant(resp.Grant)
	if err != nil {
		return RefreshedGrant{}, err
	}
	if grant.GrantId != sent.GrantId {
		return RefreshedGrant{}, actAsMismatch("grant_id")
	}
	if !SameGrantee(grant.Grantee, sent.Grantee) {
		return RefreshedGrant{}, actAsMismatch("grantee")
	}
	if !asciiEqualFold(grant.SubjectDomain, subjectDomain) {
		return RefreshedGrant{}, actAsMismatch("subject_domain")
	}
	return RefreshedGrant{Grant: resp.Grant, Decoded: grant, Signed: resp.Signed}, nil
}

// ResolveGrantRevocations asks the application's own RP for the signed
// revocations of grantIDs from subjectDomain
// (Rp/resolve-act-as-revocations). Pass the grant's subject_domain exactly.
// grantIDs must hold 1 to MaxRevocationLookupIDs ids.
//
// It returns only revocations that verify against subjectDomain's signing
// keys and that name a requested grant id. It gets those keys through the
// same RP (Rp/resolve-domain-keys) and applies the domain-key revocations
// that come with them. It drops every other record.
//
// The audience decides how fresh its revocation data must be, and so how
// often to call this. Put the grant ids of the result in
// AudienceContext.RevokedGrantIDs.
func ResolveGrantRevocations(ctx context.Context, transport api.Transport, subjectDomain string, grantIDs []string) ([]api.ActAsGrantRevocation, error) {
	if strings.TrimSpace(subjectDomain) == "" {
		return nil, &ProtocolError{Detail: "subject domain must not be empty"}
	}
	if len(grantIDs) == 0 || len(grantIDs) > MaxRevocationLookupIDs {
		return nil, &ProtocolError{Detail: "ask for between 1 and 100 grant ids"}
	}
	client := api.NewRpClient(transport)
	resp, err := client.ResolveActAsRevocations(ctx, api.RpResolveActAsRevocationsRequest{
		SubjectDomain: subjectDomain,
		GrantIds:      grantIDs,
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Revocations) == 0 {
		return nil, nil
	}

	keys, err := client.ResolveDomainKeys(ctx, api.RpResolveDomainKeysRequest{Domain: subjectDomain})
	if err != nil {
		return nil, err
	}
	if !asciiEqualFold(keys.Domain, subjectDomain) {
		return nil, &ProtocolError{Detail: "RP domain-key response names another domain"}
	}
	domainKeys := applyDomainKeyRevocations(keys.Keys, keys.Revocations, subjectDomain)

	requested := make(map[string]bool, len(grantIDs))
	for _, id := range grantIDs {
		requested[id] = true
	}
	var out []api.ActAsGrantRevocation
	seen := make(map[string]bool)
	for _, signed := range resp.Revocations {
		rev, err := VerifyGrantRevocation(signed, domainKeys, subjectDomain)
		if err != nil || !requested[rev.GrantId] || seen[rev.GrantId] {
			continue
		}
		seen[rev.GrantId] = true
		out = append(out, rev)
	}
	return out, nil
}

// GrantRequestURL builds the browser URL of a grant request:
// <browserBase>/auth/act-as?signed_request=<base64url(CBOR(signed))>, with no
// base64 padding. browserBase is the home domain's browser base URL, for
// example "https://home.example". A path prefix in browserBase is kept.
//
// This SDK has no browser-endpoint discovery, so the caller supplies
// browserBase. browserBase must use https, except for a loopback host, which
// may use http for local tests.
func GrantRequestURL(browserBase string, signed api.SignedActAsGrantRequest) (string, error) {
	u, err := url.Parse(browserBase)
	if err != nil {
		return "", &ProtocolError{Detail: "browser base is not a URL: " + err.Error()}
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", &ProtocolError{Detail: "browser base must be an absolute URL with a host and no credentials, query, or fragment"}
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return "", &ProtocolError{Detail: "browser base must use https"}
		}
	default:
		return "", &ProtocolError{Detail: "browser base must use https"}
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/auth/act-as"
	u.RawPath = ""
	u.RawQuery = url.Values{
		"signed_request": {base64.RawURLEncoding.EncodeToString(api.EncodeSignedActAsGrantRequest(signed))},
	}.Encode()
	return u.String(), nil
}

// asciiEqualFold compares two domains with ASCII-only case folding.
// strings.EqualFold also folds Unicode (for example U+212A KELVIN SIGN
// equals "k"), which must not make a non-ASCII domain match.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func isLoopbackHost(host string) bool {
	if asciiEqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
