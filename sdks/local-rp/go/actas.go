package localrp

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/url"
	"strings"
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

// Act-as grants, grantee side (docs/spec/reserved/act-as-grants.md). A user
// lets this local RP (the grantee) act as the user at an enrolled
// application (the audience). A local RP can never be an audience: a peer
// cannot resolve its keys through DNS. This file implements the grantee
// steps only:
//
//  1. BeginActAs signs an ActAsGrantRequest and returns the browser redirect
//     to the user's home domain (`/auth/act-as`).
//  2. CompleteActAsCallback reads the grant id from the callback and checks
//     the nonce.
//  3. RefreshActAsGrant fetches (or renews) the grant over the pinned TCP
//     CSIL-RPC path (`ActAs/refresh-grant`).
//  4. PresentActAs signs one presentation for one call to the audience.
//
// The grantee key is the descriptor signing key. Every proof carries the
// signed descriptor, so the verifier can check the key. Mirrors
// crates/liblinkkeys/src/act_as.rs (GranteeSigner::LocalRp).

// Domain-separation tags for the grantee's act-as signatures.
const (
	CtxActAsGrantRequest   = "linkkeys-act-as-grant-request-v1alpha"
	CtxActAsRefreshRequest = "linkkeys-act-as-refresh-request-v1alpha"
	CtxActAsPresentation   = "linkkeys-act-as-presentation-v1alpha"
)

// BrowserRouteActAs is the home domain's browser route for an act-as grant
// request.
const BrowserRouteActAs = "/auth/act-as"

// DefaultActAsRequestWindow is the default validity window of a grant
// request, from Now.
const DefaultActAsRequestWindow = 300 * time.Second

// MaxActAsRequestWindow is the longest grant-request window this SDK sends.
// The reference home domain refuses windows longer than this.
const MaxActAsRequestWindow = 900 * time.Second

// ActAsRefreshRequestWindow is the validity window of a refresh request.
const ActAsRefreshRequestWindow = 300 * time.Second

// formatActAsTime is whole-second RFC3339 in UTC ending in Z, the same form
// liblinkkeys::act_as::format_time produces.
func formatActAsTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// localRpGrantee is the GranteeRef that names this local RP.
func localRpGrantee(km *LocalRpKeyMaterial) api.GranteeRef {
	fp := km.Fingerprint
	return api.GranteeRef{LocalRpDescriptorFingerprint: &fp}
}

// proveActAs signs CBOR([tag, payload]) with the descriptor signing key and
// wraps the signature in a local-RP GranteeProof.
func proveActAs(km *LocalRpKeyMaterial, tag string, payload []byte) api.GranteeProof {
	descriptor := km.Descriptor
	return api.GranteeProof{
		LocalRpDescriptor: &descriptor,
		Signature: api.ApplicationKeySignature{
			SignedByKeyId: km.Fingerprint,
			Signature:     signEd25519(km.SigningPrivateKey, EnvelopeSignatureInput(tag, payload)),
		},
	}
}

func checkKeyMaterial(km *LocalRpKeyMaterial) error {
	if km == nil || km.Fingerprint == "" {
		return &InvalidInputError{Detail: "act-as needs key material with a descriptor fingerprint"}
	}
	return nil
}

// SignActAsGrantRequest encodes request with the CSIL codec and signs it with
// the descriptor signing key under CtxActAsGrantRequest. The caller sets
// request.Grantee to this local RP (BeginActAs does).
func SignActAsGrantRequest(request api.ActAsGrantRequest, km *LocalRpKeyMaterial) (api.SignedActAsGrantRequest, error) {
	if err := checkKeyMaterial(km); err != nil {
		return api.SignedActAsGrantRequest{}, err
	}
	bytes := api.EncodeActAsGrantRequest(request)
	return api.SignedActAsGrantRequest{Request: bytes, Proof: proveActAs(km, CtxActAsGrantRequest, bytes)}, nil
}

// SignActAsRefreshRequest encodes request with the CSIL codec and signs it
// with the descriptor signing key under CtxActAsRefreshRequest.
func SignActAsRefreshRequest(request api.ActAsRefreshRequest, km *LocalRpKeyMaterial) (api.SignedActAsRefreshRequest, error) {
	if err := checkKeyMaterial(km); err != nil {
		return api.SignedActAsRefreshRequest{}, err
	}
	bytes := api.EncodeActAsRefreshRequest(request)
	return api.SignedActAsRefreshRequest{Request: bytes, Proof: proveActAs(km, CtxActAsRefreshRequest, bytes)}, nil
}

// SignedActAsGrantRequestToURLParam encodes a signed grant request for the
// `/auth/act-as?signed_request=<...>` query parameter (unpadded base64url
// of its CBOR).
func SignedActAsGrantRequestToURLParam(signed api.SignedActAsGrantRequest) string {
	return encodeURLParam(api.EncodeSignedActAsGrantRequest(signed))
}

// freshActAsNonce is 32 random bytes, unpadded base64url.
func freshActAsNonce() (string, error) {
	b := make([]byte, 32)
	if err := randomBytes(b); err != nil {
		return "", err
	}
	return encodeURLParam(b), nil
}

// BeginActAsConfig is the input to BeginActAs.
type BeginActAsConfig struct {
	// KeyMaterial is this local RP's identity. The home domain must already
	// have approved it.
	KeyMaterial *LocalRpKeyMaterial
	// UserDomain is the LinkKeys login or domain the user entered, parsed
	// like BeginLocalLoginConfig.UserDomain. Only the domain is used.
	UserDomain string
	// ScopeSet is the CBOR of the SignedActAsScopeSet exactly as the
	// audience sent it. It is embedded unchanged.
	ScopeSet []byte
	// RequestedLifetimeSeconds is optional. When set, it must be positive.
	RequestedLifetimeSeconds *int64
	// RequestedRenewalWindowSeconds is optional. When set, it must not be
	// negative.
	RequestedRenewalWindowSeconds *int64
	// CallbackURL is where the home domain sends the browser back with
	// `act_as_grant_id` and `nonce`. Must be http:// or https://.
	CallbackURL string
	Now         time.Time
	// DNS is the DNS TXT lookup seam for browser endpoint discovery.
	// Defaults to DefaultDNSResolver() when nil.
	DNS DnsResolver
	// RequestWindow is the grant request's validity window from Now.
	// Defaults to DefaultActAsRequestWindow when zero. At most
	// MaxActAsRequestWindow.
	RequestWindow time.Duration
}

// ActAsRedirect is the URL the app sends the user's browser to.
type ActAsRedirect struct {
	RedirectURL string
}

// PendingActAs is the state the app persists between BeginActAs and
// CompleteActAsCallback. Treat it as single-use.
type PendingActAs struct {
	Nonce       string `json:"nonce"`
	UserDomain  string `json:"user_domain"`
	CallbackURL string `json:"callback_url"`
}

// BeginActAs builds and signs an ActAsGrantRequest that names this local RP
// as the grantee, and returns the browser redirect to the user's home
// domain plus the pending state. The redirect host comes from
// `_linkkeys_apis.<domain>` discovery, with the same fallback to
// `https://<domain>` as BeginLocalLogin.
func BeginActAs(config BeginActAsConfig) (*ActAsRedirect, *PendingActAs, error) {
	if err := checkKeyMaterial(config.KeyMaterial); err != nil {
		return nil, nil, err
	}
	if err := validateCallbackScheme(config.CallbackURL); err != nil {
		return nil, nil, err
	}
	identity, err := parseIdentityInput(config.UserDomain)
	if err != nil {
		return nil, nil, err
	}
	window := config.RequestWindow
	if window == 0 {
		window = DefaultActAsRequestWindow
	}
	if window < 0 || window > MaxActAsRequestWindow {
		return nil, nil, &InvalidInputError{Detail: fmt.Sprintf("act-as request window must be between 1s and %s", MaxActAsRequestWindow)}
	}
	if v := config.RequestedLifetimeSeconds; v != nil && *v <= 0 {
		return nil, nil, &InvalidInputError{Detail: "requested lifetime must be positive"}
	}
	if v := config.RequestedRenewalWindowSeconds; v != nil && *v < 0 {
		return nil, nil, &InvalidInputError{Detail: "requested renewal window must not be negative"}
	}
	scopeSet, err := api.DecodeSignedActAsScopeSet(config.ScopeSet)
	if err != nil {
		return nil, nil, &DecodeError{Detail: "signed act-as scope set: " + err.Error()}
	}
	nonce, err := freshActAsNonce()
	if err != nil {
		return nil, nil, err
	}

	request := api.ActAsGrantRequest{
		Grantee:                       localRpGrantee(config.KeyMaterial),
		ScopeSet:                      scopeSet,
		RequestedLifetimeSeconds:      config.RequestedLifetimeSeconds,
		RequestedRenewalWindowSeconds: config.RequestedRenewalWindowSeconds,
		CallbackUrl:                   config.CallbackURL,
		Nonce:                         nonce,
		RequestedAt:                   formatActAsTime(config.Now),
		ExpiresAt:                     formatActAsTime(config.Now.Add(window)),
	}
	signed, err := SignActAsGrantRequest(request, config.KeyMaterial)
	if err != nil {
		return nil, nil, err
	}

	dns := config.DNS
	if dns == nil {
		dns = DefaultDNSResolver()
	}
	redirectURL, err := resolveBrowserEndpoint(dns, identity.domain, BrowserRouteActAs, SignedActAsGrantRequestToURLParam(signed))
	if err != nil {
		return nil, nil, err
	}
	return &ActAsRedirect{RedirectURL: redirectURL}, &PendingActAs{
		Nonce:       nonce,
		UserDomain:  identity.domain,
		CallbackURL: config.CallbackURL,
	}, nil
}

// CompleteActAsCallback reads `act_as_grant_id` and `nonce` from the
// callback (a full URL or a bare query string) and returns the grant id.
// The nonce must equal pending.Nonce (constant-time compare). The grant
// itself does not travel through the browser: fetch it with
// RefreshActAsGrant.
func CompleteActAsCallback(pending *PendingActAs, callback string) (string, error) {
	if pending == nil || pending.Nonce == "" {
		return "", &InvalidInputError{Detail: "pending act-as state is missing"}
	}
	rawQuery := callback
	if i := strings.IndexByte(callback, '?'); i >= 0 {
		u, err := url.Parse(callback)
		if err != nil {
			return "", &InvalidInputError{Detail: "act-as callback URL does not parse"}
		}
		rawQuery = u.RawQuery
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", &InvalidInputError{Detail: "act-as callback query does not parse"}
	}
	// A repeated parameter is ambiguous: refuse it rather than pick one.
	if len(query["act_as_grant_id"]) > 1 || len(query["nonce"]) > 1 {
		return "", &InvalidInputError{Detail: "act-as callback repeats a parameter"}
	}
	grantID := query.Get("act_as_grant_id")
	nonce := query.Get("nonce")
	if grantID == "" || nonce == "" {
		return "", &InvalidInputError{Detail: "act-as callback needs act_as_grant_id and nonce"}
	}
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(pending.Nonce)) != 1 {
		return "", &LocalRpError{Kind: ErrKindNonceMismatch, Detail: "act-as callback nonce does not match the pending request"}
	}
	return grantID, nil
}

// RefreshActAsGrantConfig is the input to RefreshActAsGrant.
type RefreshActAsGrantConfig struct {
	KeyMaterial *LocalRpKeyMaterial
	// UserDomain is the user's home domain (PendingActAs.UserDomain).
	UserDomain string
	GrantID    string
	Now        time.Time
	// Transport is the TCP dial seam. Defaults to DefaultTransport() when
	// nil.
	Transport Transport
	// DNS is the DNS TXT lookup seam. Defaults to DefaultDNSResolver() when
	// nil.
	DNS DnsResolver
}

// RefreshActAsGrant signs an ActAsRefreshRequest and calls
// `ActAs/refresh-grant` on the user's home domain over the same DNS-pinned
// TCP CSIL-RPC path as RedeemClaimTicket. It returns the current grant and
// whether the home domain signed it during this call. The same call fetches
// a new grant and renews a current one.
func RefreshActAsGrant(config RefreshActAsGrantConfig) (*api.SignedActAsGrant, bool, error) {
	if err := checkKeyMaterial(config.KeyMaterial); err != nil {
		return nil, false, err
	}
	if config.GrantID == "" {
		return nil, false, &InvalidInputError{Detail: "grant id is required"}
	}
	identity, err := parseIdentityInput(config.UserDomain)
	if err != nil {
		return nil, false, err
	}
	nonce, err := freshActAsNonce()
	if err != nil {
		return nil, false, err
	}
	signed, err := SignActAsRefreshRequest(api.ActAsRefreshRequest{
		GrantId:     config.GrantID,
		Grantee:     localRpGrantee(config.KeyMaterial),
		RequestedAt: formatActAsTime(config.Now),
		ExpiresAt:   formatActAsTime(config.Now.Add(ActAsRefreshRequestWindow)),
		Nonce:       nonce,
	}, config.KeyMaterial)
	if err != nil {
		return nil, false, err
	}

	tr := config.Transport
	if tr == nil {
		tr = DefaultTransport()
	}
	dns := config.DNS
	if dns == nil {
		dns = DefaultDNSResolver()
	}
	endpoint, err := DiscoverDomainEndpoint(dns, identity.domain)
	if err != nil {
		return nil, false, err
	}
	payload := api.EncodeRefreshActAsGrantRequest(api.RefreshActAsGrantRequest{Request: signed})
	respBytes, err := call(tr, endpoint, "ActAs", "refresh-grant", payload)
	if err != nil {
		return nil, false, err
	}
	resp, err := api.DecodeRefreshActAsGrantResponse(respBytes)
	if err != nil {
		return nil, false, &DecodeError{Detail: "refresh-grant response: " + err.Error()}
	}
	// The audience verifies the grant signature. This only checks that the
	// home domain returned the grant this call asked for, so a confused or
	// hostile server cannot hand this grantee another grant.
	grant, err := api.DecodeActAsGrant(resp.Grant.Grant)
	if err != nil {
		return nil, false, &DecodeError{Detail: "refresh-grant grant: " + err.Error()}
	}
	if grant.GrantId != config.GrantID {
		return nil, false, &ProtocolError{Detail: "refresh-grant returned another grant id"}
	}
	if grant.Grantee.Application != nil || grant.Grantee.LocalRpDescriptorFingerprint == nil ||
		*grant.Grantee.LocalRpDescriptorFingerprint != config.KeyMaterial.Fingerprint {
		return nil, false, &ProtocolError{Detail: "refresh-grant returned a grant for another grantee"}
	}
	if !asciiEqualFold(grant.SubjectDomain, identity.domain) {
		return nil, false, &ProtocolError{Detail: "refresh-grant returned a grant from another subject domain"}
	}
	return &resp.Grant, resp.Signed, nil
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

// ActAsGrantHash is SHA-256 of a grant's signed bytes (SignedActAsGrant.Grant).
func ActAsGrantHash(grantBytes []byte) []byte {
	sum := sha256.Sum256(grantBytes)
	return sum[:]
}

// PresentActAs signs one presentation for one call to the audience and
// returns the credential plus its CBOR. requestDigest is defined by the
// audience's application protocol. nonce must be fresh for each call: the
// audience owns replay protection.
func PresentActAs(grant api.SignedActAsGrant, audience api.ApplicationRef, requestDigest []byte, now time.Time, nonce []byte, km *LocalRpKeyMaterial) (*api.ActAsCredential, []byte, error) {
	if err := checkKeyMaterial(km); err != nil {
		return nil, nil, err
	}
	presentation := api.EncodeActAsPresentation(api.ActAsPresentation{
		GrantHash:     ActAsGrantHash(grant.Grant),
		Audience:      audience,
		RequestDigest: append([]byte{}, requestDigest...),
		PresentedAt:   formatActAsTime(now),
		Nonce:         append([]byte{}, nonce...),
	})
	credential := api.ActAsCredential{
		Grant: grant,
		Presentation: api.SignedActAsPresentation{
			Presentation: presentation,
			Proof:        proveActAs(km, CtxActAsPresentation, presentation),
		},
	}
	return &credential, api.EncodeActAsCredential(credential), nil
}
