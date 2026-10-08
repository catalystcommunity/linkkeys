package localrp_test

// Act-as grantee tests. The signing test consumes the local_rp_grantee case
// of sdks/regular-rp/conformance/act_as_grantee_signing.json (the same file
// crates/liblinkkeys/tests/act_as_conformance.rs checks). Every other test
// is hermetic: fake DNS answers, and a loopback fake IDP for refresh.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	rpctransport "github.com/catalystcommunity/csilgen/transports/go"
	localrp "github.com/catalystcommunity/linkkeys/sdks/local-rp/go"
	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

type actAsAppRef struct {
	SubjectUserID string `json:"subject_user_id"`
	SubjectDomain string `json:"subject_domain"`
	ApplicationID string `json:"application_id"`
}

type actAsVectors struct {
	LocalRpGrantee struct {
		Fingerprint             string `json:"fingerprint"`
		SignedDescriptorCborHex string `json:"signed_descriptor_cbor_hex"`
		SigningPrivateKeyHex    string `json:"signing_private_key_hex"`
	} `json:"local_rp_grantee"`
	Cases []struct {
		Name    string `json:"name"`
		Grantee struct {
			LocalRpDescriptorFingerprint *string `json:"local_rp_descriptor_fingerprint"`
		} `json:"grantee"`
		GrantRequest struct {
			Inputs struct {
				CallbackURL                   string `json:"callback_url"`
				ExpiresAt                     string `json:"expires_at"`
				Nonce                         string `json:"nonce"`
				RequestedAt                   string `json:"requested_at"`
				RequestedLifetimeSeconds      *int64 `json:"requested_lifetime_seconds"`
				RequestedRenewalWindowSeconds *int64 `json:"requested_renewal_window_seconds"`
				ScopeSetSignedCborHex         string `json:"scope_set_signed_cbor_hex"`
			} `json:"inputs"`
			RequestCborHex string `json:"request_cbor_hex"`
			SignedCborHex  string `json:"signed_cbor_hex"`
			URLParam       string `json:"url_param"`
		} `json:"grant_request"`
		RefreshRequest struct {
			Inputs struct {
				ExpiresAt   string `json:"expires_at"`
				GrantID     string `json:"grant_id"`
				Nonce       string `json:"nonce"`
				RequestedAt string `json:"requested_at"`
			} `json:"inputs"`
			RequestCborHex string `json:"request_cbor_hex"`
			SignedCborHex  string `json:"signed_cbor_hex"`
		} `json:"refresh_request"`
		Presentation struct {
			Inputs struct {
				Audience           actAsAppRef `json:"audience"`
				GrantSignedCborHex string      `json:"grant_signed_cbor_hex"`
				NonceHex           string      `json:"nonce_hex"`
				PresentedAt        string      `json:"presented_at"`
				RequestDigestHex   string      `json:"request_digest_hex"`
			} `json:"inputs"`
			CredentialCborHex   string `json:"credential_cbor_hex"`
			GrantHashHex        string `json:"grant_hash_hex"`
			PresentationCborHex string `json:"presentation_cbor_hex"`
		} `json:"presentation"`
	} `json:"cases"`
}

func loadActAsVectors(t *testing.T) actAsVectors {
	t.Helper()
	path := filepath.Join("..", "..", "regular-rp", "conformance", "act_as_grantee_signing.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v actAsVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return v
}

// vectorKeyMaterial is the local RP the vectors sign with. Only the signing
// key, descriptor, and fingerprint matter for act-as.
func vectorKeyMaterial(t *testing.T, v actAsVectors) *localrp.LocalRpKeyMaterial {
	t.Helper()
	seed := mustHex32(t, v.LocalRpGrantee.SigningPrivateKeyHex)
	descriptor, err := api.DecodeSignedLocalRpDescriptor(mustHex(t, v.LocalRpGrantee.SignedDescriptorCborHex))
	if err != nil {
		t.Fatalf("decode vector descriptor: %v", err)
	}
	var pub [32]byte
	copy(pub[:], ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))
	if got := localrp.Fingerprint(pub[:]); got != v.LocalRpGrantee.Fingerprint {
		t.Fatalf("vector signing key fingerprint %s, want %s", got, v.LocalRpGrantee.Fingerprint)
	}
	return &localrp.LocalRpKeyMaterial{
		SigningPrivateKey: seed,
		SigningPublicKey:  pub,
		Descriptor:        descriptor,
		Fingerprint:       v.LocalRpGrantee.Fingerprint,
	}
}

func TestActAsGranteeSigningVectorsLocalRp(t *testing.T) {
	v := loadActAsVectors(t)
	km := vectorKeyMaterial(t, v)
	found := false
	for _, c := range v.Cases {
		if c.Name != "local_rp_grantee" {
			continue
		}
		found = true
		if c.Grantee.LocalRpDescriptorFingerprint == nil || *c.Grantee.LocalRpDescriptorFingerprint != km.Fingerprint {
			t.Fatalf("vector grantee does not name the local RP fingerprint")
		}
		grantee := api.GranteeRef{LocalRpDescriptorFingerprint: &km.Fingerprint}

		g := c.GrantRequest
		scopeSet, err := api.DecodeSignedActAsScopeSet(mustHex(t, g.Inputs.ScopeSetSignedCborHex))
		if err != nil {
			t.Fatalf("decode scope set: %v", err)
		}
		signed, err := localrp.SignActAsGrantRequest(api.ActAsGrantRequest{
			Grantee:                       grantee,
			ScopeSet:                      scopeSet,
			RequestedLifetimeSeconds:      g.Inputs.RequestedLifetimeSeconds,
			RequestedRenewalWindowSeconds: g.Inputs.RequestedRenewalWindowSeconds,
			CallbackUrl:                   g.Inputs.CallbackURL,
			Nonce:                         g.Inputs.Nonce,
			RequestedAt:                   g.Inputs.RequestedAt,
			ExpiresAt:                     g.Inputs.ExpiresAt,
		}, km)
		if err != nil {
			t.Fatalf("SignActAsGrantRequest: %v", err)
		}
		if !bytes.Equal(signed.Request, mustHex(t, g.RequestCborHex)) {
			t.Errorf("grant request bytes differ")
		}
		if !bytes.Equal(api.EncodeSignedActAsGrantRequest(signed), mustHex(t, g.SignedCborHex)) {
			t.Errorf("signed grant request bytes differ")
		}
		if got := localrp.SignedActAsGrantRequestToURLParam(signed); got != g.URLParam {
			t.Errorf("url_param differs")
		}

		r := c.RefreshRequest
		refresh, err := localrp.SignActAsRefreshRequest(api.ActAsRefreshRequest{
			GrantId:     r.Inputs.GrantID,
			Grantee:     grantee,
			RequestedAt: r.Inputs.RequestedAt,
			ExpiresAt:   r.Inputs.ExpiresAt,
			Nonce:       r.Inputs.Nonce,
		}, km)
		if err != nil {
			t.Fatalf("SignActAsRefreshRequest: %v", err)
		}
		if !bytes.Equal(refresh.Request, mustHex(t, r.RequestCborHex)) {
			t.Errorf("refresh request bytes differ")
		}
		if !bytes.Equal(api.EncodeSignedActAsRefreshRequest(refresh), mustHex(t, r.SignedCborHex)) {
			t.Errorf("signed refresh request bytes differ")
		}

		p := c.Presentation
		grant, err := api.DecodeSignedActAsGrant(mustHex(t, p.Inputs.GrantSignedCborHex))
		if err != nil {
			t.Fatalf("decode grant: %v", err)
		}
		if !bytes.Equal(localrp.ActAsGrantHash(grant.Grant), mustHex(t, p.GrantHashHex)) {
			t.Errorf("grant hash differs")
		}
		presentedAt := parseRFC3339(t, p.Inputs.PresentedAt)
		credential, credentialBytes, err := localrp.PresentActAs(grant, api.ApplicationRef{
			SubjectUserId: p.Inputs.Audience.SubjectUserID,
			SubjectDomain: p.Inputs.Audience.SubjectDomain,
			ApplicationId: p.Inputs.Audience.ApplicationID,
		}, mustHex(t, p.Inputs.RequestDigestHex), presentedAt, mustHex(t, p.Inputs.NonceHex), km)
		if err != nil {
			t.Fatalf("PresentActAs: %v", err)
		}
		if !bytes.Equal(credential.Presentation.Presentation, mustHex(t, p.PresentationCborHex)) {
			t.Errorf("presentation bytes differ")
		}
		if !bytes.Equal(credentialBytes, mustHex(t, p.CredentialCborHex)) {
			t.Errorf("credential bytes differ")
		}
	}
	if !found {
		t.Fatal("vector file has no local_rp_grantee case")
	}
}

// verifyLocalRpProof checks that the proof carries km's descriptor and that
// the descriptor key signed CBOR([tag, payload]).
func verifyLocalRpProof(t *testing.T, now time.Time, km *localrp.LocalRpKeyMaterial, proof api.GranteeProof, tag string, payload []byte) {
	t.Helper()
	if proof.ApplicationInstanceId != nil || proof.LocalRpDescriptor == nil {
		t.Fatal("proof is not in the local-RP form")
	}
	descriptor, err := localrp.VerifyLocalRpDescriptor(*proof.LocalRpDescriptor, now, localrp.DefaultClockSkewSeconds)
	if err != nil {
		t.Fatalf("proof descriptor does not verify: %v", err)
	}
	if descriptor.Fingerprint != km.Fingerprint || proof.Signature.SignedByKeyId != km.Fingerprint {
		t.Fatal("proof does not name the local RP fingerprint")
	}
	if !ed25519.Verify(ed25519.PublicKey(descriptor.SigningPublicKey), localrp.EnvelopeSignatureInput(tag, payload), proof.Signature.Signature) {
		t.Fatal("proof signature does not verify with the descriptor key")
	}
}

func actAsScopeSetBytes(t *testing.T) []byte {
	t.Helper()
	v := loadActAsVectors(t)
	for _, c := range v.Cases {
		if c.Name == "local_rp_grantee" {
			return mustHex(t, c.GrantRequest.Inputs.ScopeSetSignedCborHex)
		}
	}
	t.Fatal("no local_rp_grantee case")
	return nil
}

func beginActAsWith(t *testing.T, dns localrp.DnsResolver, userDomain string) (*localrp.LocalRpKeyMaterial, *localrp.ActAsRedirect, *localrp.PendingActAs, []byte) {
	t.Helper()
	now := time.Now()
	km := fixedKeyMaterial(t, now)
	scopeSet := actAsScopeSetBytes(t)
	lifetime := int64(1800)
	redirect, pending, err := localrp.BeginActAs(localrp.BeginActAsConfig{
		KeyMaterial:              km,
		UserDomain:               userDomain,
		ScopeSet:                 scopeSet,
		RequestedLifetimeSeconds: &lifetime,
		CallbackURL:              "http://app.lan:8080/act-as/callback",
		Now:                      now,
		DNS:                      dns,
	})
	if err != nil {
		t.Fatalf("BeginActAs: %v", err)
	}
	return km, redirect, pending, scopeSet
}

func TestBeginActAsUsesDiscoveredHostAndSignsRequest(t *testing.T) {
	dns := apisResolver("v=lk1 tcp=linkkeys.ident.example.test https=login.example.test/linkkeys")
	km, redirect, pending, scopeSet := beginActAsWith(t, dns, "alice@"+browserTestDomain)

	const prefix = "https://login.example.test/linkkeys/auth/act-as?signed_request="
	if !strings.HasPrefix(redirect.RedirectURL, prefix) {
		t.Fatalf("redirect %q does not start with %q", redirect.RedirectURL, prefix)
	}
	if pending.UserDomain != browserTestDomain {
		t.Fatalf("pending user domain %q, want identity domain", pending.UserDomain)
	}
	u, err := url.Parse(redirect.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Has("username") {
		t.Fatal("act-as redirect must not carry a username hint")
	}
	raw, err := base64.RawURLEncoding.DecodeString(u.Query().Get("signed_request"))
	if err != nil {
		t.Fatalf("signed_request is not base64url: %v", err)
	}
	signed, err := api.DecodeSignedActAsGrantRequest(raw)
	if err != nil {
		t.Fatalf("decode signed request: %v", err)
	}
	verifyLocalRpProof(t, time.Now(), km, signed.Proof, localrp.CtxActAsGrantRequest, signed.Request)
	request, err := api.DecodeActAsGrantRequest(signed.Request)
	if err != nil {
		t.Fatal(err)
	}
	if request.Grantee.Application != nil || request.Grantee.LocalRpDescriptorFingerprint == nil || *request.Grantee.LocalRpDescriptorFingerprint != km.Fingerprint {
		t.Fatal("grantee is not this local RP")
	}
	if !bytes.Equal(api.EncodeSignedActAsScopeSet(request.ScopeSet), scopeSet) {
		t.Fatal("scope set is not embedded unchanged")
	}
	if request.Nonce != pending.Nonce || request.CallbackUrl != pending.CallbackURL {
		t.Fatal("request nonce/callback do not match pending state")
	}
	if nonce, err := base64.RawURLEncoding.DecodeString(request.Nonce); err != nil || len(nonce) != 32 {
		t.Fatalf("nonce is not 32 bytes of base64url: %v", err)
	}
	if request.RequestedLifetimeSeconds == nil || *request.RequestedLifetimeSeconds != 1800 || request.RequestedRenewalWindowSeconds != nil {
		t.Fatal("requested terms not carried as given")
	}
	start := parseRFC3339(t, request.RequestedAt)
	end := parseRFC3339(t, request.ExpiresAt)
	if end.Sub(start) != localrp.DefaultActAsRequestWindow || !strings.HasSuffix(request.RequestedAt, "Z") {
		t.Fatalf("request window %s..%s", request.RequestedAt, request.ExpiresAt)
	}
}

func TestBeginActAsFallsBackToIdentityDomain(t *testing.T) {
	for _, dns := range []localrp.DnsResolver{
		&mapDNSResolver{err: errors.New("SERVFAIL")},
		apisResolver("v=lk1 tcp=only.example.test"),
	} {
		_, redirect, _, _ := beginActAsWith(t, dns, browserTestDomain)
		want := "https://" + browserTestDomain + "/auth/act-as?signed_request="
		if !strings.HasPrefix(redirect.RedirectURL, want) {
			t.Fatalf("redirect %q, want prefix %q", redirect.RedirectURL, want)
		}
	}
}

func TestBeginActAsRejectsBadInput(t *testing.T) {
	now := time.Now()
	km := fixedKeyMaterial(t, now)
	dns := &mapDNSResolver{err: errors.New("SERVFAIL")}
	base := localrp.BeginActAsConfig{
		KeyMaterial: km,
		UserDomain:  browserTestDomain,
		ScopeSet:    actAsScopeSetBytes(t),
		CallbackURL: "http://app.lan/cb",
		Now:         now,
		DNS:         dns,
	}
	zero := int64(0)
	negative := int64(-1)
	for name, mutate := range map[string]func(*localrp.BeginActAsConfig){
		"window too long":   func(c *localrp.BeginActAsConfig) { c.RequestWindow = localrp.MaxActAsRequestWindow + time.Second },
		"zero lifetime":     func(c *localrp.BeginActAsConfig) { c.RequestedLifetimeSeconds = &zero },
		"negative renewal":  func(c *localrp.BeginActAsConfig) { c.RequestedRenewalWindowSeconds = &negative },
		"garbage scope set": func(c *localrp.BeginActAsConfig) { c.ScopeSet = []byte{0xff} },
		"bad callback":      func(c *localrp.BeginActAsConfig) { c.CallbackURL = "myapp://cb" },
		"bad identity":      func(c *localrp.BeginActAsConfig) { c.UserDomain = "https://x" },
	} {
		c := base
		mutate(&c)
		if _, _, err := localrp.BeginActAs(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := base
	c.RequestWindow = localrp.MaxActAsRequestWindow
	if _, _, err := localrp.BeginActAs(c); err != nil {
		t.Errorf("max window rejected: %v", err)
	}
}

func TestCompleteActAsCallback(t *testing.T) {
	pending := &localrp.PendingActAs{Nonce: "n0nce-value", UserDomain: "example.test", CallbackURL: "http://app.lan/cb"}

	for _, cb := range []string{
		"http://app.lan/cb?act_as_grant_id=grant-1&nonce=n0nce-value",
		"act_as_grant_id=grant-1&nonce=n0nce-value",
	} {
		id, err := localrp.CompleteActAsCallback(pending, cb)
		if err != nil || id != "grant-1" {
			t.Fatalf("%q: got %q, %v", cb, id, err)
		}
	}

	_, err := localrp.CompleteActAsCallback(pending, "http://app.lan/cb?act_as_grant_id=grant-1&nonce=other")
	var lrpErr *localrp.LocalRpError
	if !errors.As(err, &lrpErr) || lrpErr.Kind != localrp.ErrKindNonceMismatch {
		t.Fatalf("nonce mismatch: got %v", err)
	}
	for _, cb := range []string{
		"http://app.lan/cb?nonce=n0nce-value",
		"http://app.lan/cb?act_as_grant_id=grant-1",
		"http://app.lan/cb?act_as_grant_id=grant-1&nonce=n0nce-valu",
		// A repeated parameter is refused, even when one value is correct.
		"http://app.lan/cb?act_as_grant_id=grant-1&nonce=n0nce-value&nonce=other",
		"http://app.lan/cb?act_as_grant_id=evil&act_as_grant_id=grant-1&nonce=n0nce-value",
	} {
		if _, err := localrp.CompleteActAsCallback(pending, cb); err == nil {
			t.Errorf("%q: accepted", cb)
		}
	}
}

// vectorLocalRpGrant is the act-as grant the vectors issue to the local
// RP: grant_id "grant-1", subject_domain home.conformance.example.
func vectorLocalRpGrant(t *testing.T, v actAsVectors) api.SignedActAsGrant {
	t.Helper()
	for _, c := range v.Cases {
		if c.Name == "local_rp_grantee" {
			grant, err := api.DecodeSignedActAsGrant(mustHex(t, c.Presentation.Inputs.GrantSignedCborHex))
			if err != nil {
				t.Fatalf("decode vector grant: %v", err)
			}
			return grant
		}
	}
	t.Fatal("no local_rp_grantee case")
	return api.SignedActAsGrant{}
}

const vectorHomeDomain = "home.conformance.example"

// refreshDNS pins the fake IDP's TLS key for the vectors' home domain.
func refreshDNS(addr string) *mapDNSResolver {
	pub := ed25519.NewKeyFromSeed(domainSigningSeedFlowTest[:]).Public().(ed25519.PublicKey)
	return &mapDNSResolver{records: map[string][]string{
		"_linkkeys." + vectorHomeDomain:      {"v=lk1 fp=" + localrp.Fingerprint([]byte(pub))},
		"_linkkeys_apis." + vectorHomeDomain: {"v=lk1 tcp=" + addr},
		"_linkkeys.other.example":            {"v=lk1 fp=" + localrp.Fingerprint([]byte(pub))},
		"_linkkeys_apis.other.example":       {"v=lk1 tcp=" + addr},
	}}
}

// vectorRefreshNow is inside the vector descriptor's validity window.
var vectorRefreshNow = time.Date(2026, 10, 6, 12, 40, 0, 0, time.UTC)

func refreshWith(t *testing.T, km *localrp.LocalRpKeyMaterial, grantID, userDomain string, respond func() rpctransport.RpcResponse) (*api.SignedActAsGrant, bool, error) {
	t.Helper()
	addr := spawnFakeIDP(t, domainSigningSeedFlowTest, 1, nil, func(string, string, []byte) rpctransport.RpcResponse { return respond() })
	return localrp.RefreshActAsGrant(localrp.RefreshActAsGrantConfig{
		KeyMaterial: km, UserDomain: userDomain, GrantID: grantID, Now: vectorRefreshNow,
		Transport: testTransport{}, DNS: refreshDNS(addr),
	})
}

func TestRefreshActAsGrantOverPinnedRPC(t *testing.T) {
	v := loadActAsVectors(t)
	km := vectorKeyMaterial(t, v)
	grant := vectorLocalRpGrant(t, v)

	type seen struct {
		service, op string
		payload     []byte
	}
	got := make(chan seen, 1)
	addr := spawnFakeIDP(t, domainSigningSeedFlowTest, 1, nil, func(service, op string, payload []byte) rpctransport.RpcResponse {
		got <- seen{service, op, payload}
		return rpctransport.NewRpcResponseOk("RefreshActAsGrantResponse", api.EncodeRefreshActAsGrantResponse(api.RefreshActAsGrantResponse{Grant: grant, Signed: true}))
	})

	out, signedNow, err := localrp.RefreshActAsGrant(localrp.RefreshActAsGrantConfig{
		KeyMaterial: km,
		UserDomain:  "Home.Conformance.Example",
		GrantID:     "grant-1",
		Now:         vectorRefreshNow,
		Transport:   testTransport{},
		DNS:         refreshDNS(addr),
	})
	if err != nil {
		t.Fatalf("RefreshActAsGrant: %v", err)
	}
	if !signedNow || !bytes.Equal(api.EncodeSignedActAsGrant(*out), api.EncodeSignedActAsGrant(grant)) {
		t.Fatal("response not returned as served")
	}

	s := <-got
	if s.service != "ActAs" || s.op != "refresh-grant" {
		t.Fatalf("called %s/%s", s.service, s.op)
	}
	req, err := api.DecodeRefreshActAsGrantRequest(s.payload)
	if err != nil {
		t.Fatalf("payload does not decode: %v", err)
	}
	verifyLocalRpProof(t, vectorRefreshNow, km, req.Request.Proof, localrp.CtxActAsRefreshRequest, req.Request.Request)
	refresh, err := api.DecodeActAsRefreshRequest(req.Request.Request)
	if err != nil {
		t.Fatal(err)
	}
	if refresh.GrantId != "grant-1" || refresh.Grantee.Application != nil || refresh.Grantee.LocalRpDescriptorFingerprint == nil || *refresh.Grantee.LocalRpDescriptorFingerprint != km.Fingerprint {
		t.Fatal("refresh request does not name this grant and grantee")
	}
	if refresh.RequestedAt != "2026-10-06T12:40:00Z" || refresh.ExpiresAt != "2026-10-06T12:45:00Z" {
		t.Fatalf("refresh window %s..%s", refresh.RequestedAt, refresh.ExpiresAt)
	}
	if n, err := base64.RawURLEncoding.DecodeString(refresh.Nonce); err != nil || len(n) != 32 {
		t.Fatal("refresh nonce is not 32 random bytes")
	}
}

func TestRefreshActAsGrantRejectsMismatchedGrant(t *testing.T) {
	v := loadActAsVectors(t)
	km := vectorKeyMaterial(t, v)
	grant := vectorLocalRpGrant(t, v)
	ok := func() rpctransport.RpcResponse {
		return rpctransport.NewRpcResponseOk("RefreshActAsGrantResponse", api.EncodeRefreshActAsGrantResponse(api.RefreshActAsGrantResponse{Grant: grant}))
	}
	// Another grant id.
	if _, _, err := refreshWith(t, km, "grant-2", vectorHomeDomain, ok); err == nil {
		t.Error("accepted a grant for another grant id")
	}
	// Another grantee.
	other := fixedKeyMaterial(t, vectorRefreshNow)
	if _, _, err := refreshWith(t, other, "grant-1", vectorHomeDomain, ok); err == nil {
		t.Error("accepted a grant for another grantee")
	}
	// Another subject domain.
	if _, _, err := refreshWith(t, km, "grant-1", "other.example", ok); err == nil {
		t.Error("accepted a grant from another subject domain")
	}
	// Grant bytes that do not decode.
	garbage := func() rpctransport.RpcResponse {
		return rpctransport.NewRpcResponseOk("RefreshActAsGrantResponse", api.EncodeRefreshActAsGrantResponse(api.RefreshActAsGrantResponse{Grant: api.SignedActAsGrant{Grant: []byte{0xff}, Signatures: []api.ClaimSignature{}}}))
	}
	var decodeErr *localrp.DecodeError
	if _, _, err := refreshWith(t, km, "grant-1", vectorHomeDomain, garbage); !errors.As(err, &decodeErr) {
		t.Errorf("want DecodeError for undecodable grant, got %v", err)
	}
}

func TestRefreshActAsGrantSurfacesServerError(t *testing.T) {
	km := vectorKeyMaterial(t, loadActAsVectors(t))
	_, _, err := refreshWith(t, km, "grant-1", vectorHomeDomain, func() rpctransport.RpcResponse {
		return rpctransport.NewRpcResponseTransportError(rpctransport.StatusUnknownServiceOrOp, "no such grant")
	})
	var serverErr *localrp.ServerError
	if !errors.As(err, &serverErr) {
		t.Fatalf("want ServerError, got %v", err)
	}
}

func TestRefreshActAsGrantRejectsGarbageResponse(t *testing.T) {
	km := vectorKeyMaterial(t, loadActAsVectors(t))
	_, _, err := refreshWith(t, km, "grant-1", vectorHomeDomain, func() rpctransport.RpcResponse {
		return rpctransport.NewRpcResponseOk("RefreshActAsGrantResponse", []byte{0xff, 0xff})
	})
	var decodeErr *localrp.DecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("want DecodeError, got %v", err)
	}
}
