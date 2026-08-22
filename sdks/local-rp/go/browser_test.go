package localrp_test

import (
	"bytes"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	localrp "github.com/catalystcommunity/linkkeys/sdks/local-rp/go"
	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

// mapDNSResolver is a hermetic DnsResolver with canned TXT answers per name.
// No test in this file performs a live DNS request.
type mapDNSResolver struct {
	records map[string][]string
	err     error
}

func (m *mapDNSResolver) TxtLookup(name string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	if txts, ok := m.records[name]; ok {
		return txts, nil
	}
	return nil, errors.New("no fake record for " + name)
}

const browserTestDomain = "ident.example.test"

func apisResolver(txts ...string) *mapDNSResolver {
	return &mapDNSResolver{records: map[string][]string{
		"_linkkeys_apis." + browserTestDomain: txts,
	}}
}

func beginWith(t *testing.T, dns localrp.DnsResolver) (*localrp.LocalLoginRedirect, *localrp.PendingLogin, localrp.BeginLocalLoginConfig) {
	t.Helper()
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	identity, err := localrp.GenerateLocalRpIdentity(localrp.GenerateLocalRpIdentityConfig{
		AppName: "browser-test",
		Now:     now,
	})
	if err != nil {
		t.Fatalf("GenerateLocalRpIdentity: %v", err)
	}
	config := localrp.BeginLocalLoginConfig{
		KeyMaterial: identity,
		CallbackURL: "http://app.lan:8080/cb",
		UserDomain:  browserTestDomain,
		Now:         now,
		DNS:         dns,
	}
	redirect, pending, err := localrp.BeginLocalLogin(config)
	if err != nil {
		t.Fatalf("BeginLocalLogin: %v", err)
	}
	return redirect, pending, config
}

// Case 1: a valid https= host is used for the redirect instead of the
// identity domain. Case 8: PendingLogin.UserDomain stays the identity
// domain — verification stays bound to it, not to the service host.
func TestBeginUsesDiscoveredHTTPSHost(t *testing.T) {
	redirect, pending, _ := beginWith(t, apisResolver(
		"v=lk1 tcp=linkkeys.ident.example.test https=linkkeys.ident.example.test",
	))
	wantPrefix := "https://linkkeys.ident.example.test/auth/local-rp?signed_request="
	if !strings.HasPrefix(redirect.RedirectURL, wantPrefix) {
		t.Errorf("RedirectURL = %q, want prefix %q", redirect.RedirectURL, wantPrefix)
	}
	if strings.HasPrefix(redirect.RedirectURL, "https://"+browserTestDomain+"/") {
		t.Errorf("RedirectURL used the identity domain instead of the discovered host: %q", redirect.RedirectURL)
	}
	if pending.UserDomain != browserTestDomain {
		t.Errorf("PendingLogin.UserDomain = %q, want the identity domain %q", pending.UserDomain, browserTestDomain)
	}
}

// Case 2: an https= value with a path prefix preserves that prefix.
func TestBeginPreservesHTTPSPathPrefix(t *testing.T) {
	redirect, _, _ := beginWith(t, apisResolver(
		"v=lk1 https=login.example.test/linkkeys",
	))
	wantPrefix := "https://login.example.test/linkkeys/auth/local-rp?signed_request="
	if !strings.HasPrefix(redirect.RedirectURL, wantPrefix) {
		t.Errorf("RedirectURL = %q, want prefix %q", redirect.RedirectURL, wantPrefix)
	}
}

// Case 3: a record with only tcp= falls back to the identity domain.
func TestBeginTcpOnlyRecordFallsBackToIdentityDomain(t *testing.T) {
	redirect, _, _ := beginWith(t, apisResolver("v=lk1 tcp=linkkeys.ident.example.test"))
	wantPrefix := "https://" + browserTestDomain + "/auth/local-rp?signed_request="
	if !strings.HasPrefix(redirect.RedirectURL, wantPrefix) {
		t.Errorf("RedirectURL = %q, want prefix %q", redirect.RedirectURL, wantPrefix)
	}
}

// Case 4: a DNS lookup error falls back to the identity domain.
func TestBeginDNSErrorFallsBackToIdentityDomain(t *testing.T) {
	redirect, _, _ := beginWith(t, &mapDNSResolver{err: errors.New("SERVFAIL")})
	wantPrefix := "https://" + browserTestDomain + "/auth/local-rp?signed_request="
	if !strings.HasPrefix(redirect.RedirectURL, wantPrefix) {
		t.Errorf("RedirectURL = %q, want prefix %q", redirect.RedirectURL, wantPrefix)
	}
}

// Cases 5 + 6: invalid TXT records are ignored, and across several records
// the FIRST valid record with https= is selected.
func TestBeginSelectsFirstValidHTTPSAcrossRecords(t *testing.T) {
	redirect, _, _ := beginWith(t, apisResolver(
		"not a linkkeys record",
		"v=lk2 https=wrong-version.example.test",
		"v=lk1 tcp=tcp-only.example.test",
		"v=lk1 https=first.example.test",
		"v=lk1 https=second.example.test",
	))
	wantPrefix := "https://first.example.test/auth/local-rp?signed_request="
	if !strings.HasPrefix(redirect.RedirectURL, wantPrefix) {
		t.Errorf("RedirectURL = %q, want prefix %q", redirect.RedirectURL, wantPrefix)
	}
}

// Case 7: signed_request rides the discovered URL unchanged — it decodes to
// the signed login request whose fields match this login.
func TestBeginSignedRequestSurvivesDiscoveredURL(t *testing.T) {
	redirect, pending, config := beginWith(t, apisResolver(
		"v=lk1 https=login.example.test/linkkeys",
	))
	u, err := url.Parse(redirect.RedirectURL)
	if err != nil {
		t.Fatalf("RedirectURL does not parse: %v", err)
	}
	param := u.Query().Get("signed_request")
	if param == "" {
		t.Fatal("signed_request query parameter missing")
	}
	signed, err := localrp.SignedLocalRpLoginRequestFromURLParam(param)
	if err != nil {
		t.Fatalf("signed_request does not decode: %v", err)
	}
	request, err := api.DecodeLocalRpLoginRequest(signed.Request)
	if err != nil {
		t.Fatalf("inner request does not decode: %v", err)
	}
	if request.CallbackUrl != config.CallbackURL {
		t.Errorf("callback_url = %q, want %q", request.CallbackUrl, config.CallbackURL)
	}
	if !bytes.Equal(request.Nonce, pending.Nonce) {
		t.Error("request nonce does not match pending nonce")
	}
}

func TestBeginParsesIdentityInput(t *testing.T) {
	_, _, config := beginWith(t, &mapDNSResolver{err: errors.New("SERVFAIL")})
	config.UserDomain = "Alice+work@ID.Example.TEST"
	redirect, pending, err := localrp.BeginLocalLogin(config)
	if err != nil {
		t.Fatalf("BeginLocalLogin: %v", err)
	}
	if !strings.Contains(redirect.RedirectURL, "username=Alice%2Bwork") {
		t.Fatalf("redirect missing encoded username: %s", redirect.RedirectURL)
	}
	if pending.UserDomain != "id.example.test" {
		t.Fatalf("pending domain = %q", pending.UserDomain)
	}
}

func TestBeginRejectsMalformedIdentityInput(t *testing.T) {
	_, _, config := beginWith(t, &mapDNSResolver{err: errors.New("SERVFAIL")})
	for _, input := range []string{"alice", "alice@@example.test", "https://example.test", "alice@example.test:+443"} {
		config.UserDomain = input
		if _, _, err := localrp.BeginLocalLogin(config); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}

// Case 9: a config without a DNS field compiles unchanged (this test is that
// caller) and the default is the memoized system resolver. The default path
// is not executed here — that would be a live DNS request.
func TestBeginConfigWithoutResolverStillCompiles(t *testing.T) {
	_ = localrp.BeginLocalLoginConfig{
		CallbackURL: "http://app.lan:8080/cb",
		UserDomain:  browserTestDomain,
	}
	if localrp.DefaultDNSResolver() == nil {
		t.Fatal("DefaultDNSResolver() must supply the default resolver")
	}
}

// ---------------------------------------------------------------------
// Direct tests for the exported helpers
// ---------------------------------------------------------------------

func TestResolveBrowserBase(t *testing.T) {
	base, err := localrp.ResolveBrowserBase(apisResolver(
		"v=lk1 tcp=x.example.test https=login.example.test:8443/linkkeys",
	), browserTestDomain)
	if err != nil {
		t.Fatalf("ResolveBrowserBase: %v", err)
	}
	if base != "https://login.example.test:8443/linkkeys" {
		t.Errorf("base = %q", base)
	}

	// A record whose https= value smuggles URL structure is skipped; with no
	// other candidate, resolution errors so the caller can fall back.
	for _, hostile := range []string{
		"v=lk1 https=user@evil.example.test",
		"v=lk1 https=evil.example.test/x?y=1",
		"v=lk1 https=evil.example.test/x#frag",
	} {
		if _, err := localrp.ResolveBrowserBase(apisResolver(hostile), browserTestDomain); err == nil {
			t.Errorf("ResolveBrowserBase accepted hostile record %q", hostile)
		}
	}

	if _, err := localrp.ResolveBrowserBase(apisResolver("v=lk1 tcp=only.example.test"), browserTestDomain); err == nil {
		t.Error("ResolveBrowserBase must error when no record has https=")
	}
}

func TestBuildBrowserEndpoint(t *testing.T) {
	got, err := localrp.BuildBrowserEndpoint("https://h.example.test", localrp.BrowserRouteLocalRp, "PAYLOAD-123_abc")
	if err != nil {
		t.Fatalf("BuildBrowserEndpoint: %v", err)
	}
	if got != "https://h.example.test/auth/local-rp?signed_request=PAYLOAD-123_abc" {
		t.Errorf("got %q", got)
	}

	// Path prefix, with and without a trailing slash, and the regular-RP
	// route — the same helper serves /auth/authorize glue.
	for base, want := range map[string]string{
		"https://h.example.test/pfx":  "https://h.example.test/pfx/auth/authorize?signed_request=s",
		"https://h.example.test/pfx/": "https://h.example.test/pfx/auth/authorize?signed_request=s",
	} {
		got, err := localrp.BuildBrowserEndpoint(base, localrp.BrowserRouteAuthorize, "s")
		if err != nil {
			t.Fatalf("BuildBrowserEndpoint(%q): %v", base, err)
		}
		if got != want {
			t.Errorf("BuildBrowserEndpoint(%q) = %q, want %q", base, got, want)
		}
	}

	// A non-HTTPS scheme must never be selectable.
	for _, bad := range []string{
		"http://h.example.test",
		"ftp://h.example.test",
		"https://",
		"https://u:p@h.example.test",
	} {
		if _, err := localrp.BuildBrowserEndpoint(bad, localrp.BrowserRouteLocalRp, "s"); err == nil {
			t.Errorf("BuildBrowserEndpoint accepted invalid base %q", bad)
		}
	}
	if _, err := localrp.BuildBrowserEndpoint("https://h.example.test", "auth/no-leading-slash", "s"); err == nil {
		t.Error("BuildBrowserEndpoint must reject a route without a leading slash")
	}
}
