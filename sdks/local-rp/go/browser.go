package localrp

import (
	"fmt"
	"net/url"
	"strings"
)

// Browser endpoint discovery: resolve an identity domain's browser-facing
// HTTPS base from its `_linkkeys_apis` TXT record, and build browser route
// URLs against it.
//
// The identity domain (the domain the user selected, e.g. `todandlorna.com`)
// is a trust and discovery domain. It is not necessarily the host that
// serves the browser login routes — the `https=` endpoint of
// `_linkkeys_apis.<identity-domain>` is (docs/spec/trust-and-anchors.md:
// "`https=` is the browser-facing endpoint"). These helpers are shared by
// BeginLocalLogin (route BrowserRouteLocalRp) and by regular-RP application
// glue (route BrowserRouteAuthorize), so discovery is implemented once.

// BrowserRouteLocalRp is the browser route for the DNS-less local-RP login
// flow.
const BrowserRouteLocalRp = "/auth/local-rp"

// BrowserRouteAuthorize is the browser route for the regular (domain-keyed)
// RP login flow.
const BrowserRouteAuthorize = "/auth/authorize"

// validateBrowserBase checks that base is a usable https browser base URL:
// parseable, https scheme, a host, an optional path prefix, and nothing
// else. A TXT record value must never smuggle in userinfo, a query, a
// fragment, or (via ParseLinkKeysApisTXT's unconditional `https://` prefix
// plus this check) a non-HTTPS scheme.
func validateBrowserBase(base string) (*url.URL, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, &InvalidInputError{Detail: fmt.Sprintf("browser base %q is not a valid URL: %s", base, err)}
	}
	if u.Scheme != "https" {
		return nil, &InvalidInputError{Detail: fmt.Sprintf("browser base %q must use https", base)}
	}
	if u.Host == "" {
		return nil, &InvalidInputError{Detail: fmt.Sprintf("browser base %q has no host", base)}
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, &InvalidInputError{Detail: fmt.Sprintf("browser base %q must be host[:port][/path] only", base)}
	}
	return u, nil
}

// ResolveBrowserBase resolves identityDomain's browser-facing HTTPS base URL
// (e.g. `https://linkkeys.todandlorna.com` or
// `https://login.example.com/linkkeys`) from its
// `_linkkeys_apis.<identityDomain>` TXT record.
//
// It selects the first LinkKeys v1 record whose `https=` endpoint is a valid
// browser base; invalid TXT records and records without `https=` are
// skipped. It returns an error when the lookup fails or no record yields a
// valid base — the caller decides the fallback (BeginLocalLogin falls back
// to `https://<identityDomain>`).
//
// The resolved base is a service location only. Identity verification stays
// bound to the identity domain — never bind trust decisions to the host
// this returns.
func ResolveBrowserBase(dns DnsResolver, identityDomain string) (string, error) {
	name := LinkKeysApisDNSName(identityDomain)
	txts, err := dns.TxtLookup(name)
	if err != nil {
		return "", err
	}
	for _, txt := range txts {
		apis, err := ParseLinkKeysApisTXT(txt)
		if err != nil || apis.HTTPSBase == nil {
			continue
		}
		if _, err := validateBrowserBase(*apis.HTTPSBase); err != nil {
			continue
		}
		return *apis.HTTPSBase, nil
	}
	return "", &DNSError{Detail: fmt.Sprintf("no usable %s TXT record with an https= endpoint", name)}
}

// BuildBrowserEndpoint builds the full browser URL for route (e.g.
// BrowserRouteLocalRp) under browserBase, carrying signedRequest as the
// `signed_request` query parameter. A path prefix in the base is preserved:
// base `https://login.example.com/linkkeys` and route `/auth/local-rp`
// produce `https://login.example.com/linkkeys/auth/local-rp?...`.
//
// The URL is assembled with net/url. `signed_request` values are
// URL-param-encoded (unpadded base64url) by construction, so query encoding
// passes them through byte-identically.
func BuildBrowserEndpoint(browserBase, route, signedRequest string) (string, error) {
	u, err := validateBrowserBase(browserBase)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(route, "/") {
		return "", &InvalidInputError{Detail: fmt.Sprintf("route %q must start with /", route)}
	}
	u = u.JoinPath(route)
	query := url.Values{}
	query.Set("signed_request", signedRequest)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

// resolveBrowserEndpoint is the begin-flow composition: discover the
// identity domain's browser base and build the route URL, falling back to
// `https://<identityDomain>` when DNS lookup fails, no valid record carries
// `https=`, or the discovered base is invalid. The fallback preserves the
// pre-discovery behavior, so a domain that serves its browser routes at the
// apex keeps working without a `_linkkeys_apis` record.
func resolveBrowserEndpoint(dns DnsResolver, identityDomain, route, signedRequest string) (string, error) {
	base, err := ResolveBrowserBase(dns, identityDomain)
	if err != nil {
		base = "https://" + identityDomain
	}
	return BuildBrowserEndpoint(base, route, signedRequest)
}
