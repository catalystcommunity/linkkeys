"""Browser endpoint discovery: resolve an identity domain's browser-facing
HTTPS base from its `_linkkeys_apis` TXT record, and build browser route
URLs against it. Mirrors `sdks/local-rp/go/browser.go`.

The identity domain (the domain the user selected, e.g. `todandlorna.com`)
is a trust and discovery domain. It is not necessarily the host that serves
the browser login routes -- the `https=` endpoint of
`_linkkeys_apis.<identity-domain>` is (docs/spec/trust-and-anchors.md:
"`https=` is the browser-facing endpoint"). These helpers are shared by
`begin_local_login` (route `BROWSER_ROUTE_LOCAL_RP`) and by regular-RP
application glue (route `BROWSER_ROUTE_AUTHORIZE`), so discovery is
implemented once.
"""

from __future__ import annotations

from urllib.parse import SplitResult, urlencode, urlsplit, urlunsplit

from . import dns as dns_mod

# The browser route for the DNS-less local-RP login flow.
BROWSER_ROUTE_LOCAL_RP = "/auth/local-rp"

# The browser route for the regular (domain-keyed) RP login flow.
BROWSER_ROUTE_AUTHORIZE = "/auth/authorize"

# The browser route where a grantee asks the user for an act-as grant.
BROWSER_ROUTE_ACT_AS = "/auth/act-as"


class BrowserEndpointError(Exception):
    """A browser base or route is not usable, or no `_linkkeys_apis` record
    yields a valid `https=` base."""


def _validate_browser_base(base: str) -> SplitResult:
    """Check that `base` is a usable https browser base URL: parseable,
    https scheme, a host, an optional path prefix, and nothing else. A TXT
    record value must never smuggle in userinfo, a query, a fragment, or
    (via `parse_linkkeys_apis_txt`'s unconditional `https://` prefix plus
    this check) a non-HTTPS scheme."""
    try:
        u = urlsplit(base)
        _ = u.port  # raises ValueError on a malformed port
    except ValueError as e:
        raise BrowserEndpointError(f"browser base {base!r} is not a valid URL: {e}") from e
    if u.scheme != "https":
        raise BrowserEndpointError(f"browser base {base!r} must use https")
    if not u.hostname:
        raise BrowserEndpointError(f"browser base {base!r} has no host")
    if u.username is not None or u.password is not None or u.query or u.fragment or "?" in base or "#" in base:
        raise BrowserEndpointError(f"browser base {base!r} must be host[:port][/path] only")
    return u


def resolve_browser_base(dns: dns_mod.DnsResolver, identity_domain: str) -> str:
    """Resolve `identity_domain`'s browser-facing HTTPS base URL (e.g.
    `https://linkkeys.todandlorna.com` or
    `https://login.example.com/linkkeys`) from its
    `_linkkeys_apis.<identity_domain>` TXT record.

    Selects the first LinkKeys v1 record whose `https=` endpoint is a valid
    browser base; invalid TXT records and records without `https=` are
    skipped. Raises when the lookup fails (the resolver's own exception
    propagates) or when no record yields a valid base
    (`BrowserEndpointError`) -- the caller decides the fallback
    (`begin_local_login` falls back to `https://<identity_domain>`).

    The resolved base is a service location only. Identity verification
    stays bound to the identity domain -- never bind trust decisions to the
    host this returns."""
    name = dns_mod.linkkeys_apis_dns_name(identity_domain)
    for txt in dns.txt_lookup(name):
        try:
            https_base = dns_mod.parse_linkkeys_apis_txt(txt).https_base
        except dns_mod.DnsParseError:
            continue
        if https_base is None:
            continue
        try:
            _validate_browser_base(https_base)
        except BrowserEndpointError:
            continue
        return https_base
    raise BrowserEndpointError(f"no usable {name} TXT record with an https= endpoint")


def build_browser_endpoint(browser_base: str, route: str, signed_request: str) -> str:
    """Build the full browser URL for `route` (e.g. `BROWSER_ROUTE_LOCAL_RP`)
    under `browser_base`, carrying `signed_request` as the `signed_request`
    query parameter. A path prefix in the base is preserved: base
    `https://login.example.com/linkkeys` and route `/auth/local-rp` produce
    `https://login.example.com/linkkeys/auth/local-rp?...`.

    The URL is assembled with `urllib.parse`. `signed_request` values are
    URL-param-encoded (unpadded base64url) by construction, so query
    encoding passes them through byte-identically."""
    u = _validate_browser_base(browser_base)
    if not route.startswith("/"):
        raise BrowserEndpointError(f"route {route!r} must start with /")
    path = u.path.rstrip("/") + route
    return urlunsplit((u.scheme, u.netloc, path, urlencode({"signed_request": signed_request}), ""))


def resolve_browser_endpoint(dns: dns_mod.DnsResolver, identity_domain: str, route: str, signed_request: str) -> str:
    """The begin-flow composition: discover the identity domain's browser
    base and build the route URL, falling back to `https://<identity_domain>`
    when DNS lookup fails, no valid record carries `https=`, or the
    discovered base is invalid. The fallback preserves the pre-discovery
    behavior, so a domain that serves its browser routes at the apex keeps
    working without a `_linkkeys_apis` record."""
    try:
        base = resolve_browser_base(dns, identity_domain)
    except Exception:  # noqa: BLE001 - any lookup/selection failure falls back, as in Go
        base = f"https://{identity_domain}"
    return build_browser_endpoint(base, route, signed_request)
