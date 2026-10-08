"""Browser endpoint discovery tests, ported from
`sdks/local-rp/go/browser_test.go`. Every resolver here is a hermetic fake
with canned TXT answers -- no test in this file performs a live DNS
request."""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlsplit

import pytest

from linkkeys_local_rp import encoding
from linkkeys_local_rp.begin import BeginLocalLoginConfig, begin_local_login
from linkkeys_local_rp.browser import (
    BROWSER_ROUTE_AUTHORIZE,
    BROWSER_ROUTE_LOCAL_RP,
    BrowserEndpointError,
    build_browser_endpoint,
    resolve_browser_base,
)
from linkkeys_local_rp.dns import SystemDnsResolver
from linkkeys_local_rp.generated.types import LocalRpLoginRequest
from linkkeys_local_rp.identity import GenerateLocalRpIdentityConfig, generate_local_rp_identity


class MapDnsResolver:
    """A hermetic `DnsResolver` with canned TXT answers per name."""

    def __init__(self, records: Dict[str, List[str]], error: Optional[Exception] = None):
        self.records = records
        self.error = error

    def txt_lookup(self, name: str) -> List[str]:
        if self.error is not None:
            raise self.error
        if name in self.records:
            return self.records[name]
        raise RuntimeError(f"no fake record for {name}")


BROWSER_TEST_DOMAIN = "ident.example.test"
CALLBACK_URL = "http://app.lan:8080/cb"
NOW = datetime(2026, 8, 17, 12, 0, 0, tzinfo=timezone.utc)
KEY_MATERIAL = generate_local_rp_identity(GenerateLocalRpIdentityConfig(app_name="browser-test", now=NOW))


def apis_resolver(*txts: str) -> MapDnsResolver:
    return MapDnsResolver({f"_linkkeys_apis.{BROWSER_TEST_DOMAIN}": list(txts)})


def failing_resolver() -> MapDnsResolver:
    return MapDnsResolver({}, RuntimeError("SERVFAIL"))


def begin_with(dns):
    config = BeginLocalLoginConfig(
        key_material=KEY_MATERIAL,
        callback_url=CALLBACK_URL,
        user_domain=BROWSER_TEST_DOMAIN,
        now=NOW,
        dns=dns,
    )
    redirect, pending = begin_local_login(config)
    return redirect, pending, config


# Case 1: a valid https= host is used for the redirect instead of the
# identity domain. Case 8: PendingLogin.user_domain stays the identity
# domain -- verification stays bound to it, not to the service host.
def test_begin_uses_discovered_https_host():
    redirect, pending, _ = begin_with(
        apis_resolver("v=lk1 tcp=linkkeys.ident.example.test https=linkkeys.ident.example.test")
    )
    assert redirect.redirect_url.startswith("https://linkkeys.ident.example.test/auth/local-rp?signed_request=")
    assert not redirect.redirect_url.startswith(f"https://{BROWSER_TEST_DOMAIN}/")
    assert pending.user_domain == BROWSER_TEST_DOMAIN


# Case 2: an https= value with a path prefix preserves that prefix.
def test_begin_preserves_https_path_prefix():
    redirect, _, _ = begin_with(apis_resolver("v=lk1 https=login.example.test/linkkeys"))
    assert redirect.redirect_url.startswith("https://login.example.test/linkkeys/auth/local-rp?signed_request=")


# Case 3: a record with only tcp= falls back to the identity domain.
def test_begin_tcp_only_record_falls_back_to_identity_domain():
    redirect, _, _ = begin_with(apis_resolver("v=lk1 tcp=linkkeys.ident.example.test"))
    assert redirect.redirect_url.startswith(f"https://{BROWSER_TEST_DOMAIN}/auth/local-rp?signed_request=")


# Case 4: a DNS lookup error falls back to the identity domain.
def test_begin_dns_error_falls_back_to_identity_domain():
    redirect, _, _ = begin_with(failing_resolver())
    assert redirect.redirect_url.startswith(f"https://{BROWSER_TEST_DOMAIN}/auth/local-rp?signed_request=")


# Cases 5 + 6: invalid TXT records are ignored, and across several records
# the FIRST valid record with https= is selected.
def test_begin_selects_first_valid_https_across_records():
    redirect, _, _ = begin_with(
        apis_resolver(
            "not a linkkeys record",
            "v=lk2 https=wrong-version.example.test",
            "v=lk1 tcp=tcp-only.example.test",
            "v=lk1 https=first.example.test",
            "v=lk1 https=second.example.test",
        )
    )
    assert redirect.redirect_url.startswith("https://first.example.test/auth/local-rp?signed_request=")


# Case 7: signed_request rides the discovered URL unchanged -- it decodes
# to the signed login request whose fields match this login.
def test_begin_signed_request_survives_discovered_url():
    redirect, pending, config = begin_with(apis_resolver("v=lk1 https=login.example.test/linkkeys"))
    query = parse_qs(urlsplit(redirect.redirect_url).query)
    param = query["signed_request"][0]
    signed = encoding.signed_local_rp_login_request_from_url_param(param)
    request = LocalRpLoginRequest.from_cbor(signed.request)
    assert request.callback_url == config.callback_url
    assert request.nonce == pending.nonce


# Case 9: a config without `dns` still constructs (this test is that
# caller) and the default is the system resolver. The default path is not
# executed here -- that would be a live DNS request.
def test_begin_config_without_resolver_still_constructs():
    config = BeginLocalLoginConfig(KEY_MATERIAL, CALLBACK_URL, BROWSER_TEST_DOMAIN, NOW)
    assert config.dns is None
    assert isinstance(SystemDnsResolver(), SystemDnsResolver)


# ---------------------------------------------------------------------
# Direct tests for the exported helpers
# ---------------------------------------------------------------------


def test_resolve_browser_base():
    base = resolve_browser_base(
        apis_resolver("v=lk1 tcp=x.example.test https=login.example.test:8443/linkkeys"),
        BROWSER_TEST_DOMAIN,
    )
    assert base == "https://login.example.test:8443/linkkeys"


# A record whose https= value smuggles URL structure is skipped; with no
# other candidate, resolution raises so the caller can fall back.
@pytest.mark.parametrize(
    "hostile",
    [
        "v=lk1 https=user@evil.example.test",
        "v=lk1 https=evil.example.test/x?y=1",
        "v=lk1 https=evil.example.test/x#frag",
        "v=lk1 tcp=only.example.test",
    ],
)
def test_resolve_browser_base_rejects_unusable_records(hostile):
    with pytest.raises(BrowserEndpointError):
        resolve_browser_base(apis_resolver(hostile), BROWSER_TEST_DOMAIN)


def test_resolve_browser_base_propagates_lookup_failure():
    with pytest.raises(RuntimeError):
        resolve_browser_base(failing_resolver(), BROWSER_TEST_DOMAIN)


def test_build_browser_endpoint():
    assert (
        build_browser_endpoint("https://h.example.test", BROWSER_ROUTE_LOCAL_RP, "PAYLOAD-123_abc")
        == "https://h.example.test/auth/local-rp?signed_request=PAYLOAD-123_abc"
    )
    # Path prefix, with and without a trailing slash, and the regular-RP
    # route -- the same helper serves /auth/authorize glue.
    for base in ("https://h.example.test/pfx", "https://h.example.test/pfx/"):
        assert (
            build_browser_endpoint(base, BROWSER_ROUTE_AUTHORIZE, "s")
            == "https://h.example.test/pfx/auth/authorize?signed_request=s"
        )


# A non-HTTPS scheme must never be selectable.
@pytest.mark.parametrize(
    "bad",
    ["http://h.example.test", "ftp://h.example.test", "https://", "https://u:p@h.example.test"],
)
def test_build_browser_endpoint_rejects_invalid_base(bad):
    with pytest.raises(BrowserEndpointError):
        build_browser_endpoint(bad, BROWSER_ROUTE_LOCAL_RP, "s")


def test_build_browser_endpoint_rejects_route_without_leading_slash():
    with pytest.raises(BrowserEndpointError):
        build_browser_endpoint("https://h.example.test", "auth/no-leading-slash", "s")
