//! Browser endpoint discovery: resolve an identity domain's browser-facing
//! HTTPS base from its `_linkkeys_apis` TXT record, and build browser route
//! URLs against it. Mirrors `sdks/local-rp/go/browser.go`.
//!
//! The identity domain (the domain the user selected, e.g. `todandlorna.com`)
//! is a trust and discovery domain. It is not necessarily the host that
//! serves the browser login routes — the `https=` endpoint of
//! `_linkkeys_apis.<identity-domain>` is (docs/spec/trust-and-anchors.md:
//! "`https=` is the browser-facing endpoint"). These helpers are shared by
//! [`crate::begin_local_login`] (route [`BROWSER_ROUTE_LOCAL_RP`]) and by
//! regular-RP application glue (route [`BROWSER_ROUTE_AUTHORIZE`]), so
//! discovery is implemented once.

use crate::dns::DnsResolver;
use crate::Error;
use liblinkkeys::dns::{linkkeys_apis_dns_name, parse_linkkeys_apis_txt};
use url::Url;

/// The browser route for the DNS-less local-RP login flow.
pub const BROWSER_ROUTE_LOCAL_RP: &str = "/auth/local-rp";

/// The browser route where a grantee asks the user for an act-as grant.
pub const BROWSER_ROUTE_ACT_AS: &str = "/auth/act-as";

/// The browser route for the regular (domain-keyed) RP login flow.
pub const BROWSER_ROUTE_AUTHORIZE: &str = "/auth/authorize";

/// Checks that `base` is a usable https browser base URL: parseable, https
/// scheme, a host, an optional path prefix, and nothing else. A TXT record
/// value must never smuggle in userinfo, a query, a fragment, or (via
/// `parse_linkkeys_apis_txt`'s unconditional `https://` prefix plus this
/// check) a non-HTTPS scheme.
fn validate_browser_base(base: &str) -> Result<Url, Error> {
    let url = Url::parse(base).map_err(|e| {
        Error::InvalidInput(format!("browser base {base:?} is not a valid URL: {e}"))
    })?;
    if url.scheme() != "https" {
        return Err(Error::InvalidInput(format!(
            "browser base {base:?} must use https"
        )));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(Error::InvalidInput(format!(
            "browser base {base:?} has no host"
        )));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::InvalidInput(format!(
            "browser base {base:?} must be host[:port][/path] only"
        )));
    }
    Ok(url)
}

/// Resolves `identity_domain`'s browser-facing HTTPS base URL (e.g.
/// `https://linkkeys.todandlorna.com` or
/// `https://login.example.com/linkkeys`) from its
/// `_linkkeys_apis.<identity_domain>` TXT record.
///
/// It selects the first LinkKeys v1 record whose `https=` endpoint is a
/// valid browser base; invalid TXT records and records without `https=` are
/// skipped. It returns an error when the lookup fails or no record yields a
/// valid base — the caller decides the fallback ([`crate::begin_local_login`]
/// falls back to `https://<identity_domain>`).
///
/// The resolved base is a service location only. Identity verification
/// stays bound to the identity domain — never bind trust decisions to the
/// host this returns.
pub fn resolve_browser_base(dns: &dyn DnsResolver, identity_domain: &str) -> Result<String, Error> {
    let name = linkkeys_apis_dns_name(identity_domain);
    let txts = dns.txt_lookup(&name)?;
    txts.iter()
        .filter_map(|txt| parse_linkkeys_apis_txt(txt).ok())
        .filter_map(|apis| apis.https_base)
        .find(|base| validate_browser_base(base).is_ok())
        .ok_or_else(|| {
            Error::Dns(format!(
                "no usable {name} TXT record with an https= endpoint"
            ))
        })
}

/// Builds the full browser URL for `route` (e.g. [`BROWSER_ROUTE_LOCAL_RP`])
/// under `browser_base`, carrying `signed_request` as the `signed_request`
/// query parameter. A path prefix in the base is preserved: base
/// `https://login.example.com/linkkeys` and route `/auth/local-rp` produce
/// `https://login.example.com/linkkeys/auth/local-rp?...`.
///
/// The URL is assembled with the `url` crate. `signed_request` values are
/// URL-param-encoded (unpadded base64url) by construction, so query encoding
/// passes them through byte-identically.
pub fn build_browser_endpoint(
    browser_base: &str,
    route: &str,
    signed_request: &str,
) -> Result<String, Error> {
    let mut url = validate_browser_base(browser_base)?;
    if !route.starts_with('/') {
        return Err(Error::InvalidInput(format!(
            "route {route:?} must start with /"
        )));
    }
    {
        // An https URL always has a path-segment view; the `?` cannot fire
        // after validate_browser_base succeeded. Appending segment-wise
        // (rather than `Url::join`) keeps the base's path prefix.
        let mut segments = url.path_segments_mut().map_err(|_| {
            Error::InvalidInput(format!("browser base {browser_base:?} cannot be a base"))
        })?;
        segments.pop_if_empty();
        segments.extend(route.split('/').filter(|s| !s.is_empty()));
    }
    url.query_pairs_mut()
        .append_pair("signed_request", signed_request);
    Ok(url.into())
}

/// The begin-flow composition: discover the identity domain's browser base
/// and build the route URL, falling back to `https://<identity_domain>` when
/// DNS lookup fails, no valid record carries `https=`, or the discovered base
/// is invalid. The fallback preserves the pre-discovery behavior, so a domain
/// that serves its browser routes at the apex keeps working without a
/// `_linkkeys_apis` record.
pub(crate) fn resolve_browser_endpoint(
    dns: &dyn DnsResolver,
    identity_domain: &str,
    route: &str,
    signed_request: &str,
) -> Result<String, Error> {
    let base = resolve_browser_base(dns, identity_domain)
        .unwrap_or_else(|_| format!("https://{identity_domain}"));
    build_browser_endpoint(&base, route, signed_request)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::dns::DnsLookupError;
    use std::collections::HashMap;

    /// Hermetic resolver with canned TXT answers per name. No test in this
    /// module performs a live DNS request.
    pub(crate) struct MapDnsResolver {
        pub records: HashMap<String, Vec<String>>,
        pub error: Option<String>,
    }

    impl MapDnsResolver {
        pub fn failing(message: &str) -> Self {
            Self {
                records: HashMap::new(),
                error: Some(message.to_string()),
            }
        }

        pub fn apis(domain: &str, txts: &[&str]) -> Self {
            let mut records = HashMap::new();
            records.insert(
                format!("_linkkeys_apis.{domain}"),
                txts.iter().map(|s| s.to_string()).collect(),
            );
            Self {
                records,
                error: None,
            }
        }
    }

    impl DnsResolver for MapDnsResolver {
        fn txt_lookup(&self, name: &str) -> Result<Vec<String>, DnsLookupError> {
            if let Some(message) = &self.error {
                return Err(DnsLookupError::Lookup(message.clone()));
            }
            self.records
                .get(name)
                .cloned()
                .ok_or_else(|| DnsLookupError::Lookup(format!("no fake record for {name}")))
        }
    }

    const DOMAIN: &str = "ident.example.test";

    #[test]
    fn resolve_browser_base_selects_valid_https_record() {
        let dns = MapDnsResolver::apis(
            DOMAIN,
            &["v=lk1 tcp=x.example.test https=login.example.test:8443/linkkeys"],
        );
        assert_eq!(
            resolve_browser_base(&dns, DOMAIN).unwrap(),
            "https://login.example.test:8443/linkkeys"
        );
    }

    #[test]
    fn resolve_browser_base_skips_hostile_records() {
        // A record whose https= value smuggles URL structure is skipped;
        // with no other candidate, resolution errors so the caller can
        // fall back.
        for hostile in [
            "v=lk1 https=user@evil.example.test",
            "v=lk1 https=evil.example.test/x?y=1",
            "v=lk1 https=evil.example.test/x#frag",
        ] {
            let dns = MapDnsResolver::apis(DOMAIN, &[hostile]);
            assert!(
                resolve_browser_base(&dns, DOMAIN).is_err(),
                "accepted hostile record {hostile:?}"
            );
        }
    }

    #[test]
    fn resolve_browser_base_errors_without_https_or_on_lookup_failure() {
        let dns = MapDnsResolver::apis(DOMAIN, &["v=lk1 tcp=only.example.test"]);
        assert!(matches!(
            resolve_browser_base(&dns, DOMAIN),
            Err(Error::Dns(_))
        ));
        let dns = MapDnsResolver::failing("SERVFAIL");
        assert!(matches!(
            resolve_browser_base(&dns, DOMAIN),
            Err(Error::Dns(_))
        ));
    }

    #[test]
    fn build_browser_endpoint_joins_base_route_and_query() {
        assert_eq!(
            build_browser_endpoint(
                "https://h.example.test",
                BROWSER_ROUTE_LOCAL_RP,
                "PAYLOAD-123_abc"
            )
            .unwrap(),
            "https://h.example.test/auth/local-rp?signed_request=PAYLOAD-123_abc"
        );
        // Path prefix, with and without a trailing slash, and the
        // regular-RP route — the same helper serves /auth/authorize glue.
        for (base, want) in [
            (
                "https://h.example.test/pfx",
                "https://h.example.test/pfx/auth/authorize?signed_request=s",
            ),
            (
                "https://h.example.test/pfx/",
                "https://h.example.test/pfx/auth/authorize?signed_request=s",
            ),
        ] {
            assert_eq!(
                build_browser_endpoint(base, BROWSER_ROUTE_AUTHORIZE, "s").unwrap(),
                want,
                "base {base:?}"
            );
        }
    }

    #[test]
    fn build_browser_endpoint_rejects_invalid_bases_and_routes() {
        // A non-HTTPS scheme must never be selectable.
        for bad in [
            "http://h.example.test",
            "ftp://h.example.test",
            "https://",
            "https://u:p@h.example.test",
        ] {
            assert!(
                build_browser_endpoint(bad, BROWSER_ROUTE_LOCAL_RP, "s").is_err(),
                "accepted invalid base {bad:?}"
            );
        }
        assert!(
            build_browser_endpoint("https://h.example.test", "auth/no-leading-slash", "s").is_err()
        );
    }

    #[test]
    fn resolve_browser_endpoint_falls_back_to_identity_domain() {
        let dns = MapDnsResolver::failing("SERVFAIL");
        assert_eq!(
            resolve_browser_endpoint(&dns, DOMAIN, BROWSER_ROUTE_LOCAL_RP, "s").unwrap(),
            format!("https://{DOMAIN}/auth/local-rp?signed_request=s")
        );
    }
}
