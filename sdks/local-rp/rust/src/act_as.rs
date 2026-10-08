//! Act-as grants, grantee side (`docs/spec/reserved/act-as-grants.md`).
//!
//! A user lets this local RP (the grantee) act as the user at an enrolled
//! application (the audience). A local RP can only be a grantee: a peer
//! cannot resolve a local RP's keys through DNS, so a local RP is never an
//! audience. The user's home domain must already have approved this local
//! RP, and its local-RP policy must admit local-RP grantees.
//!
//! The flow:
//!
//! 1. [`begin_act_as`] signs an `ActAsGrantRequest` around the audience's
//!    signed scope set and returns the browser redirect to the home domain's
//!    `/auth/act-as` route, plus a [`PendingActAs`] the app persists.
//! 2. The home domain shows the user a consent page, then redirects the
//!    browser to the callback URL with `act_as_grant_id` and `nonce`.
//!    [`complete_act_as_callback`] checks the nonce and returns the grant id.
//! 3. [`refresh_act_as_grant`] fetches the grant (and later renews it) with
//!    the `ActAs/refresh-grant` operation over the same DNS-pinned TCP
//!    CSIL-RPC path that claim-ticket redemption uses.
//! 4. [`present_act_as`] signs one presentation for one call to the
//!    audience and returns the `ActAsCredential` to send with that call.
//!
//! Every signature is made by the descriptor signing key and covers
//! `CBOR([tag, payload_bytes])`; the construction itself lives in
//! `liblinkkeys::act_as` (`GranteeSigner::LocalRp`), so this module only
//! assembles inputs and moves bytes.

use crate::browser::{resolve_browser_endpoint, BROWSER_ROUTE_ACT_AS};
use crate::dns::DnsResolver;
use crate::identity::LocalRpKeyMaterial;
use crate::transport::Transport;
use crate::Error;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use liblinkkeys::act_as::{self, GranteeSigner};
use liblinkkeys::generated::types::{
    ActAsCredential, ActAsGrantRequest, ActAsRefreshRequest, ApplicationRef, GranteeRef,
    SignedActAsGrant, SignedActAsGrantRequest, SignedActAsRefreshRequest,
};
use liblinkkeys::identity_input::parse_identity_input;
use liblinkkeys::local_rp::LocalRpError;
use serde::{Deserialize, Serialize};
use std::fmt;
use url::Url;

/// Default grant-request window: the request is valid for five minutes.
pub const DEFAULT_ACT_AS_REQUEST_WINDOW: Duration = Duration::seconds(300);
/// Longest grant-request window. The reference home domain refuses windows
/// longer than it keeps nonces (900 seconds).
pub const MAX_ACT_AS_REQUEST_WINDOW: Duration = Duration::seconds(900);
/// Refresh-request window: the request is valid for five minutes.
pub const ACT_AS_REFRESH_REQUEST_WINDOW: Duration = Duration::seconds(300);

fn signer(key_material: &LocalRpKeyMaterial) -> GranteeSigner<'_> {
    GranteeSigner::LocalRp {
        descriptor: &key_material.descriptor,
        fingerprint: &key_material.fingerprint,
        signing_private_key: &key_material.signing_private_key,
    }
}

/// This local RP as a grantee: its descriptor signing-key fingerprint.
pub fn local_rp_grantee(key_material: &LocalRpKeyMaterial) -> GranteeRef {
    GranteeRef {
        application: None,
        local_rp_descriptor_fingerprint: Some(key_material.fingerprint.clone()),
    }
}

fn fresh_nonce() -> String {
    let nonce: [u8; 32] = rand::random();
    Base64UrlUnpadded::encode_string(&nonce)
}

/// Sign a fully built grant request with the descriptor signing key. Most
/// callers use [`begin_act_as`]; this lower-level step exists for callers
/// that build the request themselves (and for the conformance vectors).
pub fn sign_act_as_grant_request(
    key_material: &LocalRpKeyMaterial,
    request: &ActAsGrantRequest,
) -> Result<SignedActAsGrantRequest, Error> {
    act_as::sign_grant_request(request, &signer(key_material)).map_err(Error::from)
}

/// The `signed_request` query value: base64url (no padding) of
/// `CBOR(SignedActAsGrantRequest)`.
pub fn act_as_grant_request_url_param(signed: &SignedActAsGrantRequest) -> String {
    Base64UrlUnpadded::encode_string(&liblinkkeys::generated::encode_signed_act_as_grant_request(
        signed,
    ))
}

/// Sign a fully built refresh request with the descriptor signing key.
/// [`refresh_act_as_grant`] builds and signs one for each call.
pub fn sign_act_as_refresh_request(
    key_material: &LocalRpKeyMaterial,
    request: &ActAsRefreshRequest,
) -> Result<SignedActAsRefreshRequest, Error> {
    act_as::sign_refresh_request(request, &signer(key_material)).map_err(Error::from)
}

/// Input to [`begin_act_as`].
#[derive(Clone)]
pub struct BeginActAsConfig<'a> {
    pub key_material: &'a LocalRpKeyMaterial,
    /// The user's LinkKeys login (`user@domain`) or home domain, parsed like
    /// [`crate::BeginLocalLoginConfig::user_domain`]. Only the domain is
    /// used.
    pub user_identity: String,
    /// The CBOR bytes of the `SignedActAsScopeSet` exactly as the audience
    /// returned them. They are embedded unchanged.
    pub scope_set: &'a [u8],
    /// Requested grant lifetime. `None` sets no limit from the grantee.
    pub requested_lifetime_seconds: Option<i64>,
    /// Requested renewal window. `None` means no renewal.
    pub requested_renewal_window_seconds: Option<i64>,
    /// Where the home domain sends the browser after consent. Must be
    /// `http://` or `https://`.
    pub callback_url: String,
    pub now: DateTime<Utc>,
    /// The DNS seam for browser endpoint discovery. Defaults to
    /// [`crate::default_dns_resolver`].
    pub dns: Option<&'a dyn DnsResolver>,
    /// Request window from `now`. Defaults to
    /// [`DEFAULT_ACT_AS_REQUEST_WINDOW`]; at most
    /// [`MAX_ACT_AS_REQUEST_WINDOW`].
    pub request_window: Option<Duration>,
}

impl fmt::Debug for BeginActAsConfig<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BeginActAsConfig")
            .field("key_material", &self.key_material)
            .field("user_identity", &self.user_identity)
            .field("scope_set_len", &self.scope_set.len())
            .field(
                "requested_lifetime_seconds",
                &self.requested_lifetime_seconds,
            )
            .field(
                "requested_renewal_window_seconds",
                &self.requested_renewal_window_seconds,
            )
            .field("callback_url", &self.callback_url)
            .field("now", &self.now)
            .field("dns", &self.dns.map(|_| "<injected>"))
            .field("request_window", &self.request_window)
            .finish()
    }
}

impl<'a> BeginActAsConfig<'a> {
    pub fn new(
        key_material: &'a LocalRpKeyMaterial,
        user_identity: impl Into<String>,
        scope_set: &'a [u8],
        callback_url: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            key_material,
            user_identity: user_identity.into(),
            scope_set,
            requested_lifetime_seconds: None,
            requested_renewal_window_seconds: None,
            callback_url: callback_url.into(),
            now,
            dns: None,
            request_window: None,
        }
    }
}

/// The browser redirect to the home domain's act-as consent route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActAsRedirect {
    pub redirect_url: String,
}

/// What [`begin_act_as`] returns for the app to persist until the callback.
/// Single-use: discard it after one [`complete_act_as_callback`] attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingActAs {
    /// The request nonce. The home domain echoes it to the callback.
    pub nonce: String,
    /// The user's home domain. Refresh calls go to this domain.
    pub user_domain: String,
    pub callback_url: String,
}

/// Build, sign, and encode an act-as grant request, and return the browser
/// redirect plus the pending state. The redirect host comes from
/// `_linkkeys_apis.<domain>` discovery, with a fallback to
/// `https://<domain>`, exactly as [`crate::begin_local_login`] does.
pub fn begin_act_as(config: BeginActAsConfig<'_>) -> Result<(ActAsRedirect, PendingActAs), Error> {
    if !(config.callback_url.starts_with("http://") || config.callback_url.starts_with("https://"))
    {
        return Err(Error::InvalidInput(
            "callback_url must be http:// or https://".into(),
        ));
    }
    let identity = parse_identity_input(&config.user_identity)
        .map_err(|error| Error::InvalidInput(error.to_string()))?;
    let window = config
        .request_window
        .unwrap_or(DEFAULT_ACT_AS_REQUEST_WINDOW);
    if window <= Duration::zero() || window > MAX_ACT_AS_REQUEST_WINDOW {
        return Err(Error::InvalidInput(format!(
            "request window must be between 1 and {} seconds",
            MAX_ACT_AS_REQUEST_WINDOW.num_seconds()
        )));
    }
    if config.requested_lifetime_seconds.is_some_and(|v| v <= 0) {
        return Err(Error::InvalidInput(
            "requested lifetime must be positive".into(),
        ));
    }
    if config
        .requested_renewal_window_seconds
        .is_some_and(|v| v < 0)
    {
        return Err(Error::InvalidInput(
            "requested renewal window must not be negative".into(),
        ));
    }
    let scope_set = liblinkkeys::generated::decode_signed_act_as_scope_set(config.scope_set)
        .map_err(|e| Error::Decode(format!("signed scope set: {e}")))?;

    let nonce = fresh_nonce();
    let request = ActAsGrantRequest {
        grantee: local_rp_grantee(config.key_material),
        scope_set,
        requested_lifetime_seconds: config.requested_lifetime_seconds,
        requested_renewal_window_seconds: config.requested_renewal_window_seconds,
        // A local RP has no enrolling account, so it never sends a handle claim.
        grantee_handle_claim: None,
        callback_url: config.callback_url.clone(),
        nonce: nonce.clone(),
        requested_at: act_as::format_time(config.now),
        expires_at: act_as::format_time(config.now + window),
    };
    let signed = sign_act_as_grant_request(config.key_material, &request)?;
    let param = act_as_grant_request_url_param(&signed);

    let dns: &dyn DnsResolver = match config.dns {
        Some(dns) => dns,
        None => crate::default_dns_resolver(),
    };
    let redirect_url =
        resolve_browser_endpoint(dns, &identity.domain, BROWSER_ROUTE_ACT_AS, &param)?;

    Ok((
        ActAsRedirect { redirect_url },
        PendingActAs {
            nonce,
            user_domain: identity.domain,
            callback_url: config.callback_url,
        },
    ))
}

/// Timing-safe equality. Lengths are not secret; equal-length contents are
/// compared without an early exit.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

/// Read the act-as callback. `callback` is the full URL the callback arrived
/// at, or only its query string (with or without the leading `?`). It must
/// carry exactly one `act_as_grant_id` and one `nonce`, and the nonce must
/// equal [`PendingActAs::nonce`]. Returns the grant id. Fetch the grant with
/// [`refresh_act_as_grant`].
pub fn complete_act_as_callback(pending: &PendingActAs, callback: &str) -> Result<String, Error> {
    let query = match Url::parse(callback) {
        Ok(url) => url.query().unwrap_or_default().to_string(),
        Err(_) => callback.trim_start_matches('?').to_string(),
    };
    let mut grant_id: Option<String> = None;
    let mut nonce: Option<String> = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let slot = match key.as_ref() {
            "act_as_grant_id" => &mut grant_id,
            "nonce" => &mut nonce,
            _ => continue,
        };
        if slot.is_some() {
            return Err(Error::InvalidInput(format!(
                "act-as callback repeats the {key} parameter"
            )));
        }
        *slot = Some(value.into_owned());
    }
    let nonce = nonce
        .ok_or_else(|| Error::InvalidInput("act-as callback has no nonce parameter".into()))?;
    if !constant_time_eq(nonce.as_bytes(), pending.nonce.as_bytes()) {
        return Err(Error::Verification(LocalRpError::NonceMismatch));
    }
    match grant_id {
        Some(id) if !id.is_empty() => Ok(id),
        _ => Err(Error::InvalidInput(
            "act-as callback has no act_as_grant_id parameter".into(),
        )),
    }
}

/// Input to [`refresh_act_as_grant`].
pub struct RefreshActAsGrantConfig<'a> {
    pub key_material: &'a LocalRpKeyMaterial,
    /// The user's home domain ([`PendingActAs::user_domain`]).
    pub user_domain: &'a str,
    pub grant_id: &'a str,
    pub now: DateTime<Utc>,
    /// The TCP dial seam. Defaults to [`crate::default_transport`].
    pub transport: &'a dyn Transport,
    /// The DNS seam. Defaults to [`crate::default_dns_resolver`].
    pub dns: &'a dyn DnsResolver,
}

impl<'a> RefreshActAsGrantConfig<'a> {
    pub fn new(
        key_material: &'a LocalRpKeyMaterial,
        user_domain: &'a str,
        grant_id: &'a str,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            key_material,
            user_domain,
            grant_id,
            now,
            transport: crate::default_transport(),
            dns: crate::default_dns_resolver(),
        }
    }
}

/// What [`refresh_act_as_grant`] returns.
#[derive(Debug, Clone, PartialEq)]
pub struct RefreshedActAsGrant {
    /// The current grant. Send it unchanged with every presentation.
    pub grant: SignedActAsGrant,
    /// True when the home domain signed a new grant for this call.
    pub signed: bool,
}

/// Fetch or renew a grant: `ActAs/refresh-grant` on the user's home domain,
/// over TCP CSIL-RPC pinned to the domain's DNS `fp=` set.
///
/// The SDK checks that the returned grant decodes and names the requested
/// grant id, this local RP, and the domain it called. It does not verify the
/// home domain's signature: the audience does that when it receives a
/// presentation.
pub fn refresh_act_as_grant(
    config: RefreshActAsGrantConfig<'_>,
) -> Result<RefreshedActAsGrant, Error> {
    if config.grant_id.is_empty() {
        return Err(Error::InvalidInput("grant_id must not be empty".into()));
    }
    let grantee = local_rp_grantee(config.key_material);
    let request = ActAsRefreshRequest {
        grant_id: config.grant_id.to_string(),
        grantee: grantee.clone(),
        requested_at: act_as::format_time(config.now),
        expires_at: act_as::format_time(config.now + ACT_AS_REFRESH_REQUEST_WINDOW),
        nonce: fresh_nonce(),
    };
    let signed = sign_act_as_refresh_request(config.key_material, &request)?;
    let response =
        crate::rpc::refresh_act_as_grant(config.transport, config.dns, config.user_domain, signed)?;

    let grant = act_as::decode_grant(&response.grant)?;
    if grant.grant_id != config.grant_id {
        return Err(Error::ActAs(act_as::ActAsError::Mismatch("grant_id")));
    }
    if !act_as::same_grantee(&grant.grantee, &grantee) {
        return Err(Error::ActAs(act_as::ActAsError::Mismatch("grantee")));
    }
    if !grant
        .subject_domain
        .eq_ignore_ascii_case(config.user_domain)
    {
        return Err(Error::ActAs(act_as::ActAsError::Mismatch("subject_domain")));
    }
    Ok(RefreshedActAsGrant {
        grant: response.grant,
        signed: response.signed,
    })
}

/// A signed presentation for one call to the audience.
#[derive(Debug, Clone, PartialEq)]
pub struct ActAsPresentationCredential {
    pub credential: ActAsCredential,
    /// `CBOR(ActAsCredential)`, ready to send.
    pub credential_cbor: Vec<u8>,
}

/// Sign one presentation of `grant` to `audience` for one request.
///
/// `request_digest` is defined by the audience's application protocol.
/// `nonce` must be fresh for each presentation; the audience owns replay
/// protection. `presented_at` is encoded as whole-second RFC3339 UTC.
pub fn present_act_as(
    grant: &SignedActAsGrant,
    audience: &ApplicationRef,
    request_digest: &[u8],
    presented_at: DateTime<Utc>,
    nonce: &[u8],
    key_material: &LocalRpKeyMaterial,
) -> Result<ActAsPresentationCredential, Error> {
    let credential = act_as::present(
        grant,
        audience,
        request_digest,
        presented_at,
        nonce,
        &signer(key_material),
    )?;
    let credential_cbor = liblinkkeys::generated::encode_act_as_credential(&credential);
    Ok(ActAsPresentationCredential {
        credential,
        credential_cbor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending() -> PendingActAs {
        PendingActAs {
            nonce: "expected-nonce".into(),
            user_domain: "example.test".into(),
            callback_url: "http://app.lan/cb".into(),
        }
    }

    #[test]
    fn callback_accepts_full_url_and_bare_query() {
        let p = pending();
        assert_eq!(
            complete_act_as_callback(
                &p,
                "http://app.lan/cb?act_as_grant_id=grant%2D1&nonce=expected-nonce"
            )
            .unwrap(),
            "grant-1"
        );
        assert_eq!(
            complete_act_as_callback(&p, "?nonce=expected-nonce&act_as_grant_id=g2").unwrap(),
            "g2"
        );
        assert_eq!(
            complete_act_as_callback(&p, "act_as_grant_id=g3&nonce=expected-nonce").unwrap(),
            "g3"
        );
    }

    #[test]
    fn callback_rejects_wrong_missing_or_repeated_values() {
        let p = pending();
        assert!(matches!(
            complete_act_as_callback(&p, "act_as_grant_id=g&nonce=other-nonce"),
            Err(Error::Verification(LocalRpError::NonceMismatch))
        ));
        assert!(matches!(
            complete_act_as_callback(&p, "act_as_grant_id=g&nonce=expected-nonc"),
            Err(Error::Verification(LocalRpError::NonceMismatch))
        ));
        assert!(complete_act_as_callback(&p, "act_as_grant_id=g").is_err());
        assert!(complete_act_as_callback(&p, "nonce=expected-nonce").is_err());
        assert!(complete_act_as_callback(&p, "act_as_grant_id=&nonce=expected-nonce").is_err());
        assert!(
            complete_act_as_callback(&p, "act_as_grant_id=g&nonce=other&nonce=expected-nonce")
                .is_err()
        );
    }

    #[test]
    fn constant_time_eq_matches_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
