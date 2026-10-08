//! Act-as grants: the home-domain side (docs/spec/reserved/act-as-grants.md).
//!
//! The home domain authenticates the user, shows the audience's signed scope
//! set, signs the user's decision, renews it when the user allowed renewal,
//! and publishes revocations. It never interprets a scope string, and it is
//! never in the request path between the grantee and the audience.
//!
//! The protocol rules live in `liblinkkeys::act_as`. This module adds what
//! needs state or the network: key resolution, the local-RP approval gate,
//! nonce single-use, the domain's signing keys, storage, and configuration.

use std::sync::LazyLock;

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use liblinkkeys::act_as::{
    self as aa, ActAsError, DomainTermBounds, OfferedTerms, RefreshDecision,
};
use liblinkkeys::application_keys::{self as ak, ApplicationKeyRef, InstanceRef};
use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    ActAsGrantRequest, ActAsGrantRevocation, ActAsGrantSummary, ActAsScopeSet, ApplicationRef,
    BrowserActAsCompleteRequest, BrowserActAsCompleteResponse, BrowserActAsInspectResponse,
    BrowserActAsParty, BrowserActAsScopeEntry, DomainPublicKey, GetActAsGrantRevocationsRequest,
    GetActAsGrantRevocationsResponse, GranteeRef, ListActAsGrantsResponse,
    RefreshActAsGrantRequest, RefreshActAsGrantResponse, RevokeActAsGrantRequest,
    RevokeActAsGrantResponse, RpResolveApplicationKeysRequest, SignedActAsGrant,
    SignedActAsGrantRequest,
};

use crate::conversions::get_domain_name;
use crate::db::act_as::{ActAsGrantRecord, GranteeColumns};
use crate::db::models::User;
use crate::db::DbPool;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// One `ACT_AS_DENIED_SCOPES` entry: `<audience domain>/<application id>/<scope>`,
/// where any segment may be `*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeDenial {
    pub audience_domain: String,
    pub application_id: String,
    pub scope: String,
}

impl ScopeDenial {
    fn parse(raw: &str) -> Result<Self, String> {
        let parts: Vec<&str> = raw.split('/').collect();
        let [domain, app, scope] = parts.as_slice() else {
            return Err(format!(
                "ACT_AS_DENIED_SCOPES entry {raw:?} must be <domain>/<application>/<scope>"
            ));
        };
        if domain.is_empty() || app.is_empty() || scope.is_empty() {
            return Err(format!(
                "ACT_AS_DENIED_SCOPES entry {raw:?} has an empty segment"
            ));
        }
        Ok(Self {
            // Domain names are case-insensitive. An entry written in another
            // case must still deny.
            audience_domain: domain.to_ascii_lowercase(),
            application_id: (*app).to_string(),
            scope: (*scope).to_string(),
        })
    }

    fn matches(&self, audience: &ApplicationRef, scope: &str) -> bool {
        let seg = |pattern: &str, value: &str| pattern == "*" || pattern == value;
        (self.audience_domain == "*"
            || self
                .audience_domain
                .eq_ignore_ascii_case(&audience.subject_domain))
            && seg(&self.application_id, &audience.application_id)
            && seg(&self.scope, scope)
    }
}

#[derive(Debug, Clone)]
pub struct ActAsConfig {
    pub bounds: DomainTermBounds,
    pub clock_skew_seconds: i64,
    pub denied_scopes: Vec<ScopeDenial>,
    /// How this home domain treats scope-set signatures by keys revoked since.
    pub revoked_key_policy: aa::RevokedKeyPolicy,
}

fn revoked_key_policy_from_env() -> Result<aa::RevokedKeyPolicy, String> {
    match std::env::var("ACT_AS_REVOKED_KEY_POLICY")
        .unwrap_or_default()
        .trim()
    {
        "" | "accept-before-revocation" => Ok(aa::RevokedKeyPolicy::AcceptBeforeRevocation),
        "refuse-revoked" => Ok(aa::RevokedKeyPolicy::RefuseRevoked),
        other => Err(format!(
            "ACT_AS_REVOKED_KEY_POLICY {other:?} must be accept-before-revocation or refuse-revoked"
        )),
    }
}

impl ActAsConfig {
    fn from_env() -> Result<Self, String> {
        use crate::config::nonneg_i64_env;
        let denied_scopes = std::env::var("ACT_AS_DENIED_SCOPES")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ScopeDenial::parse)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            bounds: DomainTermBounds {
                default_lifetime_seconds: nonneg_i64_env(
                    "ACT_AS_GRANT_DEFAULT_LIFETIME_SECONDS",
                    aa::DEFAULT_LIFETIME_SECONDS,
                )?,
                max_lifetime_seconds: nonneg_i64_env(
                    "ACT_AS_GRANT_MAX_LIFETIME_SECONDS",
                    aa::DEFAULT_MAX_LIFETIME_SECONDS,
                )?,
                max_renewal_window_seconds: nonneg_i64_env(
                    "ACT_AS_GRANT_MAX_RENEWAL_WINDOW_SECONDS",
                    aa::DEFAULT_MAX_RENEWAL_WINDOW_SECONDS,
                )?,
            },
            clock_skew_seconds: nonneg_i64_env("ACT_AS_CLOCK_SKEW_SECONDS", 300)?,
            denied_scopes,
            revoked_key_policy: revoked_key_policy_from_env()?,
        })
    }

    fn validate(&self) -> Result<(), String> {
        self.bounds.validate().map_err(|e| {
            format!(
                "ACT_AS_GRANT_* lifetimes are unusable: {e}. The default lifetime must be \
                 positive and not larger than the maximum."
            )
        })
    }

    fn denied(&self, audience: &ApplicationRef, scope: &str) -> bool {
        self.denied_scopes
            .iter()
            .any(|d| d.matches(audience, scope))
    }
}

static CONFIG: LazyLock<ActAsConfig> = LazyLock::new(|| {
    ActAsConfig::from_env().unwrap_or_else(|e| {
        // The startup gate turns this into a refusal to serve. This fallback
        // only keeps a mis-set variable from panicking a request thread.
        log::error!("act-as configuration is invalid: {e}");
        ActAsConfig {
            bounds: DomainTermBounds::default(),
            clock_skew_seconds: 300,
            denied_scopes: Vec::new(),
            revoked_key_policy: aa::RevokedKeyPolicy::default(),
        }
    })
});

pub fn config() -> &'static ActAsConfig {
    &CONFIG
}

/// Startup gate. The server refuses to start on an error.
pub fn validate_configuration() -> Result<(), String> {
    ActAsConfig::from_env()?.validate()
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn error(code: i32, message: impl Into<String>) -> ServiceError {
    ServiceError {
        code,
        message: message.into(),
    }
}

fn internal(context: &str, cause: impl std::fmt::Display) -> ServiceError {
    log::error!("act-as: {context}: {cause}");
    error(500, "internal error")
}

/// Protocol violations describe the caller's own request, never our state,
/// and never include key material.
fn protocol(e: ActAsError) -> ServiceError {
    match e {
        ActAsError::GrantExpired => error(403, "the grant has expired; ask the user again"),
        ActAsError::GrantRevoked => error(403, "the grant is revoked"),
        other => error(400, other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Key resolution
// ---------------------------------------------------------------------------

/// Where the home domain gets an application instance's attested keys. The
/// production source goes through the RP key cache; tests supply canned keys.
pub trait InstanceKeySource {
    /// The usable, attestation-verified keys of one instance of `app`.
    fn instance_keys(
        &self,
        app: &ApplicationRef,
        instance_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<ApplicationKeyRef>, ServiceError>;

    /// Every attestation-verified key of the instance, including keys that
    /// expired or were revoked since, each with its `revoked_at`. A scope set
    /// stays valid when the key that signed it was valid at the time.
    fn attested_instance_keys(
        &self,
        app: &ApplicationRef,
        instance_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<ApplicationKeyRef>, ServiceError> {
        self.instance_keys(app, instance_id, now)
    }

    /// The signing keys of `domain`, to verify a handle claim. An empty list
    /// means "not available": no handle is shown.
    fn domain_keys(&self, _domain: &str) -> Vec<DomainPublicKey> {
        Vec::new()
    }
}

/// Resolve keys through the RP key cache. Must run on a thread that may
/// block: a TCP dispatch thread or a `spawn_blocking` closure.
pub struct CachedKeySource<'a> {
    pub pool: &'a DbPool,
    pub net: &'a crate::net::Net,
    pub rt: &'a tokio::runtime::Handle,
}

impl CachedKeySource<'_> {
    fn verified_set(
        &self,
        app: &ApplicationRef,
        instance_id: &str,
        now: DateTime<Utc>,
    ) -> Result<ak::VerifiedApplicationKeySet, ServiceError> {
        let resolved = crate::services::rp_cache::resolve_application_keys(
            self.pool,
            self.net,
            self.rt,
            RpResolveApplicationKeysRequest {
                subject_user_id: app.subject_user_id.clone(),
                subject_domain: app.subject_domain.clone(),
                application_id: app.application_id.clone(),
                instance_id: instance_id.to_string(),
                max_cache_age_seconds: None,
            },
        )
        .map_err(|e| {
            log::warn!(
                "act-as: resolving keys for {}@{} instance {instance_id} failed: {}",
                app.application_id,
                app.subject_domain,
                e.message
            );
            error(
                400,
                "the application's keys could not be resolved from its home domain",
            )
        })?;
        let instance = InstanceRef {
            subject_user_id: &app.subject_user_id,
            subject_domain: &app.subject_domain,
            application_id: &app.application_id,
            instance_id,
        };
        Ok(ak::verify_application_key_set(
            &resolved.application_keys,
            &resolved.application_key_revocations,
            &resolved.home_domain_keys,
            &instance,
            now,
            config().clock_skew_seconds,
        ))
    }
}

impl InstanceKeySource for CachedKeySource<'_> {
    fn instance_keys(
        &self,
        app: &ApplicationRef,
        instance_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<ApplicationKeyRef>, ServiceError> {
        Ok(usable_key_refs(&self.verified_set(
            app,
            instance_id,
            now,
        )?))
    }

    fn attested_instance_keys(
        &self,
        app: &ApplicationRef,
        instance_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<ApplicationKeyRef>, ServiceError> {
        Ok(attested_key_refs(&self.verified_set(
            app,
            instance_id,
            now,
        )?))
    }

    fn domain_keys(&self, domain: &str) -> Vec<DomainPublicKey> {
        if domain == get_domain_name() {
            return self
                .pool
                .list_active_domain_keys()
                .map(|keys| keys.iter().map(Into::into).collect())
                .unwrap_or_default();
        }
        crate::services::rp_cache::resolve_domain_keys(
            self.pool,
            self.net,
            self.rt,
            liblinkkeys::generated::types::RpResolveDomainKeysRequest {
                domain: domain.to_string(),
                max_cache_age_seconds: None,
            },
        )
        .map(|r| r.keys)
        .unwrap_or_else(|e| {
            log::info!(
                "act-as: no keys for {domain} to check a handle claim: {}",
                e.message
            );
            Vec::new()
        })
    }
}

/// Every attestation-verified key of a set, with its revocation time. The
/// verifier's validity rule decides which of them may vouch for a signature.
pub fn attested_key_refs(set: &ak::VerifiedApplicationKeySet) -> Vec<ApplicationKeyRef> {
    set.keys
        .iter()
        .map(|k| ApplicationKeyRef {
            key_id: k.attestation.key_id.clone(),
            key_usage: k.attestation.key_usage.clone(),
            algorithm: k.attestation.algorithm.clone(),
            public_key: k.attestation.public_key.clone(),
            fingerprint: k.attestation.fingerprint.clone(),
            created_at: k.attestation.key_created_at.clone(),
            expires_at: k.attestation.key_expires_at.clone(),
            revoked_at: match &k.status {
                ak::KeyStatus::Revoked { revoked_at } => Some(revoked_at.clone()),
                _ => None,
            },
        })
        .collect()
}

/// The usable keys of a verified set, in the form the act-as verifiers take.
pub fn usable_key_refs(set: &ak::VerifiedApplicationKeySet) -> Vec<ApplicationKeyRef> {
    set.keys
        .iter()
        .filter(|k| k.is_usable())
        .map(|k| ApplicationKeyRef {
            key_id: k.attestation.key_id.clone(),
            key_usage: k.attestation.key_usage.clone(),
            algorithm: k.attestation.algorithm.clone(),
            public_key: k.attestation.public_key.clone(),
            fingerprint: k.attestation.fingerprint.clone(),
            created_at: k.attestation.key_created_at.clone(),
            expires_at: k.attestation.key_expires_at.clone(),
            revoked_at: None,
        })
        .collect()
}

/// The keys that may sign for `grantee`: an application instance's attested
/// keys, or nothing for a local RP (its proof carries its own descriptor).
fn grantee_keys(
    pool: &DbPool,
    keys: &dyn InstanceKeySource,
    grantee: &GranteeRef,
    proof_instance_id: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Vec<ApplicationKeyRef>, ServiceError> {
    match (
        &grantee.application,
        &grantee.local_rp_descriptor_fingerprint,
    ) {
        (Some(app), None) => {
            let instance_id =
                proof_instance_id.ok_or_else(|| protocol(ActAsError::ProofDoesNotMatchGrantee))?;
            keys.instance_keys(app, instance_id, now)
        }
        (None, Some(fingerprint)) => {
            check_local_rp_admitted(pool, fingerprint)?;
            Ok(Vec::new())
        }
        _ => Err(protocol(ActAsError::MalformedGrantee)),
    }
}

/// A local RP can be a grantee only where local RPs may log in at all, and
/// only once the domain approved it. Act-as does not create pending entries:
/// the local RP must have completed a normal login first.
fn check_local_rp_admitted(pool: &DbPool, fingerprint: &str) -> Result<(), ServiceError> {
    let policy = pool
        .effective_local_rp_policy()
        .map_err(|e| internal("reading local RP policy", e))?;
    if policy == crate::db::local_rp::POLICY_DISABLED {
        return Err(error(403, "local RP access is disabled on this domain"));
    }
    match pool
        .find_local_rp(fingerprint)
        .map_err(|e| internal("reading local RP", e))?
    {
        Some(rp) if rp.status == crate::db::local_rp::STATUS_APPROVED => Ok(()),
        _ => Err(error(
            403,
            "this local application is not approved on this domain",
        )),
    }
}

// ---------------------------------------------------------------------------
// Grant requests (browser consent)
// ---------------------------------------------------------------------------

/// The longest request window a grantee may set. Nonces are kept for this
/// long plus skew, so a replay inside any accepted window always hits a
/// recorded nonce.
pub const MAX_REQUEST_WINDOW_SECONDS: i64 = 900;

/// How long a consumed grant-request nonce must stay recorded.
pub fn nonce_ttl() -> std::time::Duration {
    std::time::Duration::from_secs(
        (MAX_REQUEST_WINDOW_SECONDS + 2 * config().clock_skew_seconds).unsigned_abs(),
    )
}

/// Refuse a signed request whose window is longer than
/// [`MAX_REQUEST_WINDOW_SECONDS`]. A longer window would let a captured
/// request be replayed for as long as its signer chose.
fn check_request_window(requested_at: &str, expires_at: &str) -> Result<(), ServiceError> {
    let window = DateTime::parse_from_rfc3339(expires_at)
        .ok()
        .zip(DateTime::parse_from_rfc3339(requested_at).ok())
        .map(|(end, start)| (end - start).num_seconds());
    if window.is_none_or(|w| w > MAX_REQUEST_WINDOW_SECONDS) {
        return Err(error(
            400,
            format!("the request window must be at most {MAX_REQUEST_WINDOW_SECONDS} seconds"),
        ));
    }
    Ok(())
}

/// An unambiguous key from text parts: each part is prefixed with its byte
/// length, so no part can absorb a neighbour's separator.
fn length_prefixed(parts: &[&str]) -> String {
    parts.iter().map(|p| format!("{}:{p};", p.len())).collect()
}

/// A grant request that passed every check that does not need the user.
pub struct ValidatedRequest {
    pub request: ActAsGrantRequest,
    pub scope_set: ActAsScopeSet,
    pub offered: OfferedTerms,
    /// Per scope-set entry, in order: true when home-domain policy removed it.
    pub removed_by_policy: Vec<bool>,
    pub grantee_label: String,
    /// Identifies the grantee and its signing key, for the nonce key.
    pub signer_key: String,
}

/// Decode and verify a `signed_request` URL parameter.
pub fn validate_request(
    pool: &DbPool,
    keys: &dyn InstanceKeySource,
    signed_request: &str,
    now: DateTime<Utc>,
) -> Result<ValidatedRequest, ServiceError> {
    let cfg = config();
    let bytes = Base64UrlUnpadded::decode_vec(signed_request)
        .map_err(|_| error(400, "the request is not valid base64url"))?;
    let signed: SignedActAsGrantRequest =
        liblinkkeys::generated::decode_signed_act_as_grant_request(&bytes)
            .map_err(|e| error(400, format!("the request does not decode: {e}")))?;

    // Find the grantee's keys from the unverified request, then verify.
    let unverified = aa::decode_grant_request(&signed).map_err(protocol)?;
    let instance_keys = grantee_keys(
        pool,
        keys,
        &unverified.grantee,
        aa::proof_instance_id(&signed.proof),
        now,
    )?;
    let request = aa::verify_grant_request(&signed, &instance_keys, now, cfg.clock_skew_seconds)
        .map_err(protocol)?;
    check_request_window(&request.requested_at, &request.expires_at)?;
    if !callback_scheme_ok(&request.callback_url) {
        return Err(error(400, "callback_url must be an http or https URL"));
    }

    // The audience's scope set, against the audience's own attested keys.
    let unverified_set =
        liblinkkeys::generated::decode_act_as_scope_set(&request.scope_set.scope_set)
            .map_err(|e| error(400, format!("the scope set does not decode: {e}")))?;
    let audience_keys = keys.attested_instance_keys(
        &unverified_set.audience,
        &request.scope_set.signer_instance_id,
        now,
    )?;
    let scope_set = aa::verify_scope_set(
        &request.scope_set,
        &unverified_set.audience,
        &audience_keys,
        cfg.revoked_key_policy,
    )
    .map_err(protocol)?;
    aa::check_scope_set_current(&scope_set, now, cfg.clock_skew_seconds).map_err(protocol)?;
    if !aa::same_grantee(&scope_set.grantee, &request.grantee) {
        return Err(protocol(ActAsError::Mismatch("scope_set.grantee")));
    }

    let offered = aa::offered_terms(
        request.requested_lifetime_seconds,
        request.requested_renewal_window_seconds,
        &cfg.bounds,
    );
    let removed_by_policy = scope_set
        .entries
        .iter()
        .map(|e| cfg.denied(&scope_set.audience, &e.scope))
        .collect();
    // An instance id and a key id are unique only inside one application, so
    // the nonce key names the whole application too.
    let (grantee_label, signer_key) = match (&request.grantee.application, &signed.proof) {
        (Some(app), proof) => (
            format!("{} ({})", app.application_id, app.subject_domain),
            length_prefixed(&[
                "app",
                &app.subject_domain,
                &app.subject_user_id,
                &app.application_id,
                proof.application_instance_id.as_deref().unwrap_or_default(),
                &proof.signature.signed_by_key_id,
            ]),
        ),
        (None, proof) => {
            let name = proof
                .local_rp_descriptor
                .as_ref()
                .and_then(|d| {
                    liblinkkeys::generated::decode_local_rp_descriptor(&d.descriptor).ok()
                })
                .map(|d| d.app_name)
                .unwrap_or_else(|| "a local application".to_string());
            (
                name,
                length_prefixed(&["local_rp", &proof.signature.signed_by_key_id]),
            )
        }
    };
    Ok(ValidatedRequest {
        request,
        scope_set,
        offered,
        removed_by_policy,
        grantee_label,
        signer_key,
    })
}

fn callback_scheme_ok(url: &str) -> bool {
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let scheme = scheme.to_ascii_lowercase();
            (scheme == "http" || scheme == "https") && !rest.is_empty()
        }
        None => false,
    }
}

fn require_grantor(user: &User) -> Result<(), ServiceError> {
    if !user.is_active || user.purged_at.is_some() {
        return Err(error(403, "this account is not active"));
    }
    if user.is_admin_account {
        return Err(error(
            403,
            "an administrator account cannot let an application act for it",
        ));
    }
    Ok(())
}

/// What the consent screen shows.
pub fn inspect(
    pool: &DbPool,
    keys: &dyn InstanceKeySource,
    user: &User,
    signed_request: &str,
    now: DateTime<Utc>,
) -> Result<BrowserActAsInspectResponse, ServiceError> {
    require_grantor(user)?;
    let v = validate_request(pool, keys, signed_request, now)?;
    let grantee_party = match &v.request.grantee.application {
        Some(app) => application_party(
            pool,
            keys,
            user,
            app,
            v.request.grantee_handle_claim.as_ref(),
        )?,
        None => local_rp_party(pool, user, &v.request.grantee, &v.grantee_label)?,
    };
    let audience_party = application_party(
        pool,
        keys,
        user,
        &v.scope_set.audience,
        v.scope_set.audience_handle_claim.as_ref(),
    )?;
    Ok(BrowserActAsInspectResponse {
        grantee: v.request.grantee.clone(),
        grantee_party,
        audience: v.scope_set.audience.clone(),
        audience_party,
        entries: v
            .scope_set
            .entries
            .iter()
            .zip(&v.removed_by_policy)
            .map(|(e, removed)| BrowserActAsScopeEntry {
                scope: e.scope.clone(),
                description: e.description.clone(),
                removed_by_policy: *removed,
            })
            .collect(),
        language: v.scope_set.language.clone(),
        default_lifetime_seconds: v.offered.default_lifetime_seconds,
        max_lifetime_seconds: v.offered.max_lifetime_seconds,
        default_renewal_window_seconds: v.offered.default_renewal_window_seconds,
        max_renewal_window_seconds: v.offered.max_renewal_window_seconds,
    })
}

// ---------------------------------------------------------------------------
// Consent-screen parties
// ---------------------------------------------------------------------------

/// Earlier act-as grants of this user that involve `domain`, or a claim
/// consent to it.
fn user_has_history_with_domain(
    pool: &DbPool,
    user: &User,
    domain: &str,
) -> Result<bool, ServiceError> {
    let grants = pool
        .list_act_as_grants_for_user(&user.id)
        .map_err(|e| internal("reading act-as grants", e))?;
    let in_grants = grants.iter().any(|g| {
        g.audience_subject_domain.eq_ignore_ascii_case(domain)
            || matches!(&g.grantee, GranteeColumns::Application { subject_domain, .. }
                if subject_domain.eq_ignore_ascii_case(domain))
    });
    if in_grants {
        return Ok(true);
    }
    Ok(pool
        .find_active_consent_grant(&user.id, domain)
        .map_err(|e| internal("reading consent grants", e))?
        .is_some())
}

/// One application on the consent screen: its domain first, the three trust
/// signals, and the handle when a signed handle claim verifies.
fn application_party(
    pool: &DbPool,
    keys: &dyn InstanceKeySource,
    user: &User,
    app: &ApplicationRef,
    handle_claim: Option<&liblinkkeys::generated::types::Claim>,
) -> Result<BrowserActAsParty, ServiceError> {
    let domain = app.subject_domain.to_ascii_lowercase();
    let handle = handle_claim.and_then(|claim| {
        let domain_keys = keys.domain_keys(&app.subject_domain);
        aa::verify_handle_claim(claim, app, &domain_keys)
            .map_err(|e| log::info!("act-as: handle claim for {domain} not shown: {e}"))
            .ok()
    });
    let operator_trusted = pool
        .list_all_trusted_issuers()
        .map_err(|e| internal("reading trusted issuers", e))?
        .iter()
        .any(|t| t.issuer_domain.eq_ignore_ascii_case(&domain));
    Ok(BrowserActAsParty {
        own_domain: domain == get_domain_name().to_ascii_lowercase(),
        user_has_history: user_has_history_with_domain(pool, user, &domain)?,
        domain_key_pinned: pool
            .find_domain_pin(&domain)
            .map_err(|e| internal("reading domain pins", e))?
            .is_some(),
        operator_trusted,
        domain: Some(domain),
        application_id: Some(app.application_id.clone()),
        subject_user_id: Some(app.subject_user_id.clone()),
        handle,
        local_rp_name: None,
        local_rp_fingerprint: None,
    })
}

/// A local-RP grantee has no domain. Its history is earlier grants to the
/// same fingerprint, and the domain already approved it, or validation would
/// have refused the request.
fn local_rp_party(
    pool: &DbPool,
    user: &User,
    grantee: &GranteeRef,
    name: &str,
) -> Result<BrowserActAsParty, ServiceError> {
    let fingerprint = grantee
        .local_rp_descriptor_fingerprint
        .clone()
        .unwrap_or_default();
    let user_has_history = pool
        .list_act_as_grants_for_user(&user.id)
        .map_err(|e| internal("reading act-as grants", e))?
        .iter()
        .any(|g| matches!(&g.grantee, GranteeColumns::LocalRp { fingerprint: f } if *f == fingerprint));
    Ok(BrowserActAsParty {
        domain: None,
        application_id: None,
        subject_user_id: None,
        handle: None,
        local_rp_name: Some(name.to_string()),
        local_rp_fingerprint: Some(fingerprint),
        own_domain: false,
        user_has_history,
        domain_key_pinned: false,
        operator_trusted: true,
    })
}

/// The user approved. Sign and store the grant, and send the browser back.
///
/// `burn_nonce` records the request nonce and returns false when it was
/// already used. It runs after every check, just before signing.
pub fn complete(
    pool: &DbPool,
    keys: &dyn InstanceKeySource,
    burn_nonce: &dyn Fn(&str) -> bool,
    user: &User,
    req: &BrowserActAsCompleteRequest,
    now: DateTime<Utc>,
) -> Result<BrowserActAsCompleteResponse, ServiceError> {
    require_grantor(user)?;
    let v = validate_request(pool, keys, &req.signed_request, now)?;
    aa::check_approved_scope(&v.scope_set, &req.approved_scope).map_err(protocol)?;
    for (entry, removed) in v.scope_set.entries.iter().zip(&v.removed_by_policy) {
        if *removed && req.approved_scope.contains(&entry.scope) {
            return Err(error(
                400,
                format!("{:?} is not allowed by this domain", entry.scope),
            ));
        }
    }
    let (lifetime, window) =
        aa::issued_terms(&v.offered, req.lifetime_seconds, req.renewal_window_seconds)
            .map_err(protocol)?;

    if !burn_nonce(&format!("act-as:{}:{}", v.signer_key, v.request.nonce)) {
        return Err(error(
            400,
            "this request was already used; start again from the application",
        ));
    }

    let grant_id = uuid::Uuid::now_v7().to_string();
    let domain = get_domain_name();
    let grant = aa::build_grant(&aa::NewGrant {
        grant_id: &grant_id,
        user_id: &user.id,
        subject_domain: &domain,
        grantee: &v.request.grantee,
        audience: &v.scope_set.audience,
        scope_set: &v.request.scope_set,
        approved_scope: &req.approved_scope,
        lifetime_seconds: lifetime,
        renewal_window_seconds: window,
        now,
    })
    .map_err(protocol)?;
    let signed = sign_grant(pool, &grant)?;
    let record = ActAsGrantRecord {
        grant_id: grant_id.clone(),
        user_id: user.id.clone(),
        grantee: grantee_columns(&grant.grantee)?,
        audience_subject_user_id: grant.audience.subject_user_id.clone(),
        audience_subject_domain: grant.audience.subject_domain.clone(),
        audience_application_id: grant.audience.application_id.clone(),
        approved_scope: grant.approved_scope.clone(),
        lifetime_seconds: lifetime,
        series_issued_at: grant.series_issued_at.clone(),
        renewable_until: grant.renewable_until.clone(),
        signed_grant: liblinkkeys::generated::encode_signed_act_as_grant(&signed),
        issued_at: grant.issued_at.clone(),
        expires_at: grant.expires_at.clone(),
        revoked_at: None,
        signed_revocation: None,
    };
    pool.insert_act_as_grant(&record)
        .map_err(|e| internal("storing act-as grant", e))?;
    log::info!(
        "act-as grant {grant_id} issued for user {} to {} at {}/{}",
        user.id,
        v.grantee_label,
        grant.audience.subject_domain,
        grant.audience.application_id
    );

    let separator = if v.request.callback_url.contains('?') {
        '&'
    } else {
        '?'
    };
    Ok(BrowserActAsCompleteResponse {
        redirect_url: format!(
            "{}{separator}act_as_grant_id={}&nonce={}",
            v.request.callback_url,
            urlencoding::encode(&grant_id),
            urlencoding::encode(&v.request.nonce)
        ),
    })
}

fn grantee_columns(grantee: &GranteeRef) -> Result<GranteeColumns, ServiceError> {
    match (
        &grantee.application,
        &grantee.local_rp_descriptor_fingerprint,
    ) {
        (Some(app), None) => Ok(GranteeColumns::Application {
            subject_user_id: app.subject_user_id.clone(),
            subject_domain: app.subject_domain.clone(),
            application_id: app.application_id.clone(),
        }),
        (None, Some(fp)) => Ok(GranteeColumns::LocalRp {
            fingerprint: fp.clone(),
        }),
        _ => Err(protocol(ActAsError::MalformedGrantee)),
    }
}

fn with_domain_signers<T>(
    pool: &DbPool,
    what: &str,
    f: impl FnOnce(&[liblinkkeys::claims::ClaimSigner<'_>]) -> Result<T, ActAsError>,
) -> Result<T, ServiceError> {
    let domain = get_domain_name();
    crate::services::warm_signer::with_active_signers(pool, |signers| {
        let claim_signers: Vec<liblinkkeys::claims::ClaimSigner<'_>> = signers
            .iter()
            .map(|s| liblinkkeys::claims::ClaimSigner {
                domain: &domain,
                key_id: s.key_id,
                algorithm: s.algorithm,
                private_key_bytes: s.private_key,
            })
            .collect();
        f(&claim_signers)
    })
    .map_err(|e| internal(what, e))?
    .map_err(|e| internal(what, e))
}

fn sign_grant(
    pool: &DbPool,
    grant: &liblinkkeys::generated::types::ActAsGrant,
) -> Result<SignedActAsGrant, ServiceError> {
    with_domain_signers(pool, "signing act-as grant", |s| aa::sign_grant(grant, s))
}

// ---------------------------------------------------------------------------
// Refresh (ActAs/refresh-grant)
// ---------------------------------------------------------------------------

pub fn refresh(
    pool: &DbPool,
    keys: &dyn InstanceKeySource,
    req: &RefreshActAsGrantRequest,
    now: DateTime<Utc>,
) -> Result<RefreshActAsGrantResponse, ServiceError> {
    let cfg = config();
    let unverified = aa::decode_refresh_request(&req.request).map_err(protocol)?;
    // One answer for "unknown" and "not yours": the caller learns nothing
    // about grants it cannot prove it holds.
    let not_found = || error(404, "no such grant for this grantee");
    let Some(record) = pool
        .find_act_as_grant(&unverified.grant_id)
        .map_err(|e| internal("reading act-as grant", e))?
    else {
        return Err(not_found());
    };
    let stored = liblinkkeys::generated::decode_signed_act_as_grant(&record.signed_grant)
        .map_err(|e| internal("decoding stored act-as grant", e))?;
    let grant = aa::decode_grant(&stored).map_err(|e| internal("decoding stored grant", e))?;
    if !aa::same_grantee(&unverified.grantee, &grant.grantee) {
        return Err(not_found());
    }
    let instance_keys = grantee_keys(
        pool,
        keys,
        &grant.grantee,
        aa::proof_instance_id(&req.request.proof),
        now,
    )?;
    let request = aa::verify_refresh_request(
        &req.request,
        &grant.grantee,
        &instance_keys,
        now,
        cfg.clock_skew_seconds,
    )
    .map_err(protocol)?;
    // The same cap as a grant request: a signed refresh request must not
    // stay replayable for longer than its signer needs to send it.
    check_request_window(&request.requested_at, &request.expires_at)?;

    if record.revoked_at.is_some() {
        return Err(protocol(ActAsError::GrantRevoked));
    }
    let user = pool
        .find_user_by_id(&record.user_id)
        .map_err(|e| internal("reading grant owner", e))?;
    if !user.is_active || user.purged_at.is_some() {
        return Err(error(403, "the user's account is not active"));
    }

    match aa::refresh_decision(&grant, record.lifetime_seconds, now).map_err(protocol)? {
        RefreshDecision::Stored => Ok(RefreshActAsGrantResponse {
            grant: stored,
            signed: false,
        }),
        RefreshDecision::Renew {
            issued_at,
            expires_at,
        } => {
            let renewed = aa::renewed_grant(&grant, issued_at.clone(), expires_at.clone());
            let signed = sign_grant(pool, &renewed)?;
            let bytes = liblinkkeys::generated::encode_signed_act_as_grant(&signed);
            let updated = pool
                .replace_current_act_as_grant(
                    &record.grant_id,
                    &bytes,
                    &issued_at,
                    &expires_at,
                    &record.expires_at,
                )
                .map_err(|e| internal("storing renewed act-as grant", e))?;
            if updated == 1 {
                return Ok(RefreshActAsGrantResponse {
                    grant: signed,
                    signed: true,
                });
            }
            // A concurrent refresh renewed first, or the user revoked. Answer
            // with whatever is stored now.
            let current = pool
                .find_act_as_grant(&record.grant_id)
                .map_err(|e| internal("re-reading act-as grant", e))?
                .ok_or_else(not_found)?;
            if current.revoked_at.is_some() {
                return Err(protocol(ActAsError::GrantRevoked));
            }
            Ok(RefreshActAsGrantResponse {
                grant: liblinkkeys::generated::decode_signed_act_as_grant(&current.signed_grant)
                    .map_err(|e| internal("decoding stored act-as grant", e))?,
                signed: false,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Public revocation read (ActAs/get-grant-revocations)
// ---------------------------------------------------------------------------

pub fn get_revocations(
    pool: &DbPool,
    req: &GetActAsGrantRevocationsRequest,
) -> Result<GetActAsGrantRevocationsResponse, ServiceError> {
    if req.grant_ids.is_empty() || req.grant_ids.len() > aa::MAX_REVOCATION_LOOKUP_IDS {
        return Err(error(
            400,
            format!(
                "ask for between 1 and {} grant ids",
                aa::MAX_REVOCATION_LOOKUP_IDS
            ),
        ));
    }
    let revocations = pool
        .act_as_grant_revocations(&req.grant_ids)
        .map_err(|e| internal("reading act-as revocations", e))?
        .iter()
        .map(|bytes| {
            liblinkkeys::generated::decode_signed_act_as_grant_revocation(bytes)
                .map_err(|e| internal("decoding stored act-as revocation", e))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(GetActAsGrantRevocationsResponse { revocations })
}

// ---------------------------------------------------------------------------
// Account self-service
// ---------------------------------------------------------------------------

pub fn list_for_user(pool: &DbPool, user: &User) -> Result<ListActAsGrantsResponse, ServiceError> {
    let grants = pool
        .list_act_as_grants_for_user(&user.id)
        .map_err(|e| internal("listing act-as grants", e))?
        .into_iter()
        .map(|r| ActAsGrantSummary {
            grant_id: r.grant_id,
            grantee: match r.grantee {
                GranteeColumns::Application {
                    subject_user_id,
                    subject_domain,
                    application_id,
                } => GranteeRef {
                    application: Some(ApplicationRef {
                        subject_user_id,
                        subject_domain,
                        application_id,
                    }),
                    local_rp_descriptor_fingerprint: None,
                },
                GranteeColumns::LocalRp { fingerprint } => GranteeRef {
                    application: None,
                    local_rp_descriptor_fingerprint: Some(fingerprint),
                },
            },
            audience: ApplicationRef {
                subject_user_id: r.audience_subject_user_id,
                subject_domain: r.audience_subject_domain,
                application_id: r.audience_application_id,
            },
            approved_scope: r.approved_scope,
            issued_at: r.issued_at,
            expires_at: r.expires_at,
            renewable_until: r.renewable_until,
            revoked_at: r.revoked_at,
        })
        .collect();
    Ok(ListActAsGrantsResponse { grants })
}

pub fn revoke_for_user(
    pool: &DbPool,
    user: &User,
    req: &RevokeActAsGrantRequest,
    now: DateTime<Utc>,
) -> Result<RevokeActAsGrantResponse, ServiceError> {
    let not_found = || error(404, "no such grant");
    let record = pool
        .find_act_as_grant(&req.grant_id)
        .map_err(|e| internal("reading act-as grant", e))?
        .filter(|r| r.user_id == user.id)
        .ok_or_else(not_found)?;
    if let Some(revoked_at) = record.revoked_at {
        return Ok(RevokeActAsGrantResponse { revoked_at });
    }
    let revoked_at = aa::format_time(now);
    let revocation = ActAsGrantRevocation {
        grant_id: record.grant_id.clone(),
        user_id: user.id.clone(),
        subject_domain: get_domain_name(),
        revoked_at: revoked_at.clone(),
    };
    let signed = with_domain_signers(pool, "signing act-as revocation", |s| {
        aa::sign_grant_revocation(&revocation, s)
    })?;
    let bytes = liblinkkeys::generated::encode_signed_act_as_grant_revocation(&signed);
    let updated = pool
        .revoke_act_as_grant(&record.grant_id, &user.id, &revoked_at, &bytes)
        .map_err(|e| internal("storing act-as revocation", e))?;
    if updated == 0 {
        // A concurrent revoke won. Report the stored time.
        let current = pool
            .find_act_as_grant(&record.grant_id)
            .map_err(|e| internal("re-reading act-as grant", e))?
            .and_then(|r| r.revoked_at)
            .ok_or_else(not_found)?;
        return Ok(RevokeActAsGrantResponse {
            revoked_at: current,
        });
    }
    log::info!(
        "act-as grant {} revoked by user {}",
        record.grant_id,
        user.id
    );
    Ok(RevokeActAsGrantResponse { revoked_at })
}

// ---------------------------------------------------------------------------
// RP forwarding (Rp/act-as-refresh-grant, Rp/resolve-act-as-revocations)
// ---------------------------------------------------------------------------

/// Forward a grantee's signed refresh to the user's home domain. When that
/// domain is this server, answer locally. Must run on a thread that may block.
pub fn rp_forward_refresh(
    pool: &DbPool,
    net: &crate::net::Net,
    rt: &tokio::runtime::Handle,
    req: liblinkkeys::generated::types::RpActAsRefreshRequest,
) -> Result<RefreshActAsGrantResponse, ServiceError> {
    let domain = req.subject_domain.trim().to_ascii_lowercase();
    if domain.is_empty() {
        return Err(error(400, "subject_domain is required"));
    }
    let request = RefreshActAsGrantRequest {
        request: req.request,
    };
    if domain == get_domain_name() {
        let keys = CachedKeySource { pool, net, rt };
        return refresh(pool, &keys, &request, Utc::now());
    }
    let payload = liblinkkeys::generated::encode_refresh_act_as_grant_request(&request);
    let bytes = remote_call(net, rt, &domain, "refresh-grant", payload)?;
    liblinkkeys::generated::decode_refresh_act_as_grant_response(&bytes)
        .map_err(|e| error(502, format!("{domain} answered with an invalid grant: {e}")))
}

/// Fetch signed grant revocations from the user's home domain. When that
/// domain is this server, answer locally. Must run on a thread that may block.
pub fn rp_resolve_revocations(
    pool: &DbPool,
    net: &crate::net::Net,
    rt: &tokio::runtime::Handle,
    req: liblinkkeys::generated::types::RpResolveActAsRevocationsRequest,
) -> Result<GetActAsGrantRevocationsResponse, ServiceError> {
    let domain = req.subject_domain.trim().to_ascii_lowercase();
    if domain.is_empty() {
        return Err(error(400, "subject_domain is required"));
    }
    let request = GetActAsGrantRevocationsRequest {
        grant_ids: req.grant_ids,
    };
    if request.grant_ids.is_empty() || request.grant_ids.len() > aa::MAX_REVOCATION_LOOKUP_IDS {
        return Err(error(
            400,
            format!(
                "ask for between 1 and {} grant ids",
                aa::MAX_REVOCATION_LOOKUP_IDS
            ),
        ));
    }
    if domain == get_domain_name() {
        return get_revocations(pool, &request);
    }
    let payload = liblinkkeys::generated::encode_get_act_as_grant_revocations_request(&request);
    let bytes = remote_call(net, rt, &domain, "get-grant-revocations", payload)?;
    liblinkkeys::generated::decode_get_act_as_grant_revocations_response(&bytes).map_err(|e| {
        error(
            502,
            format!("{domain} answered with invalid revocations: {e}"),
        )
    })
}

/// One pinned CSIL-RPC call to another domain's ActAs service.
fn remote_call(
    net: &crate::net::Net,
    rt: &tokio::runtime::Handle,
    domain: &str,
    op: &str,
    payload: Vec<u8>,
) -> Result<Vec<u8>, ServiceError> {
    rt.block_on(async {
        let (addr, hostname, fingerprints) = crate::services::rp_cache::discover(net, domain)
            .await
            .map_err(|e| {
                log::warn!("act-as: discovering {domain} failed: {e}");
                error(502, format!("{domain} could not be reached"))
            })?;
        net.rpc
            .call(
                &addr,
                &hostname,
                fingerprints,
                None,
                "ActAs",
                op,
                payload,
                None,
            )
            .await
            .map_err(|e| {
                // The remote server's own error message is safe to relay: it
                // describes the caller's request, never our state.
                log::warn!("act-as: {domain} ActAs/{op} failed: {e}");
                error(502, format!("{domain}: {e}"))
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(domain: &str, id: &str) -> ApplicationRef {
        ApplicationRef {
            subject_user_id: "u".into(),
            subject_domain: domain.into(),
            application_id: id.into(),
        }
    }

    #[test]
    fn scope_denials_match_with_wildcards() {
        let d = ScopeDenial::parse("bank.example/*/transfer").unwrap();
        assert!(d.matches(&app("bank.example", "payments"), "transfer"));
        assert!(!d.matches(&app("bank.example", "payments"), "read"));
        assert!(!d.matches(&app("other.example", "payments"), "transfer"));
        let all = ScopeDenial::parse("*/*/admin").unwrap();
        assert!(all.matches(&app("x", "y"), "admin"));
    }

    #[test]
    fn scope_denial_domains_ignore_case() {
        let d = ScopeDenial::parse("Bank.Example/payments/transfer").unwrap();
        assert!(d.matches(&app("bank.example", "payments"), "transfer"));
        assert!(d.matches(&app("BANK.example", "payments"), "transfer"));
        assert!(!d.matches(&app("bank.example", "Payments"), "transfer"));
    }

    #[test]
    fn nonce_key_parts_cannot_run_together() {
        assert_ne!(
            length_prefixed(&["a:b", "c"]),
            length_prefixed(&["a", "b:c"])
        );
        assert_ne!(length_prefixed(&["ab", "c"]), length_prefixed(&["a", "bc"]));
    }

    #[test]
    fn request_windows_longer_than_the_cap_are_refused() {
        assert!(check_request_window("2026-10-06T12:00:00Z", "2026-10-06T12:15:00Z").is_ok());
        assert!(check_request_window("2026-10-06T12:00:00Z", "2026-10-06T12:15:01Z").is_err());
        assert!(check_request_window("not a time", "2026-10-06T12:15:00Z").is_err());
    }

    #[test]
    fn malformed_scope_denials_are_refused() {
        assert!(ScopeDenial::parse("only/two").is_err());
        assert!(ScopeDenial::parse("a//c").is_err());
        assert!(ScopeDenial::parse("a/b/c/d").is_err());
    }

    #[test]
    fn callback_scheme_must_be_http_or_https() {
        assert!(callback_scheme_ok("https://c.example/cb"));
        assert!(callback_scheme_ok("http://app.lan:8080/cb"));
        assert!(!callback_scheme_ok("javascript://alert(1)"));
        assert!(!callback_scheme_ok("https://"));
        assert!(!callback_scheme_ok("c.example/cb"));
    }
}
