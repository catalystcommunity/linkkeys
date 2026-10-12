//! DNS-less local RP sign-in through the browser app
//! (`dns-less-local-rp-design.md` at the repo root).
//!
//! `GET /auth/local-rp` verifies the local app's signed request and hands it
//! to the browser app in the URL fragment. The app signs the person in, then
//! calls `BrowserAuthorization/inspect-local-rp` and `complete-local-rp`.
//! Every check runs again on each call; nothing from an earlier step is
//! trusted.
//!
//! Differences from the DNS-pinned flow, all deliberate (see the design doc):
//! - The local RP's descriptor carries its own keys (self-signed, SSH-host
//!   style), so there is no DNS/HTTP key fetch. Every check here is local
//!   and synchronous.
//! - Domain admission policy (`disabled` / `admin-approval-required` /
//!   `allow-by-default`) and per-fingerprint approval status gate the flow
//!   before consent is shown. An unknown fingerprint under
//!   `admin-approval-required` ends as "pending", not a redirect.
//! - The callback carries a claim-get ticket, not claims: on approval this
//!   module issues a ticket (`crate::services::local_rp::issue_ticket`),
//!   builds and domain-signs a `LocalRpCallbackPayload`, seals it with the
//!   negotiated AEAD suite, and redirects with `encrypted_token=`.
//! - A missing or declined required claim is an error here (no redirect),
//!   unlike the DNS flow, which narrows the authorized set and lets the RP
//!   decide.
//!
//! Errors carry a stable reason code as their message (`reason::*`). The
//! browser app shows the matching catalog text (`app.error.reason.<code>`).

use base64ct::{Base64UrlUnpadded, Encoding as _};
use rand::Rng;
use rocket::response::Redirect;
use rocket::State;

use crate::conversions::get_domain_name;
use crate::db::models::{BrowserSession, LocalRp, User};
use crate::db::DbPool;

use liblinkkeys::crypto::AeadSuite;
use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    BrowserLocalRpCompleteRequest, BrowserLocalRpCompleteResponse, BrowserLocalRpInspectResponse,
    ClaimRequest, LocalRpDescriptor, LocalRpLoginRequest, RequestedClaim,
};
use liblinkkeys::local_rp::LocalRpError;

use super::nonce_store;

/// Lifetime of the encrypted callback payload (Wire Precision: "callback
/// lifetime is short, default 5 minutes").
const LOCAL_RP_CALLBACK_TTL_SECONDS: i64 = 300;

/// Lifetime of an issued claim-get ticket (design doc: "Valid for a bounded
/// window, default 1 hour").
const LOCAL_RP_TICKET_TTL_SECONDS: i64 = 3600;

/// Reason codes for a refused local-app sign-in. They are part of the
/// browser contract: `/app/error?reason=<code>` and the `message` of a
/// refused `inspect-local-rp` / `complete-local-rp` call.
pub(super) mod reason {
    pub const MALFORMED: &str = "malformed";
    pub const SIGNATURE_INVALID: &str = "signature_invalid";
    pub const EXPIRED: &str = "expired";
    pub const BAD_SCHEME: &str = "bad_scheme";
    pub const NO_COMMON_SUITE: &str = "no_common_suite";
    pub const POLICY_DISABLED: &str = "policy_disabled";
    pub const REJECTED: &str = "rejected";
    pub const PENDING_CAP_REACHED: &str = "pending_cap_reached";
    pub const REQUIRED_CLAIM_MISSING: &str = "required_claim_missing";
    pub const REPLAYED: &str = "replayed";
    pub const ASSURANCE: &str = "assurance";
    pub const SESSION_ENDED: &str = "session_ended";
    pub const ACCOUNT_BLOCKED: &str = "account_blocked";
    pub const INTERNAL: &str = "internal";
}

fn refused(code: i32, reason: &str) -> ServiceError {
    ServiceError {
        code,
        message: reason.to_string(),
    }
}

// ---------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------

/// True when `url` starts with an `http://` or `https://` scheme, exactly
/// (Wire Precision / "Callback URL Rules": every other scheme — `javascript:`,
/// `data:`, custom app schemes — is rejected outright).
fn callback_scheme_ok(url: &str) -> bool {
    match url.split_once("://") {
        Some((scheme, _)) => {
            let scheme = scheme.to_ascii_lowercase();
            scheme == "http" || scheme == "https"
        }
        None => false,
    }
}

/// The host (and port, if present) a callback URL will be sent back to, for
/// consent-screen display only (Consent UI Requirements: "the callback host
/// the browser will be sent back to"). Never used for a security decision:
/// the signed payload carries the authoritative `callback_url`.
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let host_with_extras = after_scheme.split(['/', '?', '#']).next()?;
    let host = host_with_extras
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(host_with_extras);
    (!host.is_empty()).then(|| host.to_string())
}

/// Decode and fully verify a `signed_request`: envelope signature, nested
/// descriptor (signature, fingerprint binding), timestamps (request and
/// descriptor, clock-skew tolerant), callback URL scheme, and AEAD suite
/// negotiability.
fn validate_signed_local_rp_request(
    signed_request: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(LocalRpLoginRequest, LocalRpDescriptor, AeadSuite), &'static str> {
    let signed =
        liblinkkeys::encoding::signed_local_rp_login_request_from_url_param(signed_request)
            .map_err(|_| reason::MALFORMED)?;

    let request = liblinkkeys::local_rp::verify_local_rp_login_request(
        &signed,
        now,
        liblinkkeys::local_rp::DEFAULT_CLOCK_SKEW_SECONDS,
    )
    .map_err(|e| match e {
        LocalRpError::Decode(_) => reason::MALFORMED,
        LocalRpError::Expired | LocalRpError::NotYetValid => reason::EXPIRED,
        _ => reason::SIGNATURE_INVALID,
    })?;

    let descriptor =
        liblinkkeys::generated::decode_local_rp_descriptor(&request.descriptor.descriptor)
            .map_err(|_| reason::MALFORMED)?;

    if !callback_scheme_ok(&request.callback_url) {
        return Err(reason::BAD_SCHEME);
    }

    let suite =
        AeadSuite::select_supported(&descriptor.supported_suites).ok_or(reason::NO_COMMON_SUITE)?;

    Ok((request, descriptor, suite))
}

/// Pre-authentication gate: policy-disabled and denied/revoked fingerprints
/// are refused before the person is asked to sign in (design doc step 8
/// happens before step 9's "user authenticates and consents").
fn precheck_local_rp_gate(pool: &DbPool, fingerprint: &str) -> Result<(), &'static str> {
    let policy = pool
        .effective_local_rp_policy()
        .map_err(|_| reason::INTERNAL)?;
    if policy == crate::db::local_rp::POLICY_DISABLED {
        return Err(reason::POLICY_DISABLED);
    }
    if let Some(rp) = pool
        .find_local_rp(fingerprint)
        .map_err(|_| reason::INTERNAL)?
    {
        if rp.status == crate::db::local_rp::STATUS_DENIED
            || rp.status == crate::db::local_rp::STATUS_REVOKED
        {
            return Err(reason::REJECTED);
        }
    }
    Ok(())
}

/// Outcome of resolving an authenticated attempt against domain policy and
/// the local RP approval registry (design doc step 8, post-authentication
/// half).
enum Admission {
    Approved(Box<LocalRp>),
    Pending,
    Refused(&'static str),
}

/// Resolve admission for an authenticated person's attempt (call only after
/// the caller has authenticated `user_id`): applies domain policy plus the
/// pending-queue guard / allow-by-default auto-approval from
/// `crate::services::local_rp`, per the design's status matrix:
/// disabled -> refuse; denied/revoked fingerprint -> refuse; approved
/// fingerprint -> continue; unknown fingerprint -> pending (admin-approval)
/// or auto-approved (allow-by-default); known-but-pending fingerprint ->
/// refresh last-seen/drift and stay pending (unless an admin has since acted).
fn resolve_local_rp_admission(
    pool: &DbPool,
    user_id: &str,
    descriptor: &LocalRpDescriptor,
) -> Admission {
    use crate::db::local_rp::{
        POLICY_ALLOW_BY_DEFAULT, POLICY_DISABLED, STATUS_APPROVED, STATUS_DENIED, STATUS_REVOKED,
    };
    use crate::services::local_rp::{PendingAttemptError, PendingAttemptOutcome};

    let terminal = |status: &str| status == STATUS_DENIED || status == STATUS_REVOKED;
    let policy = match pool.effective_local_rp_policy() {
        Ok(p) => p,
        Err(_) => return Admission::Refused(reason::INTERNAL),
    };
    if policy == POLICY_DISABLED {
        return Admission::Refused(reason::POLICY_DISABLED);
    }
    let existing = match pool.find_local_rp(&descriptor.fingerprint) {
        Ok(e) => e,
        Err(_) => return Admission::Refused(reason::INTERNAL),
    };
    let record_attempt = || {
        crate::services::local_rp::record_login_attempt(
            pool,
            user_id,
            &descriptor.fingerprint,
            &descriptor.signing_public_key,
            &descriptor.encryption_public_key,
            &descriptor.app_name,
            descriptor.local_domain_hint.as_deref(),
        )
    };

    match existing {
        Some(rp) if terminal(&rp.status) => Admission::Refused(reason::REJECTED),
        Some(rp) if rp.status == STATUS_APPROVED => Admission::Approved(Box::new(rp)),
        // Already known and pending: refresh last-seen/drift, then re-check
        // the status, because an admin may have acted between attempts.
        Some(_) => match record_attempt() {
            Ok(PendingAttemptOutcome::Refreshed { local_rp, drift }) => {
                if !drift.is_empty() {
                    log::warn!(
                        "local RP {} metadata drift on repeat attempt: {:?}",
                        descriptor.fingerprint,
                        drift.iter().map(|d| d.field).collect::<Vec<_>>()
                    );
                }
                if local_rp.status == STATUS_APPROVED {
                    Admission::Approved(Box::new(local_rp))
                } else if terminal(&local_rp.status) {
                    Admission::Refused(reason::REJECTED)
                } else {
                    Admission::Pending
                }
            }
            Ok(PendingAttemptOutcome::Created(_)) => Admission::Pending,
            Err(_) => Admission::Refused(reason::INTERNAL),
        },
        None if policy == POLICY_ALLOW_BY_DEFAULT => {
            match crate::services::local_rp::record_allow_by_default_login(
                pool,
                user_id,
                &descriptor.fingerprint,
                &descriptor.signing_public_key,
                &descriptor.encryption_public_key,
                &descriptor.app_name,
                descriptor.local_domain_hint.as_deref(),
            ) {
                Ok(rp) if rp.status == STATUS_APPROVED => Admission::Approved(Box::new(rp)),
                Ok(rp) if terminal(&rp.status) => Admission::Refused(reason::REJECTED),
                Ok(_) => Admission::Pending,
                Err(_) => Admission::Refused(reason::INTERNAL),
            }
        }
        None => match record_attempt() {
            Ok(_) => Admission::Pending,
            Err(
                PendingAttemptError::PendingCapReached
                | PendingAttemptError::PerUserPendingCapReached,
            ) => Admission::Refused(reason::PENDING_CAP_REACHED),
            Err(_) => Admission::Refused(reason::INTERNAL),
        },
    }
}

// ---------------------------------------------------------------------
// Claim request / standing grant
// ---------------------------------------------------------------------

/// Build a `ClaimRequest` from a `LocalRpLoginRequest`'s bare
/// `required_claims`/`requested_claims` lists, with each type's datatype from
/// this domain's registry (plain text for an unregistered type), so the
/// shared consent machinery (`liblinkkeys::consent`) applies unchanged.
fn build_claim_request(pool: &DbPool, requested: &[String], required: &[String]) -> ClaimRequest {
    use std::collections::BTreeSet;

    let required_set: BTreeSet<&str> = required.iter().map(String::as_str).collect();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut req_list = Vec::new();
    let mut opt_list = Vec::new();
    for ct in required.iter().chain(requested.iter()) {
        if !seen.insert(ct.as_str()) {
            continue;
        }
        let rc = RequestedClaim {
            claim_type: ct.clone(),
            datatype: pool
                .find_claim_policy(ct)
                .ok()
                .flatten()
                .map(|p| p.value_type)
                .unwrap_or_else(|| "text".to_string()),
        };
        if required_set.contains(ct.as_str()) {
            req_list.push(rc);
        } else {
            opt_list.push(rc);
        }
    }
    ClaimRequest {
        required: req_list,
        optional: opt_list,
    }
}

/// The claims a silent completion may release: a normal (not claims_update)
/// request that a standing grant, or admin policy forcing every required
/// claim, already covers, with a value for every authorized required claim.
fn silent_authorization(
    pool: &DbPool,
    user_id: &str,
    request: &LocalRpLoginRequest,
    fingerprint: &str,
    req: &ClaimRequest,
    policy: &liblinkkeys::consent::DomainPolicy,
) -> Option<Vec<String>> {
    if request
        .flow_context
        .as_ref()
        .is_some_and(|context| context.flow == "claims_update")
    {
        return None;
    }
    let prior = pool
        .find_active_consent_grant(user_id, fingerprint)
        .ok()
        .flatten();
    let admin_covers_all_required = !req.required.is_empty()
        && req
            .required
            .iter()
            .all(|claim| policy.forced_allow.contains(&claim.claim_type));
    if prior.is_none() && !admin_covers_all_required {
        return None;
    }
    let prior_claims = prior
        .as_ref()
        .map(|grant| grant.claim_types.as_slice())
        .unwrap_or(&[]);
    let authorized = liblinkkeys::consent::compute_authorized_claims(req, prior_claims, policy);
    if !super::all_required_authorized(req, &authorized)
        || super::first_authorized_required_without_value(pool, user_id, req, &authorized).is_some()
    {
        return None;
    }
    super::filter_authorized_to_active_values(pool, user_id, &authorized).ok()
}

// ---------------------------------------------------------------------
// Browser contract
// ---------------------------------------------------------------------

/// Check the person and their browser session before any local-app work.
fn check_person(
    pool: &DbPool,
    user: &User,
    session: &BrowserSession,
    request: &LocalRpLoginRequest,
) -> Result<User, ServiceError> {
    let fresh = pool
        .find_user_by_id(&user.id)
        .map_err(|_| refused(403, reason::SESSION_ENDED))?;
    if !fresh.is_active || fresh.purged_at.is_some() {
        return Err(refused(403, reason::SESSION_ENDED));
    }
    if fresh.is_admin_account {
        return Err(refused(403, reason::ACCOUNT_BLOCKED));
    }
    if !crate::services::browser_session::valid_digest_for_user(
        pool,
        &session.token_digest,
        &fresh.id,
    )
    .unwrap_or(false)
    {
        return Err(refused(403, reason::SESSION_ENDED));
    }
    let requirement = crate::services::auth::resolve_assurance_requirement(
        request.authentication_requirements.as_ref(),
        1,
    )
    .map_err(|_| refused(400, reason::ASSURANCE))?;
    if !crate::services::auth::evidence_satisfies(&super::session_evidence(session)?, requirement) {
        return Err(refused(403, reason::ASSURANCE));
    }
    Ok(fresh)
}

/// `BrowserAuthorization/inspect-local-rp`.
pub(super) fn inspect(
    pool: &DbPool,
    user: &User,
    session: &BrowserSession,
    signed_request: &str,
) -> Result<BrowserLocalRpInspectResponse, ServiceError> {
    let (request, descriptor, _suite) =
        validate_signed_local_rp_request(signed_request, chrono::Utc::now())
            .map_err(|r| refused(400, r))?;
    let user = check_person(pool, user, session, &request)?;
    let callback_host =
        extract_host(&request.callback_url).unwrap_or_else(|| request.callback_url.clone());
    let rp = match resolve_local_rp_admission(pool, &user.id, &descriptor) {
        Admission::Refused(r) => return Err(refused(403, r)),
        Admission::Pending => {
            return Ok(BrowserLocalRpInspectResponse {
                admission: "pending".to_string(),
                app_name: descriptor.app_name,
                fingerprint: descriptor.fingerprint,
                callback_host,
                first_seen_at: None,
                claims: Vec::new(),
                request_reason: None,
                already_consented: None,
                authorized_claims: None,
            })
        }
        Admission::Approved(rp) => rp,
    };
    let req = build_claim_request(pool, &request.requested_claims, &request.required_claims);
    let policy = super::domain_policy_for(pool, &descriptor.fingerprint)
        .map_err(|_| refused(500, reason::INTERNAL))?;
    let authorized_claims = silent_authorization(
        pool,
        &user.id,
        &request,
        &descriptor.fingerprint,
        &req,
        &policy,
    );
    Ok(BrowserLocalRpInspectResponse {
        admission: "consent".to_string(),
        claims: super::consent_claims(pool, &user.id, &descriptor.fingerprint, &req, &policy),
        app_name: descriptor.app_name,
        fingerprint: descriptor.fingerprint,
        callback_host,
        first_seen_at: Some(rp.created_at),
        request_reason: request
            .flow_context
            .and_then(|context| context.request_reason),
        already_consented: authorized_claims.as_ref().map(|_| true),
        authorized_claims,
    })
}

/// `BrowserAuthorization/complete-local-rp`.
pub(super) fn complete(
    pool: &DbPool,
    nonces: &nonce_store::NonceStore,
    user: &User,
    session: &BrowserSession,
    value: BrowserLocalRpCompleteRequest,
) -> Result<BrowserLocalRpCompleteResponse, ServiceError> {
    let (request, descriptor, suite) =
        validate_signed_local_rp_request(&value.signed_request, chrono::Utc::now())
            .map_err(|r| refused(400, r))?;
    let user = check_person(pool, user, session, &request)?;

    // The admission policy or the app's status may have changed since the
    // consent screen was shown.
    match pool.effective_local_rp_policy() {
        Ok(p) if p == crate::db::local_rp::POLICY_DISABLED => {
            return Err(refused(403, reason::POLICY_DISABLED))
        }
        Ok(_) => {}
        Err(_) => return Err(refused(500, reason::INTERNAL)),
    }
    match pool.find_local_rp(&descriptor.fingerprint) {
        Ok(Some(rp)) if rp.status == crate::db::local_rp::STATUS_APPROVED => {}
        _ => return Err(refused(403, reason::REJECTED)),
    }

    let req = build_claim_request(pool, &request.requested_claims, &request.required_claims);
    let policy = super::domain_policy_for(pool, &descriptor.fingerprint)
        .map_err(|_| refused(500, reason::INTERNAL))?;
    let authorized = if value.use_standing_grant == Some(true) {
        if !value.claim_types_to_set.is_empty() || !value.claim_values_to_set.is_empty() {
            return Err(refused(400, reason::MALFORMED));
        }
        silent_authorization(
            pool,
            &user.id,
            &request,
            &descriptor.fingerprint,
            &req,
            &policy,
        )
        .ok_or_else(|| ServiceError {
            code: 400,
            message: "The saved approval no longer covers this request".to_string(),
        })?
    } else {
        let authorized = liblinkkeys::consent::compute_authorized_claims(
            &req,
            &value.authorized_claims,
            &policy,
        );
        super::store_inline_claim_values(
            pool,
            &user.id,
            &req,
            &authorized,
            &value.claim_types_to_set,
            &value.claim_values_to_set,
        )
        .map_err(|message| ServiceError { code: 400, message })?
    };
    let redirect_url = finalize_local_rp_login(
        pool,
        nonces,
        &user,
        &session.token_digest,
        &request,
        &descriptor,
        suite,
        &req,
        &authorized,
    )?;
    Ok(BrowserLocalRpCompleteResponse { redirect_url })
}

/// Complete an approved local-RP sign-in: enforce the required-claims gate
/// (a missing/declined required claim is an error, no redirect), burn the
/// request's single-use nonce, persist a standing consent grant (audience =
/// the local RP fingerprint, so a repeat sign-in can skip consent), issue a
/// claim-get ticket, build and sign the callback payload, seal it with the
/// negotiated AEAD suite, and produce the callback redirect URL.
#[allow(clippy::too_many_arguments)]
fn finalize_local_rp_login(
    pool: &DbPool,
    nonces: &nonce_store::NonceStore,
    user: &User,
    browser_session_digest: &str,
    request: &LocalRpLoginRequest,
    descriptor: &LocalRpDescriptor,
    suite: AeadSuite,
    req: &ClaimRequest,
    authorized_claims: &[String],
) -> Result<String, ServiceError> {
    let internal = |_| refused(500, reason::INTERNAL);
    if !request
        .required_claims
        .iter()
        .all(|rc| authorized_claims.iter().any(|a| a == rc))
    {
        return Err(refused(400, reason::REQUIRED_CLAIM_MISSING));
    }
    // The session may have ended while the claim values were stored.
    if !crate::services::browser_session::valid_digest_for_user(
        pool,
        browser_session_digest,
        &user.id,
    )
    .unwrap_or(false)
    {
        return Err(refused(403, reason::SESSION_ENDED));
    }

    // Single-use: burn the nonce now, at ticket issuance, so an abandoned
    // consent screen does not consume the request early. Scoped to the
    // descriptor's fingerprint so two unrelated local RPs that choose
    // colliding nonce bytes cannot burn each other's sign-in.
    let nonce_key = format!(
        "local-rp:{}:{}",
        descriptor.fingerprint,
        Base64UrlUnpadded::encode_string(&request.nonce)
    );
    if !nonces.record(&nonce_key) {
        return Err(refused(400, reason::REPLAYED));
    }

    let requested = super::requested_types(req);
    if !requested.is_empty() {
        let now = chrono::Utc::now();
        let issued_at = now.to_rfc3339();
        let expires_at =
            (now + chrono::Duration::seconds(super::consent_ttl_seconds())).to_rfc3339();
        let grant_id = uuid::Uuid::now_v7().to_string();
        let signed = super::sign_consent_grant_for_user(
            pool,
            &grant_id,
            &user.id,
            &descriptor.fingerprint,
            authorized_claims,
            &issued_at,
            &expires_at,
        )
        .map_err(|_| refused(500, reason::INTERNAL))?;
        let grant_bytes = liblinkkeys::generated::encode_signed_consent_grant(&signed);
        pool.upsert_consent_grant(
            &grant_id,
            &user.id,
            &get_domain_name(),
            &descriptor.fingerprint,
            authorized_claims,
            &requested,
            &grant_bytes,
            None,
            &issued_at,
            &expires_at,
        )
        .map_err(internal)?;
    }

    // The claim-get ticket: 32 random bytes, opaque; only the SHA-256 hex is
    // stored (Wire Precision: "Claim ticket bytes").
    let mut raw_ticket = [0u8; 32];
    rand::thread_rng().fill(&mut raw_ticket);
    let ticket_hash = liblinkkeys::crypto::fingerprint(&raw_ticket);
    let ticket_expires_at =
        chrono::Utc::now() + chrono::Duration::seconds(LOCAL_RP_TICKET_TTL_SECONDS);
    crate::services::local_rp::issue_ticket(
        pool,
        &ticket_hash,
        &descriptor.fingerprint,
        &user.id,
        &get_domain_name(),
        authorized_claims,
        ticket_expires_at,
    )
    .map_err(|_| refused(500, reason::INTERNAL))?;

    let now = chrono::Utc::now();
    let issued_at = now.to_rfc3339();
    let expires_at = (now + chrono::Duration::seconds(LOCAL_RP_CALLBACK_TTL_SECONDS)).to_rfc3339();
    let payload = liblinkkeys::local_rp::build_local_rp_callback_payload(
        &user.id,
        &get_domain_name(),
        raw_ticket.to_vec(),
        &descriptor.fingerprint,
        &request.callback_url,
        request.nonce.clone(),
        request.state.clone(),
        &issued_at,
        &expires_at,
    );

    let domain_keys = pool.list_active_domain_keys().map_err(internal)?;
    let dk = super::pick_active_signing_key(&domain_keys).ok_or(refused(500, reason::INTERNAL))?;
    let passphrase =
        std::env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| refused(500, reason::INTERNAL))?;
    let sk_bytes =
        liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, passphrase.as_bytes())
            .map_err(|_| refused(500, reason::INTERNAL))?;
    let algorithm = liblinkkeys::crypto::SigningAlgorithm::parse_str(&dk.algorithm)
        .ok_or(refused(500, reason::INTERNAL))?;
    let signed_payload = liblinkkeys::local_rp::sign_local_rp_callback_payload(
        &payload, &dk.id, algorithm, &sk_bytes,
    )
    .map_err(|_| refused(500, reason::INTERNAL))?;

    let enc_pk: [u8; 32] = descriptor
        .encryption_public_key
        .as_slice()
        .try_into()
        .map_err(|_| refused(500, reason::INTERNAL))?;
    let encrypted = liblinkkeys::local_rp::seal_local_rp_callback(
        &signed_payload,
        suite,
        &enc_pk,
        &descriptor.fingerprint,
        request.nonce.clone(),
        request.state.clone(),
        &issued_at,
        &expires_at,
    )
    .map_err(|_| refused(500, reason::INTERNAL))?;
    let encoded = liblinkkeys::encoding::local_rp_encrypted_callback_to_url_param(&encrypted)
        .map_err(|_| refused(500, reason::INTERNAL))?;

    let separator = if request.callback_url.contains('?') {
        "&"
    } else {
        "?"
    };
    Ok(format!(
        "{}{}encrypted_token={}",
        request.callback_url, separator, encoded
    ))
}

// ---------------------------------------------------------------------
// Entry route
// ---------------------------------------------------------------------

/// The local app's entry link. Verifies the request and the pre-sign-in
/// gate, then hands the request to the browser app in the URL fragment (never
/// sent to the server again by the browser) or sends the browser to the
/// app's error page with a reason code. Never redirects to the request's
/// (unverified) callback URL.
#[rocket::get("/auth/local-rp?<signed_request>&<username>")]
pub(super) fn auth_local_rp_get(
    pool: &State<DbPool>,
    signed_request: Option<&str>,
    username: Option<&str>,
) -> Redirect {
    let error = |r: &str| Redirect::found(format!("/app/error?reason={r}"));
    let Some(sr) = signed_request else {
        return error(reason::MALFORMED);
    };
    let (request, descriptor, _) = match validate_signed_local_rp_request(sr, chrono::Utc::now()) {
        Ok(v) => v,
        Err(r) => return error(r),
    };
    if let Err(r) = precheck_local_rp_gate(pool, &descriptor.fingerprint) {
        return error(r);
    }
    match crate::services::auth::resolve_assurance_requirement(
        request.authentication_requirements.as_ref(),
        1,
    ) {
        Ok(requirement) if crate::services::auth::provider_can_satisfy(requirement) => {}
        _ => return error(reason::ASSURANCE),
    }
    let username_query = username
        .filter(|value| !value.is_empty())
        .map(|value| format!("?username={}", urlencoding::encode(value)))
        .unwrap_or_default();
    Redirect::found(format!(
        "/app/local-rp{username_query}#request={}",
        urlencoding::encode(sr)
    ))
}
