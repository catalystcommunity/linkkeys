// LINKKEYS-TRUST-CRITICAL: a change to this file needs a trust approval. See docs/trust-change-control.md.
//! Claim verification on the RP server, for its applications.
//!
//! - `Rp/verify-claims` ([`verify_claims`]): this is the "verification by the
//!   viewer's own domain" of `docs/claim-trust-verification.md` §6–§7. The
//!   application sends claims (typically from `Rp/userinfo-fetch`) and the
//!   subject from the verified assertion. The RP gets the keys of each signing
//!   domain through the same cache as `Rp/resolve-domain-keys` (pinned to DNS,
//!   revocations applied), and [`liblinkkeys::claims::check_claim`] makes the
//!   decision. The application applies its own trust policy to the result.
//! - `RequestedClaim.verified_by` for a login: the RP records the requirement
//!   at `Rp/sign-request` ([`login_requirements`]) and enforces it on the
//!   `Rp/userinfo-fetch` reply ([`enforce_login_requirements`]). The IDP is
//!   not trusted to enforce it.
//!
//! This module gets keys, enforces the request bounds, and applies the one
//! policy that `verified_by` names. The signature decisions are
//! `check_claim`'s.

use std::collections::BTreeSet;

use liblinkkeys::claims::{check_claim, DomainKeySet};
use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    Claim, ClaimCheck, ClaimCheckStatus, ClaimRequest, DomainPublicKey, RequestedClaim,
    RpErrorCode, RpResolveDomainKeysRequest, RpVerifyClaimsRequest, RpVerifyClaimsResponse,
    UserInfo, VerifyingParty,
};
use liblinkkeys::revocation::apply_revocation_certificates;

use crate::db::applications::LoginClaimRequirements;
use crate::db::DbPool;
use crate::net::Net;
use crate::web::rp::{
    core_bad_request, core_internal, core_refused, core_upstream, login_nonce_hash, CoreError,
};

/// The most claims in one request.
pub const MAX_CLAIMS: usize = 64;
/// The most distinct signing domains in one request. Each one can cost a
/// key fetch, so this bounds the onward work of one call.
pub const MAX_SIGNING_DOMAINS: usize = 16;
/// How long the RP keeps the claim requirements of a login. A login token
/// older than this is refused at `userinfo-fetch`, so a removed requirement
/// is never skipped. A LinkKeys assertion is valid for 5 minutes.
pub const LOGIN_REQUIREMENT_TTL_SECONDS: i64 = 86_400;

pub fn verify_claims(
    pool: &DbPool,
    net: &Net,
    rt: &tokio::runtime::Handle,
    request: RpVerifyClaimsRequest,
) -> Result<RpVerifyClaimsResponse, ServiceError> {
    verify_claims_with(request, |domain| resolved_keys(pool, net, rt, domain))
}

/// The keys of `domain` from the RP cache, with its revocations applied.
/// `None` when the RP cannot get them.
fn resolved_keys(
    pool: &DbPool,
    net: &Net,
    rt: &tokio::runtime::Handle,
    domain: &str,
) -> Option<Vec<DomainPublicKey>> {
    match crate::services::rp_cache::resolve_domain_keys(
        pool,
        net,
        rt,
        RpResolveDomainKeysRequest {
            domain: domain.to_string(),
            max_cache_age_seconds: None,
        },
    ) {
        Ok(resolved) => Some(apply_revocation_certificates(
            &resolved.keys,
            &resolved.revocations,
            domain,
        )),
        Err(e) => {
            log::info!("verify-claims: no keys for {domain}: {}", e.message);
            None
        }
    }
}

/// [`verify_claims`] with the key lookup as a parameter. `keys_for` returns
/// the keys of one signing domain, or `None` when they are not available.
pub(crate) fn verify_claims_with(
    request: RpVerifyClaimsRequest,
    mut keys_for: impl FnMut(&str) -> Option<Vec<DomainPublicKey>>,
) -> Result<RpVerifyClaimsResponse, ServiceError> {
    let subject_domain = request.subject_domain.trim();
    if subject_domain.is_empty() {
        return Err(bad_request("subject_domain must not be empty"));
    }
    if request.user_id.trim().is_empty() {
        return Err(bad_request("user_id must not be empty"));
    }
    if request.claims.is_empty() || request.claims.len() > MAX_CLAIMS {
        return Err(bad_request(&format!(
            "claims must hold 1 to {MAX_CLAIMS} claims"
        )));
    }
    let domains: BTreeSet<&str> = request
        .claims
        .iter()
        .flat_map(|c| c.signatures.iter().map(|s| s.domain.as_str()))
        .collect();
    if domains.len() > MAX_SIGNING_DOMAINS {
        return Err(bad_request(&format!(
            "the claims have more than {MAX_SIGNING_DOMAINS} signing domains"
        )));
    }

    // A domain whose keys are not available has no entry, so check_claim
    // reports it as `keys_unavailable`.
    let key_sets: Vec<DomainKeySet> = domains
        .into_iter()
        .filter(|domain| !domain.is_empty())
        .filter_map(|domain| {
            keys_for(domain).map(|keys| DomainKeySet {
                domain: domain.to_string(),
                keys,
            })
        })
        .collect();

    let now = liblinkkeys::timestamp::now_whole_milliseconds();
    let checks = request
        .claims
        .iter()
        .map(|claim| check_claim(claim, &request.user_id, subject_domain, &key_sets, now))
        .collect();
    Ok(RpVerifyClaimsResponse { checks })
}

/// The claim types of `request` that the home domain must verify. A type
/// that is both required and optional is required.
pub fn login_requirements(request: &ClaimRequest) -> LoginClaimRequirements {
    fn home_types(claims: &[RequestedClaim]) -> Vec<String> {
        let types: BTreeSet<&str> = claims
            .iter()
            .filter(|c| c.verified_by == Some(VerifyingParty::HomeDomain))
            .map(|c| c.claim_type.as_str())
            .collect();
        types.into_iter().map(str::to_string).collect()
    }
    let required = home_types(&request.required);
    let optional = home_types(&request.optional)
        .into_iter()
        .filter(|t| !required.contains(t))
        .collect();
    LoginClaimRequirements { required, optional }
}

/// Enforce the claim requirements that the login of `token` recorded at
/// `sign-request` on the `userinfo-fetch` reply `info`. See
/// [`apply_requirements`]. A login without requirements gets `info`
/// unchanged.
pub(crate) fn enforce_login_requirements(
    pool: &DbPool,
    net: &Net,
    rt: &tokio::runtime::Handle,
    caller: &crate::db::models::User,
    token: &str,
    info: UserInfo,
) -> Result<UserInfo, CoreError> {
    // fetch_userinfo_core decoded the same token, and the IDP redeemed it.
    let assertion = liblinkkeys::encoding::assertion_from_url_param(token)
        .ok()
        .and_then(|signed| {
            liblinkkeys::generated::decode_identity_assertion(&signed.assertion).ok()
        })
        .ok_or_else(|| core_bad_request("userinfo-fetch: the token is not a signed assertion"))?;
    let now = liblinkkeys::timestamp::now_whole_milliseconds();
    if assertion.issued_at + time::Duration::seconds(LOGIN_REQUIREMENT_TTL_SECONDS) < now {
        return Err(core_bad_request(
            "userinfo-fetch: the login is too old to check its claim requirements",
        ));
    }
    let Some(requirements) = pool
        .take_rp_login_claim_requirements(&caller.id, &login_nonce_hash(&assertion.nonce))
        .map_err(|e| core_internal("userinfo-fetch: reading the claim requirements", e))?
    else {
        return Ok(info);
    };
    apply_requirements(&requirements, &assertion.domain, info, |claims| {
        verify_claims_with(
            RpVerifyClaimsRequest {
                subject_domain: assertion.domain.clone(),
                user_id: assertion.user_id.clone(),
                claims: claims.to_vec(),
            },
            |domain| resolved_keys(pool, net, rt, domain),
        )
        .map(|r| r.checks)
    })
}

/// Apply `requirements` to `info`. For each type with a requirement, the
/// claims that `home_domain` did not verify ([`verified_by`]) are removed. A
/// required type with no claim left refuses the login with
/// `required_claim_unverified`.
///
/// `check` gets the claims of the governed types and returns one check for
/// each, in order. It binds the subject (the assertion user and domain).
pub(crate) fn apply_requirements(
    requirements: &LoginClaimRequirements,
    home_domain: &str,
    mut info: UserInfo,
    check: impl FnOnce(&[Claim]) -> Result<Vec<ClaimCheck>, ServiceError>,
) -> Result<UserInfo, CoreError> {
    let governed = |claim_type: &str| {
        requirements.required.iter().any(|t| t == claim_type)
            || requirements.optional.iter().any(|t| t == claim_type)
    };
    let to_check: Vec<Claim> = info
        .claims
        .iter()
        .filter(|c| governed(&c.claim_type))
        .cloned()
        .collect();
    let checks = if to_check.is_empty() {
        Vec::new()
    } else {
        check(&to_check)
            .map_err(|e| core_upstream("userinfo-fetch: checking the claims", e.message))?
    };
    if checks.len() != to_check.len() {
        return Err(core_internal(
            "userinfo-fetch: checking the claims",
            "the check count does not match the claim count",
        ));
    }
    // Keep a governed claim only when its own check passed. Two claims can
    // share an id only in a malformed reply, and then both must pass.
    let failed: BTreeSet<&str> = to_check
        .iter()
        .zip(&checks)
        .filter(|(_, check)| !verified_by(check, home_domain))
        .map(|(claim, _)| claim.claim_id.as_str())
        .collect();
    let failed: BTreeSet<String> = failed.into_iter().map(str::to_string).collect();
    info.claims
        .retain(|c| !governed(&c.claim_type) || !failed.contains(&c.claim_id));
    for required in &requirements.required {
        if !info.claims.iter().any(|c| &c.claim_type == required) {
            return Err(core_refused(
                RpErrorCode::RequiredClaimUnverified,
                &format!("the required claim {required} is not verified by {home_domain}"),
            ));
        }
    }
    Ok(info)
}

/// Whether `check` shows a current claim that `domain` signed: the claim
/// status is valid and the signatures of `domain` are valid. The signatures
/// of other domains do not change the result.
pub(crate) fn verified_by(check: &ClaimCheck, domain: &str) -> bool {
    check.claim_status == ClaimCheckStatus::Valid
        && check
            .signing_domains
            .iter()
            .any(|d| d.domain == domain && d.status == ClaimCheckStatus::Valid)
}

fn bad_request(message: &str) -> ServiceError {
    ServiceError {
        code: 400,
        message: format!("verify-claims: {message}"),
    }
}
