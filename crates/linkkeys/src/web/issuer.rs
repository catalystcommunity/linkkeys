//! `BrowserIssuer`: this domain acting as an issuer for a signing request that
//! a user of another domain brings. The operator pastes the request in the
//! browser app; the server verifies it against the subject domain's keys,
//! signs the values the operator attests, and deposits each signed claim at
//! the subject's home domain. Browser-session only, because it needs the
//! network for key fetch and deposit.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    InspectSigningRequestRequest, InspectSigningRequestResponse, IssueForSigningRequestRequest,
    IssueForSigningRequestResponse, IssuedClaimResult, SignedSigningRequest, SigningRequest,
};

use crate::conversions::get_domain_name;
use crate::db::DbPool;
use crate::net::Net;
use crate::services::{attestation, authorization};

fn error(code: i32, message: impl Into<String>) -> ServiceError {
    ServiceError {
        code,
        message: message.into(),
    }
}

/// The caller may use the issuer screens: `manage_claims` on the domain, or
/// an `issue_claims` relation on at least one claim type. Which types the
/// caller may sign is checked per type when signing.
fn may_use_issuer(pool: &DbPool, user_id: &str) -> bool {
    authorization::user_has_permission(
        pool,
        user_id,
        authorization::RELATION_MANAGE_CLAIMS,
        "domain",
        &get_domain_name(),
    ) || pool
        .list_relations_for_subject("user", user_id)
        .map(|relations| {
            relations.iter().any(|relation| {
                relation.relation == authorization::RELATION_ISSUE_CLAIMS
                    && relation.object_type == "claim_type"
            })
        })
        .unwrap_or(false)
}

fn decode(text: &str) -> Result<(SignedSigningRequest, SigningRequest), ServiceError> {
    let not_a_request = || error(400, "That text is not a signing request.");
    let bytes = Base64UrlUnpadded::decode_vec(text.trim()).map_err(|_| not_a_request())?;
    let signed = liblinkkeys::generated::decode_signed_signing_request(&bytes)
        .map_err(|_| not_a_request())?;
    let request = liblinkkeys::generated::decode_signing_request(&signed.request)
        .map_err(|_| not_a_request())?;
    Ok((signed, request))
}

/// The request must be addressed to this domain, and its signature must check
/// out against the subject domain's keys.
async fn verify(
    pool: &DbPool,
    net: &Net,
    signed: &SignedSigningRequest,
    request: &SigningRequest,
) -> Result<(), ServiceError> {
    let our = get_domain_name();
    if request.issuer_domain != our {
        return Err(error(
            400,
            format!(
                "This request is addressed to {}, not this domain.",
                request.issuer_domain
            ),
        ));
    }
    let keys = super::rp::fetch_domain_keys(pool, net, &request.subject_domain)
        .await
        .map_err(|e| {
            error(
                502,
                format!("Could not get the keys of {}: {e}", request.subject_domain),
            )
        })?;
    let keysets = vec![liblinkkeys::claims::DomainKeySet {
        domain: request.subject_domain.clone(),
        keys,
    }];
    liblinkkeys::signing_request::verify_signing_request(
        signed,
        &request.subject_domain,
        &our,
        &keysets,
    )
    .map(|_| ())
    .map_err(|e| error(400, e.to_string()))
}

async fn verified(
    pool: &DbPool,
    net: &Net,
    user_id: &str,
    signed_request: &str,
) -> Result<SigningRequest, ServiceError> {
    if !may_use_issuer(pool, user_id) {
        return Err(error(403, "You are not allowed to issue claims."));
    }
    let (signed, request) = decode(signed_request)?;
    verify(pool, net, &signed, &request).await?;
    Ok(request)
}

pub(super) async fn inspect(
    pool: &DbPool,
    net: &Net,
    user_id: &str,
    req: InspectSigningRequestRequest,
) -> Result<InspectSigningRequestResponse, ServiceError> {
    let request = verified(pool, net, user_id, &req.signed_request).await?;
    let issuable_claim_types = request
        .requested_claim_types
        .iter()
        .filter(|claim_type| attestation::user_can_issue_claim(pool, user_id, claim_type))
        .cloned()
        .collect();
    Ok(InspectSigningRequestResponse {
        subject_user_id: request.subject_user_id,
        subject_domain: request.subject_domain,
        requested_claim_types: request.requested_claim_types,
        expires_at: request.expires_at,
        issuable_claim_types,
    })
}

pub(super) async fn issue(
    pool: &DbPool,
    net: &Net,
    user_id: &str,
    req: IssueForSigningRequestRequest,
) -> Result<IssueForSigningRequestResponse, ServiceError> {
    if req.claim_types.len() != req.claim_values.len() {
        return Err(error(400, "claim_types and claim_values differ in length"));
    }
    // Verify again before signing: the request text comes from the client.
    let request = verified(pool, net, user_id, &req.signed_request).await?;
    let result = |claim_type: &str, outcome: &str, message: Option<String>| IssuedClaimResult {
        claim_type: claim_type.to_string(),
        outcome: outcome.to_string(),
        message,
        claim_code: None,
    };
    let mut results = Vec::new();
    for (claim_type, value) in req.claim_types.iter().zip(&req.claim_values) {
        let (claim_type, value) = (claim_type.trim(), value.trim());
        if claim_type.is_empty() || value.is_empty() {
            continue;
        }
        if !request
            .requested_claim_types
            .iter()
            .any(|t| t == claim_type)
        {
            results.push(result(
                claim_type,
                "skipped",
                Some("not requested".to_string()),
            ));
            continue;
        }
        if !attestation::user_can_issue_claim(pool, user_id, claim_type) {
            results.push(result(
                claim_type,
                "skipped",
                Some("not allowed".to_string()),
            ));
            continue;
        }
        let claim = match attestation::issue_attested_claim(
            pool,
            &request.subject_user_id,
            &request.subject_domain,
            claim_type,
            value.as_bytes(),
        ) {
            Ok(claim) => claim,
            Err(e) => {
                results.push(result(claim_type, "failed", Some(e.message)));
                continue;
            }
        };
        match super::rp::deposit_claim_to_domain(net, &request.subject_domain, &claim).await {
            Ok(()) => results.push(result(claim_type, "deposited", None)),
            Err(e) => results.push(IssuedClaimResult {
                claim_code: Some(Base64UrlUnpadded::encode_string(
                    &liblinkkeys::generated::encode_claim(&claim),
                )),
                ..result(claim_type, "handoff", Some(e))
            }),
        }
    }
    Ok(IssueForSigningRequestResponse { results })
}
