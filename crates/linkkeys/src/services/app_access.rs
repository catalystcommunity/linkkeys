//! App access policies: admin management and the sign-in check.
//!
//! The rules (pattern matching, deny-over-allow, claim conditions) live in
//! `liblinkkeys::app_access`. This module resolves which stored policies apply
//! to an account and turns the decision into an `AppAccessDenial`.
//!
//! Every sign-in path calls [`denial_for`] before it issues anything. The
//! check fails closed: a storage error refuses the sign-in.

use crate::db::models::{AppAccessPolicy as PolicyRecord, AppAccessTarget as TargetRecord};
use crate::db::DbPool;
use liblinkkeys::app_access::{self as aa, AccessDecision, AccessMode, ClaimOperator};
use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    AppAccessDenial, AppAccessPolicy, AppAccessTarget, EmptyRequest, ListAppAccessPoliciesResponse,
    PreviewAppAccessRequest, PreviewAppAccessResponse, RemoveAppAccessPolicyRequest,
    RemoveAppAccessPolicyResponse, SetAppAccessPolicyRequest, SetAppAccessPolicyResponse,
};
use std::collections::HashMap;

/// The longest policy name accepted.
const MAX_NAME_LEN: usize = 100;
/// The most patterns, and the most targets, in one policy.
const MAX_ENTRIES: usize = 200;

const KIND_EVERYONE: &str = "everyone";
const KIND_USER: &str = "user";
const KIND_GROUP: &str = "group";
const KIND_CLAIM: &str = "claim";

fn invalid(message: impl Into<String>) -> ServiceError {
    ServiceError {
        code: 400,
        message: message.into(),
    }
}

fn storage(context: &str, e: diesel::result::Error) -> ServiceError {
    log::error!("app access: {context}: {e}");
    ServiceError {
        code: 500,
        message: "Could not check app access".to_string(),
    }
}

// ---------------------------------------------------------------------------
// The sign-in check
// ---------------------------------------------------------------------------

/// The account facts that targets test, loaded only when a policy needs them.
struct Subject<'a> {
    pool: &'a DbPool,
    user_id: &'a str,
    groups: Option<Vec<String>>,
    claims: Option<HashMap<String, Vec<Vec<u8>>>>,
}

impl Subject<'_> {
    fn groups(&mut self) -> Result<&[String], ServiceError> {
        if self.groups.is_none() {
            let relations = self
                .pool
                .list_relations_for_subject("user", self.user_id)
                .map_err(|e| storage("reading group memberships", e))?;
            self.groups = Some(
                relations
                    .into_iter()
                    .filter(|r| r.relation == "member" && r.object_type == "group")
                    .map(|r| r.object_id)
                    .collect(),
            );
        }
        Ok(self.groups.as_deref().unwrap_or_default())
    }

    fn claim_values(&mut self, claim_type: &str) -> Result<Vec<&[u8]>, ServiceError> {
        if self.claims.is_none() {
            let rows = self
                .pool
                .list_active_claims(self.user_id)
                .map_err(|e| storage("reading claims", e))?;
            let mut by_type: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
            for row in rows {
                by_type
                    .entry(row.claim_type)
                    .or_default()
                    .push(row.claim_value);
            }
            self.claims = Some(by_type);
        }
        Ok(self
            .claims
            .as_ref()
            .and_then(|claims| claims.get(claim_type))
            .map(|values| values.iter().map(Vec::as_slice).collect())
            .unwrap_or_default())
    }

    fn is_targeted_by(&mut self, target: &TargetRecord) -> Result<bool, ServiceError> {
        Ok(match target.kind.as_str() {
            KIND_EVERYONE => true,
            KIND_USER => target.user_id.as_deref() == Some(self.user_id),
            KIND_GROUP => {
                let group = target.group_name.as_deref().unwrap_or_default();
                self.groups()?.iter().any(|g| g == group)
            }
            KIND_CLAIM => {
                let (Some(claim_type), Some(operator)) = (
                    target.claim_type.as_deref(),
                    target
                        .claim_operator
                        .as_deref()
                        .and_then(ClaimOperator::parse),
                ) else {
                    log::warn!("app access: skipping a claim target with no valid operator");
                    return Ok(false);
                };
                let today = chrono::Utc::now().date_naive();
                let values = self.claim_values(claim_type)?;
                aa::condition_matches(operator, target.claim_value.as_deref(), &values, today)
            }
            other => {
                log::warn!("app access: skipping a target of unknown kind {other:?}");
                false
            }
        })
    }
}

/// The policies that apply to `user_id`, in name order.
fn applicable_policies(
    pool: &DbPool,
    user_id: &str,
) -> Result<Vec<aa::AccessPolicy>, ServiceError> {
    let records = pool
        .list_app_access_policies()
        .map_err(|e| storage("reading policies", e))?;
    let mut subject = Subject {
        pool,
        user_id,
        groups: None,
        claims: None,
    };
    let mut applicable = Vec::new();
    for record in records {
        let Some(mode) = AccessMode::parse(&record.mode) else {
            // The table CHECK makes this impossible; refuse rather than ignore
            // a policy that might be a deny list.
            return Err(storage(
                "reading policies",
                diesel::result::Error::DeserializationError(
                    format!("unknown mode {:?}", record.mode).into(),
                ),
            ));
        };
        let mut targeted = false;
        for target in &record.targets {
            if subject.is_targeted_by(target)? {
                targeted = true;
                break;
            }
        }
        if targeted {
            applicable.push(aa::AccessPolicy {
                name: record.name,
                mode,
                patterns: record.patterns,
                message: record.message,
            });
        }
    }
    Ok(applicable)
}

/// `Some` when an app access policy blocks `user_id` from the application at
/// `domain` (`None` for a local app, which has no domain).
pub fn denial_for(
    pool: &DbPool,
    user_id: &str,
    domain: Option<&str>,
) -> Result<Option<AppAccessDenial>, ServiceError> {
    let domain = domain.map(aa::normalize_domain);
    let policies = applicable_policies(pool, user_id)?;
    match aa::evaluate(&policies, domain.as_deref()) {
        AccessDecision::Allowed => Ok(None),
        AccessDecision::Denied { policies, messages } => {
            log::info!(
                "app access: policies {:?} blocked a sign-in to {}",
                policies,
                domain.as_deref().unwrap_or("a local app")
            );
            Ok(Some(AppAccessDenial { domain, messages }))
        }
    }
}

/// The first denial among several domains that one sign-in involves (for
/// example an act-as grantee and its audience).
pub fn denial_for_any(
    pool: &DbPool,
    user_id: &str,
    domains: &[Option<&str>],
) -> Result<Option<AppAccessDenial>, ServiceError> {
    for domain in domains {
        if let Some(denial) = denial_for(pool, user_id, *domain)? {
            return Ok(Some(denial));
        }
    }
    Ok(None)
}

/// The error a completion returns when a policy blocks it. The consent UI
/// shows the inspect response's blocked page first; this covers a policy that
/// changed between inspect and complete, and API callers.
pub fn denial_error(denial: &AppAccessDenial) -> ServiceError {
    let mut message = "This account cannot sign in to this application.".to_string();
    for extra in &denial.messages {
        message.push(' ');
        message.push_str(extra);
    }
    ServiceError { code: 403, message }
}

// ---------------------------------------------------------------------------
// Admin operations
// ---------------------------------------------------------------------------

fn to_wire(record: PolicyRecord) -> AppAccessPolicy {
    AppAccessPolicy {
        id: record.id,
        name: record.name,
        mode: record.mode,
        patterns: record.patterns,
        message: record.message,
        targets: record
            .targets
            .into_iter()
            .map(|t| AppAccessTarget {
                kind: t.kind,
                user_id: t.user_id,
                group_name: t.group_name,
                claim_type: t.claim_type,
                claim_operator: t.claim_operator,
                claim_value: t.claim_value,
            })
            .collect(),
    }
}

fn nonempty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// Validate one target and return its canonical stored form.
fn canonical_target(pool: &DbPool, target: &AppAccessTarget) -> Result<TargetRecord, ServiceError> {
    let empty = TargetRecord {
        kind: target.kind.trim().to_string(),
        user_id: None,
        group_name: None,
        claim_type: None,
        claim_operator: None,
        claim_value: None,
    };
    match empty.kind.as_str() {
        KIND_EVERYONE => Ok(empty),
        KIND_USER => {
            let user_id = nonempty(target.user_id.as_deref())
                .ok_or_else(|| invalid("A user target needs a user"))?;
            let user = match pool.find_user_by_id(&user_id) {
                Ok(user) => user,
                Err(diesel::result::Error::NotFound) => {
                    return Err(invalid(format!("No user has the id {user_id}")))
                }
                Err(e) => return Err(storage("reading a target user", e)),
            };
            Ok(TargetRecord {
                user_id: Some(user.id),
                ..empty
            })
        }
        KIND_GROUP => {
            let group_name = nonempty(target.group_name.as_deref())
                .ok_or_else(|| invalid("A group target needs a group name"))?;
            Ok(TargetRecord {
                group_name: Some(group_name),
                ..empty
            })
        }
        KIND_CLAIM => {
            let claim_type = nonempty(target.claim_type.as_deref())
                .ok_or_else(|| invalid("A claim target needs a claim type"))?;
            let operator = target
                .claim_operator
                .as_deref()
                .map(str::trim)
                .and_then(ClaimOperator::parse)
                .ok_or_else(|| {
                    invalid("The claim condition must be present, absent, equals, age_under, or age_at_least")
                })?;
            let value = aa::validate_condition(operator, target.claim_value.as_deref())
                .map_err(|e| invalid(format!("Claim condition on {claim_type}: {e}")))?;
            Ok(TargetRecord {
                claim_type: Some(claim_type),
                claim_operator: Some(operator.as_str().to_string()),
                claim_value: value,
                ..empty
            })
        }
        _ => Err(invalid(
            "A target kind must be everyone, user, group, or claim",
        )),
    }
}

pub fn list_app_access_policies(
    pool: &DbPool,
    _req: EmptyRequest,
) -> Result<ListAppAccessPoliciesResponse, ServiceError> {
    let records = pool
        .list_app_access_policies()
        .map_err(|e| storage("reading policies", e))?;
    Ok(ListAppAccessPoliciesResponse {
        policies: records.into_iter().map(to_wire).collect(),
    })
}

pub fn set_app_access_policy(
    pool: &DbPool,
    req: SetAppAccessPolicyRequest,
) -> Result<SetAppAccessPolicyResponse, ServiceError> {
    let name = req.name.trim().to_string();
    if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
        return Err(invalid(format!(
            "The policy name must have 1 to {MAX_NAME_LEN} characters"
        )));
    }
    let mode = AccessMode::parse(req.mode.trim())
        .ok_or_else(|| invalid("The mode must be allow or deny"))?;

    if req.patterns.len() > MAX_ENTRIES || req.targets.len() > MAX_ENTRIES {
        return Err(invalid(format!(
            "A policy can have at most {MAX_ENTRIES} patterns and {MAX_ENTRIES} targets"
        )));
    }
    let mut patterns: Vec<String> = Vec::new();
    for raw in &req.patterns {
        let pattern = aa::normalize_pattern(raw)
            .map_err(|e| invalid(format!("Pattern {:?}: {e}", raw.trim())))?;
        if !patterns.contains(&pattern) {
            patterns.push(pattern);
        }
    }
    if patterns.is_empty() {
        return Err(invalid("A policy needs at least one domain pattern"));
    }

    let message = nonempty(req.message.as_deref());
    if message
        .as_ref()
        .is_some_and(|m| m.len() > aa::MAX_MESSAGE_LEN)
    {
        return Err(invalid(format!(
            "The message must be at most {} bytes",
            aa::MAX_MESSAGE_LEN
        )));
    }

    let mut targets: Vec<TargetRecord> = Vec::new();
    for target in &req.targets {
        let target = canonical_target(pool, target)?;
        if !targets.contains(&target) {
            targets.push(target);
        }
    }

    let existing = pool
        .list_app_access_policies()
        .map_err(|e| storage("reading policies", e))?;
    let id = match nonempty(req.id.as_deref()) {
        Some(id) => {
            if !existing.iter().any(|p| p.id == id) {
                return Err(ServiceError {
                    code: 404,
                    message: "No app access policy has this id".to_string(),
                });
            }
            id
        }
        None => uuid::Uuid::now_v7().to_string(),
    };
    if existing.iter().any(|p| p.id != id && p.name == name) {
        return Err(ServiceError {
            code: 409,
            message: format!("Another app access policy is named {name:?}"),
        });
    }

    let record = PolicyRecord {
        id,
        name,
        mode: mode.as_str().to_string(),
        message,
        patterns,
        targets,
    };
    pool.save_app_access_policy(&record).map_err(|e| match e {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => ServiceError {
            code: 409,
            message: format!("Another app access policy is named {:?}", record.name),
        },
        other => storage("saving a policy", other),
    })?;
    Ok(SetAppAccessPolicyResponse {
        policy: to_wire(record),
    })
}

pub fn remove_app_access_policy(
    pool: &DbPool,
    req: RemoveAppAccessPolicyRequest,
) -> Result<RemoveAppAccessPolicyResponse, ServiceError> {
    let removed = match pool.delete_app_access_policy(req.id.trim()) {
        Ok(count) => count,
        Err(diesel::result::Error::NotFound) => 0,
        Err(e) => return Err(storage("removing a policy", e)),
    };
    if removed == 0 {
        return Err(ServiceError {
            code: 404,
            message: "No app access policy has this id".to_string(),
        });
    }
    Ok(RemoveAppAccessPolicyResponse { success: true })
}

pub fn preview_app_access(
    pool: &DbPool,
    req: PreviewAppAccessRequest,
) -> Result<PreviewAppAccessResponse, ServiceError> {
    let user_id = req.user_id.trim();
    match pool.find_user_by_id(user_id) {
        Ok(_) => {}
        Err(diesel::result::Error::NotFound) => {
            return Err(invalid(format!("No user has the id {user_id}")))
        }
        Err(e) => return Err(storage("reading the preview user", e)),
    }
    let domain = nonempty(req.domain.as_deref()).map(|d| aa::normalize_domain(&d));
    let policies = applicable_policies(pool, user_id)?;
    let applied_policies = policies.iter().map(|p| p.name.clone()).collect();
    Ok(match aa::evaluate(&policies, domain.as_deref()) {
        AccessDecision::Allowed => PreviewAppAccessResponse {
            allowed: true,
            applied_policies,
            blocking_policies: Vec::new(),
            messages: Vec::new(),
        },
        AccessDecision::Denied { policies, messages } => PreviewAppAccessResponse {
            allowed: false,
            applied_policies,
            blocking_policies: policies,
            messages,
        },
    })
}
