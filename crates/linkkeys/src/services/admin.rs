use std::env;

use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    AdminLocalRp, AdminUser, ApproveLocalRpRequest, ApproveLocalRpResponse, AuthenticateRequest,
    AuthenticateResponse, CheckPermissionRequest, CheckPermissionResponse, Claim,
    CreateUserRequest, CreateUserResponse, DeactivateUserRequest, DeactivateUserResponse,
    DenyLocalRpRequest, DenyLocalRpResponse, GetLocalRpPolicyRequest, GetLocalRpPolicyResponse,
    GetLocalRpRequest, GetLocalRpResponse, GetUserRequest, GetUserResponse, GrantRelationRequest,
    GrantRelationResponse, ListLocalRpsRequest, ListLocalRpsResponse, ListRelationsRequest,
    ListRelationsResponse, ListSettablePoliciesResponse, ListUserClaimsRequest,
    ListUserClaimsResponse, ListUsersRequest, ListUsersResponse, RemoveClaimRequest,
    RemoveClaimResponse, RemoveCredentialRequest, RemoveCredentialResponse, RemoveRelationRequest,
    RemoveRelationResponse, ResetPasswordRequest, ResetPasswordResponse, RevokeLocalRpRequest,
    RevokeLocalRpResponse, SetClaimRequest, SetClaimResponse, SetLocalRpPolicyRequest,
    SetLocalRpPolicyResponse, SetUserClaimRequest, SetUserClaimResponse, SettableClaimPolicy,
    UpdateUserRequest, UpdateUserResponse,
};

use crate::db::models;
use crate::db::DbPool;
use crate::services::{auth, password};

fn svc_err(msg: &str) -> ServiceError {
    ServiceError {
        code: 1,
        message: msg.to_string(),
    }
}

fn db_err(e: diesel::result::Error) -> ServiceError {
    log::error!("Database error: {}", e);
    ServiceError {
        code: 500,
        message: "Internal database error".to_string(),
    }
}

const VALID_RELATIONS: &[&str] = &[
    "admin",
    "manage_users",
    "manage_claims",
    "api_access",
    "issue_claims",
    "member",
];
const VALID_SUBJECT_TYPES: &[&str] = &["user", "group"];
const VALID_OBJECT_TYPES: &[&str] = &["domain", "group", "user", "claim_type"];

fn user_to_admin_user(user: &models::User) -> AdminUser {
    AdminUser {
        id: user.id.clone(),
        username: user.username.clone(),
        display_name: user.display_name.clone(),
        is_active: user.is_active,
        created_at: user.created_at.clone(),
        updated_at: user.updated_at.clone(),
    }
}

fn relation_to_csil(rel: &models::Relation) -> liblinkkeys::generated::types::Relation {
    liblinkkeys::generated::types::Relation {
        id: rel.id.clone(),
        subject_type: rel.subject_type.clone(),
        subject_id: rel.subject_id.clone(),
        relation: rel.relation.clone(),
        object_type: rel.object_type.clone(),
        object_id: rel.object_id.clone(),
        created_at: rel.created_at.clone(),
        removed_at: rel.removed_at.clone(),
    }
}

pub fn list_users(
    pool: &DbPool,
    _req: ListUsersRequest,
) -> Result<ListUsersResponse, ServiceError> {
    let users = pool.list_all_users().map_err(db_err)?;
    Ok(ListUsersResponse {
        users: users.iter().map(user_to_admin_user).collect(),
    })
}

pub fn get_user(pool: &DbPool, req: GetUserRequest) -> Result<GetUserResponse, ServiceError> {
    let user = pool.find_user_by_id(&req.user_id).map_err(db_err)?;
    Ok(GetUserResponse {
        user: user_to_admin_user(&user),
    })
}

pub fn create_user(
    pool: &DbPool,
    req: CreateUserRequest,
) -> Result<CreateUserResponse, ServiceError> {
    let user = pool
        .create_user(&req.username, &req.display_name)
        .map_err(db_err)?;

    let api_key = if let Some(ref pw) = req.password {
        password::validate(pw)?;
        // Store password credential
        let hash = password::hash_for_storage(pw)?;
        pool.create_auth_credential(&user.id, auth::CREDENTIAL_TYPE_PASSWORD, &hash)
            .map_err(db_err)?;
        None
    } else {
        // Generate API key
        let (key, hash) = auth::generate_api_key(&user.id);
        pool.create_auth_credential(&user.id, auth::CREDENTIAL_TYPE_API_KEY, &hash)
            .map_err(db_err)?;
        Some(key)
    };

    // Generate keypairs
    let passphrase =
        env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| svc_err("DOMAIN_KEY_PASSPHRASE not set"))?;
    for years in &[2i64, 3, 4] {
        let (verifying_key, signing_key) = liblinkkeys::crypto::generate_ed25519_keypair();
        let pk_bytes = verifying_key.as_bytes().to_vec();
        let sk_bytes = signing_key.to_bytes();
        let encrypted = liblinkkeys::crypto::encrypt_private_key(&sk_bytes, passphrase.as_bytes())
            .map_err(|e| svc_err(&format!("encrypt error: {}", e)))?;
        let fp = liblinkkeys::crypto::fingerprint(&pk_bytes);
        let expires = chrono::Utc::now() + chrono::Duration::days(365 * years);
        pool.create_user_key(&user.id, &pk_bytes, &encrypted, &fp, "ed25519", expires)
            .map_err(db_err)?;
    }

    Ok(CreateUserResponse {
        user: user_to_admin_user(&user),
        api_key,
    })
}

pub fn update_user(
    pool: &DbPool,
    req: UpdateUserRequest,
) -> Result<UpdateUserResponse, ServiceError> {
    let user = if let Some(ref display_name) = req.display_name {
        pool.update_display_name(&req.user_id, display_name)
            .map_err(db_err)?
    } else {
        pool.find_user_by_id(&req.user_id).map_err(db_err)?
    };
    Ok(UpdateUserResponse {
        user: user_to_admin_user(&user),
    })
}

pub fn deactivate_user(
    pool: &DbPool,
    req: DeactivateUserRequest,
) -> Result<DeactivateUserResponse, ServiceError> {
    let user = pool.deactivate_user(&req.user_id).map_err(db_err)?;
    pool.revoke_all_credentials_for_user(&req.user_id)
        .map_err(db_err)?;
    Ok(DeactivateUserResponse {
        user: user_to_admin_user(&user),
    })
}

pub fn activate_user(pool: &DbPool, user_id: &str) -> Result<AdminUser, ServiceError> {
    let user = pool.activate_user(user_id).map_err(db_err)?;
    Ok(user_to_admin_user(&user))
}

/// Verify a user's password (username + password), returning the user on
/// success. Uses the same PasswordAuthenticator the web login does (Argon2id,
/// transparent rehash). SEC-05: rate-limited per username like the web login.
/// Failures never distinguish a wrong password from an unknown user. Callers
/// (e.g. the catalystlinkkeys web app) authenticate over CSIL-RPC and mint their
/// own session; this op requires `manage_users`.
pub fn authenticate(
    pool: &DbPool,
    req: AuthenticateRequest,
) -> Result<AuthenticateResponse, ServiceError> {
    use auth::Authenticator;
    if !crate::services::ratelimit::LOGIN.check(&req.username.trim().to_lowercase()) {
        return Err(svc_err("Too many attempts. Please wait and try again."));
    }
    let authenticator = auth::PasswordAuthenticator::new(pool.clone());
    match authenticator.authenticate(&req.username, &req.password) {
        Ok(user) => Ok(AuthenticateResponse {
            user: user_to_admin_user(&user),
        }),
        Err(_) => Err(svc_err("Invalid username or password")),
    }
}

pub fn reset_password(
    pool: &DbPool,
    req: ResetPasswordRequest,
) -> Result<ResetPasswordResponse, ServiceError> {
    let user = pool.find_user_by_id(&req.user_id).map_err(db_err)?;
    if user.purged_at.is_some() {
        return Err(svc_err("cannot reset password for a purged user"));
    }

    password::validate(&req.new_password)?;

    // Remove old password credentials
    let old_creds = pool
        .find_credentials_for_user(&req.user_id, auth::CREDENTIAL_TYPE_PASSWORD)
        .map_err(db_err)?;
    for cred in &old_creds {
        pool.remove_credential(&cred.id).map_err(db_err)?;
    }

    // Create new password credential
    let hash = password::hash_for_storage(&req.new_password)?;
    pool.create_auth_credential(&req.user_id, auth::CREDENTIAL_TYPE_PASSWORD, &hash)
        .map_err(db_err)?;

    Ok(ResetPasswordResponse { success: true })
}

pub fn remove_credential(
    pool: &DbPool,
    req: RemoveCredentialRequest,
) -> Result<RemoveCredentialResponse, ServiceError> {
    // Verify the credential exists before removing
    let _credential = pool
        .find_credential_by_id(&req.credential_id)
        .map_err(|e| match e {
            diesel::result::Error::NotFound => ServiceError {
                code: 404,
                message: "Credential not found".to_string(),
            },
            other => db_err(other),
        })?;
    pool.remove_credential(&req.credential_id).map_err(db_err)?;
    Ok(RemoveCredentialResponse { success: true })
}

pub fn set_claim(pool: &DbPool, req: SetClaimRequest) -> Result<SetClaimResponse, ServiceError> {
    let passphrase =
        env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| svc_err("DOMAIN_KEY_PASSPHRASE not set"))?;
    if req.claim_value.as_bytes().is_empty() {
        return Err(svc_err("claim value cannot be empty"));
    }

    let domain_keys = pool.list_active_domain_keys().map_err(db_err)?;
    // Sign with every active domain key (>=3 by design) so the claim carries a
    // quorum of signatures from this domain.
    let signers = crate::claim_signing::active_signers(&domain_keys, passphrase.as_bytes())
        .map_err(|e| svc_err(&e.to_string()))?;

    use chrono::Timelike;
    let expires_chrono = req
        .expires_at
        .as_deref()
        .map(|s| chrono::DateTime::parse_from_rfc3339(s).map(|dt| dt.with_timezone(&chrono::Utc)))
        .transpose()
        .map_err(|e| svc_err(&format!("invalid expires_at: {}", e)))?
        // Normalize to whole seconds: the expires_at is part of the claim's
        // signed payload, so it must round-trip byte-identically through both
        // Postgres (timestamptz, microsecond) and SQLite (RFC3339 text) storage.
        .map(|dt| dt.with_nanosecond(0).unwrap_or(dt));

    let claim_id = uuid::Uuid::now_v7().to_string();
    let claim_value_bytes = req.claim_value.as_bytes();
    let expires_str = expires_chrono.as_ref().map(|e| e.to_rfc3339());
    // Attestation time: signed, so normalize to whole seconds for the same
    // byte-identical round-trip as expires_at.
    let attested_chrono = chrono::Utc::now().with_nanosecond(0).unwrap();
    let attested_str = attested_chrono.to_rfc3339();
    // The subject is a local user, so the subject's home domain is our own.
    let subject_domain = crate::conversions::get_domain_name();

    let signed_claim = crate::claim_signing::sign_with_active(
        &liblinkkeys::claims::ClaimSpec {
            claim_id: &claim_id,
            claim_type: &req.claim_type,
            claim_value: claim_value_bytes,
            user_id: &req.user_id,
            subject_domain: &subject_domain,
            expires_at: expires_str.as_deref(),
            attested_at: &attested_str,
        },
        &signers,
    )
    .map_err(|e| svc_err(&e.to_string()))?;

    let stored = pool
        .replace_active_claim_of_type(
            &claim_id,
            &req.user_id,
            &req.claim_type,
            claim_value_bytes,
            &signed_claim.signatures,
            expires_chrono,
            attested_chrono,
        )
        .map_err(db_err)?;

    let claim: Claim = (&stored).into();
    Ok(SetClaimResponse { claim })
}

/// Approve a queued self-asserted claim: sign the held value with the domain's
/// active keys, store it for the subject, and mark the queue entry approved.
/// Signs with our own keys (the IDP is vouching), so there is no foreign-key
/// concern with the held value.
pub fn approve_claim(pool: &DbPool, approval_id: &str, admin_id: &str) -> Result<(), ServiceError> {
    let approval = pool.find_approval(approval_id).map_err(|e| match e {
        diesel::result::Error::NotFound => ServiceError {
            code: 404,
            message: "Approval not found".to_string(),
        },
        other => db_err(other),
    })?;
    if approval.status != "pending" {
        return Err(svc_err("approval already resolved"));
    }
    crate::services::self_service::sign_and_store(
        pool,
        &approval.user_id,
        &approval.claim_type,
        &approval.claim_value,
    )?;
    pool.resolve_approval(approval_id, "approved", admin_id)
        .map_err(db_err)?;
    Ok(())
}

/// Reject a queued claim: mark it rejected without signing anything.
pub fn reject_claim(pool: &DbPool, approval_id: &str, admin_id: &str) -> Result<(), ServiceError> {
    pool.resolve_approval(approval_id, "rejected", admin_id)
        .map_err(db_err)?;
    Ok(())
}

pub fn remove_claim(
    pool: &DbPool,
    req: RemoveClaimRequest,
) -> Result<RemoveClaimResponse, ServiceError> {
    // Verify the claim exists before removing
    let _claim = pool.find_claim_by_id(&req.claim_id).map_err(|e| match e {
        diesel::result::Error::NotFound => ServiceError {
            code: 404,
            message: "Claim not found".to_string(),
        },
        other => db_err(other),
    })?;
    pool.remove_claim(&req.claim_id).map_err(db_err)?;
    Ok(RemoveClaimResponse { success: true })
}

pub fn list_user_claims(
    pool: &DbPool,
    req: ListUserClaimsRequest,
) -> Result<ListUserClaimsResponse, ServiceError> {
    let _user = pool.find_user_by_id(&req.user_id).map_err(|e| match e {
        diesel::result::Error::NotFound => ServiceError {
            code: 404,
            message: "User not found".to_string(),
        },
        other => db_err(other),
    })?;
    let mut claim_types: Vec<String> = pool
        .list_active_claims(&req.user_id)
        .map_err(db_err)?
        .into_iter()
        .map(|c| c.claim_type)
        .collect();
    claim_types.sort();
    claim_types.dedup();
    Ok(ListUserClaimsResponse { claim_types })
}

pub fn set_user_claim(
    pool: &DbPool,
    req: SetUserClaimRequest,
) -> Result<SetUserClaimResponse, ServiceError> {
    let _user = pool.find_user_by_id(&req.user_id).map_err(|e| match e {
        diesel::result::Error::NotFound => ServiceError {
            code: 404,
            message: "User not found".to_string(),
        },
        other => db_err(other),
    })?;

    let outcome = crate::services::self_service::set_my_claim(
        pool,
        &req.user_id,
        &req.claim_type,
        req.claim_value.as_bytes(),
    )?;

    let claim = match outcome {
        crate::services::self_service::SetOutcome::Signed
        | crate::services::self_service::SetOutcome::StoredUnsigned => pool
            .list_active_claims(&req.user_id)
            .map_err(db_err)?
            .into_iter()
            .find(|c| c.claim_type == req.claim_type)
            .map(|c| (&c).into()),
        crate::services::self_service::SetOutcome::VerificationRequired
        | crate::services::self_service::SetOutcome::Queued => None,
    };

    let outcome = match outcome {
        crate::services::self_service::SetOutcome::Signed => "signed",
        crate::services::self_service::SetOutcome::StoredUnsigned => "stored_unsigned",
        crate::services::self_service::SetOutcome::VerificationRequired => "verification_required",
        crate::services::self_service::SetOutcome::Queued => "queued",
    }
    .to_string();

    Ok(SetUserClaimResponse { outcome, claim })
}

pub fn list_settable_policies(
    pool: &DbPool,
    _req: liblinkkeys::generated::types::EmptyRequest,
) -> Result<ListSettablePoliciesResponse, ServiceError> {
    let mut policies: Vec<SettableClaimPolicy> =
        crate::services::self_service::list_user_settable_policies(pool)?
            .into_iter()
            .filter(|p| matches!(p.set_rule.as_str(), "user_self" | "idp_on_request"))
            .map(|p| SettableClaimPolicy {
                claim_type: p.claim_type,
                datatype: p.value_type,
                set_rule: p.set_rule,
                requires_approval: p.requires_approval,
                signing_rule: p.signing_rule,
            })
            .collect();
    policies.sort_by(|a, b| a.claim_type.cmp(&b.claim_type));
    Ok(ListSettablePoliciesResponse { policies })
}

pub fn grant_relation(
    pool: &DbPool,
    req: GrantRelationRequest,
) -> Result<GrantRelationResponse, ServiceError> {
    if !VALID_RELATIONS.contains(&req.relation.as_str()) {
        return Err(ServiceError {
            code: 400,
            message: format!(
                "Unknown relation type: {}. Valid: {:?}",
                req.relation, VALID_RELATIONS
            ),
        });
    }
    if !VALID_SUBJECT_TYPES.contains(&req.subject_type.as_str()) {
        return Err(ServiceError {
            code: 400,
            message: format!(
                "Unknown subject type: {}. Valid: {:?}",
                req.subject_type, VALID_SUBJECT_TYPES
            ),
        });
    }
    if !VALID_OBJECT_TYPES.contains(&req.object_type.as_str()) {
        return Err(ServiceError {
            code: 400,
            message: format!(
                "Unknown object type: {}. Valid: {:?}",
                req.object_type, VALID_OBJECT_TYPES
            ),
        });
    }

    // Normalization (db-05): subject_type / relation / object_type are already
    // canonical — they're validated above against the lowercase VALID_* sets, so
    // case/variant divergence can't be stored. The free-form id fields are
    // whitespace-trimmed for consistency; they are NOT case-folded because
    // identifiers (group names, etc.) may be legitimately case-sensitive.
    let rel = pool
        .create_relation(
            &req.subject_type,
            req.subject_id.trim(),
            &req.relation,
            &req.object_type,
            req.object_id.trim(),
        )
        .map_err(db_err)?;
    Ok(GrantRelationResponse {
        relation: relation_to_csil(&rel),
    })
}

pub fn remove_relation(
    pool: &DbPool,
    req: RemoveRelationRequest,
) -> Result<RemoveRelationResponse, ServiceError> {
    pool.remove_relation(&req.relation_id).map_err(db_err)?;
    Ok(RemoveRelationResponse { success: true })
}

pub fn list_relations(
    pool: &DbPool,
    req: ListRelationsRequest,
) -> Result<ListRelationsResponse, ServiceError> {
    let relations = match (
        &req.subject_type,
        &req.subject_id,
        &req.object_type,
        &req.object_id,
    ) {
        (Some(st), Some(si), _, _) => pool.list_relations_for_subject(st, si).map_err(db_err)?,
        (_, _, Some(ot), Some(oi)) => pool.list_relations_for_object(ot, oi).map_err(db_err)?,
        _ => {
            // If no filters, list all for domain object as a reasonable default
            return Err(svc_err(
                "Must provide subject_type+subject_id or object_type+object_id",
            ));
        }
    };
    Ok(ListRelationsResponse {
        relations: relations.iter().map(relation_to_csil).collect(),
    })
}

pub fn check_permission_handler(
    pool: &DbPool,
    req: CheckPermissionRequest,
) -> Result<CheckPermissionResponse, ServiceError> {
    let allowed = pool
        .check_permission(
            &req.user_id,
            &req.relation,
            &req.object_type,
            &req.object_id,
        )
        .map_err(db_err)?;
    Ok(CheckPermissionResponse { allowed })
}

// -- DNS-less local RP admin surface (dns-less-local-rp-design.md, Phase 7) --
//
// Approval keys on the fingerprint alone (design doc: "Admin approval keys on
// the local RP fingerprint alone"). `app_name`/`local_domain_hint` are
// display/audit metadata only: `AdminLocalRp` always reflects the most
// recently *reported* values (whatever a login attempt last sent), plus
// `created_at` (first-seen) and `last_seen_at` for admins to judge freshness.
//
// Metadata drift itself (old value vs. newly reported value on a repeat
// attempt) is detected by `crate::services::local_rp::record_login_attempt`
// but is only `log::warn!`'d at that call site (see `web/local_rp_ui.rs`) —
// it is not persisted anywhere. There is deliberately no new column/table for
// drift history in this phase (no migrations without being truly forced);
// admins reviewing a fingerprint here see current metadata and first/last
// seen timestamps, not a historical diff. If persistent drift history is
// needed later, that is a schema addition for a future phase, not this one.
fn local_rp_to_admin(rp: &crate::db::models::LocalRp) -> AdminLocalRp {
    AdminLocalRp {
        fingerprint: rp.fingerprint.clone(),
        signing_public_key: rp.signing_public_key.clone(),
        encryption_public_key: rp.encryption_public_key.clone(),
        app_name: rp.app_name.clone(),
        local_domain_hint: rp.local_domain_hint.clone(),
        status: rp.status.clone(),
        created_at: rp.created_at.clone(),
        updated_at: rp.updated_at.clone(),
        expires_at: rp.expires_at.clone(),
        last_seen_at: rp.last_seen_at.clone(),
        admin_notes: rp.admin_notes.clone(),
    }
}

/// List local RP identities, optionally filtered to one `status`
/// (pending/approved/denied/revoked), oldest-first. `offset`/`limit` page the
/// in-memory result: the registry is bounded (pending entries are capped at
/// `crate::services::local_rp::MAX_PENDING_LOCAL_RPS`; other statuses are a
/// human-reviewed admin queue), so DB-level pagination is not worth the added
/// storage-layer surface yet.
pub fn list_local_rps(
    pool: &DbPool,
    req: ListLocalRpsRequest,
) -> Result<ListLocalRpsResponse, ServiceError> {
    let all = pool.list_local_rps(req.status.as_deref()).map_err(db_err)?;
    let offset = req.offset.unwrap_or(0).max(0) as usize;
    let limit = req
        .limit
        .and_then(|l| usize::try_from(l).ok())
        .unwrap_or(usize::MAX);
    let local_rps = all
        .iter()
        .skip(offset)
        .take(limit)
        .map(local_rp_to_admin)
        .collect();
    Ok(ListLocalRpsResponse { local_rps })
}

pub fn get_local_rp(
    pool: &DbPool,
    req: GetLocalRpRequest,
) -> Result<GetLocalRpResponse, ServiceError> {
    let rp = pool
        .find_local_rp(&req.fingerprint)
        .map_err(db_err)?
        .ok_or_else(|| ServiceError {
            code: 404,
            message: "Local RP not found".to_string(),
        })?;
    Ok(GetLocalRpResponse {
        local_rp: local_rp_to_admin(&rp),
    })
}

/// Shared transition plumbing for approve/deny/revoke: delegates the
/// from/to validity matrix to `crate::services::local_rp::transition_status`
/// (which also handles revoke's claim-ticket cleanup) and maps its error
/// cases onto `ServiceError`.
fn transition_local_rp(
    pool: &DbPool,
    fingerprint: &str,
    to: &str,
    admin_notes: Option<&str>,
) -> Result<AdminLocalRp, ServiceError> {
    crate::services::local_rp::transition_status(pool, fingerprint, to, admin_notes)
        .map(|rp| local_rp_to_admin(&rp))
        .map_err(|e| match e {
            crate::services::local_rp::StatusTransitionError::NotFound => ServiceError {
                code: 404,
                message: "Local RP not found".to_string(),
            },
            crate::services::local_rp::StatusTransitionError::Invalid { from, to } => {
                let from = if from.is_empty() {
                    "not a recognised transition target".to_string()
                } else {
                    from
                };
                ServiceError {
                    code: 400,
                    message: format!("invalid local RP status transition: {} -> {}", from, to),
                }
            }
            crate::services::local_rp::StatusTransitionError::Db(e) => db_err(e),
        })
}

/// Approve a local RP fingerprint: pending or previously-denied only (an
/// admin may change their mind on a denial).
pub fn approve_local_rp(
    pool: &DbPool,
    req: ApproveLocalRpRequest,
) -> Result<ApproveLocalRpResponse, ServiceError> {
    let local_rp = transition_local_rp(
        pool,
        &req.fingerprint,
        crate::db::local_rp::STATUS_APPROVED,
        req.admin_notes.as_deref(),
    )?;
    Ok(ApproveLocalRpResponse { local_rp })
}

/// Deny a pending local RP fingerprint.
pub fn deny_local_rp(
    pool: &DbPool,
    req: DenyLocalRpRequest,
) -> Result<DenyLocalRpResponse, ServiceError> {
    let local_rp = transition_local_rp(
        pool,
        &req.fingerprint,
        crate::db::local_rp::STATUS_DENIED,
        req.admin_notes.as_deref(),
    )?;
    Ok(DenyLocalRpResponse { local_rp })
}

/// Revoke a previously-approved local RP fingerprint. Revocation is terminal
/// (no un-revoking): it stops future logins and deletes the RP's outstanding
/// claim tickets, but sessions an app already minted from earlier logins are
/// the app's own to manage — revocation does not reach into app sessions.
pub fn revoke_local_rp(
    pool: &DbPool,
    req: RevokeLocalRpRequest,
) -> Result<RevokeLocalRpResponse, ServiceError> {
    let local_rp = transition_local_rp(
        pool,
        &req.fingerprint,
        crate::db::local_rp::STATUS_REVOKED,
        req.admin_notes.as_deref(),
    )?;
    Ok(RevokeLocalRpResponse { local_rp })
}

/// This domain's local-RP admission policy (dns-less-local-rp-design.md,
/// "Server Work"/"CSIL Work": "Domain policy APIs/CLI/config to set local RP
/// mode"). Like every other Admin op this acts on the caller's own domain —
/// there is no domain parameter. Returns the *effective* policy: the stored
/// value, or `crate::db::local_rp::DEFAULT_POLICY`
/// ("admin-approval-required") when the domain has never set one explicitly.
pub fn get_local_rp_policy(
    pool: &DbPool,
    _req: GetLocalRpPolicyRequest,
) -> Result<GetLocalRpPolicyResponse, ServiceError> {
    let policy = pool.effective_local_rp_policy().map_err(db_err)?;
    Ok(GetLocalRpPolicyResponse { policy })
}

/// Set this domain's local-RP admission policy. `DbPool::
/// set_local_rp_domain_policy` validates `req.policy` against the recognised
/// vocabulary (`disabled` / `admin-approval-required` / `allow-by-default`,
/// see `crate::db::local_rp::is_valid_policy`) and rejects anything else with
/// an error string, mapped here to a 400 rather than an internal error.
pub fn set_local_rp_policy(
    pool: &DbPool,
    req: SetLocalRpPolicyRequest,
) -> Result<SetLocalRpPolicyResponse, ServiceError> {
    pool.set_local_rp_domain_policy(&req.policy)
        .map_err(|message| ServiceError { code: 400, message })?;
    Ok(SetLocalRpPolicyResponse { policy: req.policy })
}
