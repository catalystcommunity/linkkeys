use std::env;

use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    ActivateUserRequest, ActivateUserResponse, AddTrustedIssuerRequest, AddTrustedIssuerResponse,
    AdminIssueAttestationRequest, AdminIssueAttestationResponse, AdminLocalRp, AdminUser,
    ApproveClaimRequest, ApproveClaimResponse, ApproveLocalRpRequest, ApproveLocalRpResponse,
    AuthenticateRequest, AuthenticateResponse, CheckPermissionRequest, CheckPermissionResponse,
    Claim, ClaimApproval, ClaimTypeLabel, ClaimTypePolicy, CreateUserRequest, CreateUserResponse,
    DeactivateUserRequest, DeactivateUserResponse, DenyLocalRpRequest, DenyLocalRpResponse,
    GetLocalRpPolicyRequest, GetLocalRpPolicyResponse, GetLocalRpRequest, GetLocalRpResponse,
    GetUserRequest, GetUserResponse, GrantRelationRequest, GrantRelationResponse,
    ListClaimTypesResponse, ListLocalRpsRequest, ListLocalRpsResponse,
    ListPendingClaimApprovalsResponse, ListRelationsRequest, ListRelationsResponse,
    ListReleaseRulesResponse, ListSettablePoliciesResponse, ListTrustedIssuersResponse,
    ListUserClaimsRequest, ListUserClaimsResponse, ListUsersRequest, ListUsersResponse,
    PurgeLocalRpTicketsRequest, PurgeLocalRpTicketsResponse, PurgeUserRequest, PurgeUserResponse,
    RejectClaimRequest, RejectClaimResponse, ReleaseRule, RemoveClaimRequest, RemoveClaimResponse,
    RemoveClaimTypeLabelRequest, RemoveClaimTypeLabelResponse, RemoveClaimTypeRequest,
    RemoveClaimTypeResponse, RemoveCredentialRequest, RemoveCredentialResponse,
    RemoveRelationRequest, RemoveRelationResponse, RemoveReleaseRuleRequest,
    RemoveReleaseRuleResponse, RemoveTrustedIssuerRequest, RemoveTrustedIssuerResponse,
    ResetPasswordRequest, ResetPasswordResponse, RevokeDomainKeyRequest, RevokeDomainKeyResponse,
    RevokeLocalRpRequest, RevokeLocalRpResponse, SetClaimRequest, SetClaimResponse,
    SetClaimTypeLabelRequest, SetClaimTypeLabelResponse, SetClaimTypeRequest, SetClaimTypeResponse,
    SetLocalRpPolicyRequest, SetLocalRpPolicyResponse, SetReleaseRuleRequest,
    SetReleaseRuleResponse, SetUserClaimRequest, SetUserClaimResponse, SettableClaimPolicy,
    TrustedIssuer, UpdateUserRequest, UpdateUserResponse,
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

/// CSIL-RPC entry point for [`activate_user`] (`Admin/activate-user`): the
/// direct request/response mirror of `deactivate_user` above, reusing the
/// same [`activate_user`] call the web UI's "Activate User" button makes
/// (`web/admin_ui.rs`'s `admin_ui_activate_user`).
pub fn activate_user_request(
    pool: &DbPool,
    req: ActivateUserRequest,
) -> Result<ActivateUserResponse, ServiceError> {
    let user = activate_user(pool, &req.user_id)?;
    Ok(ActivateUserResponse { user })
}

/// Irreversibly minimize a user to a permanent tombstone (`Admin/purge-user`):
/// CSIL-RPC entry point onto the exact same `DbPool::purge_user_tombstone`
/// call `main.rs`'s `user purge-local` CLI command makes, replicating that
/// command's guards. An API caller gets no interactive `--force`/
/// `--force-admin` confirmation prompt, so unlike the CLI (which allows
/// `--force-admin` to override), this op never purges a protected admin
/// account — there is no override lever over the wire.
pub fn purge_user(pool: &DbPool, req: PurgeUserRequest) -> Result<PurgeUserResponse, ServiceError> {
    let user = pool.find_user_by_id(&req.user_id).map_err(|e| match e {
        diesel::result::Error::NotFound => ServiceError {
            code: 404,
            message: "User not found".to_string(),
        },
        other => db_err(other),
    })?;
    if user.purged_at.is_some() {
        return Err(svc_err("user is already purged"));
    }
    let domain = crate::conversions::get_domain_name();
    let protected = pool
        .is_protected_admin_user(&user.id, &domain)
        .map_err(db_err)?;
    if protected {
        return Err(svc_err(
            "refusing to purge a protected admin account over CSIL-RPC",
        ));
    }

    let summary = pool
        .purge_user_tombstone(&req.user_id, req.reason.as_deref())
        .map_err(db_err)?;

    Ok(PurgeUserResponse {
        user: user_to_admin_user(&summary.user),
        credentials_revoked: summary.credentials_revoked as i64,
        keys_revoked: summary.keys_revoked as i64,
        claims_revoked: summary.claims_revoked as i64,
        relations_removed: summary.relations_removed as i64,
        profiles_deleted: summary.profiles_deleted as i64,
        consent_grants_deleted: summary.consent_grants_deleted as i64,
        release_prefs_deleted: summary.release_prefs_deleted as i64,
        email_verifications_deleted: summary.email_verifications_deleted as i64,
        reviews_resolved: summary.reviews_resolved as i64,
        local_rp_claim_tickets_deleted: summary.local_rp_claim_tickets_deleted as i64,
    })
}

/// Revoke one of this domain's own signing keys (`Admin/revoke-domain-key`):
/// CSIL-RPC entry point that reuses the exact same calls `main.rs`'s
/// `domain revoke-key` CLI command makes (`DbPool::revoke_domain_key`, then a
/// sibling-signed revocation certificate from the domain's remaining active
/// signing keys, stored via `DbPool::insert_issued_revocation`). DNS removal
/// is a manual operator step the CLI only prints a reminder about; this op
/// carries the same reminder in the response instead.
pub fn revoke_domain_key(
    pool: &DbPool,
    req: RevokeDomainKeyRequest,
) -> Result<RevokeDomainKeyResponse, ServiceError> {
    use liblinkkeys::claims::ClaimSigner;
    use liblinkkeys::revocation::{
        build_revocation_certificate, RevocationSpec, REVOCATION_QUORUM,
    };

    let revoked = pool.revoke_domain_key(&req.key_id).map_err(|e| match e {
        diesel::result::Error::NotFound => ServiceError {
            code: 404,
            message: "Domain key not found".to_string(),
        },
        other => db_err(other),
    })?;

    // Produce the sibling-signed revocation certificate from the remaining
    // active signing keys (the target is now excluded from
    // list_active_domain_keys), same as domain_emit_revocation_cert in the
    // CLI. Fewer than REVOCATION_QUORUM surviving signers is not an error —
    // the revocation is still recorded locally and enforced via DNS removal.
    let mut certificate_issued = false;
    if let Ok(passphrase) = env::var("DOMAIN_KEY_PASSPHRASE") {
        let active = pool.list_active_domain_keys().unwrap_or_default();
        let signer_keys: Vec<_> = active
            .into_iter()
            .filter(|k| k.key_usage == "sign" && k.id != revoked.id)
            .collect();
        let active_signers =
            crate::claim_signing::active_signers(&signer_keys, passphrase.as_bytes())
                .unwrap_or_default();
        if active_signers.len() >= REVOCATION_QUORUM {
            let domain = crate::conversions::get_domain_name();
            let revoked_at = revoked.revoked_at.clone().unwrap_or_default();
            let signers: Vec<ClaimSigner> = active_signers
                .iter()
                .map(|s| ClaimSigner {
                    domain: &domain,
                    key_id: &s.key_id,
                    algorithm: s.algorithm,
                    private_key_bytes: &s.private_key,
                })
                .collect();
            let spec = RevocationSpec {
                target_key_id: &revoked.id,
                target_fingerprint: &revoked.fingerprint,
                revoked_at: &revoked_at,
            };
            if let Ok(cert) = build_revocation_certificate(&spec, &signers) {
                let cbor = liblinkkeys::generated::encode_revocation_certificate(&cert);
                if let Ok(when) = chrono::DateTime::parse_from_rfc3339(&revoked_at) {
                    if pool
                        .insert_issued_revocation(
                            &revoked.id,
                            &revoked.fingerprint,
                            when.with_timezone(&chrono::Utc),
                            &cbor,
                        )
                        .is_ok()
                    {
                        certificate_issued = true;
                    }
                }
            }
        }
    }

    Ok(RevokeDomainKeyResponse {
        revoked_key: (&revoked).into(),
        certificate_issued,
        dns_removal_reminder: format!(
            "Remove this key's fingerprint ({}) from the domain's _linkkeys DNS TXT record so peers drop it on their next recheck.",
            revoked.fingerprint
        ),
    })
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
    if req.claim_value.is_empty() {
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

fn claim_approval_to_csil(a: &models::ClaimApproval) -> ClaimApproval {
    ClaimApproval {
        id: a.id.clone(),
        user_id: a.user_id.clone(),
        claim_type: a.claim_type.clone(),
        claim_value: a.claim_value.clone(),
        status: a.status.clone(),
        resolved_by: a.resolved_by.clone(),
        resolved_at: a.resolved_at.clone(),
        created_at: a.created_at.clone(),
    }
}

/// List every claim queued for admin approval — the same rows
/// `render_policy_admin`'s approvals table shows, via
/// `DbPool::list_pending_approvals`.
pub fn list_pending_claim_approvals(
    pool: &DbPool,
    _req: liblinkkeys::generated::types::EmptyRequest,
) -> Result<ListPendingClaimApprovalsResponse, ServiceError> {
    let approvals = pool.list_pending_approvals().map_err(db_err)?;
    Ok(ListPendingClaimApprovalsResponse {
        approvals: approvals.iter().map(claim_approval_to_csil).collect(),
    })
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

/// CSIL-RPC entry point for [`approve_claim`] (`Admin/approve-claim`): the TCP
/// dispatcher supplies `admin_id` from the caller's authenticated identity
/// (the API key's user), the same way `web::policy_admin_ui::approve` supplies
/// the web session's user id.
pub fn approve_claim_request(
    pool: &DbPool,
    req: ApproveClaimRequest,
    admin_id: &str,
) -> Result<ApproveClaimResponse, ServiceError> {
    approve_claim(pool, &req.approval_id, admin_id)?;
    Ok(ApproveClaimResponse { success: true })
}

/// Reject a queued claim: mark it rejected without signing anything.
pub fn reject_claim(pool: &DbPool, approval_id: &str, admin_id: &str) -> Result<(), ServiceError> {
    pool.resolve_approval(approval_id, "rejected", admin_id)
        .map_err(db_err)?;
    Ok(())
}

/// CSIL-RPC entry point for [`reject_claim`] (`Admin/reject-claim`); see
/// [`approve_claim_request`] for the `admin_id` sourcing note.
pub fn reject_claim_request(
    pool: &DbPool,
    req: RejectClaimRequest,
    admin_id: &str,
) -> Result<RejectClaimResponse, ServiceError> {
    reject_claim(pool, &req.approval_id, admin_id)?;
    Ok(RejectClaimResponse { success: true })
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

/// Admin-triggered claim-ticket cleanup (mirrors `recheck-pins`'s
/// cron-friendly shape, but is a plain DB op with no outbound/DNS
/// dependency, so it runs through the normal `admin_op!` dispatch path
/// rather than `recheck-pins`'s dedicated TCP-carrier path). Deletes every
/// expired `LocalRp` claim-get ticket using the server's own clock.
pub fn purge_local_rp_tickets(
    pool: &DbPool,
    _req: PurgeLocalRpTicketsRequest,
) -> Result<PurgeLocalRpTicketsResponse, ServiceError> {
    let purged = crate::services::local_rp::purge_expired_tickets(pool, chrono::Utc::now())
        .map_err(db_err)?;
    Ok(PurgeLocalRpTicketsResponse {
        purged_count: purged as i64,
    })
}

// -- Claim-type registry admin (policy-admin web UI parity) --
//
// Second entry point onto the exact same DB calls `web/policy_admin_ui.rs`'s
// handlers (`upsert_policy`/`delete_policy`/`upsert_claim_label`/
// `delete_claim_label`) make, so a controller holding an admin-relation API
// key can manage the registry without the web UI. Validation mirrors those
// handlers exactly — see the comment on each fn for which web handler it
// reuses the behavior of.

fn claim_policy_to_csil(p: &models::ClaimTypePolicy) -> ClaimTypePolicy {
    ClaimTypePolicy {
        claim_type: p.claim_type.clone(),
        label: p.label.clone(),
        description: p.description.clone(),
        value_type: p.value_type.clone(),
        max_bytes: p.max_bytes,
        set_rule: p.set_rule.clone(),
        signing_rule: p.signing_rule.clone(),
        requires_approval: p.requires_approval,
        user_settable: p.user_settable,
        default_auto_sign: p.default_auto_sign,
        suggested: p.suggested,
    }
}

fn claim_label_to_csil(l: &models::ClaimLabelI18n) -> ClaimTypeLabel {
    ClaimTypeLabel {
        claim_type: l.claim_type.clone(),
        locale: l.locale.clone(),
        label: l.label.clone(),
        description: l.description.clone(),
    }
}

/// List the domain's full claim-type registry — the same rows
/// `render_policy_admin`'s registry table shows, via
/// `DbPool::list_claim_policies`. The web page lists them but (until this
/// op) there was no CSIL-RPC read path for the registry.
pub fn list_claim_types(
    pool: &DbPool,
    _req: liblinkkeys::generated::types::EmptyRequest,
) -> Result<ListClaimTypesResponse, ServiceError> {
    let policies = pool.list_claim_policies().map_err(db_err)?;
    Ok(ListClaimTypesResponse {
        claim_types: policies.iter().map(claim_policy_to_csil).collect(),
    })
}

/// Create-or-update a claim-type definition. Mirrors
/// `web::policy_admin_ui::upsert_policy` field-for-field, including its
/// server-side validation (an unparseable `value_type`/`set_rule`/
/// `signing_rule` would otherwise be stored and only fail at claim-set
/// time), then calls the same `DbPool::upsert_claim_policy`.
pub fn set_claim_type(
    pool: &DbPool,
    req: SetClaimTypeRequest,
) -> Result<SetClaimTypeResponse, ServiceError> {
    use liblinkkeys::claim_policy::{SetRule, SigningRule, ValueType};

    let claim_type = req.claim_type.trim();
    if claim_type.is_empty() {
        return Err(ServiceError {
            code: 400,
            message: "claim_type is required".to_string(),
        });
    }
    if req.max_bytes <= 0 {
        return Err(ServiceError {
            code: 400,
            message: "max_bytes must be a positive number".to_string(),
        });
    }
    if ValueType::parse(&req.value_type).is_none() {
        return Err(ServiceError {
            code: 400,
            message: "invalid value type".to_string(),
        });
    }
    if SetRule::parse(&req.set_rule).is_none() {
        return Err(ServiceError {
            code: 400,
            message: "invalid set rule".to_string(),
        });
    }
    if SigningRule::parse(&req.signing_rule).is_none() {
        return Err(ServiceError {
            code: 400,
            message: "invalid signing rule".to_string(),
        });
    }

    let policy = models::ClaimTypePolicy {
        claim_type: claim_type.to_string(),
        label: req.label.trim().to_string(),
        description: req.description.clone().unwrap_or_default(),
        value_type: req.value_type,
        max_bytes: req.max_bytes,
        set_rule: req.set_rule,
        signing_rule: req.signing_rule,
        requires_approval: req.requires_approval,
        user_settable: req.user_settable,
        default_auto_sign: req.default_auto_sign,
        suggested: req.suggested,
    };
    pool.upsert_claim_policy(policy.clone()).map_err(db_err)?;
    Ok(SetClaimTypeResponse {
        claim_type: claim_policy_to_csil(&policy),
    })
}

/// Delete a claim-type definition by id. Mirrors
/// `web::policy_admin_ui::delete_policy`: delegates straight to
/// `DbPool::delete_claim_policy` with no existence pre-check (an
/// already-absent claim type is a no-op success there, same as here).
pub fn remove_claim_type(
    pool: &DbPool,
    req: RemoveClaimTypeRequest,
) -> Result<RemoveClaimTypeResponse, ServiceError> {
    pool.delete_claim_policy(req.claim_type.trim())
        .map_err(db_err)?;
    Ok(RemoveClaimTypeResponse { success: true })
}

/// Set a claim-type name translation. Mirrors
/// `web::policy_admin_ui::upsert_claim_label` exactly: requires non-empty
/// claim_type/locale/label, requires the claim type already be registered
/// (only translate what exists), and calls the same
/// `DbPool::upsert_claim_label_i18n`.
pub fn set_claim_type_label(
    pool: &DbPool,
    req: SetClaimTypeLabelRequest,
) -> Result<SetClaimTypeLabelResponse, ServiceError> {
    let claim_type = req.claim_type.trim();
    let locale = req.locale.trim();
    let label = req.label.trim();
    if claim_type.is_empty() || locale.is_empty() || label.is_empty() {
        return Err(ServiceError {
            code: 400,
            message: "claim type, locale and name are required".to_string(),
        });
    }
    if !matches!(pool.find_claim_policy(claim_type), Ok(Some(_))) {
        return Err(ServiceError {
            code: 404,
            message: "unknown claim type".to_string(),
        });
    }
    let description = req
        .description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let entry = models::ClaimLabelI18n {
        claim_type: claim_type.to_string(),
        locale: locale.to_string(),
        label: label.to_string(),
        description,
    };
    pool.upsert_claim_label_i18n(entry.clone())
        .map_err(db_err)?;
    Ok(SetClaimTypeLabelResponse {
        label: claim_label_to_csil(&entry),
    })
}

/// Delete a claim-type name translation. Mirrors
/// `web::policy_admin_ui::delete_claim_label`: delegates straight to
/// `DbPool::delete_claim_label_i18n` with no existence pre-check.
pub fn remove_claim_type_label(
    pool: &DbPool,
    req: RemoveClaimTypeLabelRequest,
) -> Result<RemoveClaimTypeLabelResponse, ServiceError> {
    pool.delete_claim_label_i18n(req.claim_type.trim(), req.locale.trim())
        .map_err(db_err)?;
    Ok(RemoveClaimTypeLabelResponse { success: true })
}

// -- Trusted-issuer and release-default admin (policy-admin web UI parity,
// slice 2) --
//
// Second entry point onto the exact same DB calls `web/policy_admin_ui.rs`'s
// handlers (`add_issuer`/`remove_issuer`/`upsert_release`/`delete_release`)
// make, so a controller holding an admin-relation API key can manage trusted
// issuers and per-audience release defaults without the web UI. Unlike
// `add_issuer`, this op does not best-effort cache the issuer's domain keys —
// that requires an async `Net` fetch the synchronous TCP dispatch path
// doesn't have; trust is still recorded immediately and keys are cached on a
// later deposit/refresh, same as when the web handler's fetch fails.

fn trusted_issuer_to_csil(t: &models::TrustedIssuer) -> TrustedIssuer {
    TrustedIssuer {
        claim_type: t.claim_type.clone(),
        issuer_domain: t.issuer_domain.clone(),
    }
}

fn release_policy_to_csil(r: &models::ReleasePolicy) -> ReleaseRule {
    ReleaseRule {
        audience: r.audience.clone(),
        claim_type: r.claim_type.clone(),
        disposition: r.disposition.clone(),
    }
}

/// List every trusted issuer across all claim types — the same rows
/// `render_policy_admin`'s trusted-issuers table shows, via
/// `DbPool::list_all_trusted_issuers`.
pub fn list_trusted_issuers(
    pool: &DbPool,
    _req: liblinkkeys::generated::types::EmptyRequest,
) -> Result<ListTrustedIssuersResponse, ServiceError> {
    let issuers = pool.list_all_trusted_issuers().map_err(db_err)?;
    Ok(ListTrustedIssuersResponse {
        trusted_issuers: issuers.iter().map(trusted_issuer_to_csil).collect(),
    })
}

/// Add a trusted issuer for a claim type. Mirrors
/// `web::policy_admin_ui::add_issuer`'s DB call
/// (`DbPool::add_trusted_issuer`, insert-if-absent).
pub fn add_trusted_issuer(
    pool: &DbPool,
    req: AddTrustedIssuerRequest,
) -> Result<AddTrustedIssuerResponse, ServiceError> {
    let claim_type = req.claim_type.trim();
    let issuer_domain = req.issuer_domain.trim();
    pool.add_trusted_issuer(claim_type, issuer_domain)
        .map_err(db_err)?;
    Ok(AddTrustedIssuerResponse {
        trusted_issuer: TrustedIssuer {
            claim_type: claim_type.to_string(),
            issuer_domain: issuer_domain.to_string(),
        },
    })
}

/// Remove a trusted issuer for a claim type. Mirrors
/// `web::policy_admin_ui::remove_issuer`: delegates straight to
/// `DbPool::remove_trusted_issuer` with no existence pre-check.
pub fn remove_trusted_issuer(
    pool: &DbPool,
    req: RemoveTrustedIssuerRequest,
) -> Result<RemoveTrustedIssuerResponse, ServiceError> {
    pool.remove_trusted_issuer(req.claim_type.trim(), req.issuer_domain.trim())
        .map_err(db_err)?;
    Ok(RemoveTrustedIssuerResponse { success: true })
}

/// List every per-audience release rule — the same rows
/// `render_policy_admin`'s release-rules table shows, via
/// `DbPool::list_release_policies`.
pub fn list_release_rules(
    pool: &DbPool,
    _req: liblinkkeys::generated::types::EmptyRequest,
) -> Result<ListReleaseRulesResponse, ServiceError> {
    let rules = pool.list_release_policies().map_err(db_err)?;
    Ok(ListReleaseRulesResponse {
        release_rules: rules.iter().map(release_policy_to_csil).collect(),
    })
}

/// Create-or-update a release rule. Mirrors
/// `web::policy_admin_ui::upsert_release` exactly, including its
/// server-side validation of `disposition` (an unparseable disposition
/// would otherwise be stored and misapplied at consent time), then calls
/// the same `DbPool::upsert_release_policy`.
pub fn set_release_rule(
    pool: &DbPool,
    req: SetReleaseRuleRequest,
) -> Result<SetReleaseRuleResponse, ServiceError> {
    if req.disposition != "forced_allow" && req.disposition != "forced_deny" {
        return Err(ServiceError {
            code: 400,
            message: "invalid disposition".to_string(),
        });
    }
    let audience = req.audience.trim();
    let claim_type = req.claim_type.trim();
    pool.upsert_release_policy(audience, claim_type, &req.disposition)
        .map_err(db_err)?;
    Ok(SetReleaseRuleResponse {
        release_rule: ReleaseRule {
            audience: audience.to_string(),
            claim_type: claim_type.to_string(),
            disposition: req.disposition,
        },
    })
}

/// Delete a release rule. Mirrors `web::policy_admin_ui::delete_release`:
/// delegates straight to `DbPool::delete_release_policy` with no
/// existence pre-check.
pub fn remove_release_rule(
    pool: &DbPool,
    req: RemoveReleaseRuleRequest,
) -> Result<RemoveReleaseRuleResponse, ServiceError> {
    pool.delete_release_policy(req.audience.trim(), req.claim_type.trim())
        .map_err(db_err)?;
    Ok(RemoveReleaseRuleResponse { success: true })
}

/// Admin issues (signs) and stores an attested claim directly for one of this
/// domain's own users — the `policy-admin` "Issue an attestation" web flow
/// (`issue_verify` + `issue_sign`), collapsed to one CSIL-RPC call for a
/// controller that already holds this domain's `admin` relation.
///
/// Reuses the exact signing call `issue_sign` makes
/// (`attestation::issue_attested_claim`, signed with the domain's active keys —
/// the subject is always this domain, since `user_id` names one of our own
/// accounts). Unlike the web flow, storage does not round-trip through
/// `Attestation/deposit-claim` over the network: that path exists to let an
/// EXTERNAL issuer deposit into a subject's home domain (and requires the
/// signing domain to be registered as a trusted issuer of itself for this
/// claim type, purely an artifact of reusing the external-deposit gate). Here
/// we ARE the subject's home domain and the caller already holds full domain
/// `admin` authority — the same authority `set_claim` already exercises with
/// no request/consent gate — so the signed claim is stored directly with
/// `DbPool::create_claim`, the same low-level primitive the deposit path
/// itself uses to persist a verified attestation.
pub fn admin_issue_attestation(
    pool: &DbPool,
    req: AdminIssueAttestationRequest,
) -> Result<AdminIssueAttestationResponse, ServiceError> {
    pool.find_user_by_id(&req.user_id).map_err(|e| match e {
        diesel::result::Error::NotFound => ServiceError {
            code: 404,
            message: "User not found".to_string(),
        },
        other => db_err(other),
    })?;

    let our_domain = crate::conversions::get_domain_name();
    let signed = crate::services::attestation::issue_attested_claim(
        pool,
        &req.user_id,
        &our_domain,
        &req.claim_type,
        &req.claim_value,
    )?;

    let expires = signed
        .expires_at
        .as_deref()
        .map(|s| chrono::DateTime::parse_from_rfc3339(s).map(|dt| dt.with_timezone(&chrono::Utc)))
        .transpose()
        .map_err(|_| svc_err("invalid expires_at"))?;
    let attested = chrono::DateTime::parse_from_rfc3339(&signed.attested_at)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|_| svc_err("invalid attested_at"))?;

    let stored = pool
        .create_claim(
            &signed.claim_id,
            &req.user_id,
            &signed.claim_type,
            &signed.claim_value,
            &signed.signatures,
            expires,
            attested,
        )
        .map_err(db_err)?;

    let claim: Claim = (&stored).into();
    Ok(AdminIssueAttestationResponse { claim })
}
