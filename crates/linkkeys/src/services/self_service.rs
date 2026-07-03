//! User self-service over the claim-type policy registry: a user setting their
//! own claims (auto-validated and -signed per the registry), toggling whether a
//! claim is kept signed, managing their own profiles, and discovering what they
//! may set. The set/sign decision is the pure `liblinkkeys::claim_policy`
//! evaluator; this module is the fallible adapter that loads policy, signs with
//! the domain keys, and persists.
//!
//! Every operation here takes a structured input and returns a structured
//! result, so the same logic backs the web editor today and a CLI / native agent
//! later — the transport only renders.

use std::env;

use liblinkkeys::claim_policy::{
    evaluate_set, ClaimPolicy, SetAction, SetRule, Setter, SigningRule, ValueType,
};
use liblinkkeys::generated::services::ServiceError;

use crate::db::models;
use crate::db::DbPool;

fn svc_err(code: i32, msg: &str) -> ServiceError {
    ServiceError {
        code,
        message: msg.to_string(),
    }
}

fn db_err(e: diesel::result::Error) -> ServiceError {
    log::error!("Database error: {}", e);
    svc_err(500, "Internal database error")
}

/// What happened to a self-service set attempt — the caller renders an
/// appropriate message/badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOutcome {
    /// Validated and signed with the domain keys; the value is now verified.
    Signed,
    /// Stored without a domain signature (auto-sign off, or an unsigned lane).
    StoredUnsigned,
    /// A verification flow is required before this value can be signed (lane B).
    VerificationRequired,
    /// Held for admin approval before signing.
    Queued,
}

/// Map a registry row onto the pure evaluator's policy view, or fail if the row
/// holds an unparseable rule (a registry corruption / generator bug, not user
/// error).
fn to_policy(row: &models::ClaimTypePolicy) -> Result<ClaimPolicy, ServiceError> {
    let value_type = ValueType::parse(&row.value_type)
        .ok_or_else(|| svc_err(500, "registry: bad value_type"))?;
    let set_rule =
        SetRule::parse(&row.set_rule).ok_or_else(|| svc_err(500, "registry: bad set_rule"))?;
    let signing_rule = SigningRule::parse(&row.signing_rule)
        .ok_or_else(|| svc_err(500, "registry: bad signing_rule"))?;
    Ok(ClaimPolicy {
        claim_type: row.claim_type.clone(),
        value_type,
        max_bytes: row.max_bytes.max(0) as u64,
        set_rule,
        signing_rule,
        requires_approval: row.requires_approval,
        user_settable: row.user_settable,
    })
}

/// Set a claim for a profile on behalf of the user. Looks up the registry,
/// evaluates the set, and either signs+stores, stores unsigned, defers to
/// verification, or queues for approval. `subject_id` is the profile the claim
/// is about (the default profile == the account id today).
pub fn set_my_claim(
    pool: &DbPool,
    subject_id: &str,
    claim_type: &str,
    value: &[u8],
) -> Result<SetOutcome, ServiceError> {
    let row = pool
        .find_claim_policy(claim_type)
        .map_err(db_err)?
        .ok_or_else(|| {
            svc_err(
                400,
                &liblinkkeys::claim_policy::RejectionReason::UnknownClaimType.to_string(),
            )
        })?;

    // Server-side authorization: the registry's `user_settable` flag is the gate,
    // not just a UI hint. `claim_type` arrives from a client-controlled form
    // field, so a user must never be able to set a type the admin didn't open to
    // self-service (e.g. `email_verified`, which the IDP sets as a side effect).
    if !row.user_settable {
        return Err(svc_err(
            403,
            &liblinkkeys::claim_policy::RejectionReason::SetterNotAuthorized.to_string(),
        ));
    }

    let policy = to_policy(&row)?;

    let action = evaluate_set(&policy, Setter::User, value)
        .map_err(|reason| svc_err(400, &reason.to_string()))?;

    // The user's auto-sign preference, defaulting to the registry default.
    let auto_sign = pool
        .get_profile_pref(subject_id, claim_type)
        .map_err(db_err)?
        .unwrap_or(row.default_auto_sign);

    match action {
        SetAction::SelfSign => {
            if auto_sign {
                sign_and_store(pool, subject_id, claim_type, value)?;
                Ok(SetOutcome::Signed)
            } else {
                store_unsigned(pool, subject_id, claim_type, value)?;
                Ok(SetOutcome::StoredUnsigned)
            }
        }
        SetAction::StoreUnsigned => {
            store_unsigned(pool, subject_id, claim_type, value)?;
            Ok(SetOutcome::StoredUnsigned)
        }
        // Lane B: the value isn't stored until a verification flow completes
        // (see services::verification). Self-service set just signals that.
        SetAction::Verify => Ok(SetOutcome::VerificationRequired),
        SetAction::Queue => {
            pool.enqueue_approval(subject_id, claim_type, value)
                .map_err(db_err)?;
            Ok(SetOutcome::Queued)
        }
        // A user can't reach the attested path — set_rule gates it to issuers —
        // so this is unreachable in practice; fail closed if it ever isn't.
        SetAction::AcceptAttested => Err(svc_err(400, "this claim must be attested by an issuer")),
    }
}

/// Decrypt the domain's active signing keys, sign a fresh claim binding
/// `subject_id@<our domain>`, and store it — revoking any prior active claim of
/// the same type first so a profile holds one active value per type. Exposed to
/// the verification flow, which signs `email` / `email_verified` once a
/// challenge is confirmed.
///
/// NOTE(follow-up): the revoke and create run on separate pooled connections, so
/// they are not atomic. For single-user self-service this is low-risk, but two
/// concurrent sets of the same type could leave two active values. Wrap both in
/// one transaction when a transaction-scoped DbPool accessor exists.
pub(crate) fn sign_and_store(
    pool: &DbPool,
    subject_id: &str,
    claim_type: &str,
    value: &[u8],
) -> Result<(), ServiceError> {
    let passphrase = env::var("DOMAIN_KEY_PASSPHRASE")
        .map_err(|_| svc_err(500, "DOMAIN_KEY_PASSPHRASE not set"))?;
    let domain_keys = pool.list_active_domain_keys().map_err(db_err)?;
    let signers = crate::claim_signing::active_signers(&domain_keys, passphrase.as_bytes())
        .map_err(|e| svc_err(500, &e.to_string()))?;

    let claim_id = uuid::Uuid::now_v7().to_string();
    let subject_domain = crate::conversions::get_domain_name();
    use chrono::Timelike;
    let attested_chrono = chrono::Utc::now().with_nanosecond(0).unwrap();
    let attested_str = attested_chrono.to_rfc3339();
    let signed = crate::claim_signing::sign_with_active(
        &liblinkkeys::claims::ClaimSpec {
            claim_id: &claim_id,
            claim_type,
            claim_value: value,
            user_id: subject_id,
            subject_domain: &subject_domain,
            expires_at: None,
            attested_at: &attested_str,
        },
        &signers,
    )
    .map_err(|e| svc_err(500, &e.to_string()))?;

    pool.revoke_active_claims_of_type(subject_id, claim_type)
        .map_err(db_err)?;
    pool.create_claim(
        &claim_id,
        subject_id,
        claim_type,
        value,
        &signed.signatures,
        None,
        attested_chrono,
    )
    .map_err(db_err)?;
    Ok(())
}

/// Store a claim with no domain signature, revoking any prior active value.
fn store_unsigned(
    pool: &DbPool,
    subject_id: &str,
    claim_type: &str,
    value: &[u8],
) -> Result<(), ServiceError> {
    let claim_id = uuid::Uuid::now_v7().to_string();
    pool.revoke_active_claims_of_type(subject_id, claim_type)
        .map_err(db_err)?;
    pool.create_claim(
        &claim_id,
        subject_id,
        claim_type,
        value,
        &[],
        None,
        chrono::Utc::now(),
    )
    .map_err(db_err)?;
    Ok(())
}

/// Record whether the user wants a claim type kept signed automatically. Only
/// meaningful for a `user_settable` type; the value is (re)applied on the next
/// set.
pub fn set_signing_pref(
    pool: &DbPool,
    profile_id: &str,
    claim_type: &str,
    auto_sign: bool,
) -> Result<(), ServiceError> {
    pool.upsert_profile_pref(profile_id, claim_type, auto_sign)
        .map_err(db_err)?;
    Ok(())
}

/// The registry entries a user may set themselves, for the profile editor and
/// the discovery endpoint.
pub fn list_user_settable_policies(
    pool: &DbPool,
) -> Result<Vec<models::ClaimTypePolicy>, ServiceError> {
    let all = pool.list_claim_policies().map_err(db_err)?;
    Ok(all.into_iter().filter(|p| p.user_settable).collect())
}

/// Create an additional presentable profile for the account (capped by
/// `MAX_PROFILES_PER_ACCOUNT`). Deletion is an admin action — users never delete.
pub fn create_profile(
    pool: &DbPool,
    account_id: &str,
    label: Option<&str>,
) -> Result<models::Profile, ServiceError> {
    pool.create_presentable_profile(account_id, label)
        .map_err(|e| svc_err(400, &e))
}

/// The account's presentable profiles (the root anchor is never listed).
pub fn list_profiles(
    pool: &DbPool,
    account_id: &str,
) -> Result<Vec<models::Profile>, ServiceError> {
    pool.list_presentable_profiles_for_account(account_id)
        .map_err(db_err)
}
