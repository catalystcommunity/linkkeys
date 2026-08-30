// Test data factory: shared via `mod common;` in each test binary.
// `#[allow(dead_code)]` on each item because not every test binary uses
// every helper — Rust treats each test binary as its own crate, so any
// unused helper would otherwise be flagged per-binary.

use serde_json::Value;
use std::collections::HashMap;

use linkkeys::db::models::{
    ApplicationInstance, ApplicationKey, ApplicationKeyAttestationRecord,
    ApplicationKeyRevocationRecord, AuthCredential, ClaimTypePolicy, DomainKey, GuestbookEntry,
    LocalRp, LocalRpClaimTicket, Relation, ReleasePolicy, TrustedIssuer, User,
};
use linkkeys::db::DbPool;

#[allow(dead_code)]
pub type DataMap = HashMap<String, Value>;

#[allow(dead_code)]
pub fn create_guestbook_entry(pool: &DbPool, overrides: &DataMap) -> GuestbookEntry {
    let name = extract_str(overrides, "name", || {
        format!("test-guest-{}", rand_suffix())
    });
    pool.guestbook_create(&name)
        .expect("Failed to create test guestbook entry")
}

#[allow(dead_code)]
pub fn create_user(pool: &DbPool, overrides: &DataMap) -> User {
    let username = extract_str(overrides, "username", || {
        format!("test-user-{}", rand_suffix())
    });
    let display_name = extract_str(overrides, "display_name", || {
        format!("Test User {}", rand_suffix())
    });
    pool.create_user(&username, &display_name)
        .expect("Failed to create test user")
}

#[allow(dead_code)]
pub fn create_auth_credential(
    pool: &DbPool,
    user_id: &str,
    credential_type: &str,
    credential_hash: &str,
) -> AuthCredential {
    pool.create_auth_credential(user_id, credential_type, credential_hash)
        .expect("Failed to create test auth credential")
}

#[allow(dead_code)]
pub fn create_domain_key(pool: &DbPool) -> DomainKey {
    let (vk, sk) = liblinkkeys::crypto::generate_ed25519_keypair();
    let pk_bytes = vk.as_bytes().to_vec();
    let sk_bytes = sk.to_bytes();
    let encrypted = liblinkkeys::crypto::encrypt_private_key(&sk_bytes, b"test-passphrase")
        .expect("Failed to encrypt test key");
    let fp = liblinkkeys::crypto::fingerprint(&pk_bytes);
    let expires = chrono::Utc::now() + chrono::Duration::days(365);

    pool.create_domain_key(&pk_bytes, &encrypted, &fp, "ed25519", expires)
        .expect("Failed to create test domain key")
}

/// Create a domain X25519 ENCRYPTION key vouched by `signing_key`, mirroring
/// what a real domain does when it provisions the dedicated encryption key
/// `encrypt_token_for_rp`/`decrypt_token_core` seal/open against (never a
/// converted Ed25519 key). Returns the raw (public, private) key bytes so
/// callers can seal/open directly in the test.
#[allow(dead_code)]
pub fn create_domain_encryption_key(pool: &DbPool, signing_key: &DomainKey) -> (Vec<u8>, Vec<u8>) {
    let sk_bytes = liblinkkeys::crypto::decrypt_private_key(
        &signing_key.private_key_encrypted,
        b"test-passphrase",
    )
    .expect("decrypt test signing key");

    let (enc_pub, enc_priv) = liblinkkeys::crypto::generate_x25519_keypair();
    let enc_fp = liblinkkeys::crypto::fingerprint(&enc_pub);
    let enc_priv_encrypted =
        liblinkkeys::crypto::encrypt_private_key(&enc_priv, b"test-passphrase")
            .expect("encrypt test encryption key");
    // Whole-second expiry, as production does: the vouch signs this exact
    // string, and only whole seconds round-trip byte-identically through
    // pg timestamptz (which truncates nanoseconds).
    use chrono::Timelike;
    let expires = (chrono::Utc::now() + chrono::Duration::days(365))
        .with_nanosecond(0)
        .expect("zeroing nanoseconds cannot fail");
    let vouch = liblinkkeys::dns::sign_key_vouch(
        &enc_fp,
        &expires.to_rfc3339(),
        liblinkkeys::crypto::SigningAlgorithm::Ed25519,
        &sk_bytes,
    )
    .expect("sign test key vouch");

    pool.create_domain_encryption_key(
        &enc_pub,
        &enc_priv_encrypted,
        &enc_fp,
        &signing_key.id,
        &vouch,
        expires,
    )
    .expect("Failed to create test domain encryption key");

    (enc_pub, enc_priv)
}

#[allow(dead_code)]
pub fn create_relation(
    pool: &DbPool,
    subject_type: &str,
    subject_id: &str,
    relation: &str,
    object_type: &str,
    object_id: &str,
) -> Relation {
    pool.create_relation(subject_type, subject_id, relation, object_type, object_id)
        .expect("Failed to create test relation")
}

/// Create a claim-type registry entry directly via `DbPool::upsert_claim_policy`
/// (the same call `services::admin::set_claim_type`/the policy-admin web UI's
/// `upsert_policy` make). Overrides: `claim_type`, `label`, `description`,
/// `value_type` (default `"text"`), `max_bytes` (default `33792`), `set_rule`
/// (default `"user_self"`), `signing_rule` (default `"self_signed"`),
/// `requires_approval`, `user_settable`, `default_auto_sign`, `suggested`
/// (bool flags, default `false`).
#[allow(dead_code)]
pub fn create_claim_policy(pool: &DbPool, overrides: &DataMap) -> ClaimTypePolicy {
    let claim_type = extract_str(overrides, "claim_type", || {
        format!("test-claim-{}", rand_suffix())
    });
    let label = extract_str(overrides, "label", || {
        format!("Test Claim {}", rand_suffix())
    });
    let description = extract_str(overrides, "description", String::new);
    let value_type = extract_str(overrides, "value_type", || "text".to_string());
    let max_bytes = overrides
        .get("max_bytes")
        .and_then(|v| v.as_i64())
        .unwrap_or(33792);
    let set_rule = extract_str(overrides, "set_rule", || "user_self".to_string());
    let signing_rule = extract_str(overrides, "signing_rule", || "self_signed".to_string());
    let requires_approval = extract_bool(overrides, "requires_approval", false);
    let user_settable = extract_bool(overrides, "user_settable", false);
    let default_auto_sign = extract_bool(overrides, "default_auto_sign", false);
    let suggested = extract_bool(overrides, "suggested", false);

    let policy = ClaimTypePolicy {
        claim_type,
        label,
        description,
        value_type,
        max_bytes,
        set_rule,
        signing_rule,
        requires_approval,
        user_settable,
        default_auto_sign,
        suggested,
    };
    pool.upsert_claim_policy(policy.clone())
        .expect("Failed to create test claim policy");
    policy
}

/// Create a trusted-issuer entry directly via `DbPool::add_trusted_issuer`
/// (the same call `services::admin::add_trusted_issuer`/the policy-admin
/// web UI's `add_issuer` make).
#[allow(dead_code)]
pub fn create_trusted_issuer(
    pool: &DbPool,
    claim_type: &str,
    issuer_domain: &str,
) -> TrustedIssuer {
    pool.add_trusted_issuer(claim_type, issuer_domain)
        .expect("Failed to create test trusted issuer");
    TrustedIssuer {
        claim_type: claim_type.to_string(),
        issuer_domain: issuer_domain.to_string(),
    }
}

/// Create a release-rule entry directly via `DbPool::upsert_release_policy`
/// (the same call `services::admin::set_release_rule`/the policy-admin web
/// UI's `upsert_release` make).
#[allow(dead_code)]
pub fn create_release_rule(
    pool: &DbPool,
    audience: &str,
    claim_type: &str,
    disposition: &str,
) -> ReleasePolicy {
    pool.upsert_release_policy(audience, claim_type, disposition)
        .expect("Failed to create test release rule");
    ReleasePolicy {
        audience: audience.to_string(),
        claim_type: claim_type.to_string(),
        disposition: disposition.to_string(),
    }
}

/// Queue a self-asserted claim for admin approval directly via
/// `DbPool::enqueue_approval` (the same call `services::self_service::
/// set_my_claim` makes for a `requires_approval` claim type). Returns the
/// approval queue entry id.
#[allow(dead_code)]
pub fn create_pending_approval(
    pool: &DbPool,
    user_id: &str,
    claim_type: &str,
    claim_value: &[u8],
) -> String {
    pool.enqueue_approval(user_id, claim_type, claim_value)
        .expect("Failed to queue test approval")
}

/// Create a local RP registry row directly (bypassing the pending-queue
/// guard, which is exercised separately via
/// `linkkeys::services::local_rp::record_login_attempt`). Overrides:
/// `app_name`, `local_domain_hint`, `status` (default `"pending"`). The
/// signing/encryption keys and fingerprint are always freshly generated
/// (fingerprint is `crypto::fingerprint` of the generated signing key, so it
/// is always internally consistent).
#[allow(dead_code)]
pub fn create_local_rp(pool: &DbPool, overrides: &DataMap) -> LocalRp {
    create_local_rp_with_signing_key(pool, overrides).0
}

/// Like [`create_local_rp`], but also returns the raw Ed25519 signing secret
/// key bytes (32-byte seed) generated for the row. `create_local_rp` discards
/// this key, so any test that needs to construct a signed request on the
/// local RP's behalf (e.g. a `SignedLocalRpTicketRedemptionRequest`
/// possession proof) must use this variant instead. Same overrides as
/// `create_local_rp`.
#[allow(dead_code)]
pub fn create_local_rp_with_signing_key(pool: &DbPool, overrides: &DataMap) -> (LocalRp, Vec<u8>) {
    let (signing_pk, signing_sk) = liblinkkeys::crypto::generate_ed25519_keypair();
    let (enc_pk, _enc_sk) = liblinkkeys::crypto::generate_x25519_keypair();
    let signing_pk_bytes = signing_pk.as_bytes().to_vec();
    let signing_sk_bytes = signing_sk.to_bytes().to_vec();
    let fingerprint = liblinkkeys::crypto::fingerprint(&signing_pk_bytes);

    let app_name = extract_str(overrides, "app_name", || {
        format!("Test App {}", rand_suffix())
    });
    let status = extract_str(overrides, "status", || "pending".to_string());
    let local_domain_hint = overrides
        .get("local_domain_hint")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let rp = pool
        .insert_local_rp(
            &fingerprint,
            &signing_pk_bytes,
            &enc_pk,
            &app_name,
            local_domain_hint.as_deref(),
            &status,
            None,
        )
        .expect("Failed to create test local RP");

    (rp, signing_sk_bytes)
}

/// Create a claim-get ticket, hierarchically filling in a fresh `approved`
/// local RP and/or a fresh user when `fingerprint`/`user_id` overrides are
/// absent. Overrides: `fingerprint`, `user_id`, `user_domain` (default
/// `"test.com"`), `ticket_hash`, `granted_claims` (JSON array of strings,
/// default `["handle", "email"]`), `expires_at` (RFC3339, default now + 1h).
#[allow(dead_code)]
pub fn create_local_rp_claim_ticket(pool: &DbPool, overrides: &DataMap) -> LocalRpClaimTicket {
    let fingerprint = match overrides.get("fingerprint").and_then(|v| v.as_str()) {
        Some(fp) => fp.to_string(),
        None => {
            let mut rp_overrides = DataMap::new();
            rp_overrides.insert("status".to_string(), Value::String("approved".to_string()));
            create_local_rp(pool, &rp_overrides).fingerprint
        }
    };
    let user_id = match overrides.get("user_id").and_then(|v| v.as_str()) {
        Some(uid) => uid.to_string(),
        None => create_user(pool, &DataMap::new()).id,
    };
    let user_domain = extract_str(overrides, "user_domain", || "test.com".to_string());
    let ticket_hash = extract_str(overrides, "ticket_hash", || {
        liblinkkeys::crypto::fingerprint(format!("test-ticket-{}", rand_suffix()).as_bytes())
    });
    let granted_claims: Vec<String> = overrides
        .get("granted_claims")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_else(|| vec!["handle".to_string(), "email".to_string()]);
    let expires_at = overrides
        .get("expires_at")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::hours(1));

    linkkeys::services::local_rp::issue_ticket(
        pool,
        &ticket_hash,
        &fingerprint,
        &user_id,
        &user_domain,
        &granted_claims,
        expires_at,
    )
    .expect("Failed to create test local RP claim ticket")
}

/// Create an application instance directly via
/// `DbPool::upsert_application_instance` (idempotent insert-or-get, same call
/// application-key enrollment makes). Overrides: `subject_user_id` (default: a
/// fresh test user), `application_id` (default `test-app-<rand>`),
/// `instance_id` (default `test-instance-<rand>`), `enrolled_at` (RFC3339,
/// default now).
#[allow(dead_code)]
pub fn create_application_instance(pool: &DbPool, overrides: &DataMap) -> ApplicationInstance {
    let subject_user_id = match overrides.get("subject_user_id").and_then(|v| v.as_str()) {
        Some(uid) => uid.to_string(),
        None => create_user(pool, &DataMap::new()).id,
    };
    let application_id = extract_str(overrides, "application_id", || {
        format!("test-app-{}", rand_suffix())
    });
    let instance_id = extract_str(overrides, "instance_id", || {
        format!("test-instance-{}", rand_suffix())
    });
    let enrolled_at = extract_datetime(overrides, "enrolled_at", chrono::Utc::now);

    pool.upsert_application_instance(&subject_user_id, &application_id, &instance_id, enrolled_at)
        .expect("Failed to create test application instance")
}

/// Create an application public key directly via `DbPool::insert_application_key`.
/// Overrides: `key_id` (default `test-appkey-<rand>`), `key_usage` (default
/// `"sign"`; use `"agree"` for an X25519 key), `algorithm` (default
/// `"ed25519"`), `created_at` (RFC3339, default now), `expires_at` (RFC3339,
/// default now + 90 days). The public key bytes and fingerprint are always
/// freshly generated (never overridable — a test that needs a specific key
/// pair should generate it and call `DbPool::insert_application_key` directly).
#[allow(dead_code)]
pub fn create_application_key(
    pool: &DbPool,
    instance_row_id: &str,
    overrides: &DataMap,
) -> ApplicationKey {
    let key_usage = extract_str(overrides, "key_usage", || "sign".to_string());
    let algorithm = extract_str(overrides, "algorithm", || "ed25519".to_string());
    let public_key = if key_usage == "agree" {
        let (pk, _sk) = liblinkkeys::crypto::generate_x25519_keypair();
        pk
    } else {
        let (vk, _sk) = liblinkkeys::crypto::generate_ed25519_keypair();
        vk.as_bytes().to_vec()
    };
    let fingerprint = liblinkkeys::crypto::fingerprint(&public_key);
    let key_id = extract_str(overrides, "key_id", || {
        format!("test-appkey-{}", rand_suffix())
    });
    let created_at = extract_datetime(overrides, "created_at", chrono::Utc::now);
    let expires_at = extract_datetime(overrides, "expires_at", || {
        chrono::Utc::now() + chrono::Duration::days(90)
    });

    pool.insert_application_key(
        instance_row_id,
        &key_id,
        &key_usage,
        &algorithm,
        &public_key,
        &fingerprint,
        created_at,
        expires_at,
    )
    .expect("Failed to create test application key")
}

/// Create (or renew) an application key's attestation directly via
/// `DbPool::upsert_application_key_attestation`. Overrides:
/// `signed_attestation` (UTF-8 test payload, default a random test string —
/// storage tests never need real CBOR, just distinguishable opaque bytes),
/// `attested_at` (RFC3339, default now), `expires_at` (RFC3339, default now +
/// 24h, matching the design's default attestation lifetime).
#[allow(dead_code)]
pub fn create_application_key_attestation(
    pool: &DbPool,
    application_key_row_id: &str,
    overrides: &DataMap,
) -> ApplicationKeyAttestationRecord {
    let signed_attestation = overrides
        .get("signed_attestation")
        .and_then(|v| v.as_str())
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_else(|| format!("test-attestation-{}", rand_suffix()).into_bytes());
    let attested_at = extract_datetime(overrides, "attested_at", chrono::Utc::now);
    let expires_at = extract_datetime(overrides, "expires_at", || {
        chrono::Utc::now() + chrono::Duration::hours(24)
    });

    pool.upsert_application_key_attestation(
        application_key_row_id,
        &signed_attestation,
        attested_at,
        expires_at,
    )
    .expect("Failed to create test application key attestation");

    pool.get_application_key_attestation(application_key_row_id)
        .expect("Failed to load test application key attestation")
        .expect("Application key attestation missing after upsert")
}

/// Record an application-key revocation directly via
/// `DbPool::insert_application_key_revocation`. Overrides: `target_key_id`
/// (default `test-appkey-<rand>`), `target_fingerprint` (default a fresh test
/// fingerprint), `revoked_at` (RFC3339, default now), `record` (UTF-8 test
/// payload, default a random test string).
#[allow(dead_code)]
pub fn create_application_key_revocation(
    pool: &DbPool,
    instance_row_id: &str,
    overrides: &DataMap,
) -> ApplicationKeyRevocationRecord {
    let target_key_id = extract_str(overrides, "target_key_id", || {
        format!("test-appkey-{}", rand_suffix())
    });
    let target_fingerprint = extract_str(overrides, "target_fingerprint", || {
        liblinkkeys::crypto::fingerprint(format!("test-fp-{}", rand_suffix()).as_bytes())
    });
    let revoked_at = extract_datetime(overrides, "revoked_at", chrono::Utc::now);
    let record = overrides
        .get("record")
        .and_then(|v| v.as_str())
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_else(|| format!("test-revocation-{}", rand_suffix()).into_bytes());

    pool.insert_application_key_revocation(
        instance_row_id,
        &target_key_id,
        &target_fingerprint,
        revoked_at,
        &record,
    )
    .expect("Failed to create test application key revocation");

    pool.list_application_key_revocations_since(instance_row_id, None)
        .expect("Failed to load test application key revocations")
        .into_iter()
        .find(|r| r.target_key_id == target_key_id)
        .expect("Application key revocation missing after insert")
}

#[allow(dead_code)]
fn extract_str(overrides: &DataMap, key: &str, default: impl Fn() -> String) -> String {
    overrides
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(default)
}

#[allow(dead_code)]
fn extract_bool(overrides: &DataMap, key: &str, default: bool) -> bool {
    overrides
        .get(key)
        .and_then(|v| v.as_bool())
        .unwrap_or(default)
}

#[allow(dead_code)]
fn extract_datetime(
    overrides: &DataMap,
    key: &str,
    default: impl Fn() -> chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    overrides
        .get(key)
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(default)
}

#[allow(dead_code)]
fn rand_suffix() -> String {
    use rand::Rng;
    let n: u32 = rand::thread_rng().gen();
    format!("{:08x}", n)
}
