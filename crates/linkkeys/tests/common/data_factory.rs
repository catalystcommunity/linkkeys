// Test data factory: shared via `mod common;` in each test binary.
// `#[allow(dead_code)]` on each item because not every test binary uses
// every helper — Rust treats each test binary as its own crate, so any
// unused helper would otherwise be flagged per-binary.

use serde_json::Value;
use std::collections::HashMap;

use linkkeys::db::models::{
    AuthCredential, DomainKey, GuestbookEntry, LocalRp, LocalRpClaimTicket, Relation, User,
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
    let expires = chrono::Utc::now() + chrono::Duration::days(365);
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

#[allow(dead_code)]
fn extract_str(overrides: &DataMap, key: &str, default: impl Fn() -> String) -> String {
    overrides
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(default)
}

#[allow(dead_code)]
fn rand_suffix() -> String {
    use rand::Rng;
    let n: u32 = rand::thread_rng().gen();
    format!("{:08x}", n)
}
