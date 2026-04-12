use serde_json::Value;
use std::collections::HashMap;

use linkkeys::db::models::{AuthCredential, DomainKey, GuestbookEntry, Relation, User};
use linkkeys::db::DbPool;

pub type DataMap = HashMap<String, Value>;

pub fn create_guestbook_entry(pool: &DbPool, overrides: &DataMap) -> GuestbookEntry {
    let name = extract_str(overrides, "name", || format!("test-guest-{}", rand_suffix()));
    pool.guestbook_create(&name)
        .expect("Failed to create test guestbook entry")
}

pub fn create_user(pool: &DbPool, overrides: &DataMap) -> User {
    let username = extract_str(overrides, "username", || format!("test-user-{}", rand_suffix()));
    let display_name = extract_str(overrides, "display_name", || format!("Test User {}", rand_suffix()));
    pool.create_user(&username, &display_name)
        .expect("Failed to create test user")
}

pub fn create_auth_credential(
    pool: &DbPool,
    user_id: &str,
    credential_type: &str,
    credential_hash: &str,
) -> AuthCredential {
    pool.create_auth_credential(user_id, credential_type, credential_hash)
        .expect("Failed to create test auth credential")
}

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

fn extract_str(overrides: &DataMap, key: &str, default: impl Fn() -> String) -> String {
    overrides
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(default)
}

fn rand_suffix() -> String {
    use rand::Rng;
    let n: u32 = rand::thread_rng().gen();
    format!("{:08x}", n)
}
