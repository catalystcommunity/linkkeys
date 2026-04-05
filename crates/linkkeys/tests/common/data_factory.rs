use serde_json::Value;
use std::collections::HashMap;

use linkkeys::db::models::{AuthCredential, DomainKey, GuestbookEntry, User};
use super::TestDb;

pub type DataMap = HashMap<String, Value>;

pub fn create_guestbook_entry(db: &mut TestDb, overrides: &DataMap) -> GuestbookEntry {
    let name = extract_str(overrides, "name", || format!("test-guest-{}", rand_suffix()));

    match db {
        #[cfg(feature = "postgres")]
        TestDb::Postgres(conn) => {
            linkkeys::db::guestbook::pg::create(conn, &name)
                .expect("Failed to create test guestbook entry")
        }
        #[cfg(feature = "sqlite")]
        TestDb::Sqlite(conn) => {
            linkkeys::db::guestbook::sqlite::create(conn, &name)
                .expect("Failed to create test guestbook entry")
        }
    }
}

pub fn create_user(db: &mut TestDb, overrides: &DataMap) -> User {
    let username = extract_str(overrides, "username", || format!("test-user-{}", rand_suffix()));
    let display_name = extract_str(overrides, "display_name", || format!("Test User {}", rand_suffix()));

    match db {
        #[cfg(feature = "postgres")]
        TestDb::Postgres(conn) => {
            linkkeys::db::users::pg::create(conn, &username, &display_name)
                .expect("Failed to create test user")
        }
        #[cfg(feature = "sqlite")]
        TestDb::Sqlite(conn) => {
            linkkeys::db::users::sqlite::create(conn, &username, &display_name)
                .expect("Failed to create test user")
        }
    }
}

pub fn create_auth_credential(
    db: &mut TestDb,
    user_id: &str,
    credential_type: &str,
    credential_hash: &str,
) -> AuthCredential {
    match db {
        #[cfg(feature = "postgres")]
        TestDb::Postgres(conn) => {
            let uid: uuid::Uuid = user_id.parse().expect("Invalid user UUID in test");
            linkkeys::db::auth_credentials::pg::create(conn, uid, credential_type, credential_hash)
                .expect("Failed to create test auth credential")
        }
        #[cfg(feature = "sqlite")]
        TestDb::Sqlite(conn) => {
            linkkeys::db::auth_credentials::sqlite::create(conn, user_id, credential_type, credential_hash)
                .expect("Failed to create test auth credential")
        }
    }
}

pub fn create_domain_key(db: &mut TestDb) -> DomainKey {
    let (vk, sk) = liblinkkeys::crypto::generate_ed25519_keypair();
    let pk_bytes = vk.as_bytes().to_vec();
    let sk_bytes = sk.to_bytes();
    let encrypted = liblinkkeys::crypto::encrypt_private_key(&sk_bytes, b"test-passphrase")
        .expect("Failed to encrypt test key");
    let fp = liblinkkeys::crypto::fingerprint(&pk_bytes);
    let expires = chrono::Utc::now() + chrono::Duration::days(365);

    match db {
        #[cfg(feature = "postgres")]
        TestDb::Postgres(conn) => {
            linkkeys::db::domain_keys::pg::create(conn, &pk_bytes, &encrypted, &fp, "ed25519", expires)
                .expect("Failed to create test domain key")
        }
        #[cfg(feature = "sqlite")]
        TestDb::Sqlite(conn) => {
            linkkeys::db::domain_keys::sqlite::create(conn, &pk_bytes, &encrypted, &fp, "ed25519", &expires.to_rfc3339())
                .expect("Failed to create test domain key")
        }
    }
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
