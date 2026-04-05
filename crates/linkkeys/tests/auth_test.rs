mod common;

use common::data_factory::{create_auth_credential, create_user, DataMap};
use common::TestDb;
use linkkeys::services::auth;
use serde_json::Value;

// -- User and Auth Credential DB Tests --

#[test]
fn test_create_user_without_password_hash() {
    let mut db = TestDb::new();
    let user = create_user(
        &mut db,
        &DataMap::from([
            ("username".into(), Value::String("alice".into())),
            ("display_name".into(), Value::String("Alice Smith".into())),
        ]),
    );
    assert_eq!(user.username, "alice");
    assert_eq!(user.display_name, "Alice Smith");
    assert!(!user.id.is_empty());
}

#[test]
fn test_create_auth_credential_password() {
    let mut db = TestDb::new();
    let user = create_user(&mut db, &DataMap::new());
    let hash = bcrypt::hash("secret123", 4).unwrap(); // cost 4 for test speed

    let cred = create_auth_credential(&mut db, &user.id, auth::CREDENTIAL_TYPE_PASSWORD, &hash);
    assert_eq!(cred.user_id, user.id);
    assert_eq!(cred.credential_type, "password");
    assert!(cred.revoked_at.is_none());
}

#[test]
fn test_create_auth_credential_api_key() {
    let mut db = TestDb::new();
    let user = create_user(&mut db, &DataMap::new());
    let hash = bcrypt::hash("some-api-key-secret", 4).unwrap();

    let cred = create_auth_credential(&mut db, &user.id, auth::CREDENTIAL_TYPE_API_KEY, &hash);
    assert_eq!(cred.credential_type, "api_key");
}

#[test]
fn test_find_credentials_for_user() {
    let mut db = TestDb::new();
    let user = create_user(&mut db, &DataMap::new());
    let hash = bcrypt::hash("pw", 4).unwrap();
    create_auth_credential(&mut db, &user.id, auth::CREDENTIAL_TYPE_PASSWORD, &hash);

    let creds = common::find_credentials_for_user(&mut db, &user.id, auth::CREDENTIAL_TYPE_PASSWORD);
    assert_eq!(creds.len(), 1);

    // API key type should return empty
    let api_creds = common::find_credentials_for_user(&mut db, &user.id, auth::CREDENTIAL_TYPE_API_KEY);
    assert!(api_creds.is_empty());
}

#[test]
fn test_find_user_by_username() {
    let mut db = TestDb::new();
    create_user(
        &mut db,
        &DataMap::from([("username".into(), Value::String("bob".into()))]),
    );

    let found = common::find_user_by_username(&mut db, "bob");
    assert_eq!(found.username, "bob");
}

#[test]
fn test_unique_username_enforced() {
    let mut db = TestDb::new();
    create_user(
        &mut db,
        &DataMap::from([("username".into(), Value::String("unique".into()))]),
    );

    // Second user with same username should fail
    let result = match &mut db {
        #[cfg(feature = "postgres")]
        TestDb::Postgres(conn) => linkkeys::db::users::pg::create(conn, "unique", "Another"),
        #[cfg(feature = "sqlite")]
        TestDb::Sqlite(conn) => linkkeys::db::users::sqlite::create(conn, "unique", "Another"),
    };
    assert!(result.is_err());
}

// -- API Key Generation Tests --

#[test]
fn test_generate_api_key_format() {
    let user_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    let (api_key, hash) = auth::generate_api_key(user_id);

    // Format: <8-char-prefix>.<base64url-secret>
    let parts: Vec<&str> = api_key.splitn(2, '.').collect();
    assert_eq!(parts.len(), 2, "API key should have prefix.secret format");
    assert_eq!(parts[0].len(), 8, "Prefix should be 8 chars");
    assert_eq!(parts[0], &user_id[..8], "Prefix should match first 8 chars of user_id");
    assert!(!parts[1].is_empty(), "Secret should not be empty");

    // Hash should be valid bcrypt
    assert!(hash.starts_with("$2b$") || hash.starts_with("$2a$"));

    // The secret part should verify against the hash
    assert!(bcrypt::verify(parts[1], &hash).unwrap());
}

#[test]
fn test_generate_api_key_unique() {
    let user_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    let (key1, _) = auth::generate_api_key(user_id);
    let (key2, _) = auth::generate_api_key(user_id);
    assert_ne!(key1, key2, "Each API key generation should be unique");
}

// -- Domain Key Tests --

#[test]
fn test_create_domain_key() {
    let mut db = TestDb::new();
    let dk = common::data_factory::create_domain_key(&mut db);

    assert!(!dk.id.is_empty());
    assert_eq!(dk.algorithm, "ed25519");
    assert!(!dk.public_key.is_empty());
    assert!(!dk.private_key_encrypted.is_empty());
    assert_eq!(dk.fingerprint.len(), 64); // SHA-256 hex
    assert!(dk.revoked_at.is_none());
}

#[test]
fn test_domain_key_private_key_encrypted() {
    let mut db = TestDb::new();
    let dk = common::data_factory::create_domain_key(&mut db);

    // The stored private key should not be the raw 32-byte seed
    assert_ne!(dk.private_key_encrypted.len(), 32, "Private key should be encrypted, not raw");
    // Encrypted format: 16 salt + 12 nonce + ciphertext (32 + 16 tag = 48)
    assert!(dk.private_key_encrypted.len() >= 76, "Encrypted key should be at least 76 bytes");

    // Should decrypt with the right passphrase
    let decrypted = liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, b"test-passphrase");
    assert!(decrypted.is_ok());
    assert_eq!(decrypted.unwrap().len(), 32);

    // Should fail with wrong passphrase
    let wrong = liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, b"wrong");
    assert!(wrong.is_err());
}
