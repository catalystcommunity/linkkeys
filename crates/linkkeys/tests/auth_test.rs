mod common;

use common::data_factory::{create_auth_credential, create_user, DataMap};
use linkkeys::services::auth;
use serde_json::Value;

// -- User and Auth Credential DB Tests --

#[test]
fn test_create_user_without_password_hash() {
    let pool = common::create_test_pool();
    let user = create_user(
        &pool,
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
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let hash = bcrypt::hash("secret123", 4).unwrap(); // cost 4 for test speed

    let cred = create_auth_credential(&pool, &user.id, auth::CREDENTIAL_TYPE_PASSWORD, &hash);
    assert_eq!(cred.user_id, user.id);
    assert_eq!(cred.credential_type, "password");
    assert!(cred.revoked_at.is_none());
}

#[test]
fn test_create_auth_credential_api_key() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let hash = bcrypt::hash("some-api-key-secret", 4).unwrap();

    let cred = create_auth_credential(&pool, &user.id, auth::CREDENTIAL_TYPE_API_KEY, &hash);
    assert_eq!(cred.credential_type, "api_key");
}

#[test]
fn test_find_credentials_for_user() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let hash = bcrypt::hash("pw", 4).unwrap();
    create_auth_credential(&pool, &user.id, auth::CREDENTIAL_TYPE_PASSWORD, &hash);

    let creds = pool
        .find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_PASSWORD)
        .unwrap();
    assert_eq!(creds.len(), 1);

    // API key type should return empty
    let api_creds = pool
        .find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_API_KEY)
        .unwrap();
    assert!(api_creds.is_empty());
}

#[test]
fn test_find_user_by_username() {
    let pool = common::create_test_pool();
    create_user(
        &pool,
        &DataMap::from([("username".into(), Value::String("bob".into()))]),
    );

    let found = pool.find_user_by_username("bob").unwrap();
    assert_eq!(found.username, "bob");
}

#[test]
fn test_unique_username_enforced() {
    let pool = common::create_test_pool();
    create_user(
        &pool,
        &DataMap::from([("username".into(), Value::String("unique".into()))]),
    );

    // Second user with same username should fail
    let result = pool.create_user("unique", "Another");
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
    let pool = common::create_test_pool();
    let dk = common::data_factory::create_domain_key(&pool);

    assert!(!dk.id.is_empty());
    assert_eq!(dk.algorithm, "ed25519");
    assert!(!dk.public_key.is_empty());
    assert!(!dk.private_key_encrypted.is_empty());
    assert_eq!(dk.fingerprint.len(), 64); // SHA-256 hex
    assert!(dk.revoked_at.is_none());
}

#[test]
fn test_domain_key_private_key_encrypted() {
    let pool = common::create_test_pool();
    let dk = common::data_factory::create_domain_key(&pool);

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

// -- Password Authentication Flow Tests --

#[test]
fn test_password_auth_flow_correct_password() {
    let pool = common::create_test_pool();
    let user = create_user(
        &pool,
        &DataMap::from([("username".into(), Value::String("auth-test-user".into()))]),
    );
    let password = "secure-pass-123";
    let hash = bcrypt::hash(password, 4).unwrap();
    create_auth_credential(&pool, &user.id, auth::CREDENTIAL_TYPE_PASSWORD, &hash);

    // Simulate the PasswordAuthenticator flow:
    // 1. Find user by username
    let found_user = pool.find_user_by_username("auth-test-user").unwrap();
    assert_eq!(found_user.id, user.id);

    // 2. Find credentials for user
    let creds = pool
        .find_credentials_for_user(&found_user.id, auth::CREDENTIAL_TYPE_PASSWORD)
        .unwrap();
    assert_eq!(creds.len(), 1);

    // 3. Verify password against credential hash
    let verified = creds
        .iter()
        .any(|c| bcrypt::verify(password, &c.credential_hash).unwrap_or(false));
    assert!(verified, "Correct password should authenticate successfully");
}

#[test]
fn test_password_auth_flow_wrong_password() {
    let pool = common::create_test_pool();
    let user = create_user(
        &pool,
        &DataMap::from([("username".into(), Value::String("wrong-pw-user".into()))]),
    );
    let hash = bcrypt::hash("real-password", 4).unwrap();
    create_auth_credential(&pool, &user.id, auth::CREDENTIAL_TYPE_PASSWORD, &hash);

    let found_user = pool.find_user_by_username("wrong-pw-user").unwrap();
    let creds = pool
        .find_credentials_for_user(&found_user.id, auth::CREDENTIAL_TYPE_PASSWORD)
        .unwrap();

    let verified = creds
        .iter()
        .any(|c| bcrypt::verify("wrong-password", &c.credential_hash).unwrap_or(false));
    assert!(
        !verified,
        "Wrong password should not authenticate"
    );
}

#[test]
fn test_expired_credential_rejected_in_auth_flow() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let hash = bcrypt::hash("will-expire", 4).unwrap();
    let cred =
        create_auth_credential(&pool, &user.id, auth::CREDENTIAL_TYPE_PASSWORD, &hash);

    // Expire the credential
    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    pool.set_credential_expires_at(&cred.id, &past).unwrap();

    // find_for_user filters out expired credentials
    let creds = pool
        .find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_PASSWORD)
        .unwrap();
    assert!(
        creds.is_empty(),
        "Expired credentials should not be returned, preventing authentication"
    );
}

#[test]
fn test_api_key_prefix_secret_format_and_verify() {
    // Test that generate_api_key produces the right format and the secret verifies
    let user_id = "abcdef01-2345-6789-abcd-ef0123456789";
    let (api_key, hash) = auth::generate_api_key(user_id);

    let parts: Vec<&str> = api_key.splitn(2, '.').collect();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].len(), 8);
    assert_eq!(parts[0], "abcdef01");

    // Secret part should verify against the stored hash
    assert!(bcrypt::verify(parts[1], &hash).unwrap());

    // A tampered secret should not verify
    let tampered = format!("{}X", parts[1]);
    assert!(!bcrypt::verify(&tampered, &hash).unwrap_or(true));
}

#[test]
fn test_api_key_credential_stored_and_retrievable() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let (api_key, hash) = auth::generate_api_key(&user.id);

    create_auth_credential(&pool, &user.id, auth::CREDENTIAL_TYPE_API_KEY, &hash);

    let creds = pool
        .find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_API_KEY)
        .unwrap();
    assert_eq!(creds.len(), 1);

    // Extract secret from the api_key and verify against stored hash
    let secret = api_key.splitn(2, '.').nth(1).unwrap();
    assert!(bcrypt::verify(secret, &creds[0].credential_hash).unwrap());
}

#[test]
fn test_revoked_credential_not_returned_in_auth_flow() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let hash = bcrypt::hash("revoke-me", 4).unwrap();
    let cred =
        create_auth_credential(&pool, &user.id, auth::CREDENTIAL_TYPE_PASSWORD, &hash);

    pool.remove_credential(&cred.id).unwrap();

    let creds = pool
        .find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_PASSWORD)
        .unwrap();
    assert!(
        creds.is_empty(),
        "Revoked credentials should not be returned"
    );
}
