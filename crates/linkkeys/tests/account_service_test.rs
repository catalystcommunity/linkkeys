mod common;

use common::data_factory::{
    create_auth_credential, create_domain_key, create_relation, create_user, DataMap,
};
use liblinkkeys::generated::types::*;
use linkkeys::services::{account, auth};

#[test]
fn test_service_change_password() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let old_hash = bcrypt::hash("old-password", 4).unwrap();
    create_auth_credential(&pool, &user.id, auth::CREDENTIAL_TYPE_PASSWORD, &old_hash);

    let req = ChangePasswordRequest {
        new_password: "new-secure-password".to_string(),
    };
    let resp = account::change_password(&pool, &user.id, req).unwrap();
    assert!(resp.success);

    // The new credential is stored as Argon2id, and verifies the new password
    // but not the old one.
    let creds = pool
        .find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_PASSWORD)
        .unwrap();
    assert_eq!(creds.len(), 1);
    assert!(creds[0].credential_hash.starts_with("$argon2"));
    assert!(liblinkkeys::crypto::verify_password(
        "new-secure-password",
        &creds[0].credential_hash
    ));
    assert!(!liblinkkeys::crypto::verify_password(
        "old-password",
        &creds[0].credential_hash
    ));
}

#[test]
fn test_service_change_password_accepts_long_password() {
    // Beyond bcrypt's old 72-byte cap; Argon2id hashes the whole thing.
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let long = "p".repeat(200);
    let req = ChangePasswordRequest {
        new_password: long.clone(),
    };
    assert!(
        account::change_password(&pool, &user.id, req)
            .unwrap()
            .success
    );

    let creds = pool
        .find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_PASSWORD)
        .unwrap();
    assert!(liblinkkeys::crypto::verify_password(
        &long,
        &creds[0].credential_hash
    ));
}

#[test]
fn test_service_change_password_rejects_too_long() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let req = ChangePasswordRequest {
        new_password: "q".repeat(1025),
    };
    assert!(
        account::change_password(&pool, &user.id, req).is_err(),
        "password over the length cap should be rejected"
    );
}

#[test]
fn test_service_change_password_rejects_short() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let req = ChangePasswordRequest {
        new_password: "short".to_string(),
    };
    let result = account::change_password(&pool, &user.id, req);
    assert!(result.is_err(), "Short password should be rejected");
}

#[test]
fn test_service_get_my_info() {
    let pool = common::create_test_pool();
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    let user = create_user(&pool, &DataMap::new());
    let dk = create_domain_key(&pool);

    // Add a relation
    create_relation(&pool, "user", &user.id, "admin", "domain", "test.com");

    // Add a claim
    let sk_bytes =
        liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, b"test-passphrase")
            .unwrap();
    let algorithm = liblinkkeys::crypto::SigningAlgorithm::parse_str(&dk.algorithm).unwrap();
    let claim_id = uuid::Uuid::now_v7().to_string();
    let signed = liblinkkeys::claims::sign_claim(
        &liblinkkeys::claims::ClaimSpec {
            claim_id: &claim_id,
            claim_type: "email",
            claim_value: b"test@test.com",
            user_id: &user.id,
            subject_domain: "test.com",
            expires_at: None,
        },
        &[liblinkkeys::claims::ClaimSigner {
            domain: "test.com",
            key_id: &dk.id,
            algorithm,
            private_key_bytes: &sk_bytes,
        }],
    )
    .unwrap();
    pool.create_claim(
        &claim_id,
        &user.id,
        "email",
        b"test@test.com",
        &signed.signatures,
        None,
    )
    .unwrap();

    let resp = account::get_my_info(&pool, &user.id).unwrap();
    assert_eq!(resp.user.id, user.id);
    assert_eq!(resp.relations.len(), 1);
    assert_eq!(resp.relations[0].relation, "admin");
    assert_eq!(resp.claims.len(), 1);
    assert_eq!(resp.claims[0].claim_type, "email");
}

#[test]
fn test_service_get_my_info_empty() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let resp = account::get_my_info(&pool, &user.id).unwrap();
    assert_eq!(resp.user.id, user.id);
    assert!(resp.relations.is_empty());
    assert!(resp.claims.is_empty());
}
