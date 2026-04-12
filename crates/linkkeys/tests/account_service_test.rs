mod common;

use common::data_factory::{create_auth_credential, create_domain_key, create_relation, create_user, DataMap};
use linkkeys::services::{account, auth};
use liblinkkeys::generated::types::*;

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

    // Verify new password works
    let creds = pool.find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_PASSWORD).unwrap();
    assert_eq!(creds.len(), 1);
    assert!(bcrypt::verify("new-secure-password", &creds[0].credential_hash).unwrap());
    assert!(!bcrypt::verify("old-password", &creds[0].credential_hash).unwrap());
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
    let sk_bytes = liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, b"test-passphrase").unwrap();
    let algorithm = liblinkkeys::crypto::SigningAlgorithm::from_str(&dk.algorithm).unwrap();
    let claim_id = uuid::Uuid::now_v7().to_string();
    let signed = liblinkkeys::claims::sign_claim(&claim_id, "email", b"test@test.com", &user.id, &dk.id, algorithm, &sk_bytes, None).unwrap();
    pool.create_claim(&user.id, "email", b"test@test.com", &dk.id, &signed.signature, None).unwrap();

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
