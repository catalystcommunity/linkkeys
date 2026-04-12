mod common;

use common::data_factory::{
    create_auth_credential, create_domain_key, create_relation, create_user, DataMap,
};
use linkkeys::services::{admin, auth};
use liblinkkeys::generated::types::*;
use serde_json::Value;

// -- User Management via Service Layer --

#[test]
fn test_service_list_users() {
    let pool = common::create_test_pool();
    create_user(
        &pool,
        &DataMap::from([("username".into(), Value::String("svc-list-user".into()))]),
    );

    let req = ListUsersRequest { offset: None, limit: None };
    let resp = admin::list_users(&pool, req).unwrap();
    assert!(resp.users.iter().any(|u| u.username == "svc-list-user"));
}

#[test]
fn test_service_get_user() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let req = GetUserRequest { user_id: user.id.clone() };
    let resp = admin::get_user(&pool, req).unwrap();
    assert_eq!(resp.user.id, user.id);
    assert_eq!(resp.user.username, user.username);
    assert!(resp.user.is_active);
}

#[test]
fn test_service_create_user_with_password() {
    let pool = common::create_test_pool();
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    create_domain_key(&pool);

    let req = CreateUserRequest {
        username: "svc-created".to_string(),
        display_name: "Service Created".to_string(),
        password: Some("password123".to_string()),
    };
    let resp = admin::create_user(&pool, req).unwrap();
    assert_eq!(resp.user.username, "svc-created");
    assert!(resp.api_key.is_none());
    assert!(resp.user.is_active);

    // Verify password credential was stored
    let creds = pool.find_credentials_for_user(&resp.user.id, auth::CREDENTIAL_TYPE_PASSWORD).unwrap();
    assert_eq!(creds.len(), 1);
    assert!(bcrypt::verify("password123", &creds[0].credential_hash).unwrap());
}

#[test]
fn test_service_create_user_with_api_key() {
    let pool = common::create_test_pool();
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    create_domain_key(&pool);

    let req = CreateUserRequest {
        username: "svc-apikey".to_string(),
        display_name: "API Key User".to_string(),
        password: None,
    };
    let resp = admin::create_user(&pool, req).unwrap();
    assert!(resp.api_key.is_some(), "Should return an API key when no password provided");
    let api_key = resp.api_key.unwrap();
    assert!(api_key.contains('.'), "API key should have prefix.secret format");
}

#[test]
fn test_service_update_user() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let req = UpdateUserRequest {
        user_id: user.id.clone(),
        display_name: Some("Updated Name".to_string()),
    };
    let resp = admin::update_user(&pool, req).unwrap();
    assert_eq!(resp.user.display_name, "Updated Name");
}

#[test]
fn test_service_deactivate_user() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let hash = bcrypt::hash("password", 4).unwrap();
    create_auth_credential(&pool, &user.id, auth::CREDENTIAL_TYPE_PASSWORD, &hash);

    let req = DeactivateUserRequest { user_id: user.id.clone() };
    let resp = admin::deactivate_user(&pool, req).unwrap();
    assert!(!resp.user.is_active);

    // Service should have revoked credentials too
    let creds = pool.find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_PASSWORD).unwrap();
    assert!(creds.is_empty(), "Credentials should be revoked after deactivation");
}

#[test]
fn test_service_activate_user() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    pool.deactivate_user(&user.id).unwrap();

    let resp = admin::activate_user(&pool, &user.id).unwrap();
    assert!(resp.is_active);
}

// -- Password Management via Service Layer --

#[test]
fn test_service_reset_password() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let old_hash = bcrypt::hash("old-password", 4).unwrap();
    create_auth_credential(&pool, &user.id, auth::CREDENTIAL_TYPE_PASSWORD, &old_hash);

    let req = ResetPasswordRequest {
        user_id: user.id.clone(),
        new_password: "new-password-123".to_string(),
    };
    let resp = admin::reset_password(&pool, req).unwrap();
    assert!(resp.success);

    // Verify old password no longer works, new password does
    let creds = pool.find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_PASSWORD).unwrap();
    assert_eq!(creds.len(), 1);
    assert!(!bcrypt::verify("old-password", &creds[0].credential_hash).unwrap());
    assert!(bcrypt::verify("new-password-123", &creds[0].credential_hash).unwrap());
}

#[test]
fn test_service_reset_password_rejects_short() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let req = ResetPasswordRequest {
        user_id: user.id.clone(),
        new_password: "short".to_string(),
    };
    let result = admin::reset_password(&pool, req);
    assert!(result.is_err(), "Short password should be rejected");
}

// -- Credential Management via Service Layer --

#[test]
fn test_service_remove_credential() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let hash = bcrypt::hash("pw", 4).unwrap();
    let cred = create_auth_credential(&pool, &user.id, auth::CREDENTIAL_TYPE_PASSWORD, &hash);

    let req = RemoveCredentialRequest { credential_id: cred.id.clone() };
    let resp = admin::remove_credential(&pool, req).unwrap();
    assert!(resp.success);

    let remaining = pool.find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_PASSWORD).unwrap();
    assert!(remaining.is_empty());
}

#[test]
fn test_service_remove_credential_not_found() {
    let pool = common::create_test_pool();

    let req = RemoveCredentialRequest { credential_id: "nonexistent-id".to_string() };
    let result = admin::remove_credential(&pool, req);
    assert!(result.is_err(), "Should fail for nonexistent credential");
}

// -- Claim Management via Service Layer --

#[test]
fn test_service_set_claim() {
    let pool = common::create_test_pool();
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    let user = create_user(&pool, &DataMap::new());
    create_domain_key(&pool);

    let req = SetClaimRequest {
        user_id: user.id.clone(),
        claim_type: "email".to_string(),
        claim_value: "alice@example.com".to_string(),
        expires_at: None,
    };
    let resp = admin::set_claim(&pool, req).unwrap();
    assert_eq!(resp.claim.claim_type, "email");
    assert_eq!(resp.claim.user_id, user.id);
}

#[test]
fn test_service_remove_claim() {
    let pool = common::create_test_pool();
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    let user = create_user(&pool, &DataMap::new());
    let dk = create_domain_key(&pool);

    // Create a claim through the DB to get a claim_id
    let sk_bytes = liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, b"test-passphrase").unwrap();
    let algorithm = liblinkkeys::crypto::SigningAlgorithm::from_str(&dk.algorithm).unwrap();
    let claim_id = uuid::Uuid::now_v7().to_string();
    let signed = liblinkkeys::claims::sign_claim(&claim_id, "role", b"admin", &user.id, &dk.id, algorithm, &sk_bytes, None).unwrap();
    let stored = pool.create_claim(&user.id, "role", b"admin", &dk.id, &signed.signature, None).unwrap();

    let req = RemoveClaimRequest { claim_id: stored.id.clone() };
    let resp = admin::remove_claim(&pool, req).unwrap();
    assert!(resp.success);

    let active = pool.list_active_claims(&user.id).unwrap();
    assert!(active.is_empty());
}

// -- Relation Management via Service Layer --

#[test]
fn test_service_grant_relation() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let req = GrantRelationRequest {
        subject_type: "user".to_string(),
        subject_id: user.id.clone(),
        relation: "admin".to_string(),
        object_type: "domain".to_string(),
        object_id: "test.com".to_string(),
    };
    let resp = admin::grant_relation(&pool, req).unwrap();
    assert_eq!(resp.relation.relation, "admin");
    assert_eq!(resp.relation.subject_id, user.id);
}

#[test]
fn test_service_grant_relation_rejects_invalid_relation() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let req = GrantRelationRequest {
        subject_type: "user".to_string(),
        subject_id: user.id.clone(),
        relation: "superadmin".to_string(), // not in allowlist
        object_type: "domain".to_string(),
        object_id: "test.com".to_string(),
    };
    let result = admin::grant_relation(&pool, req);
    assert!(result.is_err(), "Invalid relation type should be rejected");
}

#[test]
fn test_service_remove_relation() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let rel = create_relation(&pool, "user", &user.id, "admin", "domain", "test.com");

    let req = RemoveRelationRequest { relation_id: rel.id.clone() };
    let resp = admin::remove_relation(&pool, req).unwrap();
    assert!(resp.success);
}

#[test]
fn test_service_list_relations() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    create_relation(&pool, "user", &user.id, "admin", "domain", "test.com");

    let req = ListRelationsRequest {
        subject_type: Some("user".to_string()),
        subject_id: Some(user.id.clone()),
        object_type: None,
        object_id: None,
    };
    let resp = admin::list_relations(&pool, req).unwrap();
    assert_eq!(resp.relations.len(), 1);
}

#[test]
fn test_service_check_permission() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    create_relation(&pool, "user", &user.id, "admin", "domain", "test.com");

    let req = CheckPermissionRequest {
        user_id: user.id.clone(),
        relation: "manage_users".to_string(),
        object_type: "domain".to_string(),
        object_id: "test.com".to_string(),
    };
    let resp = admin::check_permission_handler(&pool, req).unwrap();
    assert!(resp.allowed, "Admin should imply manage_users");
}

// -- Expired Credential Filtering --

#[test]
fn test_expired_credential_filtered_by_find_for_user() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let hash = bcrypt::hash("pw-exp", 4).unwrap();
    let cred = create_auth_credential(&pool, &user.id, auth::CREDENTIAL_TYPE_PASSWORD, &hash);

    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    pool.set_credential_expires_at(&cred.id, &past).unwrap();

    let active = pool.find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_PASSWORD).unwrap();
    assert!(active.is_empty(), "Expired credentials should not be returned");
}

// -- Duplicate Relation Prevention --

#[test]
fn test_duplicate_active_relation_rejected() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    pool.create_relation("user", &user.id, "admin", "domain", "dup.com").unwrap();
    let result = pool.create_relation("user", &user.id, "admin", "domain", "dup.com");
    assert!(result.is_err(), "Duplicate active relation should be rejected");
}

#[test]
fn test_removed_relation_allows_re_grant() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let rel = create_relation(&pool, "user", &user.id, "admin", "domain", "regrant.com");
    pool.remove_relation(&rel.id).unwrap();

    let new_rel = pool.create_relation("user", &user.id, "admin", "domain", "regrant.com").unwrap();
    assert_ne!(new_rel.id, rel.id);
}
