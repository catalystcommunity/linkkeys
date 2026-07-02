mod common;

use common::data_factory::{
    create_auth_credential, create_domain_key, create_relation, create_user, DataMap,
};
use liblinkkeys::generated::types::*;
use linkkeys::services::{admin, auth};
use serde_json::Value;

// -- User Management via Service Layer --

#[test]
fn test_service_list_users() {
    let pool = common::create_test_pool();
    create_user(
        &pool,
        &DataMap::from([("username".into(), Value::String("svc-list-user".into()))]),
    );

    let req = ListUsersRequest {
        offset: None,
        limit: None,
    };
    let resp = admin::list_users(&pool, req).unwrap();
    assert!(resp.users.iter().any(|u| u.username == "svc-list-user"));
}

#[test]
fn test_service_get_user() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let req = GetUserRequest {
        user_id: user.id.clone(),
    };
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

    // Verify password credential was stored as Argon2id
    let creds = pool
        .find_credentials_for_user(&resp.user.id, auth::CREDENTIAL_TYPE_PASSWORD)
        .unwrap();
    assert_eq!(creds.len(), 1);
    assert!(creds[0].credential_hash.starts_with("$argon2"));
    assert!(liblinkkeys::crypto::verify_password(
        "password123",
        &creds[0].credential_hash
    ));
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
    assert!(
        resp.api_key.is_some(),
        "Should return an API key when no password provided"
    );
    let api_key = resp.api_key.unwrap();
    assert!(
        api_key.contains('.'),
        "API key should have prefix.secret format"
    );
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

    let req = DeactivateUserRequest {
        user_id: user.id.clone(),
    };
    let resp = admin::deactivate_user(&pool, req).unwrap();
    assert!(!resp.user.is_active);

    // Service should have revoked credentials too
    let creds = pool
        .find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_PASSWORD)
        .unwrap();
    assert!(
        creds.is_empty(),
        "Credentials should be revoked after deactivation"
    );
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

    // Verify the reset credential is Argon2id: old password no longer works,
    // new password does.
    let creds = pool
        .find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_PASSWORD)
        .unwrap();
    assert_eq!(creds.len(), 1);
    assert!(creds[0].credential_hash.starts_with("$argon2"));
    assert!(!liblinkkeys::crypto::verify_password(
        "old-password",
        &creds[0].credential_hash
    ));
    assert!(liblinkkeys::crypto::verify_password(
        "new-password-123",
        &creds[0].credential_hash
    ));
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

    let req = RemoveCredentialRequest {
        credential_id: cred.id.clone(),
    };
    let resp = admin::remove_credential(&pool, req).unwrap();
    assert!(resp.success);

    let remaining = pool
        .find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_PASSWORD)
        .unwrap();
    assert!(remaining.is_empty());
}

#[test]
fn test_service_remove_credential_not_found() {
    let pool = common::create_test_pool();

    let req = RemoveCredentialRequest {
        credential_id: "nonexistent-id".to_string(),
    };
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
fn test_claim_signature_roundtrips_through_storage() {
    // db-02 invariant: the claim's signed payload includes expires_at, so the
    // value must round-trip byte-identically from sign -> store -> read ->
    // verify on BOTH backends (Postgres timestamptz vs SQLite text). The
    // whole-second normalization in set_claim is what makes this hold; this
    // test locks it end-to-end (verify_claim has no other server call site).
    let pool = common::create_test_pool();
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("DOMAIN_NAME", "test.com");
    let user = create_user(&pool, &DataMap::new());
    create_domain_key(&pool);

    // Sub-second precision deliberately exercises the normalization path.
    let req = SetClaimRequest {
        user_id: user.id.clone(),
        claim_type: "over-21".to_string(),
        claim_value: "true".to_string(),
        expires_at: Some("2099-01-02T03:04:05.123456789Z".to_string()),
    };
    let resp = admin::set_claim(&pool, req).unwrap();
    // set_claim signs with all active domain keys; assert the quorum is recorded.
    assert!(
        !resp.claim.signatures.is_empty(),
        "claim must carry at least one signature"
    );

    // Re-read the STORED claim (exercises the store->read path) and verify its
    // signature against the domain's published public keys, grouped by domain.
    let stored = pool.find_claim_by_id(&resp.claim.claim_id).unwrap();
    let claim: liblinkkeys::generated::types::Claim = (&stored).into();

    let domain_keys = pool.list_active_domain_keys().unwrap();
    let domain = linkkeys::conversions::get_domain_name();
    let key_sets = vec![liblinkkeys::claims::DomainKeySet {
        domain: domain.clone(),
        keys: domain_keys.iter().map(Into::into).collect(),
    }];

    liblinkkeys::claims::verify_claim(&claim, &domain, &key_sets)
        .expect("stored claim signature must verify after store+read round-trip");
}

#[test]
fn test_resign_backfill_query_methods() {
    // Exercises the pre-alpha re-sign backfill primitives: a fully-signed claim
    // is not "missing signatures"; stripping its signatures makes it appear;
    // re-attaching signatures clears it again.
    let pool = common::create_test_pool();
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("DOMAIN_NAME", "test.com");
    let user = create_user(&pool, &DataMap::new());
    create_domain_key(&pool);

    let req = SetClaimRequest {
        user_id: user.id.clone(),
        claim_type: "email".to_string(),
        claim_value: "a@b.com".to_string(),
        expires_at: None,
    };
    let claim_id = admin::set_claim(&pool, req).unwrap().claim.claim_id;

    // Freshly-created claims carry signatures, so none are missing.
    assert!(pool
        .list_claims_missing_signatures()
        .unwrap()
        .iter()
        .all(|c| c.id != claim_id));

    // Strip signatures -> the claim now needs re-signing.
    pool.replace_claim_signatures(&claim_id, &[]).unwrap();
    let missing = pool.list_claims_missing_signatures().unwrap();
    assert!(missing.iter().any(|c| c.id == claim_id));
    assert!(
        missing
            .iter()
            .find(|c| c.id == claim_id)
            .unwrap()
            .signatures
            .is_empty(),
        "claims missing signatures are returned with an empty signature set"
    );

    // Re-attach a signature -> the claim is no longer missing.
    let resigned = ClaimSignature {
        domain: "test.com".to_string(),
        signed_by_key_id: pool.list_active_domain_keys().unwrap()[0].id.clone(),
        signature: vec![1, 2, 3],
    };
    pool.replace_claim_signatures(&claim_id, std::slice::from_ref(&resigned))
        .unwrap();
    assert!(pool
        .list_claims_missing_signatures()
        .unwrap()
        .iter()
        .all(|c| c.id != claim_id));

    // And the re-attached signature is what's read back.
    let stored = pool.find_claim_by_id(&claim_id).unwrap();
    assert_eq!(stored.signatures.len(), 1);
    assert_eq!(stored.signatures[0].domain, "test.com");
}

#[test]
fn test_service_remove_claim() {
    let pool = common::create_test_pool();
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    let user = create_user(&pool, &DataMap::new());
    let dk = create_domain_key(&pool);

    // Create a claim through the DB to get a claim_id
    let sk_bytes =
        liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, b"test-passphrase")
            .unwrap();
    let algorithm = liblinkkeys::crypto::SigningAlgorithm::parse_str(&dk.algorithm).unwrap();
    let claim_id = uuid::Uuid::now_v7().to_string();
    let signed = liblinkkeys::claims::sign_claim(
        &liblinkkeys::claims::ClaimSpec {
            claim_id: &claim_id,
            claim_type: "role",
            claim_value: b"admin",
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
    let stored = pool
        .create_claim(
            &claim_id,
            &user.id,
            "role",
            b"admin",
            &signed.signatures,
            None,
        )
        .unwrap();

    let req = RemoveClaimRequest {
        claim_id: stored.id.clone(),
    };
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

    let req = RemoveRelationRequest {
        relation_id: rel.id.clone(),
    };
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

    let active = pool
        .find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_PASSWORD)
        .unwrap();
    assert!(
        active.is_empty(),
        "Expired credentials should not be returned"
    );
}

// -- Duplicate Relation Prevention --

#[test]
fn test_duplicate_active_relation_rejected() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    pool.create_relation("user", &user.id, "admin", "domain", "dup.com")
        .unwrap();
    let result = pool.create_relation("user", &user.id, "admin", "domain", "dup.com");
    assert!(
        result.is_err(),
        "Duplicate active relation should be rejected"
    );
}

#[test]
fn test_removed_relation_allows_re_grant() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let rel = create_relation(&pool, "user", &user.id, "admin", "domain", "regrant.com");
    pool.remove_relation(&rel.id).unwrap();

    let new_rel = pool
        .create_relation("user", &user.id, "admin", "domain", "regrant.com")
        .unwrap();
    assert_ne!(new_rel.id, rel.id);
}

// -- SEC-08: key revocation --

/// Revoking a domain key removes it from the active set and is idempotent
/// (preserving the original revocation timestamp).
#[test]
fn sec08_revoke_domain_key_removes_from_active_and_is_idempotent() {
    let pool = common::create_test_pool();
    let k = create_domain_key(&pool);
    assert!(
        pool.list_active_domain_keys()
            .unwrap()
            .iter()
            .any(|x| x.id == k.id),
        "key is active before revocation"
    );

    let revoked = pool.revoke_domain_key(&k.id).unwrap();
    assert!(revoked.revoked_at.is_some(), "revoked_at is set");
    assert!(
        !pool
            .list_active_domain_keys()
            .unwrap()
            .iter()
            .any(|x| x.id == k.id),
        "revoked key no longer appears in the active set"
    );

    // Idempotent: a second revoke keeps the original timestamp.
    let again = pool.revoke_domain_key(&k.id).unwrap();
    assert_eq!(
        again.revoked_at, revoked.revoked_at,
        "re-revoking preserves the original revocation time"
    );
}

// -- SEC-04: protected admin accounts --

/// A manage_users-only operator must not reset a protected admin account's
/// password via the TCP Admin dispatch, but a full admin may. Exercises the
/// `admin_op_protected_target` + `caller_may_manage_target` guard.
#[test]
fn sec04_manage_users_cannot_reset_admin_account_password() {
    std::env::set_var("DOMAIN_NAME", "test.com");
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    let pool = common::create_test_pool();
    let domain = "test.com";

    // Target holds the admin relation -> protected.
    let target = create_user(&pool, &DataMap::new());
    create_relation(&pool, "user", &target.id, "admin", "domain", domain);

    // Caller has manage_users only, authenticated by API key.
    let caller = create_user(&pool, &DataMap::new());
    create_relation(&pool, "user", &caller.id, "manage_users", "domain", domain);
    let (api_key, hash) = auth::generate_api_key(&caller.id);
    create_auth_credential(&pool, &caller.id, auth::CREDENTIAL_TYPE_API_KEY, &hash);

    let payload = liblinkkeys::generated::encode_reset_password_request(&ResetPasswordRequest {
        user_id: target.id.clone(),
        new_password: "new-strong-password".to_string(),
    });

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "reset-password",
        payload.clone(),
        Some(&api_key),
        &pool,
        None,
    );
    assert_ne!(
        status, 0,
        "manage_users must not reset a protected admin account's password"
    );

    // Elevate the caller to admin; the same op now succeeds.
    create_relation(&pool, "user", &caller.id, "admin", "domain", domain);
    let (status2, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "reset-password",
        payload,
        Some(&api_key),
        &pool,
        None,
    );
    assert_eq!(
        status2, 0,
        "a full admin may reset a protected admin account's password"
    );
}

/// A manage_users operator can still reset an ordinary (non-admin) user's
/// password — SEC-04 only restricts protected admin targets.
#[test]
fn sec04_manage_users_may_reset_ordinary_user() {
    std::env::set_var("DOMAIN_NAME", "test.com");
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    let pool = common::create_test_pool();
    let domain = "test.com";

    let target = create_user(&pool, &DataMap::new());
    let caller = create_user(&pool, &DataMap::new());
    create_relation(&pool, "user", &caller.id, "manage_users", "domain", domain);
    let (api_key, hash) = auth::generate_api_key(&caller.id);
    create_auth_credential(&pool, &caller.id, auth::CREDENTIAL_TYPE_API_KEY, &hash);

    let payload = liblinkkeys::generated::encode_reset_password_request(&ResetPasswordRequest {
        user_id: target.id.clone(),
        new_password: "new-strong-password".to_string(),
    });
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "reset-password",
        payload,
        Some(&api_key),
        &pool,
        None,
    );
    assert_eq!(
        status, 0,
        "manage_users may reset an ordinary user's password"
    );
}
