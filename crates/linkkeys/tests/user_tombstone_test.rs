mod common;

use common::data_factory::{create_auth_credential, create_relation, create_user, DataMap};
use liblinkkeys::generated::types::ResetPasswordRequest;
use linkkeys::services::{admin, auth};

fn create_test_user_key(pool: &linkkeys::db::DbPool, user_id: &str) {
    let (vk, sk) = liblinkkeys::crypto::generate_ed25519_keypair();
    let public_key = vk.as_bytes().to_vec();
    let private_key = sk.to_bytes();
    let encrypted = liblinkkeys::crypto::encrypt_private_key(&private_key, b"test-passphrase")
        .expect("encrypt key");
    let fingerprint = liblinkkeys::crypto::fingerprint(&public_key);
    pool.create_user_key(
        user_id,
        &public_key,
        &encrypted,
        &fingerprint,
        "ed25519",
        chrono::Utc::now() + chrono::Duration::days(365),
    )
    .expect("create user key");
}

#[test]
fn purge_keeps_uuid_tombstone_and_minimizes_active_data() {
    let pool = common::create_test_pool();
    let mut overrides = DataMap::new();
    overrides.insert("username".to_string(), "purge-target".into());
    let user = create_user(&pool, &overrides);
    create_auth_credential(&pool, &user.id, auth::CREDENTIAL_TYPE_PASSWORD, "old-hash");
    create_test_user_key(&pool, &user.id);
    pool.create_claim(
        &uuid::Uuid::now_v7().to_string(),
        &user.id,
        "email",
        b"user@example.test",
        &[],
        None,
        chrono::Utc::now(),
    )
    .expect("create claim");
    create_relation(&pool, "user", &user.id, "member", "group", "engineering");
    create_relation(&pool, "group", "engineering", "member", "user", &user.id);
    pool.add_user_release_pref(&user.id, "rp.example", "email")
        .expect("add release pref");
    pool.create_email_verification(
        "purge-token",
        &user.id,
        "user@example.test",
        chrono::Utc::now() + chrono::Duration::hours(1),
    )
    .expect("create email verification");

    assert_eq!(pool.list_profiles_for_account(&user.id).unwrap().len(), 2);
    assert_eq!(pool.list_active_user_keys(&user.id).unwrap().len(), 1);
    assert_eq!(pool.list_active_claims(&user.id).unwrap().len(), 1);
    assert!(pool
        .list_relations_for_subject("user", &user.id)
        .unwrap()
        .iter()
        .any(|r| r.relation == "member"));

    let summary = pool
        .purge_user_tombstone(&user.id, Some("test cleanup"))
        .expect("purge user");

    assert_eq!(summary.user.id, user.id);
    assert_eq!(summary.user.username, "purge-target");
    assert_eq!(summary.user.display_name, "[purged]");
    assert!(!summary.user.is_active);
    assert!(summary.user.purged_at.is_some());
    assert_eq!(summary.user.purge_reason.as_deref(), Some("test cleanup"));
    assert_eq!(summary.credentials_revoked, 1);
    assert_eq!(summary.keys_revoked, 1);
    assert_eq!(summary.claims_revoked, 1);
    assert_eq!(summary.relations_removed, 2);
    assert_eq!(summary.profiles_deleted, 2);
    assert_eq!(summary.release_prefs_deleted, 1);
    assert_eq!(summary.email_verifications_deleted, 1);

    let tombstone = pool.find_user_by_id(&user.id).expect("uuid remains");
    assert_eq!(tombstone.id, user.id);
    assert!(tombstone.purged_at.is_some());
    assert!(pool.find_user_by_username("purge-target").is_ok());
    assert!(pool.create_user("purge-target", "Reused").is_err());
    assert!(pool.list_profiles_for_account(&user.id).unwrap().is_empty());
    assert!(pool.list_active_user_keys(&user.id).unwrap().is_empty());
    assert!(pool.list_active_claims(&user.id).unwrap().is_empty());
    assert!(pool
        .list_relations_for_subject("user", &user.id)
        .unwrap()
        .is_empty());
    assert!(pool
        .list_relations_for_object("user", &user.id)
        .unwrap()
        .is_empty());
    assert!(pool
        .find_credentials_for_user(&user.id, auth::CREDENTIAL_TYPE_PASSWORD)
        .unwrap()
        .is_empty());
    assert!(pool.list_user_release_prefs(&user.id).unwrap().is_empty());
    assert!(pool
        .find_email_verification("purge-token")
        .unwrap()
        .is_none());
}

#[test]
fn protected_admin_detection_covers_admin_flag_and_relation() {
    let pool = common::create_test_pool();
    let domain = "test.com";

    let admin_account = pool
        .create_admin_account("local-admin", "Local Admin", "valid-password")
        .expect("create admin account");
    assert!(pool
        .is_protected_admin_user(&admin_account.id, domain)
        .expect("check admin account"));

    let relation_admin = create_user(&pool, &DataMap::new());
    create_relation(&pool, "user", &relation_admin.id, "admin", "domain", domain);
    assert!(pool
        .is_protected_admin_user(&relation_admin.id, domain)
        .expect("check relation admin"));

    let ordinary = create_user(&pool, &DataMap::new());
    assert!(!pool
        .is_protected_admin_user(&ordinary.id, domain)
        .expect("check ordinary user"));
}

#[test]
fn reset_password_refuses_purged_user() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    pool.purge_user_tombstone(&user.id, Some("test cleanup"))
        .expect("purge user");

    let result = admin::reset_password(
        &pool,
        ResetPasswordRequest {
            user_id: user.id,
            new_password: "valid-password".to_string(),
        },
    );

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message
        .contains("cannot reset password for a purged user"));
}
