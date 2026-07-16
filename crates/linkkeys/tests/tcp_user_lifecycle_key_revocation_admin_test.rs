//! Tests for the user-lifecycle and domain-key-revocation surface on the
//! `Admin` TCP service (admin-ops slice 4): `activate-user`, `purge-user`,
//! `revoke-domain-key`.
//!
//! `activate-user` is the direct request/response mirror of the existing
//! `deactivate-user` op — it reuses `services::admin::activate_user`, the same
//! call the `user-admin` web UI's "Activate User" button makes.
//!
//! `purge-user` is a second CSIL-RPC entry point onto the exact same
//! `DbPool::purge_user_tombstone` call `main.rs`'s `user purge-local` CLI
//! command makes, replicating that command's guards (already-purged,
//! protected-admin-account) since an API caller gets no interactive
//! `--force`/`--force-admin` confirmation.
//!
//! `revoke-domain-key` reuses the exact same calls `main.rs`'s
//! `domain revoke-key` CLI command makes (`DbPool::revoke_domain_key`, then a
//! sibling-signed revocation certificate from the domain's remaining active
//! signing keys). DNS removal remains a manual operator step — the CLI's
//! reminder is carried in the response instead.
//!
//! Every op requires the `admin` relation (explicit `required_relation_for_op`
//! arm, not the `_ =>` fallthrough, mirroring the slice-1/2/3 admin test
//! files) — each test below confirms a non-admin caller is forbidden before
//! confirming an admin succeeds.

mod common;

use common::data_factory::{
    create_auth_credential, create_domain_key, create_relation, create_user, DataMap,
};
use liblinkkeys::generated::types::{
    ActivateUserRequest, DeactivateUserRequest, GetRevocationsRequest, PurgeUserRequest,
    RevokeDomainKeyRequest,
};
use linkkeys::services::auth;

const TEST_DOMAIN: &str = "test.com";

fn setup() -> linkkeys::db::DbPool {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    common::create_test_pool()
}

/// Create a service-account user with an API key, granting `admin` on the
/// domain only when `is_admin` is true. Returns (user id, API key).
fn make_caller(pool: &linkkeys::db::DbPool, is_admin: bool) -> (String, String) {
    let user = create_user(pool, &DataMap::new());
    if is_admin {
        create_relation(pool, "user", &user.id, "admin", "domain", TEST_DOMAIN);
    }
    let (api_key, hash) = auth::generate_api_key(&user.id);
    create_auth_credential(pool, &user.id, auth::CREDENTIAL_TYPE_API_KEY, &hash);
    (user.id, api_key)
}

// ---------------------------------------------------------------------
// activate-user
// ---------------------------------------------------------------------

#[test]
fn activate_user_requires_admin() {
    let pool = setup();
    let subject = create_user(&pool, &DataMap::new());
    pool.deactivate_user(&subject.id).unwrap();
    let payload = liblinkkeys::generated::encode_activate_user_request(&ActivateUserRequest {
        user_id: subject.id.clone(),
    });

    let (_, nonadmin_key) = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "activate-user",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");
    assert!(
        !pool.find_user_by_id(&subject.id).unwrap().is_active,
        "forbidden call must not have reactivated the user"
    );

    let (_, admin_key) = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "activate-user",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_activate_user_response(&body)
        .expect("decode ActivateUserResponse");
    assert!(resp.user.is_active);
}

#[test]
fn deactivate_then_activate_round_trips_is_active() {
    let pool = setup();
    let subject = create_user(&pool, &DataMap::new());
    let (_, admin_key) = make_caller(&pool, true);
    assert!(pool.find_user_by_id(&subject.id).unwrap().is_active);

    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "deactivate-user",
        liblinkkeys::generated::encode_deactivate_user_request(&DeactivateUserRequest {
            user_id: subject.id.clone(),
        }),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let deactivated = liblinkkeys::generated::decode_deactivate_user_response(&body)
        .expect("decode DeactivateUserResponse");
    assert!(!deactivated.user.is_active);
    assert!(!pool.find_user_by_id(&subject.id).unwrap().is_active);

    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "activate-user",
        liblinkkeys::generated::encode_activate_user_request(&ActivateUserRequest {
            user_id: subject.id.clone(),
        }),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let activated = liblinkkeys::generated::decode_activate_user_response(&body)
        .expect("decode ActivateUserResponse");
    assert!(activated.user.is_active);
    assert!(pool.find_user_by_id(&subject.id).unwrap().is_active);
}

// ---------------------------------------------------------------------
// purge-user
// ---------------------------------------------------------------------

#[test]
fn purge_user_requires_admin() {
    let pool = setup();
    let subject = create_user(&pool, &DataMap::new());
    pool.deactivate_user(&subject.id).unwrap();
    let payload = liblinkkeys::generated::encode_purge_user_request(&PurgeUserRequest {
        user_id: subject.id.clone(),
        reason: Some("test purge".to_string()),
    });

    let (_, nonadmin_key) = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "purge-user",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");
    assert!(
        pool.find_user_by_id(&subject.id)
            .unwrap()
            .purged_at
            .is_none(),
        "forbidden call must not have purged the user"
    );

    let (_, admin_key) = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "purge-user",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_purge_user_response(&body)
        .expect("decode PurgeUserResponse");
    assert_eq!(resp.user.id, subject.id);
    assert!(
        pool.find_user_by_id(&subject.id)
            .unwrap()
            .purged_at
            .is_some(),
        "an admin caller's purge must have tombstoned the user"
    );
}

#[test]
fn purge_user_tombstones_a_deactivated_user() {
    let pool = setup();
    let subject = create_user(&pool, &DataMap::new());
    let hash = bcrypt::hash("password", 4).unwrap();
    create_auth_credential(&pool, &subject.id, auth::CREDENTIAL_TYPE_PASSWORD, &hash);
    pool.deactivate_user(&subject.id).unwrap();
    let (_, admin_key) = make_caller(&pool, true);

    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "purge-user",
        liblinkkeys::generated::encode_purge_user_request(&PurgeUserRequest {
            user_id: subject.id.clone(),
            reason: Some("gdpr request".to_string()),
        }),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_purge_user_response(&body)
        .expect("decode PurgeUserResponse");
    assert_eq!(resp.user.id, subject.id);
    assert_eq!(resp.credentials_revoked, 1);

    let stored = pool.find_user_by_id(&subject.id).unwrap();
    assert!(stored.purged_at.is_some(), "user row must be tombstoned");
    assert_eq!(stored.purge_reason.as_deref(), Some("gdpr request"));
}

#[test]
fn purge_user_rejects_a_protected_admin_account() {
    let pool = setup();
    let subject = create_user(&pool, &DataMap::new());
    create_relation(&pool, "user", &subject.id, "admin", "domain", TEST_DOMAIN);
    let (_, admin_key) = make_caller(&pool, true);

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "purge-user",
        liblinkkeys::generated::encode_purge_user_request(&PurgeUserRequest {
            user_id: subject.id.clone(),
            reason: Some("should be refused".to_string()),
        }),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_ne!(
        status, 0,
        "purging a protected admin account must be refused, with no override over the wire"
    );
    assert!(
        pool.find_user_by_id(&subject.id)
            .unwrap()
            .purged_at
            .is_none(),
        "refused call must not have purged the user"
    );
}

#[test]
fn purge_user_rejects_an_already_purged_user() {
    let pool = setup();
    let subject = create_user(&pool, &DataMap::new());
    pool.purge_user_tombstone(&subject.id, Some("already gone"))
        .unwrap();
    let (_, admin_key) = make_caller(&pool, true);

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "purge-user",
        liblinkkeys::generated::encode_purge_user_request(&PurgeUserRequest {
            user_id: subject.id.clone(),
            reason: None,
        }),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "purging an already-purged user must fail");
}

// ---------------------------------------------------------------------
// revoke-domain-key
// ---------------------------------------------------------------------

#[test]
fn revoke_domain_key_requires_admin() {
    let pool = setup();
    create_domain_key(&pool);
    create_domain_key(&pool);
    let target = create_domain_key(&pool);
    let payload =
        liblinkkeys::generated::encode_revoke_domain_key_request(&RevokeDomainKeyRequest {
            key_id: target.id.clone(),
        });

    let (_, nonadmin_key) = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "revoke-domain-key",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");
    assert!(
        pool.list_all_domain_keys()
            .unwrap()
            .iter()
            .find(|k| k.id == target.id)
            .unwrap()
            .revoked_at
            .is_none(),
        "forbidden call must not have revoked the key"
    );

    let (_, admin_key) = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "revoke-domain-key",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_revoke_domain_key_response(&body)
        .expect("decode RevokeDomainKeyResponse");
    assert_eq!(resp.revoked_key.key_id, target.id);
    assert!(resp.revoked_key.revoked_at.is_some());
}

#[test]
fn revoke_domain_key_marks_the_key_revoked_and_leaves_siblings_valid_and_co_signs_a_certificate() {
    let pool = setup();
    // Three signing keys: one gets revoked, the other two remain to co-sign
    // (REVOCATION_QUORUM = 2), mirroring revocation_cert_test.rs's setup.
    let sibling_a = create_domain_key(&pool);
    let sibling_b = create_domain_key(&pool);
    let target = create_domain_key(&pool);
    let (_, admin_key) = make_caller(&pool, true);

    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "revoke-domain-key",
        liblinkkeys::generated::encode_revoke_domain_key_request(&RevokeDomainKeyRequest {
            key_id: target.id.clone(),
        }),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_revoke_domain_key_response(&body)
        .expect("decode RevokeDomainKeyResponse");
    assert!(resp.revoked_key.revoked_at.is_some());
    assert!(
        resp.certificate_issued,
        "with 2 siblings remaining (>= REVOCATION_QUORUM) a certificate must be produced"
    );
    assert!(!resp.dns_removal_reminder.is_empty());
    assert!(resp.dns_removal_reminder.contains(&target.fingerprint));

    // The target is revoked...
    let all_keys = pool.list_all_domain_keys().unwrap();
    let stored_target = all_keys.iter().find(|k| k.id == target.id).unwrap();
    assert!(stored_target.revoked_at.is_some());

    // ...but both siblings remain valid (unrevoked, still in the active set).
    let active = pool.list_active_domain_keys().unwrap();
    assert!(active.iter().any(|k| k.id == sibling_a.id));
    assert!(active.iter().any(|k| k.id == sibling_b.id));
    assert!(!active.iter().any(|k| k.id == target.id));

    // The certificate is retrievable via DomainKeys/get-revocations (public,
    // no admin key needed) and is over the revoked target.
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "DomainKeys",
        "get-revocations",
        liblinkkeys::generated::encode_get_revocations_request(&GetRevocationsRequest {
            since: None,
        }),
        None,
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let revocations = liblinkkeys::generated::decode_get_revocations_response(&body)
        .expect("decode GetRevocationsResponse");
    assert_eq!(revocations.revocations.len(), 1);
    assert_eq!(revocations.revocations[0].target_key_id, target.id);
    assert_eq!(
        revocations.revocations[0].target_fingerprint,
        target.fingerprint
    );
    assert_eq!(revocations.revocations[0].signatures.len(), 2);
}

#[test]
fn revoke_domain_key_rejects_unknown_id() {
    let pool = setup();
    create_domain_key(&pool);
    let (_, admin_key) = make_caller(&pool, true);
    let payload =
        liblinkkeys::generated::encode_revoke_domain_key_request(&RevokeDomainKeyRequest {
            key_id: uuid::Uuid::now_v7().to_string(),
        });

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "revoke-domain-key",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "revoking a nonexistent key id must fail");
}
