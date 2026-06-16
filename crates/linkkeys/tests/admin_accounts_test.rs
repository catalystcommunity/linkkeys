//! Admin/user account separation: an administrator becomes a separate
//! `<username>_admin` account (copied password, the admin relation, NO profile),
//! and the original is demoted to a normal user. Admin accounts are not real
//! users — they administer the domain and never present to a relying party.

mod common;

use common::data_factory::{create_user, DataMap};

const DOMAIN: &str = "admin-split.test";

fn set_domain() {
    std::env::set_var("DOMAIN_NAME", DOMAIN);
}

#[test]
fn create_admin_account_has_flag_admin_relation_and_no_profiles() {
    set_domain();
    let pool = common::create_test_pool();
    let admin = pool
        .create_admin_account("root_admin", "Root Admin", "fakehash")
        .expect("create admin account");

    assert!(admin.is_admin_account, "flagged as an admin account");
    // Has the admin relation on the domain (admin implies manage_users).
    assert!(pool
        .check_permission(&admin.id, "manage_users", "domain", DOMAIN)
        .unwrap());
    // And NO presentable profile — cannot be presented to a relying party.
    assert!(pool
        .list_profiles_for_account(&admin.id)
        .unwrap()
        .is_empty());
}

#[test]
fn split_admins_separates_and_demotes_then_is_idempotent() {
    set_domain();
    let pool = common::create_test_pool();

    // A regular user who is currently an admin (relation + password).
    let mut overrides = DataMap::new();
    overrides.insert("username".to_string(), serde_json::json!("alice"));
    let user = create_user(&pool, &overrides);
    pool.create_relation("user", &user.id, "admin", "domain", DOMAIN)
        .expect("grant admin");
    let hash = linkkeys::services::password::hash_for_storage("pw").unwrap();
    pool.create_auth_credential(&user.id, "password", &hash)
        .expect("password credential");

    assert!(
        pool.check_permission(&user.id, "manage_users", "domain", DOMAIN)
            .unwrap(),
        "precondition: alice is an admin"
    );

    let n = pool.split_admins().expect("split");
    assert_eq!(n, 1, "one admin split");

    // A separate admin account now exists, flagged, admin, no profiles.
    let admin = pool
        .find_user_by_username("alice_admin")
        .expect("alice_admin created");
    assert!(admin.is_admin_account);
    assert!(pool
        .check_permission(&admin.id, "manage_users", "domain", DOMAIN)
        .unwrap());
    assert!(pool
        .list_profiles_for_account(&admin.id)
        .unwrap()
        .is_empty());

    // The original is demoted to a normal user: no longer admin, still has its
    // presentable profile, still a regular (non-admin) account.
    assert!(
        !pool
            .check_permission(&user.id, "manage_users", "domain", DOMAIN)
            .unwrap(),
        "alice is no longer an admin"
    );
    let alice = pool.find_user_by_username("alice").unwrap();
    assert!(!alice.is_admin_account);
    assert!(
        !pool
            .list_profiles_for_account(&alice.id)
            .unwrap()
            .is_empty(),
        "alice keeps her presentable profile"
    );

    // Idempotent: re-running splits nothing (original demoted, twin exists).
    assert_eq!(pool.split_admins().expect("re-split"), 0);
}
