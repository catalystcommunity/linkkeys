//! Profiles foundation: creating an account provisions a never-leaked root
//! anchor plus a default presentable profile whose id REUSES the account id
//! (value-preserving migration to profiles — existing claims/assertions that
//! reference the account id still resolve).

mod common;

use common::data_factory::{create_user, DataMap};

#[test]
fn create_user_provisions_root_and_default_profiles() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let profiles = pool
        .list_profiles_for_account(&user.id)
        .expect("list profiles");
    assert_eq!(
        profiles.len(),
        2,
        "an account gets a root + a default profile"
    );

    let root: Vec<_> = profiles.iter().filter(|p| p.is_root).collect();
    let presentable: Vec<_> = profiles.iter().filter(|p| !p.is_root).collect();
    assert_eq!(root.len(), 1, "exactly one root anchor");
    assert_eq!(
        presentable.len(),
        1,
        "exactly one default presentable profile"
    );

    // The default presentable profile reuses the account id (preserved subject).
    assert_eq!(
        presentable[0].id, user.id,
        "default profile id == account id (value-preserving)"
    );
    // The root anchor is a distinct, fresh identity.
    assert_ne!(root[0].id, user.id, "root anchor has its own id");

    // Both profiles belong to the account.
    assert!(profiles.iter().all(|p| p.account_id == user.id));
}

#[test]
fn presentable_profile_limit_default_one_is_enforced() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    // The account already has its one default presentable profile, so creating
    // another exceeds the default cap of 1.
    let err = pool
        .create_presentable_profile(&user.id, Some("stage-name"))
        .expect_err("default limit of 1 should reject a second presentable profile");
    assert!(err.contains("limit"), "got: {}", err);

    // Still exactly one presentable profile.
    let presentable = pool
        .list_presentable_profiles_for_account(&user.id)
        .unwrap();
    assert_eq!(presentable.len(), 1);
}
