//! Admin accounts: an administrator account carries the admin relation and NO
//! profile — admin accounts administer the domain and never present to a relying
//! party. (The one-time `split_admins` startup transform that migrated legacy
//! in-band admins was removed once applied everywhere.)

mod common;

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
