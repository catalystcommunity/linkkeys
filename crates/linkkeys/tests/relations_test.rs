mod common;

use common::data_factory::{create_relation, create_user, DataMap};
use serde_json::Value;

#[test]
fn test_create_relation() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let rel = create_relation(&pool, "user", &user.id, "admin", "domain", "test.com");

    assert_eq!(rel.subject_type, "user");
    assert_eq!(rel.subject_id, user.id);
    assert_eq!(rel.relation, "admin");
    assert_eq!(rel.object_type, "domain");
    assert_eq!(rel.object_id, "test.com");
    assert!(rel.removed_at.is_none());
}

#[test]
fn test_remove_relation() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let rel = create_relation(&pool, "user", &user.id, "admin", "domain", "test.com");

    let removed = pool.remove_relation(&rel.id).unwrap();
    assert!(removed.removed_at.is_some());
}

#[test]
fn test_direct_permission_check() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    create_relation(&pool, "user", &user.id, "manage_users", "domain", "test.com");

    assert!(pool.check_permission(&user.id, "manage_users", "domain", "test.com").unwrap());
    assert!(!pool.check_permission(&user.id, "manage_claims", "domain", "test.com").unwrap());
}

#[test]
fn test_admin_implies_all() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    create_relation(&pool, "user", &user.id, "admin", "domain", "test.com");

    // Admin should pass any permission check on the same object
    assert!(pool.check_permission(&user.id, "manage_users", "domain", "test.com").unwrap());
    assert!(pool.check_permission(&user.id, "manage_claims", "domain", "test.com").unwrap());
    assert!(pool.check_permission(&user.id, "api_access", "domain", "test.com").unwrap());
    assert!(pool.check_permission(&user.id, "admin", "domain", "test.com").unwrap());

    // But not on a different object
    assert!(!pool.check_permission(&user.id, "admin", "domain", "other.com").unwrap());
}

#[test]
fn test_removed_relation_not_checked() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let rel = create_relation(&pool, "user", &user.id, "admin", "domain", "test.com");

    assert!(pool.check_permission(&user.id, "admin", "domain", "test.com").unwrap());

    pool.remove_relation(&rel.id).unwrap();

    assert!(!pool.check_permission(&user.id, "admin", "domain", "test.com").unwrap());
}

#[test]
fn test_group_transitive_permission() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    // User is member of group "engineering"
    create_relation(&pool, "user", &user.id, "member", "group", "engineering");

    // Engineering group has manage_users on domain
    create_relation(&pool, "group", "engineering", "manage_users", "domain", "test.com");

    // User should have manage_users through group membership
    assert!(pool.check_permission(&user.id, "manage_users", "domain", "test.com").unwrap());

    // But not manage_claims (group doesn't have it)
    assert!(!pool.check_permission(&user.id, "manage_claims", "domain", "test.com").unwrap());
}

#[test]
fn test_group_admin_implies_all() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    create_relation(&pool, "user", &user.id, "member", "group", "admins");
    create_relation(&pool, "group", "admins", "admin", "domain", "test.com");

    // Group admin should imply all permissions
    assert!(pool.check_permission(&user.id, "manage_users", "domain", "test.com").unwrap());
    assert!(pool.check_permission(&user.id, "manage_claims", "domain", "test.com").unwrap());
}

#[test]
fn test_no_permission_without_relation() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    // No relations at all
    assert!(!pool.check_permission(&user.id, "admin", "domain", "test.com").unwrap());
    assert!(!pool.check_permission(&user.id, "manage_users", "domain", "test.com").unwrap());
}

#[test]
fn test_user_deactivation() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    assert!(user.is_active);

    let deactivated = pool.deactivate_user(&user.id).unwrap();
    assert!(!deactivated.is_active);
}

#[test]
fn test_list_relations_for_subject() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    create_relation(&pool, "user", &user.id, "admin", "domain", "a.com");
    create_relation(&pool, "user", &user.id, "member", "group", "engineering");

    let rels = pool.list_relations_for_subject("user", &user.id).unwrap();
    assert_eq!(rels.len(), 2);
}
