//! Storage-layer tests for act-as grants (docs/spec/reserved/act-as-grants.md).
//! Pure storage: no signing, no verification, no dispatch.

mod common;

use common::data_factory::{create_act_as_grant, create_user, DataMap};
use linkkeys::db::act_as::GranteeColumns;
use serde_json::json;

fn map(entries: &[(&str, serde_json::Value)]) -> DataMap {
    entries
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

#[test]
fn insert_and_find_round_trip_an_application_grantee() {
    let pool = common::create_test_pool();
    let record = create_act_as_grant(&pool, &map(&[("approved_scope", json!(["read", "write"]))]));
    let found = pool
        .find_act_as_grant(&record.grant_id)
        .unwrap()
        .expect("grant should be found");
    assert_eq!(found, record);
    assert!(matches!(found.grantee, GranteeColumns::Application { .. }));
}

#[test]
fn insert_and_find_round_trip_a_local_rp_grantee() {
    let pool = common::create_test_pool();
    let record = create_act_as_grant(&pool, &map(&[("local_rp_fingerprint", json!("ab12"))]));
    let found = pool.find_act_as_grant(&record.grant_id).unwrap().unwrap();
    assert_eq!(
        found.grantee,
        GranteeColumns::LocalRp {
            fingerprint: "ab12".into()
        }
    );
}

#[test]
fn find_unknown_or_malformed_grant_id_is_none() {
    let pool = common::create_test_pool();
    assert!(pool
        .find_act_as_grant(&uuid::Uuid::now_v7().to_string())
        .unwrap()
        .is_none());
    assert!(pool.find_act_as_grant("not-a-uuid").unwrap().is_none());
}

#[test]
fn list_for_user_returns_only_that_users_grants() {
    let pool = common::create_test_pool();
    let alice = create_user(&pool, &DataMap::new());
    let bob = create_user(&pool, &DataMap::new());
    let a1 = create_act_as_grant(&pool, &map(&[("user_id", json!(alice.id))]));
    let a2 = create_act_as_grant(&pool, &map(&[("user_id", json!(alice.id))]));
    create_act_as_grant(&pool, &map(&[("user_id", json!(bob.id))]));
    let mut ids: Vec<String> = pool
        .list_act_as_grants_for_user(&alice.id)
        .unwrap()
        .into_iter()
        .map(|g| g.grant_id)
        .collect();
    ids.sort();
    let mut expected = vec![a1.grant_id, a2.grant_id];
    expected.sort();
    assert_eq!(ids, expected);
}

#[test]
fn replace_current_requires_the_expiry_the_caller_read() {
    let pool = common::create_test_pool();
    let record = create_act_as_grant(
        &pool,
        &map(&[
            ("issued_at", json!("2026-10-06T12:00:00Z")),
            ("renewable_until", json!("2026-10-06T15:00:00Z")),
        ]),
    );
    // A stale expected expiry loses.
    assert_eq!(
        pool.replace_current_act_as_grant(
            &record.grant_id,
            b"renewed",
            "2026-10-06T12:40:00Z",
            "2026-10-06T13:40:00Z",
            "2026-10-06T12:30:00Z",
        )
        .unwrap(),
        0
    );
    assert_eq!(
        pool.replace_current_act_as_grant(
            &record.grant_id,
            b"renewed",
            "2026-10-06T12:40:00Z",
            "2026-10-06T13:40:00Z",
            &record.expires_at,
        )
        .unwrap(),
        1
    );
    let found = pool.find_act_as_grant(&record.grant_id).unwrap().unwrap();
    assert_eq!(found.signed_grant, b"renewed");
    assert_eq!(found.issued_at, "2026-10-06T12:40:00Z");
    assert_eq!(found.expires_at, "2026-10-06T13:40:00Z");
    assert_eq!(found.series_issued_at, record.series_issued_at);
    assert_eq!(found.renewable_until, record.renewable_until);
}

#[test]
fn revoke_is_owner_only_and_once() {
    let pool = common::create_test_pool();
    let record = create_act_as_grant(&pool, &DataMap::new());
    let stranger = create_user(&pool, &DataMap::new());
    assert_eq!(
        pool.revoke_act_as_grant(
            &record.grant_id,
            &stranger.id,
            "2026-10-06T12:30:00Z",
            b"rev"
        )
        .unwrap(),
        0
    );
    assert_eq!(
        pool.revoke_act_as_grant(
            &record.grant_id,
            &record.user_id,
            "2026-10-06T12:30:00Z",
            b"rev"
        )
        .unwrap(),
        1
    );
    assert_eq!(
        pool.revoke_act_as_grant(
            &record.grant_id,
            &record.user_id,
            "2026-10-06T12:31:00Z",
            b"rev2"
        )
        .unwrap(),
        0
    );
    let found = pool.find_act_as_grant(&record.grant_id).unwrap().unwrap();
    assert_eq!(found.revoked_at.as_deref(), Some("2026-10-06T12:30:00Z"));
    assert_eq!(found.signed_revocation.as_deref(), Some(&b"rev"[..]));
    // A revoked grant can no longer be renewed.
    assert_eq!(
        pool.replace_current_act_as_grant(
            &record.grant_id,
            b"renewed",
            "2026-10-06T12:40:00Z",
            "2026-10-06T13:40:00Z",
            &record.expires_at,
        )
        .unwrap(),
        0
    );
}

#[test]
fn revocations_returns_only_requested_revoked_grants() {
    let pool = common::create_test_pool();
    let revoked = create_act_as_grant(&pool, &DataMap::new());
    let active = create_act_as_grant(&pool, &DataMap::new());
    let other_revoked = create_act_as_grant(&pool, &DataMap::new());
    for g in [&revoked, &other_revoked] {
        pool.revoke_act_as_grant(
            &g.grant_id,
            &g.user_id,
            "2026-10-06T12:30:00Z",
            g.grant_id.as_bytes(),
        )
        .unwrap();
    }
    let result = pool
        .act_as_grant_revocations(&[
            revoked.grant_id.clone(),
            active.grant_id.clone(),
            "not-a-uuid".to_string(),
        ])
        .unwrap();
    assert_eq!(result, vec![revoked.grant_id.as_bytes().to_vec()]);
    assert!(pool.act_as_grant_revocations(&[]).unwrap().is_empty());
}
