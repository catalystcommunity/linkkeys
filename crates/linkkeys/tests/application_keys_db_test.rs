//! Storage-layer tests for application-key enrollment (signing-things-request.md,
//! step 2): application instances, their public keys, each key's home-domain
//! attestation, permanent revocation evidence, and single-use enrollment
//! challenges. Pure storage — no quorum verification, no dispatch.

mod common;

use std::collections::HashMap;

use common::data_factory::{
    create_application_instance, create_application_key, create_application_key_attestation,
    create_application_key_revocation, create_user,
};
use serde_json::json;

type DataMap = HashMap<String, serde_json::Value>;

#[test]
fn instance_upsert_is_idempotent() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let overrides: DataMap = [
        ("subject_user_id".to_string(), json!(user.id)),
        ("application_id".to_string(), json!("tinku")),
        ("instance_id".to_string(), json!("instance-a")),
    ]
    .into_iter()
    .collect();

    let first = create_application_instance(&pool, &overrides);
    let second = create_application_instance(&pool, &overrides);

    assert_eq!(first.id, second.id);
    assert_eq!(first.created_at, second.created_at);

    let found = pool
        .find_application_instance(&user.id, "tinku", "instance-a")
        .unwrap()
        .expect("instance should be found");
    assert_eq!(found.id, first.id);
    assert_eq!(found.trust_reset_count, 0);
    assert!(found.last_trust_reset_at.is_none());
}

#[test]
fn find_application_instance_returns_none_for_unknown_instance() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let found = pool
        .find_application_instance(&user.id, "tinku", "no-such-instance")
        .unwrap();
    assert!(found.is_none());
}

#[test]
fn record_trust_reset_increments_count_and_stamps_time() {
    let pool = common::create_test_pool();
    let instance = create_application_instance(&pool, &DataMap::new());

    let at = chrono::Utc::now();
    let affected = pool
        .record_application_trust_reset(&instance.id, at)
        .unwrap();
    assert_eq!(affected, 1);

    let updated = pool
        .find_application_instance(
            &instance.subject_user_id,
            &instance.application_id,
            &instance.instance_id,
        )
        .unwrap()
        .unwrap();
    assert_eq!(updated.trust_reset_count, 1);
    assert!(updated.last_trust_reset_at.is_some());

    // A second reset increments again.
    pool.record_application_trust_reset(&instance.id, chrono::Utc::now())
        .unwrap();
    let twice = pool
        .find_application_instance(
            &instance.subject_user_id,
            &instance.application_id,
            &instance.instance_id,
        )
        .unwrap()
        .unwrap();
    assert_eq!(twice.trust_reset_count, 2);
}

#[test]
fn key_insert_find_list_count() {
    let pool = common::create_test_pool();
    let instance = create_application_instance(&pool, &DataMap::new());

    let overrides: DataMap = [("key_id".to_string(), json!("key-1"))]
        .into_iter()
        .collect();
    let key = create_application_key(&pool, &instance.id, &overrides);

    let found = pool
        .find_application_key(&instance.id, "key-1")
        .unwrap()
        .expect("key should be found");
    assert_eq!(found.id, key.id);
    assert_eq!(found.fingerprint, key.fingerprint);
    assert!(found.revoked_at.is_none());

    let missing = pool
        .find_application_key(&instance.id, "no-such-key")
        .unwrap();
    assert!(missing.is_none());

    // Add a second key.
    let overrides2: DataMap = [("key_id".to_string(), json!("key-2"))]
        .into_iter()
        .collect();
    create_application_key(&pool, &instance.id, &overrides2);

    let listed = pool.list_application_keys(&instance.id).unwrap();
    assert_eq!(listed.len(), 2);

    let count = pool.count_application_keys(&instance.id).unwrap();
    assert_eq!(count, 2);
}

#[test]
fn key_id_is_unique_per_instance() {
    let pool = common::create_test_pool();
    let instance = create_application_instance(&pool, &DataMap::new());

    let overrides: DataMap = [("key_id".to_string(), json!("dup-key"))]
        .into_iter()
        .collect();
    create_application_key(&pool, &instance.id, &overrides);

    // A second insert with the same (instance_row_id, key_id) must fail.
    let result = pool.insert_application_key(
        &instance.id,
        "dup-key",
        "sign",
        "ed25519",
        b"some-other-public-key-bytes-not-real",
        "some-other-fingerprint",
        chrono::Utc::now(),
        chrono::Utc::now() + chrono::Duration::days(1),
    );
    assert!(result.is_err());
}

#[test]
fn revoke_key_is_idempotent_and_excludes_from_active_count() {
    let pool = common::create_test_pool();
    let instance = create_application_instance(&pool, &DataMap::new());
    let overrides: DataMap = [("key_id".to_string(), json!("revoke-me"))]
        .into_iter()
        .collect();
    create_application_key(&pool, &instance.id, &overrides);

    assert_eq!(pool.count_application_keys(&instance.id).unwrap(), 1);

    let revoked_at = chrono::Utc::now();
    let affected = pool
        .revoke_application_key(&instance.id, "revoke-me", revoked_at)
        .unwrap();
    assert_eq!(affected, 1);

    assert_eq!(pool.count_application_keys(&instance.id).unwrap(), 0);
    // List still includes the revoked key.
    assert_eq!(pool.list_application_keys(&instance.id).unwrap().len(), 1);

    let found = pool
        .find_application_key(&instance.id, "revoke-me")
        .unwrap()
        .unwrap();
    assert!(found.revoked_at.is_some());

    // Revoking again is a no-op (0 rows affected — already revoked).
    let affected_again = pool
        .revoke_application_key(&instance.id, "revoke-me", chrono::Utc::now())
        .unwrap();
    assert_eq!(affected_again, 0);
}

#[test]
fn attestation_upsert_replaces_rather_than_duplicates() {
    let pool = common::create_test_pool();
    let instance = create_application_instance(&pool, &DataMap::new());
    let key = create_application_key(&pool, &instance.id, &DataMap::new());

    let first_overrides: DataMap = [(
        "signed_attestation".to_string(),
        json!("attestation-bytes-v1"),
    )]
    .into_iter()
    .collect();
    let first = create_application_key_attestation(&pool, &key.id, &first_overrides);
    assert_eq!(first.signed_attestation, b"attestation-bytes-v1");

    let second_overrides: DataMap = [(
        "signed_attestation".to_string(),
        json!("attestation-bytes-v2-renewed"),
    )]
    .into_iter()
    .collect();
    let second = create_application_key_attestation(&pool, &key.id, &second_overrides);
    assert_eq!(second.signed_attestation, b"attestation-bytes-v2-renewed");

    // Same row (exactly one current attestation per key), replaced in place.
    assert_eq!(first.id, second.id);

    let fetched = pool
        .get_application_key_attestation(&key.id)
        .unwrap()
        .expect("attestation should exist");
    assert_eq!(fetched.signed_attestation, b"attestation-bytes-v2-renewed");
}

#[test]
fn get_attestation_returns_none_when_absent() {
    let pool = common::create_test_pool();
    let instance = create_application_instance(&pool, &DataMap::new());
    let key = create_application_key(&pool, &instance.id, &DataMap::new());

    let fetched = pool.get_application_key_attestation(&key.id).unwrap();
    assert!(fetched.is_none());
}

#[test]
fn revocation_insert_is_idempotent_and_list_since_filters_by_time() {
    let pool = common::create_test_pool();
    let instance = create_application_instance(&pool, &DataMap::new());

    let base = chrono::Utc::now();
    let old_overrides: DataMap = [
        ("target_key_id".to_string(), json!("old-key")),
        (
            "revoked_at".to_string(),
            json!((base - chrono::Duration::days(10)).to_rfc3339()),
        ),
    ]
    .into_iter()
    .collect();
    create_application_key_revocation(&pool, &instance.id, &old_overrides);

    let new_overrides: DataMap = [
        ("target_key_id".to_string(), json!("new-key")),
        (
            "revoked_at".to_string(),
            json!((base + chrono::Duration::days(1)).to_rfc3339()),
        ),
    ]
    .into_iter()
    .collect();
    create_application_key_revocation(&pool, &instance.id, &new_overrides);

    // No filter: both present.
    let all = pool
        .list_application_key_revocations_since(&instance.id, None)
        .unwrap();
    assert_eq!(all.len(), 2);

    // Filtered to only the recent one.
    let recent = pool
        .list_application_key_revocations_since(&instance.id, Some(base))
        .unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].target_key_id, "new-key");

    // Repeat revocation of the same target_key_id is a no-op (idempotent,
    // instance_row_id+target_key_id unique).
    let affected = pool
        .insert_application_key_revocation(
            &instance.id,
            "old-key",
            "some-different-fingerprint",
            chrono::Utc::now(),
            b"a-different-record-payload",
        )
        .unwrap();
    assert_eq!(affected, 0);

    let still_two = pool
        .list_application_key_revocations_since(&instance.id, None)
        .unwrap();
    assert_eq!(still_two.len(), 2);
}

#[test]
fn challenge_is_single_use() {
    let pool = common::create_test_pool();
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);
    pool.insert_application_key_challenge(
        "challenge-1",
        "subject-uuid-string",
        "tinku",
        "instance-a",
        "add",
        "sign",
        "ed25519",
        b"pubkey-bytes",
        b"nonce-bytes",
        expires_at,
    )
    .unwrap();

    let now = chrono::Utc::now();
    let first = pool
        .consume_application_key_challenge("challenge-1", now)
        .unwrap();
    assert!(first.is_some());
    let consumed = first.unwrap();
    assert_eq!(consumed.challenge_id, "challenge-1");
    assert_eq!(consumed.public_key, b"pubkey-bytes");

    // A second consumption must fail — the challenge is already consumed.
    let second = pool
        .consume_application_key_challenge("challenge-1", chrono::Utc::now())
        .unwrap();
    assert!(second.is_none());
}

#[test]
fn expired_challenge_cannot_be_consumed() {
    let pool = common::create_test_pool();
    let expires_at = chrono::Utc::now() - chrono::Duration::minutes(1);
    pool.insert_application_key_challenge(
        "expired-challenge",
        "subject-uuid-string",
        "tinku",
        "instance-a",
        "renew",
        "sign",
        "ed25519",
        b"pubkey-bytes",
        b"nonce-bytes",
        expires_at,
    )
    .unwrap();

    let result = pool
        .consume_application_key_challenge("expired-challenge", chrono::Utc::now())
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn delete_expired_challenges_removes_only_expired() {
    let pool = common::create_test_pool();
    let now = chrono::Utc::now();
    pool.insert_application_key_challenge(
        "expired-1",
        "subject",
        "app",
        "inst",
        "add",
        "sign",
        "ed25519",
        b"pk",
        b"nonce",
        now - chrono::Duration::hours(1),
    )
    .unwrap();
    pool.insert_application_key_challenge(
        "still-valid",
        "subject",
        "app",
        "inst",
        "add",
        "sign",
        "ed25519",
        b"pk",
        b"nonce",
        now + chrono::Duration::hours(1),
    )
    .unwrap();

    let deleted = pool.delete_expired_application_key_challenges(now).unwrap();
    assert_eq!(deleted, 1);

    // The still-valid one can still be consumed.
    let consumed = pool
        .consume_application_key_challenge("still-valid", now)
        .unwrap();
    assert!(consumed.is_some());
}

#[test]
fn load_public_records_returns_none_for_unknown_instance() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let result = pool
        .load_application_public_records(&user.id, "tinku", "no-such-instance", None)
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn load_public_records_returns_active_attestations_and_revocations() {
    let pool = common::create_test_pool();
    let instance = create_application_instance(&pool, &DataMap::new());

    // An active key with a current attestation: included.
    let active_key = create_application_key(&pool, &instance.id, &DataMap::new());
    let active_attestation_overrides: DataMap = [(
        "signed_attestation".to_string(),
        json!("active-key-attestation"),
    )]
    .into_iter()
    .collect();
    create_application_key_attestation(&pool, &active_key.id, &active_attestation_overrides);

    // A revoked key with an attestation: attestation excluded, but its
    // revocation record IS included.
    let revoked_key_overrides: DataMap = [("key_id".to_string(), json!("revoked-key"))]
        .into_iter()
        .collect();
    let revoked_key = create_application_key(&pool, &instance.id, &revoked_key_overrides);
    let revoked_attestation_overrides: DataMap = [(
        "signed_attestation".to_string(),
        json!("revoked-key-attestation"),
    )]
    .into_iter()
    .collect();
    create_application_key_attestation(&pool, &revoked_key.id, &revoked_attestation_overrides);
    pool.revoke_application_key(&instance.id, "revoked-key", chrono::Utc::now())
        .unwrap();
    let revocation_overrides: DataMap = [
        ("target_key_id".to_string(), json!("revoked-key")),
        (
            "record".to_string(),
            json!("revocation-record-for-revoked-key"),
        ),
    ]
    .into_iter()
    .collect();
    create_application_key_revocation(&pool, &instance.id, &revocation_overrides);

    let records = pool
        .load_application_public_records(
            &instance.subject_user_id,
            &instance.application_id,
            &instance.instance_id,
            None,
        )
        .unwrap()
        .expect("instance should be found");

    assert_eq!(records.subject_user_id, instance.subject_user_id);
    assert_eq!(records.application_id, instance.application_id);
    assert_eq!(records.instance_id, instance.instance_id);

    // BOTH attestations are published: the active key's, and the revoked but
    // unexpired key's. Publishing the revoked key's attestation is what keeps
    // its revocation verifiable — a revocation names its target by key id and
    // fingerprint, and a verifier checks the sibling signatures against the
    // attested key set. Withhold the revoked key and a peer that still holds a
    // valid cached attestation for it would fetch the revocations, fail to
    // verify them, and go on trusting the revoked key.
    assert_eq!(records.signed_attestations.len(), 2);
    assert!(records
        .signed_attestations
        .contains(&b"active-key-attestation".to_vec()));
    assert!(records
        .signed_attestations
        .contains(&b"revoked-key-attestation".to_vec()));

    assert_eq!(records.revocation_records.len(), 1);
    assert_eq!(
        records.revocation_records[0],
        b"revocation-record-for-revoked-key".to_vec()
    );
}

#[test]
fn load_public_records_excludes_expired_keys() {
    let pool = common::create_test_pool();
    let instance = create_application_instance(&pool, &DataMap::new());

    let expired_key_overrides: DataMap = [
        ("key_id".to_string(), json!("expired-key")),
        (
            "expires_at".to_string(),
            json!((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339()),
        ),
    ]
    .into_iter()
    .collect();
    let expired_key = create_application_key(&pool, &instance.id, &expired_key_overrides);
    create_application_key_attestation(&pool, &expired_key.id, &DataMap::new());

    let records = pool
        .load_application_public_records(
            &instance.subject_user_id,
            &instance.application_id,
            &instance.instance_id,
            None,
        )
        .unwrap()
        .unwrap();

    assert!(records.signed_attestations.is_empty());
}

#[test]
fn instances_of_the_same_subject_never_see_each_others_keys() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let instance_a_overrides: DataMap = [
        ("subject_user_id".to_string(), json!(user.id)),
        ("application_id".to_string(), json!("tinku")),
        ("instance_id".to_string(), json!("instance-a")),
    ]
    .into_iter()
    .collect();
    let instance_a = create_application_instance(&pool, &instance_a_overrides);

    let instance_b_overrides: DataMap = [
        ("subject_user_id".to_string(), json!(user.id)),
        ("application_id".to_string(), json!("tinku")),
        ("instance_id".to_string(), json!("instance-b")),
    ]
    .into_iter()
    .collect();
    let instance_b = create_application_instance(&pool, &instance_b_overrides);

    assert_ne!(instance_a.id, instance_b.id);

    let key_a_overrides: DataMap = [("key_id".to_string(), json!("shared-key-id"))]
        .into_iter()
        .collect();
    create_application_key(&pool, &instance_a.id, &key_a_overrides);

    // Same key_id string is fine in a different instance — the uniqueness is
    // scoped per instance_row_id, not global.
    let key_b_overrides: DataMap = [("key_id".to_string(), json!("shared-key-id"))]
        .into_iter()
        .collect();
    create_application_key(&pool, &instance_b.id, &key_b_overrides);

    assert_eq!(pool.list_application_keys(&instance_a.id).unwrap().len(), 1);
    assert_eq!(pool.list_application_keys(&instance_b.id).unwrap().len(), 1);

    // find_application_key is scoped to instance_row_id.
    assert!(pool
        .find_application_key(&instance_a.id, "shared-key-id")
        .unwrap()
        .is_some());
    assert!(pool
        .find_application_key(&instance_b.id, "shared-key-id")
        .unwrap()
        .is_some());

    // Revoking in instance A must not affect instance B's key.
    pool.revoke_application_key(&instance_a.id, "shared-key-id", chrono::Utc::now())
        .unwrap();
    assert_eq!(pool.count_application_keys(&instance_a.id).unwrap(), 0);
    assert_eq!(pool.count_application_keys(&instance_b.id).unwrap(), 1);

    // Public projections are isolated too.
    let attestation_a_overrides: DataMap = [(
        "signed_attestation".to_string(),
        json!("attestation-for-instance-a-key"),
    )]
    .into_iter()
    .collect();
    let key_a = pool
        .find_application_key(&instance_a.id, "shared-key-id")
        .unwrap()
        .unwrap();
    // Instance A's key is revoked but not expired, so its attestation IS still
    // published (that is what keeps its revocation verifiable). What this test
    // is really about is the boundary: instance B's separate key and
    // attestation must never appear in A's projection, or in B's the other way
    // round.
    create_application_key_attestation(&pool, &key_a.id, &attestation_a_overrides);

    let key_b = pool
        .find_application_key(&instance_b.id, "shared-key-id")
        .unwrap()
        .unwrap();
    let attestation_b_overrides: DataMap = [(
        "signed_attestation".to_string(),
        json!("attestation-for-instance-b-key"),
    )]
    .into_iter()
    .collect();
    create_application_key_attestation(&pool, &key_b.id, &attestation_b_overrides);

    let records_a = pool
        .load_application_public_records(&user.id, "tinku", "instance-a", None)
        .unwrap()
        .unwrap();
    assert_eq!(records_a.signed_attestations.len(), 1);
    assert!(
        !records_a
            .signed_attestations
            .contains(&b"attestation-for-instance-b-key".to_vec()),
        "instance B's material must never reach instance A's projection"
    );

    let records_b = pool
        .load_application_public_records(&user.id, "tinku", "instance-b", None)
        .unwrap()
        .unwrap();
    assert_eq!(records_b.signed_attestations.len(), 1);
    assert_eq!(
        records_b.signed_attestations[0],
        b"attestation-for-instance-b-key".to_vec()
    );
}
