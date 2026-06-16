//! Integration test for consent-grant persistence, including the recorded
//! `offered_claims` — the RP's self-asserted DomainClaims that make its offered
//! terms a non-repudiable record. Exercises the real schema/migration/model path
//! on a database.

mod common;

use common::data_factory::{create_user, DataMap};
use liblinkkeys::crypto::{generate_keypair, SigningAlgorithm};
use liblinkkeys::domain_claims::{sign_domain_claim, DomainClaimSpec};
use liblinkkeys::generated::types::DomainClaim;

const RP: &str = "rp.example";

#[test]
fn consent_grant_records_offered_claims() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    // The RP self-asserts a privacy_policy DomainClaim; CBOR it as the IDP records it.
    let (_pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
    let claim = sign_domain_claim(
        &DomainClaimSpec {
            claim_type: "privacy_policy",
            claim_value: b"GDPR-strict-v1",
            subject_domain: RP,
            expires_at: None,
        },
        &[liblinkkeys::claims::ClaimSigner {
            domain: RP,
            key_id: "rp-1",
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &sk,
        }],
    )
    .unwrap();
    let offered = vec![claim];
    let mut offered_cbor = Vec::new();
    ciborium::ser::into_writer(&offered, &mut offered_cbor).unwrap();

    let now = chrono::Utc::now();
    let issued = now.to_rfc3339();
    let expires = (now + chrono::Duration::days(365)).to_rfc3339();
    pool.upsert_consent_grant(
        &uuid::Uuid::now_v7().to_string(),
        &user.id,
        "idp.example",
        RP,
        &["email".to_string()],
        &["email".to_string()],
        b"signed-grant-bytes",
        Some(&offered_cbor),
        &issued,
        &expires,
    )
    .expect("upsert grant");

    let row = pool
        .find_active_consent_grant(&user.id, RP)
        .expect("query")
        .expect("a grant exists");

    assert_eq!(row.claim_types, vec!["email".to_string()]);
    let recorded = row.offered_claims.expect("offered_claims recorded");
    let decoded: Vec<DomainClaim> = ciborium::de::from_reader(&recorded[..]).unwrap();
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].claim_type, "privacy_policy");
    assert_eq!(decoded[0].claim_value, b"GDPR-strict-v1");
}

#[test]
fn consent_grant_without_offered_claims_is_null() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    let now = chrono::Utc::now();
    pool.upsert_consent_grant(
        &uuid::Uuid::now_v7().to_string(),
        &user.id,
        "idp.example",
        RP,
        &[],
        &["email".to_string()],
        b"signed-grant-bytes",
        None,
        &now.to_rfc3339(),
        &(now + chrono::Duration::days(365)).to_rfc3339(),
    )
    .expect("upsert grant");

    let row = pool
        .find_active_consent_grant(&user.id, RP)
        .expect("query")
        .expect("a grant exists");
    assert!(row.offered_claims.is_none());
}
