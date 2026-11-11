//! Integration test for consent-grant persistence, including the recorded
//! `offered_claims` — the RP's self-asserted DomainClaims that make its offered
//! terms a non-repudiable record. Exercises the real schema/migration/model path
//! on a database.

mod common;

use common::data_factory::{create_user, DataMap};
use liblinkkeys::crypto::{generate_keypair, SigningAlgorithm};
use liblinkkeys::domain_claims::{sign_domain_claim, DomainClaimSpec};
use liblinkkeys::generated::types::{ApplicationRef, DomainClaim};

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
            attested_at: "2020-01-01T00:00:00+00:00",
        },
        &[liblinkkeys::claims::ClaimSigner {
            domain: RP,
            key_id: "rp-1",
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &sk,
        }],
    )
    .unwrap();
    // Offered claims are stored as a CBOR array of each claim's canonical codec
    // bytes (the generated codec has no `Vec<DomainClaim>` helper), matching the
    // server's `encode_domain_claim_list`.
    let offered = [claim];
    let encoded: Vec<Vec<u8>> = offered
        .iter()
        .map(liblinkkeys::generated::encode_domain_claim)
        .collect();
    let mut offered_cbor = Vec::new();
    ciborium::ser::into_writer(&encoded, &mut offered_cbor).unwrap();

    let now = chrono::Utc::now();
    let issued = now.to_rfc3339();
    let expires = (now + chrono::Duration::days(365)).to_rfc3339();
    pool.upsert_consent_grant(
        &uuid::Uuid::now_v7().to_string(),
        &user.id,
        "idp.example",
        RP,
        None,
        &["email".to_string()],
        &["email".to_string()],
        b"signed-grant-bytes",
        Some(&offered_cbor),
        &issued,
        &expires,
    )
    .expect("upsert grant");

    let row = pool
        .find_active_consent_grant(&user.id, RP, None)
        .expect("query")
        .expect("a grant exists");

    assert_eq!(row.claim_types, vec!["email".to_string()]);
    let recorded = row.offered_claims.expect("offered_claims recorded");
    let encoded: Vec<Vec<u8>> = ciborium::de::from_reader(&recorded[..]).unwrap();
    let decoded: Vec<DomainClaim> = encoded
        .iter()
        .map(|b| liblinkkeys::generated::decode_domain_claim(b).unwrap())
        .collect();
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
        None,
        &[],
        &["email".to_string()],
        b"signed-grant-bytes",
        None,
        &now.to_rfc3339(),
        &(now + chrono::Duration::days(365)).to_rfc3339(),
    )
    .expect("upsert grant");

    let row = pool
        .find_active_consent_grant(&user.id, RP, None)
        .expect("query")
        .expect("a grant exists");
    assert!(row.offered_claims.is_none());
}

fn upsert(pool: &linkkeys::db::DbPool, user_id: &str, app: Option<&ApplicationRef>, claim: &str) {
    let now = chrono::Utc::now();
    pool.upsert_consent_grant(
        &uuid::Uuid::now_v7().to_string(),
        user_id,
        "idp.example",
        RP,
        app,
        &[claim.to_string()],
        &[claim.to_string()],
        b"signed-grant-bytes",
        None,
        &now.to_rfc3339(),
        &(now + chrono::Duration::days(365)).to_rfc3339(),
    )
    .expect("upsert grant");
}

fn app(application_id: &str) -> ApplicationRef {
    ApplicationRef {
        subject_user_id: "00000000-0000-0000-0000-0000000000aa".to_string(),
        subject_domain: RP.to_string(),
        application_id: application_id.to_string(),
    }
}

#[test]
fn consent_grants_are_per_application() {
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    let grafana = app("homegrafana");
    let wiki = app("wiki");

    upsert(&pool, &user.id, Some(&grafana), "email");
    // A sibling application, and a request with no application, see nothing.
    assert!(pool
        .find_active_consent_grant(&user.id, RP, Some(&wiki))
        .expect("query")
        .is_none());
    assert!(pool
        .find_active_consent_grant(&user.id, RP, None)
        .expect("query")
        .is_none());

    upsert(&pool, &user.id, Some(&wiki), "phone");
    upsert(&pool, &user.id, None, "name");
    // Replacing one application's grant leaves the others alone.
    upsert(&pool, &user.id, Some(&grafana), "display_name");

    let claims = |a: Option<&ApplicationRef>| {
        pool.find_active_consent_grant(&user.id, RP, a)
            .expect("query")
            .expect("grant exists")
            .claim_types
    };
    assert_eq!(claims(Some(&grafana)), vec!["display_name"]);
    assert_eq!(claims(Some(&wiki)), vec!["phone"]);
    assert_eq!(claims(None), vec!["name"]);
    let row = pool
        .find_active_consent_grant(&user.id, RP, Some(&grafana))
        .unwrap()
        .unwrap();
    assert_eq!(row.app_application_id.as_deref(), Some("homegrafana"));
    assert!(pool
        .has_active_consent_grant_for_audience(&user.id, RP)
        .unwrap());
    assert!(!pool
        .has_active_consent_grant_for_audience(&user.id, "other.example")
        .unwrap());
}
