//! Regression guard for the signature-format upgrade
//! (`services::signature_upgrade`).
//!
//! Claims, consent grants, and key revocations signed before the `-v1alpha`
//! epoch (0.14.1) do not verify under the current format. Nothing re-signed
//! them, so relying parties that verify claim signatures rejected them. The
//! upgrade re-signs a record only when every local signature verifies in a
//! known format with a key of this domain. These tests build records in each
//! historical format, run the upgrade, and verify the result with the
//! current `liblinkkeys` verifiers.

mod common;

use std::collections::HashMap;

use liblinkkeys::claims::{verify_claim, ClaimSpec, DomainKeySet};
use liblinkkeys::crypto::{self, SigningAlgorithm};
use liblinkkeys::generated::types::{
    Claim, ClaimSignature, ConsentGrant, DomainPublicKey, RevocationCertificate, SignedConsentGrant,
};
use liblinkkeys::legacy_signatures::{
    legacy_claim_payload, legacy_consent_payload, legacy_revocation_payload, LegacyClaimFormat,
};
use linkkeys::db::models::DomainKey;
use linkkeys::db::DbPool;
use linkkeys::services::signature_upgrade::run;

const PASSPHRASE: &str = "test-passphrase";

fn domain() -> String {
    linkkeys::conversions::get_domain_name()
}

fn secret(key: &DomainKey) -> Vec<u8> {
    crypto::decrypt_private_key(&key.private_key_encrypted, PASSPHRASE.as_bytes())
        .unwrap()
        .to_vec()
}

fn sign(key: &DomainKey, payload: &[u8]) -> ClaimSignature {
    ClaimSignature {
        domain: domain(),
        signed_by_key_id: key.id.clone(),
        signature: crypto::sign_with_algorithm(SigningAlgorithm::Ed25519, payload, &secret(key))
            .unwrap(),
    }
}

fn keysets(pool: &DbPool) -> Vec<DomainKeySet> {
    vec![DomainKeySet {
        domain: domain(),
        keys: pool
            .list_all_domain_keys()
            .unwrap()
            .iter()
            .map(Into::into)
            .collect(),
    }]
}

fn whole_seconds(t: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    use chrono::Timelike;
    t.with_nanosecond(0).unwrap()
}

/// A stored claim with no signatures, read back so its fields are exactly
/// what the server serves.
fn bare_claim(pool: &DbPool, user_id: &str, claim_type: &str, value: &[u8]) -> Claim {
    let id = uuid::Uuid::now_v7().to_string();
    // Microseconds, as Postgres stored attestation times before 0.14.1.
    let attested_at = chrono::Utc::now() - chrono::Duration::days(200);
    let row = pool
        .create_claim(&id, user_id, claim_type, value, &[], None, attested_at)
        .unwrap();
    (&row).into()
}

/// Store `signatures` as the claim's signatures and return the stored claim.
fn set_signatures(pool: &DbPool, claim_id: &str, signatures: &[ClaimSignature]) -> Claim {
    pool.resign_claim(claim_id, None, signatures).unwrap();
    (&pool.find_claim_by_id(claim_id).unwrap()).into()
}

fn legacy_claim(
    pool: &DbPool,
    user_id: &str,
    format: LegacyClaimFormat,
    keys: &[&DomainKey],
) -> Claim {
    let claim = bare_claim(pool, user_id, "email", b"user@example.com");
    let payload = legacy_claim_payload(format, &claim, &domain(), &domain());
    let signatures: Vec<ClaimSignature> = keys.iter().map(|k| sign(k, &payload)).collect();
    set_signatures(pool, &claim.claim_id, &signatures)
}

fn stored(pool: &DbPool, claim_id: &str) -> Claim {
    (&pool.find_claim_by_id(claim_id).unwrap()).into()
}

fn three_keys(pool: &DbPool) -> Vec<DomainKey> {
    (0..3)
        .map(|_| common::data_factory::create_domain_key(pool))
        .collect()
}

#[test]
fn claims_in_every_historical_format_are_resigned_and_verify() {
    let pool = common::create_test_pool();
    let keys = three_keys(&pool);
    let key_refs: Vec<&DomainKey> = keys.iter().collect();
    let user = common::data_factory::create_user(&pool, &HashMap::new());

    let legacy: Vec<Claim> = LegacyClaimFormat::ALL
        .into_iter()
        .map(|format| legacy_claim(&pool, &user.id, format, &key_refs))
        .collect();
    for claim in &legacy {
        assert!(
            verify_claim(claim, &domain(), &keysets(&pool)).is_err(),
            "a legacy claim must fail the current verifier (else the test is vacuous)"
        );
    }

    // A claim already in the current format.
    let signers = linkkeys::claim_signing::active_signers(&keys, PASSPHRASE.as_bytes()).unwrap();
    let current_bare = bare_claim(&pool, &user.id, "handle", b"user");
    let current = linkkeys::claim_signing::sign_with_active(
        &ClaimSpec {
            claim_id: &current_bare.claim_id,
            claim_type: &current_bare.claim_type,
            claim_value: &current_bare.claim_value,
            user_id: &current_bare.user_id,
            subject_domain: &domain(),
            expires_at: None,
            attested_at: &current_bare.attested_at,
        },
        &signers,
    )
    .unwrap();
    let current = set_signatures(&pool, &current.claim_id, &current.signatures);

    let report = run(&pool, Some(PASSPHRASE)).unwrap();
    assert_eq!(report.claims.checked, 4);
    assert_eq!(report.claims.current, 1);
    assert_eq!(report.claims.resigned.len(), 3, "{:?}", report.claims);
    assert!(report.claims.unverifiable.is_empty());
    assert!(report.is_clean());

    for before in &legacy {
        let after = stored(&pool, &before.claim_id);
        verify_claim(&after, &domain(), &keysets(&pool)).expect("re-signed claim verifies");
        assert_eq!(after.claim_value, before.claim_value);
        assert_eq!(after.claim_type, before.claim_type);
        assert_eq!(after.expires_at, before.expires_at);
        assert_eq!(
            after.attested_at, before.attested_at,
            "the attestation time is kept"
        );
        assert_eq!(after.signatures.len(), 3);
    }
    assert_eq!(
        stored(&pool, &current.claim_id).signatures,
        current.signatures,
        "a current claim is never re-signed"
    );

    // Idempotent: the second pass finds everything current.
    let again = run(&pool, Some(PASSPHRASE)).unwrap();
    assert_eq!(again.claims.current, 4);
    assert!(again.claims.resigned.is_empty());
}

#[test]
fn tampered_legacy_claim_is_not_resigned() {
    let pool = common::create_test_pool();
    let keys = three_keys(&pool);
    let user = common::data_factory::create_user(&pool, &HashMap::new());

    // The signatures cover a different value than the row holds.
    let claim = bare_claim(&pool, &user.id, "email", b"attacker@example.net");
    let honest = Claim {
        claim_value: b"user@example.com".to_vec(),
        ..claim.clone()
    };
    let payload = legacy_claim_payload(LegacyClaimFormat::V2, &honest, &domain(), &domain());
    let signatures: Vec<ClaimSignature> = keys.iter().map(|k| sign(k, &payload)).collect();
    let before = set_signatures(&pool, &claim.claim_id, &signatures);

    let report = run(&pool, Some(PASSPHRASE)).unwrap();
    assert_eq!(report.claims.unverifiable, vec![claim.claim_id.clone()]);
    assert!(report.claims.resigned.is_empty());
    assert!(!report.is_clean());
    assert_eq!(
        stored(&pool, &claim.claim_id).signatures,
        before.signatures,
        "a tampered row must keep its broken signatures"
    );
}

#[test]
fn check_only_reports_and_changes_nothing() {
    let pool = common::create_test_pool();
    let keys = three_keys(&pool);
    let user = common::data_factory::create_user(&pool, &HashMap::new());
    let claim = legacy_claim(&pool, &user.id, LegacyClaimFormat::V1Subject, &[&keys[0]]);

    let report = run(&pool, None).unwrap();
    assert_eq!(report.claims.stale, vec![claim.claim_id.clone()]);
    assert!(report.claims.resigned.is_empty());
    assert!(report.claims.failed.is_empty());
    assert!(!report.is_clean());
    assert_eq!(stored(&pool, &claim.claim_id).signatures, claim.signatures);
}

#[test]
fn signatures_of_other_domains_are_kept() {
    let pool = common::create_test_pool();
    let keys = three_keys(&pool);
    let user = common::data_factory::create_user(&pool, &HashMap::new());
    let foreign = ClaimSignature {
        domain: "issuer.example".to_string(),
        signed_by_key_id: "issuer-key".to_string(),
        signature: vec![7; 64],
    };

    // Local legacy signature plus a foreign one: the local part is re-signed.
    let mixed = legacy_claim(&pool, &user.id, LegacyClaimFormat::V2, &[&keys[0]]);
    let mut signatures = mixed.signatures.clone();
    signatures.push(foreign.clone());
    set_signatures(&pool, &mixed.claim_id, &signatures);

    // Only a foreign signature: nothing to re-sign.
    let only_foreign = bare_claim(&pool, &user.id, "employer", b"Example Corp");
    set_signatures(
        &pool,
        &only_foreign.claim_id,
        std::slice::from_ref(&foreign),
    );

    let report = run(&pool, Some(PASSPHRASE)).unwrap();
    assert_eq!(report.claims.resigned, vec![mixed.claim_id.clone()]);
    let mut flagged = report.claims.foreign.clone();
    flagged.sort();
    let mut expected = vec![mixed.claim_id.clone(), only_foreign.claim_id.clone()];
    expected.sort();
    assert_eq!(flagged, expected);

    let after = stored(&pool, &mixed.claim_id);
    assert!(after.signatures.contains(&foreign));
    assert_eq!(
        after.signatures.len(),
        4,
        "3 active keys plus the foreign one"
    );
    assert_eq!(
        stored(&pool, &only_foreign.claim_id).signatures,
        vec![foreign]
    );
}

#[test]
fn revoked_and_expired_claims_are_skipped() {
    let pool = common::create_test_pool();
    let keys = three_keys(&pool);
    let user = common::data_factory::create_user(&pool, &HashMap::new());
    let claim = legacy_claim(&pool, &user.id, LegacyClaimFormat::V2, &[&keys[0]]);
    pool.remove_claim(&claim.claim_id).unwrap();

    let report = run(&pool, Some(PASSPHRASE)).unwrap();
    assert_eq!(report.claims.checked, 0);
}

/// SQLite rows from before 2026-07-02 got `attested_at = created_at`, which
/// SQLite wrote as "YYYY-MM-DD HH:MM:SS". That value cannot round-trip as
/// RFC3339, so the re-sign records a new attestation time.
#[test]
fn unreadable_attested_at_gets_a_new_attestation() {
    let pool = common::create_test_pool();
    #[allow(irrefutable_let_patterns)]
    let DbPool::Sqlite(sqlite) = &pool
    else {
        return; // Postgres stores timestamptz; it cannot hold this value.
    };
    let keys = three_keys(&pool);
    let user = common::data_factory::create_user(&pool, &HashMap::new());
    let claim = bare_claim(&pool, &user.id, "email", b"user@example.com");
    {
        use diesel::prelude::*;
        let mut conn = sqlite.get().unwrap();
        diesel::sql_query("UPDATE claims SET attested_at = '2026-06-10 12:00:00' WHERE id = ?")
            .bind::<diesel::sql_types::Text, _>(&claim.claim_id)
            .execute(&mut *conn)
            .unwrap();
    }
    let claim = stored(&pool, &claim.claim_id);
    let payload = legacy_claim_payload(LegacyClaimFormat::V1Subject, &claim, &domain(), &domain());
    set_signatures(&pool, &claim.claim_id, &[sign(&keys[0], &payload)]);

    let report = run(&pool, Some(PASSPHRASE)).unwrap();
    assert_eq!(report.claims.reattested, vec![claim.claim_id.clone()]);
    let after = stored(&pool, &claim.claim_id);
    assert_ne!(after.attested_at, "2026-06-10 12:00:00");
    chrono::DateTime::parse_from_rfc3339(&after.attested_at).expect("RFC3339 now");
    verify_claim(&after, &domain(), &keysets(&pool)).expect("re-signed claim verifies");
    assert!(pool
        .list_audit(10)
        .unwrap()
        .iter()
        .any(|e| e.event == "claim.reattested"));
}

#[test]
fn legacy_consent_grant_is_resigned_and_verifies() {
    let pool = common::create_test_pool();
    let keys = three_keys(&pool);
    let user = common::data_factory::create_user(&pool, &HashMap::new());
    let issued = whole_seconds(chrono::Utc::now() - chrono::Duration::days(150));
    let grant = ConsentGrant {
        grant_id: uuid::Uuid::now_v7().to_string(),
        user_id: user.id.clone(),
        subject_domain: domain(),
        audience: "rp.example".to_string(),
        claim_types: vec!["email".to_string()],
        issued_at: issued.to_rfc3339(),
        expires_at: (issued + chrono::Duration::days(365)).to_rfc3339(),
        revoked_at: None,
        application: None,
    };
    let payload = legacy_consent_payload(&grant, &domain());
    let signed = SignedConsentGrant {
        grant: liblinkkeys::generated::encode_consent_grant(&grant),
        signatures: vec![sign(&keys[0], &payload)],
    };
    pool.upsert_consent_grant(
        &grant.grant_id,
        &user.id,
        &domain(),
        &grant.audience,
        None,
        &grant.claim_types,
        &grant.claim_types,
        &liblinkkeys::generated::encode_signed_consent_grant(&signed),
        None,
        &grant.issued_at,
        &grant.expires_at,
    )
    .unwrap();

    let report = run(&pool, Some(PASSPHRASE)).unwrap();
    assert_eq!(report.consent_grants.resigned, vec![grant.grant_id.clone()]);

    let row = pool
        .find_active_consent_grant(&user.id, &grant.audience, None)
        .unwrap()
        .unwrap();
    let after = liblinkkeys::generated::decode_signed_consent_grant(&row.signed_grant).unwrap();
    let verified = liblinkkeys::consent::verify_consent(
        &after,
        &domain(),
        &grant.audience,
        None,
        &keysets(&pool),
    )
    .expect("re-signed grant verifies");
    assert_eq!(verified.claim_types, grant.claim_types);
    assert_eq!(verified.expires_at, grant.expires_at);

    let again = run(&pool, Some(PASSPHRASE)).unwrap();
    assert_eq!(again.consent_grants.current, 1);
}

#[test]
fn legacy_revocation_certificate_is_resigned_and_verifies() {
    let pool = common::create_test_pool();
    let keys = three_keys(&pool);
    let target = pool.revoke_domain_key(&keys[0].id).unwrap();
    let revoked_at = target.revoked_at.clone().unwrap();
    let payload =
        legacy_revocation_payload(&target.id, &target.fingerprint, &revoked_at, &domain());
    let cert = RevocationCertificate {
        target_key_id: target.id.clone(),
        target_fingerprint: target.fingerprint.clone(),
        revoked_at: revoked_at.clone(),
        signatures: vec![sign(&keys[1], &payload), sign(&keys[2], &payload)],
    };
    pool.insert_issued_revocation(
        &target.id,
        &target.fingerprint,
        chrono::DateTime::parse_from_rfc3339(&revoked_at)
            .unwrap()
            .with_timezone(&chrono::Utc),
        &liblinkkeys::generated::encode_revocation_certificate(&cert),
    )
    .unwrap();

    let public: Vec<DomainPublicKey> = pool
        .list_all_domain_keys()
        .unwrap()
        .iter()
        .map(Into::into)
        .collect();
    assert!(
        liblinkkeys::revocation::verify_revocation_certificate(&cert, &public, &domain()).is_err()
    );

    let report = run(&pool, Some(PASSPHRASE)).unwrap();
    assert_eq!(
        report.revocations.resigned.len(),
        1,
        "{:?}",
        report.revocations
    );

    let row = &pool.list_issued_revocations_since(None).unwrap()[0];
    let after = liblinkkeys::generated::decode_revocation_certificate(&row.cert).unwrap();
    liblinkkeys::revocation::verify_revocation_certificate(&after, &public, &domain())
        .expect("re-signed certificate verifies");
    assert_eq!(after.revoked_at, revoked_at);
}
