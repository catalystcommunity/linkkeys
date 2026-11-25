//! Regression guard for the signature-format upgrade
//! (`services::signature_upgrade`).
//!
//! Claims, consent grants, key revocations, and application-key attestations
//! signed in an older format (before the `-v1alpha` epoch, 0.14.1, or with
//! the "v1alpha text" timestamps used until CSIL typed them) do not verify
//! under the current format. The upgrade re-signs a record only when every
//! local signature verifies in a known format with a key of this domain.
//! These tests build records in each historical format, run the upgrade, and
//! verify the result with the current `liblinkkeys` verifiers.

mod common;

use std::collections::HashMap;

use liblinkkeys::claims::{verify_claim, ClaimSpec, DomainKeySet};
use liblinkkeys::crypto::{self, SigningAlgorithm};
use liblinkkeys::generated::types::{
    ApplicationKeyAttestation, Claim, ClaimSignature, ConsentGrant, DomainPublicKey, KeyAlgorithm,
    KeyUsage, RevocationCertificate, SignedApplicationKeyAttestation, SignedConsentGrant,
};
use liblinkkeys::legacy_signatures::{
    attestation_provenance, downgrade_to_v1alpha_text, legacy_claim_payload,
    legacy_consent_payload, legacy_revocation_payload, sqlite_datetime_text, LegacyClaimFormat,
    LegacyGrantTimes, Provenance, CONSENT_V1ALPHA_TAG,
};
use liblinkkeys::revocation::REVOCATION_TAG;
use liblinkkeys::timestamp::{whole_seconds, Rfc3339 as _};
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

/// A stored claim with no signatures, read back so its fields are exactly
/// what the server serves.
fn bare_claim(pool: &DbPool, user_id: &str, claim_type: &str, value: &[u8]) -> Claim {
    let id = uuid::Uuid::now_v7().to_string();
    // Microseconds, as Postgres stored attestation times before 0.14.1.
    let attested_at = time::OffsetDateTime::now_utc() - time::Duration::days(200);
    let row = pool
        .create_claim(&id, user_id, claim_type, value, &[], None, attested_at)
        .unwrap();
    (&row).into()
}

/// Store `signatures` as the claim's signatures and return the stored claim.
fn set_signatures(pool: &DbPool, claim_id: &str, signatures: &[ClaimSignature]) -> Claim {
    pool.resign_claim(claim_id, None, None, signatures).unwrap();
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
    pool.resign_claim(
        &current_bare.claim_id,
        Some(whole_seconds(current_bare.attested_at)),
        None,
        &[],
    )
    .unwrap();
    let current_bare = stored(&pool, &current_bare.claim_id);
    let current = linkkeys::claim_signing::sign_with_active(
        &ClaimSpec {
            claim_id: &current_bare.claim_id,
            claim_type: &current_bare.claim_type,
            claim_value: &current_bare.claim_value,
            user_id: &current_bare.user_id,
            subject_domain: &domain(),
            expires_at: None,
            attested_at: current_bare.attested_at,
        },
        &signers,
    )
    .unwrap();
    let current = set_signatures(&pool, &current.claim_id, &current.signatures);

    let report = run(&pool, Some(PASSPHRASE)).unwrap();
    assert_eq!(report.claims.checked, LegacyClaimFormat::ALL.len() + 1);
    assert_eq!(report.claims.current, 1);
    assert_eq!(
        report.claims.resigned.len(),
        LegacyClaimFormat::ALL.len(),
        "{:?}",
        report.claims
    );
    assert!(report.claims.unverifiable.is_empty());
    assert!(report.is_clean());

    for before in &legacy {
        let after = stored(&pool, &before.claim_id);
        verify_claim(&after, &domain(), &keysets(&pool)).expect("re-signed claim verifies");
        assert_eq!(after.claim_value, before.claim_value);
        assert_eq!(after.claim_type, before.claim_type);
        assert_eq!(after.expires_at, before.expires_at);
        assert_eq!(
            after.attested_at,
            whole_seconds(before.attested_at),
            "the attestation time is kept, to the second"
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
    assert_eq!(again.claims.current, LegacyClaimFormat::ALL.len() + 1);
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
/// SQLite wrote as "YYYY-MM-DD HH:MM:SS", and the server signed that text as
/// stored. The upgrade recognizes the signature and re-signs the same instant.
#[test]
fn sqlite_datetime_attested_at_is_recognized() {
    let pool = common::create_test_pool();
    #[allow(irrefutable_let_patterns)]
    let DbPool::Sqlite(sqlite) = &pool
    else {
        return; // Postgres stores timestamptz; it never held this text.
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
    assert_eq!(
        sqlite_datetime_text(&claim.attested_at),
        "2026-06-10 12:00:00"
    );
    // The old signature covers the SQLite text, not RFC 3339.
    let payload = liblinkkeys::legacy_signatures::legacy_claim_payload_with(
        LegacyClaimFormat::V2,
        &claim,
        &domain(),
        &domain(),
        "2026-06-10 12:00:00",
    );
    set_signatures(&pool, &claim.claim_id, &[sign(&keys[0], &payload)]);

    let report = run(&pool, Some(PASSPHRASE)).unwrap();
    assert_eq!(report.claims.resigned, vec![claim.claim_id.clone()]);
    let after = stored(&pool, &claim.claim_id);
    assert_eq!(after.attested_at, claim.attested_at);
    verify_claim(&after, &domain(), &keysets(&pool)).expect("re-signed claim verifies");
}

/// A stored signed time with a fraction of a second is cut to whole seconds
/// and audited.
#[test]
fn fractional_signed_times_are_cut_to_whole_seconds() {
    let pool = common::create_test_pool();
    let keys = three_keys(&pool);
    let user = common::data_factory::create_user(&pool, &HashMap::new());
    let claim = legacy_claim(&pool, &user.id, LegacyClaimFormat::V1AlphaText, &[&keys[0]]);
    assert_ne!(
        claim.attested_at.nanosecond(),
        0,
        "the test needs a fraction"
    );

    let report = run(&pool, Some(PASSPHRASE)).unwrap();
    assert_eq!(report.claims.reattested, vec![claim.claim_id.clone()]);
    let after = stored(&pool, &claim.claim_id);
    assert_eq!(after.attested_at, whole_seconds(claim.attested_at));
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
    let issued = whole_seconds(time::OffsetDateTime::now_utc() - time::Duration::days(150));
    let grant = ConsentGrant {
        grant_id: uuid::Uuid::now_v7().to_string(),
        user_id: user.id.clone(),
        subject_domain: domain(),
        audience: "rp.example".to_string(),
        claim_types: vec!["email".to_string()],
        issued_at: issued,
        expires_at: issued + time::Duration::days(365),
        revoked_at: None,
        application: None,
    };
    let times = LegacyGrantTimes {
        issued_at: grant.issued_at.to_rfc3339(),
        expires_at: grant.expires_at.to_rfc3339(),
    };
    let payload = legacy_consent_payload(CONSENT_V1ALPHA_TAG, &grant, &times, &domain());
    let signed = SignedConsentGrant {
        grant: downgrade_to_v1alpha_text(
            &liblinkkeys::generated::encode_consent_grant(&grant).unwrap(),
        )
        .unwrap(),
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
        &liblinkkeys::generated::encode_signed_consent_grant(&signed).unwrap(),
        None,
        grant.issued_at,
        grant.expires_at,
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
    let revoked_at = target.revoked_at.unwrap();
    let payload = legacy_revocation_payload(
        REVOCATION_TAG,
        &target.id,
        &target.fingerprint,
        &revoked_at.to_rfc3339(),
        &domain(),
    );
    let cert = RevocationCertificate {
        target_key_id: target.id.clone(),
        target_fingerprint: target.fingerprint.clone(),
        revoked_at,
        signatures: vec![sign(&keys[1], &payload), sign(&keys[2], &payload)],
    };
    pool.insert_issued_revocation(
        &target.id,
        &target.fingerprint,
        revoked_at,
        &downgrade_to_v1alpha_text(
            &liblinkkeys::generated::encode_revocation_certificate(&cert).unwrap(),
        )
        .unwrap(),
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
    assert_eq!(after.revoked_at, whole_seconds(revoked_at));
}

/// Store an application-key attestation in the v1alpha text encoding, signed
/// by `key` over the stored bytes.
fn legacy_attestation(
    pool: &DbPool,
    key: &DomainKey,
    revoked: bool,
) -> (String, ApplicationKeyAttestation) {
    let instance = common::data_factory::create_application_instance(pool, &HashMap::new());
    let app_key = common::data_factory::create_application_key(pool, &instance.id, &HashMap::new());
    if revoked {
        pool.revoke_application_key(
            &instance.id,
            &app_key.key_id,
            time::OffsetDateTime::now_utc(),
        )
        .unwrap();
    }
    let now = time::OffsetDateTime::now_utc();
    let attestation = ApplicationKeyAttestation {
        subject_user_id: instance.subject_user_id.clone(),
        subject_domain: domain(),
        application_id: instance.application_id.clone(),
        instance_id: instance.instance_id.clone(),
        key_id: app_key.key_id.clone(),
        key_usage: KeyUsage::Sign,
        algorithm: KeyAlgorithm::Ed25519,
        public_key: app_key.public_key.clone(),
        fingerprint: app_key.fingerprint.clone(),
        key_created_at: app_key.created_at,
        key_expires_at: app_key.expires_at,
        attested_at: now,
        attestation_expires_at: now + time::Duration::days(1),
    };
    let old = downgrade_to_v1alpha_text(
        &liblinkkeys::generated::encode_application_key_attestation(&attestation).unwrap(),
    )
    .unwrap();
    let message = liblinkkeys::application_keys::attestation_signature_input(&old);
    let signed = SignedApplicationKeyAttestation {
        attestation: old,
        signatures: vec![sign(key, &message)],
    };
    pool.upsert_application_key_attestation(
        &app_key.id,
        &liblinkkeys::generated::encode_signed_application_key_attestation(&signed).unwrap(),
        attestation.attested_at,
        attestation.attestation_expires_at,
    )
    .unwrap();
    (app_key.id, attestation)
}

#[test]
fn legacy_attestation_is_resigned_and_a_revoked_key_is_not() {
    let pool = common::create_test_pool();
    let keys = three_keys(&pool);
    let (live_id, live) = legacy_attestation(&pool, &keys[0], false);
    let (revoked_id, _) = legacy_attestation(&pool, &keys[0], true);

    let check_only = run(&pool, None).unwrap();
    assert_eq!(check_only.attestations.stale.len(), 1);
    assert_eq!(check_only.attestations.dropped.len(), 1);

    let report = run(&pool, Some(PASSPHRASE)).unwrap();
    assert_eq!(
        report.attestations.resigned.len(),
        1,
        "{:?}",
        report.attestations
    );
    assert_eq!(report.attestations.dropped.len(), 1);
    assert!(report.attestations.is_clean());

    let public: Vec<DomainPublicKey> = pool
        .list_all_domain_keys()
        .unwrap()
        .iter()
        .map(Into::into)
        .collect();
    let stored = pool
        .get_application_key_attestation(&live_id)
        .unwrap()
        .unwrap();
    let found = attestation_provenance(&stored.signed_attestation, &domain(), &public).unwrap();
    assert_eq!(found.provenance, Provenance::Current);
    assert_eq!(found.attestation, live);

    // The revoked key keeps its old record, which no verifier can read.
    let old = pool
        .get_application_key_attestation(&revoked_id)
        .unwrap()
        .unwrap();
    let signed =
        liblinkkeys::generated::decode_signed_application_key_attestation(&old.signed_attestation)
            .unwrap();
    assert!(
        liblinkkeys::generated::decode_application_key_attestation(&signed.attestation).is_err()
    );

    let again = run(&pool, Some(PASSPHRASE)).unwrap();
    assert_eq!(again.attestations.current, 1);
    assert!(again.attestations.resigned.is_empty());
}

#[test]
fn act_as_grants_in_an_older_encoding_are_removed() {
    let pool = common::create_test_pool();
    three_keys(&pool);
    // The data factory stores bytes that are not a current grant.
    let grant = common::data_factory::create_act_as_grant(&pool, &HashMap::new());

    let check_only = run(&pool, None).unwrap();
    assert_eq!(check_only.act_as_grants.stale, vec![grant.grant_id.clone()]);
    assert!(pool.find_act_as_grant(&grant.grant_id).unwrap().is_some());

    let report = run(&pool, Some(PASSPHRASE)).unwrap();
    assert_eq!(report.act_as_grants.dropped, vec![grant.grant_id.clone()]);
    assert!(pool.find_act_as_grant(&grant.grant_id).unwrap().is_none());
    assert!(pool
        .list_audit(10)
        .unwrap()
        .iter()
        .any(|e| e.event == "act_as_grant.dropped"));
}
