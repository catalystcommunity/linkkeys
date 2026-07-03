//! SEC-08 inter-domain revocation exchange: issuer persists a sibling-signed
//! cert, signals it, serves it; a verifier applies it to a cached peer key at the
//! domain's asserted `revoked_at`. Also checks that two active-key revocations at
//! once raise a human review.

mod common;

use common::data_factory::create_domain_key;
use liblinkkeys::claims::ClaimSigner;
use liblinkkeys::generated::types::DomainPublicKey;
use liblinkkeys::revocation::{
    build_revocation_certificate, RevocationCertificate, RevocationSpec,
};
use linkkeys::db::models::{DomainKey, PeerKey};
use linkkeys::services::revocations;

/// Build a cert revoking `target`, signed by every active signing key except the
/// target.
fn cert_for(
    pool: &linkkeys::db::DbPool,
    domain: &str,
    target: &DomainKey,
) -> RevocationCertificate {
    let signer_keys: Vec<_> = pool
        .list_active_domain_keys()
        .unwrap()
        .into_iter()
        .filter(|k| k.id != target.id && k.key_usage == "sign")
        .collect();
    let active = linkkeys::claim_signing::active_signers(&signer_keys, b"test-passphrase").unwrap();
    let signers: Vec<ClaimSigner> = active
        .iter()
        .map(|s| ClaimSigner {
            domain,
            key_id: &s.key_id,
            algorithm: s.algorithm,
            private_key_bytes: &s.private_key,
        })
        .collect();
    // If the target is still active in the DB it has no revoked_at, so stamp now.
    let revoked_at = target
        .revoked_at
        .clone()
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    build_revocation_certificate(
        &RevocationSpec {
            target_key_id: &target.id,
            target_fingerprint: &target.fingerprint,
            revoked_at: &revoked_at,
        },
        &signers,
    )
    .unwrap()
}

#[test]
fn issue_signal_serve_and_apply_roundtrip() {
    let pool = common::create_test_pool();
    let domain = "issuer.test";

    create_domain_key(&pool);
    create_domain_key(&pool);
    let target = create_domain_key(&pool);
    let revoked = pool.revoke_domain_key(&target.id).unwrap();
    let revoked_at = revoked.revoked_at.clone().unwrap();

    let cert = cert_for(&pool, domain, &revoked);
    let cbor = liblinkkeys::generated::encode_revocation_certificate(&cert);
    let when = chrono::DateTime::parse_from_rfc3339(&revoked_at)
        .unwrap()
        .with_timezone(&chrono::Utc);
    pool.insert_issued_revocation(&revoked.id, &revoked.fingerprint, when, &cbor)
        .unwrap();

    // Signal on, and serve returns the cert.
    assert!(revocations::recent_revocations_available(&pool));
    let served = revocations::serve(&pool, None);
    assert_eq!(served.len(), 1);
    assert_eq!(served[0], cert);

    // Verifier had the (now-revoked) key cached as a peer key.
    pool.cache_peer_key(&PeerKey {
        domain: domain.to_string(),
        key_id: revoked.id.clone(),
        public_key: target.public_key.clone(),
        algorithm: "ed25519".to_string(),
        fingerprint: revoked.fingerprint.clone(),
        key_usage: "sign".to_string(),
        expires_at: (chrono::Utc::now() + chrono::Duration::days(365)).to_rfc3339(),
        revoked_at: None,
    })
    .unwrap();

    // Apply: verify against the domain's current (sibling) key set.
    let active: Vec<DomainPublicKey> = pool
        .list_active_domain_keys()
        .unwrap()
        .iter()
        .map(Into::into)
        .collect();
    let revoked_ids = revocations::apply(&pool, domain, &active, &served);
    assert!(revoked_ids.contains(&revoked.id));

    // The cached peer key now carries the DOMAIN'S asserted revoked_at, not now.
    let cached = pool.list_peer_keys_for_domain(domain).unwrap();
    let row = cached.iter().find(|k| k.key_id == revoked.id).unwrap();
    assert_eq!(row.revoked_at.as_deref(), Some(revoked_at.as_str()));
}

#[test]
fn two_active_key_revocations_trigger_human_review() {
    let pool = common::create_test_pool();
    let domain = "issuer.test";

    // Four active keys so two independent quorum-2 certs can exist at once.
    let a = create_domain_key(&pool);
    let b = create_domain_key(&pool);
    create_domain_key(&pool);
    create_domain_key(&pool);

    // Certs revoking two currently-ACTIVE keys (not DB-revoked, so both remain in
    // the active set) — the anomalous "2 at once" case.
    let certs = vec![cert_for(&pool, domain, &a), cert_for(&pool, domain, &b)];
    let active: Vec<DomainPublicKey> = pool
        .list_active_domain_keys()
        .unwrap()
        .iter()
        .map(Into::into)
        .collect();

    let revoked_ids = revocations::apply(&pool, domain, &active, &certs);
    assert_eq!(revoked_ids.len(), 2);

    let reviews = pool.list_pending_reviews("key_mismatch").unwrap();
    assert!(
        reviews.iter().any(|r| r.subject.as_deref() == Some(domain)),
        "a human-review item was enqueued for the mass revocation"
    );
}
