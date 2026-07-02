//! SEC-08: the server-side sibling-signed revocation certificate path — real
//! DB-encrypted sibling keys are decrypted, co-sign a revocation, and the
//! certificate verifies against the domain's published key set.

mod common;

use common::data_factory::create_domain_key;
use liblinkkeys::claims::ClaimSigner;
use liblinkkeys::revocation::{
    build_revocation_certificate, verify_revocation_certificate, RevocationSpec,
};

#[test]
fn siblings_produce_and_verify_a_revocation_certificate() {
    let pool = common::create_test_pool();
    let domain = "rev.test";

    // Three signing keys; one will be revoked, the other two co-sign.
    create_domain_key(&pool);
    create_domain_key(&pool);
    let target = create_domain_key(&pool);

    let revoked = pool.revoke_domain_key(&target.id).unwrap();

    // Build signers from the remaining active signing keys (target excluded).
    let signer_keys: Vec<_> = pool
        .list_active_domain_keys()
        .unwrap()
        .into_iter()
        .filter(|k| k.id != revoked.id && k.key_usage == "sign")
        .collect();
    let active_signers =
        linkkeys::claim_signing::active_signers(&signer_keys, b"test-passphrase").unwrap();
    assert!(active_signers.len() >= 2, "at least two siblings remain");

    let signers: Vec<ClaimSigner> = active_signers
        .iter()
        .map(|s| ClaimSigner {
            domain,
            key_id: &s.key_id,
            algorithm: s.algorithm,
            private_key_bytes: &s.private_key,
        })
        .collect();

    let revoked_at = revoked.revoked_at.clone().unwrap();
    let cert = build_revocation_certificate(
        &RevocationSpec {
            target_key_id: &revoked.id,
            target_fingerprint: &revoked.fingerprint,
            revoked_at: &revoked_at,
        },
        &signers,
    )
    .unwrap();

    // The certificate verifies against the domain's full published key set.
    let pubkeys: Vec<liblinkkeys::generated::types::DomainPublicKey> = pool
        .list_all_domain_keys()
        .unwrap()
        .iter()
        .map(Into::into)
        .collect();
    assert!(verify_revocation_certificate(&cert, &pubkeys, domain).is_ok());

    // A single signature would not have been enough.
    let one = build_revocation_certificate(
        &RevocationSpec {
            target_key_id: &revoked.id,
            target_fingerprint: &revoked.fingerprint,
            revoked_at: &revoked_at,
        },
        &signers[..1],
    )
    .unwrap();
    assert!(verify_revocation_certificate(&one, &pubkeys, domain).is_err());
}
