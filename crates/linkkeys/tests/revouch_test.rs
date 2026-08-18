//! Tests for `revouch_encryption_keys`: the repair for the vouch-tag epoch
//! break (0.14.1 renamed `KEY_VOUCH_TAG` from `-v1` to `-v1alpha`, so every
//! earlier vouch stopped verifying and cross-domain logins failed at the
//! encryption step). The repair re-signs a stale vouch with an active signing
//! key under the current tag; vouches that already verify are left untouched.

mod common;

use liblinkkeys::crypto;
use liblinkkeys::generated::types::DomainPublicKey;
use linkkeys::db::models::DomainKey;
use linkkeys::db::DbPool;
use linkkeys::services::domain_keys::{revouch_encryption_keys, RevouchOutcome};

const TEST_PASSPHRASE: &str = "test-passphrase";

/// Sign a vouch payload under an arbitrary (e.g. superseded) tag. Mirrors
/// `liblinkkeys::dns::key_vouch_payload`, whose tag is a private constant —
/// exactly the property that made old vouches unverifiable.
fn sign_vouch_with_tag(tag: &str, fp: &str, expires_at: &str, sk: &[u8]) -> Vec<u8> {
    let payload = (tag, fp, expires_at);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&payload, &mut bytes).unwrap();
    crypto::sign_with_algorithm(crypto::SigningAlgorithm::Ed25519, &bytes, sk).unwrap()
}

/// Create a signing key plus an encryption key whose stored vouch was signed
/// under `tag`. Returns (signing key, encryption key id).
fn setup_keys(pool: &DbPool, tag: &str) -> (DomainKey, String) {
    let signing_key = common::data_factory::create_domain_key(pool);
    let sk_bytes = crypto::decrypt_private_key(
        &signing_key.private_key_encrypted,
        TEST_PASSPHRASE.as_bytes(),
    )
    .unwrap();

    let (enc_pub, enc_priv) = crypto::generate_x25519_keypair();
    let enc_fp = crypto::fingerprint(&enc_pub);
    let enc_priv_encrypted =
        crypto::encrypt_private_key(&enc_priv, TEST_PASSPHRASE.as_bytes()).unwrap();
    use chrono::Timelike;
    let expires = (chrono::Utc::now() + chrono::Duration::days(365))
        .with_nanosecond(0)
        .unwrap();
    let vouch = sign_vouch_with_tag(tag, &enc_fp, &expires.to_rfc3339(), &sk_bytes);
    let enc_key = pool
        .create_domain_encryption_key(
            &enc_pub,
            &enc_priv_encrypted,
            &enc_fp,
            &signing_key.id,
            &vouch,
            expires,
        )
        .expect("create encryption key");
    (signing_key, enc_key.id)
}

fn vouch_verifies(pool: &DbPool, enc_key_id: &str) -> bool {
    let keys = pool.list_all_domain_keys().unwrap();
    let enc = keys.iter().find(|k| k.id == enc_key_id).unwrap();
    let signer_id = enc.signed_by_key_id.clone().expect("vouch signer set");
    let signer = keys.iter().find(|k| k.id == signer_id).unwrap();
    let enc_pub: DomainPublicKey = enc.into();
    let signer_pub: DomainPublicKey = signer.into();
    liblinkkeys::dns::verify_key_vouch(&enc_pub, &signer_pub)
}

/// A vouch signed under the pre-0.14.1 tag fails verification, is re-signed by
/// the repair, verifies afterwards, and a second run changes nothing.
#[test]
fn revouch_repairs_old_tag_vouch_and_is_idempotent() {
    let pool = common::create_test_pool();
    let (_signing_key, enc_key_id) = setup_keys(&pool, "linkkeys-key-vouch-v1");

    assert!(
        !vouch_verifies(&pool, &enc_key_id),
        "an old-tag vouch must fail under the current tag (else this test is vacuous)"
    );

    let results = revouch_encryption_keys(&pool, TEST_PASSPHRASE).expect("revouch");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, enc_key_id);
    assert!(
        matches!(results[0].1, RevouchOutcome::Revouched { .. }),
        "a failing vouch must be re-signed, got {:?}",
        results[0].1
    );
    assert!(
        vouch_verifies(&pool, &enc_key_id),
        "the stored vouch must verify under the current tag after the repair"
    );

    // Second run: already valid, and the stored signature is untouched.
    let sig_after_repair = pool
        .list_all_domain_keys()
        .unwrap()
        .into_iter()
        .find(|k| k.id == enc_key_id)
        .unwrap()
        .key_signature;
    let results = revouch_encryption_keys(&pool, TEST_PASSPHRASE).expect("revouch again");
    assert_eq!(results[0].1, RevouchOutcome::AlreadyValid);
    let sig_after_second = pool
        .list_all_domain_keys()
        .unwrap()
        .into_iter()
        .find(|k| k.id == enc_key_id)
        .unwrap()
        .key_signature;
    assert_eq!(
        sig_after_repair, sig_after_second,
        "a valid vouch must never be re-signed"
    );
}

/// A vouch already signed under the current tag is reported valid and left
/// untouched on the first pass.
#[test]
fn revouch_leaves_current_tag_vouch_untouched() {
    let pool = common::create_test_pool();
    let signing_key = common::data_factory::create_domain_key(&pool);
    let (enc_pub, _enc_priv) =
        common::data_factory::create_domain_encryption_key(&pool, &signing_key);
    let enc_fp = crypto::fingerprint(&enc_pub);

    let results = revouch_encryption_keys(&pool, TEST_PASSPHRASE).expect("revouch");
    let keys = pool.list_all_domain_keys().unwrap();
    let enc = keys.iter().find(|k| k.fingerprint == enc_fp).unwrap();
    let outcome = &results.iter().find(|(id, _)| *id == enc.id).unwrap().1;
    assert_eq!(*outcome, RevouchOutcome::AlreadyValid);
}

/// A revoked encryption key is skipped: it is not re-vouched (peers must not
/// re-trust it) and does not fail the pass.
#[test]
fn revouch_skips_revoked_encryption_keys() {
    let pool = common::create_test_pool();
    let (_signing_key, enc_key_id) = setup_keys(&pool, "linkkeys-key-vouch-v1");
    pool.revoke_domain_key(&enc_key_id).expect("revoke");

    let results = revouch_encryption_keys(&pool, TEST_PASSPHRASE).expect("revouch");
    assert!(
        results.iter().all(|(id, _)| *id != enc_key_id),
        "a revoked encryption key must not appear in the re-vouch pass"
    );
}
