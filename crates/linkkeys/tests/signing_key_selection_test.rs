//! Regression test: signing paths must never select the X25519 encryption key.
//!
//! Once a domain has an encryption key (required for sealed-box token delivery),
//! the auth-request signer (`rp::sign_request_json`) and the assertion signer
//! (`web::sign_assertion_for_user`) used to pick a key at random from *all*
//! active keys. Landing on the encryption key made
//! `SigningAlgorithm::parse_str("x25519")` return `None` → 500, intermittently.
//! Both now route through `web::pick_active_signing_key`, which filters to
//! signing keys; this test guards that invariant at the shared choke point.

mod common;

use chrono::{Duration, Utc};
use liblinkkeys::crypto::{self, SigningAlgorithm};
use linkkeys::web::pick_active_signing_key;

const TEST_PASSPHRASE: &[u8] = b"test-passphrase";

/// Persist a signing key; returns its id and raw private bytes (for vouching).
fn add_signing_key(pool: &linkkeys::db::DbPool) -> (String, Vec<u8>) {
    let (vk, sk) = crypto::generate_ed25519_keypair();
    let pk = vk.as_bytes().to_vec();
    let sk_bytes = sk.to_bytes().to_vec();
    let encrypted = crypto::encrypt_private_key(&sk_bytes, TEST_PASSPHRASE).unwrap();
    let fp = crypto::fingerprint(&pk);
    let expires = Utc::now() + Duration::days(365);
    let dk = pool
        .create_domain_key(&pk, &encrypted, &fp, "ed25519", expires)
        .expect("create_domain_key");
    (dk.id, sk_bytes)
}

/// Persist an X25519 encryption key vouched by the given signing key — the
/// "trap" a signing path must never select.
fn add_encryption_key(pool: &linkkeys::db::DbPool, signer_id: &str, signer_sk: &[u8]) {
    let (enc_pub, enc_priv) = crypto::generate_x25519_keypair();
    let enc_fp = crypto::fingerprint(&enc_pub);
    let enc_priv_encrypted = crypto::encrypt_private_key(&enc_priv, TEST_PASSPHRASE).unwrap();
    let expires = Utc::now() + Duration::days(365);
    let vouch = liblinkkeys::dns::sign_key_vouch(
        &enc_fp,
        &expires.to_rfc3339(),
        SigningAlgorithm::Ed25519,
        signer_sk,
    )
    .unwrap();
    pool.create_domain_encryption_key(
        &enc_pub,
        &enc_priv_encrypted,
        &enc_fp,
        signer_id,
        &vouch,
        expires,
    )
    .expect("create_domain_encryption_key");
}

#[test]
fn pick_active_signing_key_never_returns_encryption_key() {
    let pool = common::create_test_pool();

    // The real post-split key set: 3 signing keys + 1 encryption key.
    let (signer_id, signer_sk) = add_signing_key(&pool);
    add_signing_key(&pool);
    add_signing_key(&pool);
    add_encryption_key(&pool, &signer_id, &signer_sk);

    let keys = pool.list_active_domain_keys().expect("list keys");
    assert_eq!(
        keys.iter().filter(|k| k.key_usage == "encrypt").count(),
        1,
        "fixture must contain the encryption trap key"
    );
    assert!(
        keys.iter().filter(|k| k.key_usage == "sign").count() >= 3,
        "fixture must contain multiple signing keys so the random pick is exercised"
    );

    // Hammer the random selection: the encryption key must never be chosen.
    // Pre-fix this fails with overwhelming probability (1/4 per draw).
    for _ in 0..512 {
        let k = pick_active_signing_key(&keys).expect("a signing key is available");
        assert_eq!(
            k.key_usage, "sign",
            "a signing path selected an encryption key"
        );
    }
}

#[test]
fn pick_active_signing_key_fails_closed_without_signing_keys() {
    let pool = common::create_test_pool();
    let (signer_id, signer_sk) = add_signing_key(&pool);
    add_encryption_key(&pool, &signer_id, &signer_sk);

    // A key set with only an encryption key (no signing key) yields None, so
    // callers fail closed instead of signing with the wrong key.
    let only_encryption: Vec<_> = pool
        .list_active_domain_keys()
        .expect("list keys")
        .into_iter()
        .filter(|k| k.key_usage == "encrypt")
        .collect();
    assert!(pick_active_signing_key(&only_encryption).is_none());
    assert!(pick_active_signing_key(&[]).is_none());
}
