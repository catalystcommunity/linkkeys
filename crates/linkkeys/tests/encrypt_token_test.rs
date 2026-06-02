//! Integration test for `encrypt_token_for_rp`'s self-RP short-circuit:
//! when the RP domain equals our own DOMAIN_NAME, the function reads the
//! active domain keys from the local DB instead of doing a DNS+HTTP
//! round-trip. The output must still be a valid sealed-box that the
//! domain's private key can decrypt.

mod common;

use liblinkkeys::{assertions, crypto, encoding};

const TEST_DOMAIN: &str = "selfrp.test";
const TEST_PASSPHRASE: &[u8] = b"test-passphrase";

#[rocket::async_test]
async fn encrypt_token_for_rp_self_rp_round_trips() {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");

    let pool = common::create_test_pool();

    // Generate the IDP/RP (same instance) signing keypair and persist it.
    let (vk, sk) = crypto::generate_ed25519_keypair();
    let pk_bytes = vk.as_bytes().to_vec();
    let sk_bytes = sk.to_bytes();
    let encrypted_sk = crypto::encrypt_private_key(&sk_bytes, TEST_PASSPHRASE).unwrap();
    let fingerprint = crypto::fingerprint(&pk_bytes);
    let expires = chrono::Utc::now() + chrono::Duration::days(365);
    let domain_key = pool
        .create_domain_key(&pk_bytes, &encrypted_sk, &fingerprint, "ed25519", expires)
        .expect("create_domain_key");

    // Generate the domain's X25519 ENCRYPTION key, vouched by the signing key,
    // and persist it. encrypt_token_for_rp seals to this key (not a converted
    // Ed25519 key).
    let (enc_pub, enc_priv) = crypto::generate_x25519_keypair();
    let enc_fp = crypto::fingerprint(&enc_pub);
    let enc_priv_encrypted = crypto::encrypt_private_key(&enc_priv, TEST_PASSPHRASE).unwrap();
    let enc_expires_str = expires.to_rfc3339();
    let vouch = liblinkkeys::dns::sign_key_vouch(
        &enc_fp,
        &enc_expires_str,
        crypto::SigningAlgorithm::Ed25519,
        &sk_bytes,
    )
    .unwrap();
    pool.create_domain_encryption_key(&enc_pub, &enc_priv_encrypted, &enc_fp, &domain_key.id, &vouch, expires)
        .expect("create_domain_encryption_key");

    // Build and sign an identity assertion the same way the IDP login flow does.
    let user_id = "test-user-id";
    let nonce = "test-nonce";
    let callback = "https://app.example.com/callback";
    let assertion = assertions::build_assertion(
        user_id,
        TEST_DOMAIN,
        callback,
        nonce,
        Some("Test User"),
        300,
    );
    let signed = assertions::sign_assertion(
        &assertion,
        &domain_key.id,
        crypto::SigningAlgorithm::Ed25519,
        &sk_bytes,
    )
    .unwrap();
    let token_param = encoding::assertion_to_url_param(&signed).unwrap();

    // Self-RP path: rp_domain == DOMAIN_NAME, so the DB branch is taken.
    let encrypted = linkkeys::web::encrypt_token_for_rp(&pool, &token_param, TEST_DOMAIN)
        .await
        .expect("encrypt_token_for_rp self-RP path");

    // Decrypt with the domain's X25519 ENCRYPTION private key (used directly,
    // no conversion) and check we recover the original assertion.
    let token = encoding::encrypted_token_from_url_param(&encrypted).unwrap();
    let x25519_priv: [u8; 32] = enc_priv.as_slice().try_into().unwrap();
    let plaintext = crypto::sealed_box_decrypt(
        &token.ephemeral_public_key,
        &token.nonce,
        &token.ciphertext,
        &x25519_priv,
    )
    .expect("sealed_box_decrypt with the domain's own X25519 encryption private key");

    let recovered: liblinkkeys::generated::types::SignedIdentityAssertion =
        ciborium::de::from_reader(plaintext.as_slice()).unwrap();
    let domain_pub = liblinkkeys::generated::types::DomainPublicKey::from(&domain_key);
    let verified = assertions::verify_assertion(&recovered, &[domain_pub]).unwrap();

    assert_eq!(verified.user_id, user_id);
    assert_eq!(verified.domain, TEST_DOMAIN);
    assert_eq!(verified.audience, callback);
    assert_eq!(verified.nonce, nonce);
    assert_eq!(verified.display_name.as_deref(), Some("Test User"));
}
