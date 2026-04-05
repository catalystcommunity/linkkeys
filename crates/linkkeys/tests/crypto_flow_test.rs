//! Integration tests for the full cryptographic flow:
//! auth request signing, assertion signing, token encryption/decryption, verification.

use liblinkkeys::assertions;
use liblinkkeys::auth_request;
use liblinkkeys::crypto;
use liblinkkeys::encoding;
use liblinkkeys::generated::types::{DomainPublicKey, EncryptedToken};

fn make_domain_key(key_id: &str, pk_bytes: &[u8]) -> DomainPublicKey {
    DomainPublicKey {
        key_id: key_id.to_string(),
        public_key: pk_bytes.to_vec(),
        fingerprint: crypto::fingerprint(pk_bytes),
        algorithm: "ed25519".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        revoked_at: None,
    }
}

/// Full end-to-end: RP signs auth request → IDP verifies → IDP signs assertion →
/// IDP encrypts for RP → RP decrypts → RP verifies assertion
#[test]
fn test_full_mutual_auth_flow() {
    // Setup: IDP domain keys
    let (idp_pk, idp_sk) = crypto::generate_keypair(crypto::SigningAlgorithm::Ed25519);
    let idp_key = make_domain_key("idp-key-1", &idp_pk);

    // Setup: RP domain keys
    let (rp_pk, rp_sk) = crypto::generate_keypair(crypto::SigningAlgorithm::Ed25519);
    let rp_key = make_domain_key("rp-key-1", &rp_pk);

    // Step 1: RP signs auth request
    let auth_req = auth_request::build_auth_request(
        "rp.example.com",
        "https://rp.example.com/callback",
        "nonce-12345",
        "rp-key-1",
    );
    let signed_req = auth_request::sign_auth_request(
        &auth_req,
        "rp-key-1",
        crypto::SigningAlgorithm::Ed25519,
        &rp_sk,
    )
    .unwrap();

    // Step 2: IDP verifies auth request
    let verified_req = auth_request::verify_auth_request(&signed_req, &[rp_key.clone()], 300).unwrap();
    assert_eq!(verified_req.relying_party, "rp.example.com");
    assert_eq!(verified_req.callback_url, "https://rp.example.com/callback");
    assert_eq!(verified_req.nonce, "nonce-12345");

    // Step 3: IDP signs identity assertion
    let assertion = assertions::build_assertion(
        "user-uuid-123",
        "idp.example.com",
        "https://rp.example.com/callback",
        "nonce-12345",
        Some("Alice"),
        300,
    );
    let signed_assertion = assertions::sign_assertion(
        &assertion,
        "idp-key-1",
        crypto::SigningAlgorithm::Ed25519,
        &idp_sk,
    )
    .unwrap();

    // Step 4: IDP encrypts the signed assertion for the RP
    let mut assertion_cbor = Vec::new();
    ciborium::ser::into_writer(&signed_assertion, &mut assertion_cbor).unwrap();

    let rp_x25519_pub = crypto::ed25519_public_to_x25519(&rp_pk).unwrap();
    let (ephemeral_pk, nonce, ciphertext) =
        crypto::sealed_box_encrypt(&assertion_cbor, &rp_x25519_pub).unwrap();

    let encrypted_token = EncryptedToken {
        ephemeral_public_key: ephemeral_pk,
        nonce,
        ciphertext,
    };

    // Step 5: Encode token as URL parameter (simulating redirect)
    let token_param = encoding::encrypted_token_to_url_param(&encrypted_token).unwrap();
    assert!(!token_param.is_empty());

    // Step 6: RP decodes and decrypts
    let decoded_token = encoding::encrypted_token_from_url_param(&token_param).unwrap();

    let rp_x25519_priv = crypto::ed25519_private_to_x25519(
        &rp_sk.try_into().map(|a: [u8; 32]| a).unwrap(),
    )
    .unwrap();
    let decrypted = crypto::sealed_box_decrypt(
        &decoded_token.ephemeral_public_key,
        &decoded_token.nonce,
        &decoded_token.ciphertext,
        &rp_x25519_priv,
    )
    .unwrap();

    // Step 7: RP deserializes and verifies the assertion
    let recovered_signed: liblinkkeys::generated::types::SignedIdentityAssertion =
        ciborium::de::from_reader(decrypted.as_slice()).unwrap();
    let verified_assertion =
        assertions::verify_assertion(&recovered_signed, &[idp_key]).unwrap();

    assert_eq!(verified_assertion.user_id, "user-uuid-123");
    assert_eq!(verified_assertion.domain, "idp.example.com");
    assert_eq!(verified_assertion.nonce, "nonce-12345");
    assert_eq!(verified_assertion.display_name.as_deref(), Some("Alice"));
}

/// Verify that a different RP cannot decrypt the token
#[test]
fn test_encrypted_token_wrong_rp_fails() {
    let (rp_pk, _rp_sk) = crypto::generate_keypair(crypto::SigningAlgorithm::Ed25519);
    let (_wrong_pk, wrong_sk) = crypto::generate_keypair(crypto::SigningAlgorithm::Ed25519);

    let plaintext = b"signed assertion cbor bytes";
    let rp_x25519_pub = crypto::ed25519_public_to_x25519(&rp_pk).unwrap();
    let (ephemeral_pk, nonce, ciphertext) =
        crypto::sealed_box_encrypt(plaintext, &rp_x25519_pub).unwrap();

    // Try to decrypt with the wrong RP's key
    let wrong_x25519_priv = crypto::ed25519_private_to_x25519(
        &wrong_sk.try_into().map(|a: [u8; 32]| a).unwrap(),
    )
    .unwrap();
    let result = crypto::sealed_box_decrypt(&ephemeral_pk, &nonce, &ciphertext, &wrong_x25519_priv);
    assert!(result.is_err(), "Wrong RP should not be able to decrypt");
}

/// Verify auth request from wrong RP key is rejected
#[test]
fn test_auth_request_wrong_rp_key_rejected() {
    let (_rp_pk, rp_sk) = crypto::generate_keypair(crypto::SigningAlgorithm::Ed25519);
    let (other_pk, _other_sk) = crypto::generate_keypair(crypto::SigningAlgorithm::Ed25519);
    let other_key = make_domain_key("other-key", &other_pk);

    let auth_req = auth_request::build_auth_request(
        "rp.example.com",
        "https://rp.example.com/callback",
        "nonce",
        "rp-key-1",
    );
    let signed_req = auth_request::sign_auth_request(
        &auth_req,
        "rp-key-1",
        crypto::SigningAlgorithm::Ed25519,
        &rp_sk,
    )
    .unwrap();

    // Verify against a different key — should fail (key not found)
    let result = auth_request::verify_auth_request(&signed_req, &[other_key], 300);
    assert!(result.is_err());
}
