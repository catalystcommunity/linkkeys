//! Shared helpers for signing claims with a domain's active keys.
//!
//! A claim is signed by *all* currently-active domain keys (>=3 by design) so it
//! carries a quorum of signatures from the issuing domain. Each signature binds
//! the local domain into its payload (see [`liblinkkeys::claims`]) so verifiers
//! can attribute — and key trust on — the signing domain.

use liblinkkeys::claims::{sign_claim, ClaimSigner, ClaimSpec};
use liblinkkeys::crypto::{decrypt_private_key, CryptoError, SigningAlgorithm};
use liblinkkeys::generated::types::Claim;

use crate::conversions::get_domain_name;
use crate::db::models::DomainKey;

/// An active domain signing key with its private key decrypted, ready to sign.
pub struct ActiveSigner {
    pub key_id: String,
    pub algorithm: SigningAlgorithm,
    pub private_key: Vec<u8>,
}

#[derive(Debug)]
pub enum SignerError {
    NoActiveKeys,
    Decrypt(String),
    UnsupportedAlgorithm(String),
    Sign(CryptoError),
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerError::NoActiveKeys => write!(f, "no active domain keys"),
            SignerError::Decrypt(e) => write!(f, "decrypt error: {}", e),
            SignerError::UnsupportedAlgorithm(a) => write!(f, "unsupported algorithm: {}", a),
            SignerError::Sign(e) => write!(f, "sign error: {}", e),
        }
    }
}

impl std::error::Error for SignerError {}

/// Decrypt every active domain key into a signer. Errors if there are none, and
/// warns (but proceeds) if the domain holds fewer than the recommended three.
pub fn active_signers(
    keys: &[DomainKey],
    passphrase: &[u8],
) -> Result<Vec<ActiveSigner>, SignerError> {
    let mut signers = Vec::new();
    for k in keys {
        // Only signing keys can sign claims. A domain's active key set also
        // includes encryption keys (e.g. x25519), which must be skipped — they
        // are not parseable as a SigningAlgorithm and cannot produce signatures.
        if k.key_usage != "sign" {
            continue;
        }
        let private_key = decrypt_private_key(&k.private_key_encrypted, passphrase)
            .map_err(|e| SignerError::Decrypt(e.to_string()))?;
        let algorithm = SigningAlgorithm::parse_str(&k.algorithm)
            .ok_or_else(|| SignerError::UnsupportedAlgorithm(k.algorithm.clone()))?;
        signers.push(ActiveSigner {
            key_id: k.id.clone(),
            algorithm,
            private_key,
        });
    }
    if signers.is_empty() {
        return Err(SignerError::NoActiveKeys);
    }
    if signers.len() < 3 {
        log::warn!(
            "signing claims with only {} active signing key(s); a domain should \
             maintain at least 3 signing keys for redundancy and rotation",
            signers.len()
        );
    }
    Ok(signers)
}

/// Sign `spec` with all `signers`, binding the local domain into each signature.
pub fn sign_with_active(
    spec: &ClaimSpec<'_>,
    signers: &[ActiveSigner],
) -> Result<Claim, SignerError> {
    let domain = get_domain_name();
    let claim_signers: Vec<ClaimSigner> = signers
        .iter()
        .map(|s| ClaimSigner {
            domain: &domain,
            key_id: &s.key_id,
            algorithm: s.algorithm,
            private_key_bytes: &s.private_key,
        })
        .collect();
    sign_claim(spec, &claim_signers).map_err(SignerError::Sign)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::models::DomainKey;
    use liblinkkeys::crypto::{encrypt_private_key, generate_ed25519_keypair};

    fn domain_key(id: &str, usage: &str, algorithm: &str, encrypted: Vec<u8>) -> DomainKey {
        DomainKey {
            id: id.to_string(),
            public_key: vec![],
            private_key_encrypted: encrypted,
            fingerprint: String::new(),
            algorithm: algorithm.to_string(),
            key_usage: usage.to_string(),
            created_at: String::new(),
            expires_at: String::new(),
            revoked_at: None,
            updated_at: String::new(),
            signed_by_key_id: None,
            key_signature: None,
        }
    }

    /// Regression: a domain's active key set includes an x25519 encryption key
    /// alongside the ed25519 signing keys. `active_signers` must sign with the
    /// signing keys only and silently skip the encryption key — not bail out on
    /// the unsupported algorithm (which previously broke set_claim and the
    /// startup re-sign backfill).
    #[test]
    fn active_signers_skips_encryption_keys() {
        let pass = b"test-pass";
        let (_, sk) = generate_ed25519_keypair();
        let encrypted = encrypt_private_key(&sk.to_bytes(), pass).unwrap();

        let keys = vec![
            domain_key("sign-1", "sign", "ed25519", encrypted),
            // Encryption key carries no decryptable signing material and must be
            // skipped before decrypt is ever attempted.
            domain_key("enc-1", "encrypt", "x25519", vec![]),
        ];

        let signers = active_signers(&keys, pass).expect("must succeed using the signing key");
        assert_eq!(signers.len(), 1);
        assert_eq!(signers[0].key_id, "sign-1");
    }

    #[test]
    fn active_signers_errors_when_no_signing_keys() {
        let keys = vec![domain_key("enc-1", "encrypt", "x25519", vec![])];
        assert!(matches!(
            active_signers(&keys, b"pw"),
            Err(SignerError::NoActiveKeys)
        ));
    }
}
