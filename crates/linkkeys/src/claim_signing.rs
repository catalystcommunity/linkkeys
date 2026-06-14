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
    if keys.is_empty() {
        return Err(SignerError::NoActiveKeys);
    }
    let mut signers = Vec::with_capacity(keys.len());
    for k in keys {
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
    if signers.len() < 3 {
        log::warn!(
            "signing claims with only {} active domain key(s); a domain should \
             maintain at least 3 keys for redundancy and rotation",
            signers.len()
        );
    }
    Ok(signers)
}

/// Sign `spec` with all `signers`, binding the local domain into each signature.
pub fn sign_with_active(spec: &ClaimSpec<'_>, signers: &[ActiveSigner]) -> Result<Claim, SignerError> {
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
