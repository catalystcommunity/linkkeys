use liblinkkeys::generated::types::{
    Claim, ClaimSignature, DomainPublicKey, KeyAlgorithm, KeyUsage, Profile as GeneratedProfile,
    UserPublicKey,
};
use std::env;

use crate::db::models::{ClaimRow, ClaimSignatureRow, DomainKey, Profile, UserKey};

pub fn get_domain_name() -> String {
    env::var("DOMAIN_NAME").unwrap_or_else(|_| "localhost".to_string())
}

/// A stored text label as a CSIL enum value. A label this server does not
/// know is logged and reads as `fallback`; each caller picks the value that
/// fails closed for its use.
pub fn stored_label<T>(what: &str, label: &str, parse: fn(&str) -> Option<T>, fallback: T) -> T {
    parse(label).unwrap_or_else(|| {
        log::error!("stored {what} {label:?} is not known");
        fallback
    })
}

/// The key use stored in a key row (`sign`, `encrypt`, `agree`). A label this
/// server does not know reads as `encrypt`: such a key can never sign or
/// verify a signature, so a corrupt row fails closed.
pub fn stored_key_usage(label: &str) -> KeyUsage {
    KeyUsage::from_label(label).unwrap_or_else(|| {
        log::error!("stored key use {label:?} is not known; treating the key as encrypt-only");
        KeyUsage::Encrypt
    })
}

/// The algorithm stored in a key row. A label this server does not know reads
/// as `x25519`, which cannot sign or verify, so a corrupt row fails closed.
pub fn stored_key_algorithm(label: &str) -> KeyAlgorithm {
    KeyAlgorithm::from_label(label).unwrap_or_else(|| {
        log::error!("stored key algorithm {label:?} is not known; treating it as x25519");
        KeyAlgorithm::X25519
    })
}

/// The signing algorithm of a stored key row, or None when the stored
/// algorithm cannot sign or is not known.
pub fn stored_signing_algorithm(label: &str) -> Option<liblinkkeys::crypto::SigningAlgorithm> {
    liblinkkeys::crypto::SigningAlgorithm::from_key_algorithm(&KeyAlgorithm::from_label(label)?)
}

impl From<&DomainKey> for DomainPublicKey {
    fn from(dk: &DomainKey) -> Self {
        DomainPublicKey {
            key_id: dk.id.clone(),
            public_key: dk.public_key.clone(),
            fingerprint: dk.fingerprint.clone(),
            algorithm: stored_key_algorithm(&dk.algorithm),
            key_usage: stored_key_usage(&dk.key_usage),
            created_at: dk.created_at,
            expires_at: dk.expires_at,
            revoked_at: dk.revoked_at,
            signed_by_key_id: dk.signed_by_key_id.clone(),
            key_signature: dk.key_signature.clone(),
        }
    }
}

impl From<&UserKey> for UserPublicKey {
    fn from(uk: &UserKey) -> Self {
        UserPublicKey {
            key_id: uk.id.clone(),
            user_id: uk.user_id.clone(),
            public_key: uk.public_key.clone(),
            fingerprint: uk.fingerprint.clone(),
            algorithm: stored_key_algorithm(&uk.algorithm),
            key_usage: stored_key_usage(&uk.key_usage),
            created_at: uk.created_at,
            expires_at: uk.expires_at,
            revoked_at: uk.revoked_at,
            signed_by_key_id: uk.signed_by_key_id.clone(),
            key_signature: uk.key_signature.clone(),
        }
    }
}

impl From<&ClaimSignatureRow> for ClaimSignature {
    fn from(s: &ClaimSignatureRow) -> Self {
        ClaimSignature {
            domain: s.domain.clone(),
            signed_by_key_id: s.signed_by_key_id.clone(),
            signature: s.signature.clone(),
        }
    }
}

impl From<&ClaimRow> for Claim {
    fn from(c: &ClaimRow) -> Self {
        Claim {
            claim_id: c.id.clone(),
            user_id: c.user_id.clone(),
            claim_type: c.claim_type.clone(),
            claim_value: c.claim_value.clone(),
            signatures: c.signatures.iter().map(Into::into).collect(),
            attested_at: c.attested_at,
            created_at: c.created_at,
            expires_at: c.expires_at,
            revoked_at: c.revoked_at,
        }
    }
}

impl From<&Profile> for GeneratedProfile {
    fn from(p: &Profile) -> Self {
        GeneratedProfile {
            id: p.id.clone(),
            account_id: p.account_id.clone(),
            domain: p.domain.clone(),
            is_root: p.is_root,
            label: p.label.clone(),
        }
    }
}

pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
