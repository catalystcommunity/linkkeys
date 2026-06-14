use liblinkkeys::generated::types::{Claim, ClaimSignature, DomainPublicKey, UserPublicKey};
use std::env;

use crate::db::models::{ClaimRow, ClaimSignatureRow, DomainKey, UserKey};

pub fn get_domain_name() -> String {
    env::var("DOMAIN_NAME").unwrap_or_else(|_| "localhost".to_string())
}

impl From<&DomainKey> for DomainPublicKey {
    fn from(dk: &DomainKey) -> Self {
        DomainPublicKey {
            key_id: dk.id.clone(),
            public_key: dk.public_key.clone(),
            fingerprint: dk.fingerprint.clone(),
            algorithm: dk.algorithm.clone(),
            key_usage: dk.key_usage.clone(),
            created_at: dk.created_at.clone(),
            expires_at: dk.expires_at.clone(),
            revoked_at: dk.revoked_at.clone(),
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
            algorithm: uk.algorithm.clone(),
            key_usage: uk.key_usage.clone(),
            created_at: uk.created_at.clone(),
            expires_at: uk.expires_at.clone(),
            revoked_at: uk.revoked_at.clone(),
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
            created_at: c.created_at.clone(),
            expires_at: c.expires_at.clone(),
            revoked_at: c.revoked_at.clone(),
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
