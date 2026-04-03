use liblinkkeys::generated::types::{Claim, DomainPublicKey, UserPublicKey};
use std::env;

use crate::db::models::{ClaimRow, DomainKey, UserKey};

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
            created_at: dk.created_at.clone(),
            expires_at: dk.expires_at.clone(),
            revoked_at: dk.revoked_at.clone(),
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
            created_at: uk.created_at.clone(),
            expires_at: uk.expires_at.clone(),
            revoked_at: uk.revoked_at.clone(),
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
            signed_by_key_id: c.signed_by_key_id.clone(),
            signature: c.signature.clone(),
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
