//! Relying-party claim requirements.
//!
//! When this server acts as a relying party (initiating a login at some IDP),
//! it advertises which claims it wants released, with the datatype it expects
//! each value to carry. That set is operator configuration, loaded from a TOML
//! file pointed to by `RP_CLAIMS_CONFIG`. Absent or empty => request nothing
//! (authentication only), preserving the pre-consent behavior.
//!
//! Example `rp-claims.toml`:
//! ```toml
//! [[required]]
//! claim_type = "email"
//! datatype   = "email"
//!
//! [[optional]]
//! claim_type = "display_name"
//! datatype   = "text"
//!
//! [[optional]]
//! claim_type = "avatar"
//! datatype   = "url"
//! ```

use liblinkkeys::generated::types::{ClaimRequest, DomainClaim, RequestedClaim};
use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RpClaimsConfig {
    #[serde(default)]
    pub required: Vec<RpClaim>,
    #[serde(default)]
    pub optional: Vec<RpClaim>,
    /// Claims the RP asserts ABOUT ITSELF, self-signed with the RP's own domain
    /// key at request time (e.g. a named privacy policy it agrees to). Values
    /// are UTF-8 strings; meaning is by `claim_type` convention.
    #[serde(default)]
    pub self_claims: Vec<RpSelfClaim>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RpClaim {
    pub claim_type: String,
    pub datatype: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RpSelfClaim {
    pub claim_type: String,
    pub value: String,
}

impl RpClaimsConfig {
    /// Load from the path in `RP_CLAIMS_CONFIG`. A missing variable yields the
    /// empty config; a present-but-unreadable/invalid file logs a warning and
    /// also yields empty (the RP simply requests nothing rather than failing to
    /// boot).
    pub fn load_from_env() -> Self {
        match env::var("RP_CLAIMS_CONFIG") {
            Ok(path) if !path.is_empty() => Self::load_from_path(&path).unwrap_or_else(|e| {
                log::warn!(
                    "RP_CLAIMS_CONFIG at {} could not be loaded ({}); requesting no claims",
                    path,
                    e
                );
                Self::default()
            }),
            _ => Self::default(),
        }
    }

    pub fn load_from_path(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        toml::from_str(&text).map_err(|e| e.to_string())
    }

    /// As a protocol `ClaimRequest`, or `None` when nothing is configured.
    pub fn to_claim_request(&self) -> Option<ClaimRequest> {
        if self.required.is_empty() && self.optional.is_empty() {
            return None;
        }
        Some(ClaimRequest {
            required: self.required.iter().map(RpClaim::to_requested).collect(),
            optional: self.optional.iter().map(RpClaim::to_requested).collect(),
        })
    }
}

impl RpClaim {
    fn to_requested(&self) -> RequestedClaim {
        RequestedClaim {
            claim_type: self.claim_type.clone(),
            datatype: self.datatype.clone(),
        }
    }
}

/// Load pre-signed third-party domain claims about this RP from the file in
/// `RP_DOMAIN_CLAIMS_SIGNED` (one base64url(CBOR(DomainClaim)) per non-empty
/// line). These carry their own third-party signatures (e.g. a `us.gov`-signed
/// `government_entity` claim) and are attached verbatim — the RP does not hold
/// the signer's key. Missing variable or unreadable file => empty (logged).
pub fn load_signed_domain_claims() -> Vec<DomainClaim> {
    use base64ct::{Base64UrlUnpadded, Encoding as _};

    let path = match env::var("RP_DOMAIN_CLAIMS_SIGNED") {
        Ok(p) if !p.is_empty() => p,
        _ => return Vec::new(),
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            log::warn!(
                "RP_DOMAIN_CLAIMS_SIGNED at {} unreadable ({}); ignoring",
                path,
                e
            );
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(cbor) = Base64UrlUnpadded::decode_vec(line) else {
            log::warn!(
                "RP_DOMAIN_CLAIMS_SIGNED line {} is not valid base64url; skipping",
                i + 1
            );
            continue;
        };
        match ciborium::de::from_reader::<DomainClaim, _>(&cbor[..]) {
            Ok(claim) => out.push(claim),
            Err(e) => log::warn!(
                "RP_DOMAIN_CLAIMS_SIGNED line {} is not a DomainClaim ({}); skipping",
                i + 1,
                e
            ),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_requests_nothing() {
        assert!(RpClaimsConfig::default().to_claim_request().is_none());
    }

    #[test]
    fn parses_required_and_optional_with_datatypes() {
        let toml = r#"
            [[required]]
            claim_type = "email"
            datatype = "email"

            [[optional]]
            claim_type = "display_name"
            datatype = "text"
        "#;
        let cfg: RpClaimsConfig = toml::from_str(toml).unwrap();
        let req = cfg.to_claim_request().unwrap();
        assert_eq!(req.required.len(), 1);
        assert_eq!(req.required[0].claim_type, "email");
        assert_eq!(req.required[0].datatype, "email");
        assert_eq!(req.optional[0].claim_type, "display_name");
    }

    #[test]
    fn parses_self_claims() {
        let toml = r#"
            [[self_claims]]
            claim_type = "privacy_policy"
            value = "GDPR-strict-v1"
        "#;
        let cfg: RpClaimsConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.self_claims.len(), 1);
        assert_eq!(cfg.self_claims[0].claim_type, "privacy_policy");
        assert_eq!(cfg.self_claims[0].value, "GDPR-strict-v1");
        // self_claims alone don't make a ClaimRequest (no user claims requested).
        assert!(cfg.to_claim_request().is_none());
    }
}
