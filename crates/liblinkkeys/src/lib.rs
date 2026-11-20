// LINKKEYS-TRUST-CRITICAL: a change to this file needs a trust approval. See docs/trust-change-control.md.
// Trust decisions stay inside Rust's privacy rules: no transmute or raw
// pointer can forge a capability type. Removing this line is a trust change.
#![forbid(unsafe_code)]

pub mod act_as;
pub mod app_access;
pub mod application_keys;
pub mod assertions;
pub mod auth_request;
pub mod claim_policy;
pub mod claims;
pub mod consent;
pub mod crypto;
pub mod dns;
pub mod domain_claims;
pub mod encoding;
pub mod generated;
pub mod i18n;
pub mod identity_input;
#[cfg(any(test, feature = "legacy-formats"))]
pub mod legacy_signatures;
pub mod local_rp;
pub mod revocation;
pub mod signing_request;
pub mod userinfo;
