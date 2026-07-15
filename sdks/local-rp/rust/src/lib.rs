//! # linkkeys-local-rp
//!
//! Rust SDK for LinkKeys' DNS-less local RP identity mode
//! (`dns-less-local-rp-design.md` at the repo root — read it first; this
//! crate implements its "SDK API Shape" section verbatim, Rust-idiomatically
//! adapted).
//!
//! This mode lets a locally-installed app (a LAN jukebox, a desktop tool, a
//! self-hosted service with no public DNS) use LinkKeys for login without
//! running its own DNS-pinned relying party. The app's identity is the
//! fingerprint of a locally-generated signing key (SSH-host-key style), not
//! a domain.
//!
//! ## Quickstart
//!
//! ```no_run
//! use chrono::Utc;
//! use linkkeys_local_rp::{
//!     generate_local_rp_identity, begin_local_login, complete_local_login,
//!     GenerateLocalRpIdentityConfig, BeginLocalLoginConfig, CompleteLocalLoginConfig,
//!     local_rp_identity_to_bytes, local_rp_identity_from_bytes,
//! };
//!
//! // Once, at install/setup time — persist the returned bytes with ordinary
//! // application-secret care (see `identity` module docs).
//! let identity = generate_local_rp_identity(
//!     GenerateLocalRpIdentityConfig::new("My LAN Jukebox", Utc::now()),
//! ).unwrap();
//! let stored_bytes = local_rp_identity_to_bytes(&identity);
//!
//! // Later, per login attempt:
//! let identity = local_rp_identity_from_bytes(&stored_bytes).unwrap();
//! let (redirect, pending) = begin_local_login(BeginLocalLoginConfig::new(
//!     &identity,
//!     "http://jukebox.lan:8080/auth/callback",
//!     "example.com",
//!     Utc::now(),
//! )).unwrap();
//! // App: persist `pending` (e.g. in a server-side session), then redirect
//! // the browser to `redirect.redirect_url`.
//!
//! // On callback (app's HTTP handler received `arrived_url` with an
//! // `encrypted_token=` query parameter whose value is `encrypted_token`):
//! # let encrypted_token = "";
//! # let arrived_url = "";
//! let verified = complete_local_login(CompleteLocalLoginConfig::new(
//!     &identity,
//!     &pending,
//!     encrypted_token,
//!     arrived_url,
//!     Utc::now(),
//! ));
//! // `verified` carries user id/domain, claims, domain keys used, the local
//! // RP fingerprint, and expirations — session creation, local user
//! // records, and authorization are all the app's own responsibility.
//! ```
//!
//! ## Storage and single-use responsibilities this SDK assigns to the app
//!
//! - **Key material**: persist the bytes from [`local_rp_identity_to_bytes`]
//!   with ordinary application-secret care (same tier as a database
//!   credential or API key) — see `identity` module docs.
//! - **`PendingLogin`**: persist it (it derives `Serialize`/`Deserialize`)
//!   between `begin_local_login` and `complete_local_login`, and discard it
//!   after one completion attempt. This crate owns no storage and cannot
//!   enforce single-use itself.
//! - **Sessions, local user records, authorization**: entirely the app's.
//!   This crate returns verified protocol facts; it never creates a session
//!   or writes to an app database (design doc: "SDKs must not own
//!   application storage, sessions, database writes, or local user
//!   authorization").
//!
//! ## Security notes
//!
//! - Revoking this local RP identity at the IDP kills future logins AND any
//!   outstanding claim tickets immediately (redemption re-checks approval
//!   status every time) — but it does **not** reach into sessions the app
//!   already minted from a prior successful login. Session lifecycle is the
//!   app's to manage.
//! - Key rotation is not supported as a continuity operation: generating a
//!   new identity means a new fingerprint and re-approval at every LinkKeys
//!   domain. There is no "same app, new key" story in this protocol version.
//! - Domain keys and revocations fetched over the network are only ever
//!   trusted after DNS `fp=` pinning (`crate::rpc`) — an unpinned/unauthenticated
//!   key can never reach the verification chain.
//! - The default DNS resolver is the OS-configured system resolver; LAN
//!   resolver spoofing is an accepted, documented tradeoff for this mode
//!   (matching the design doc's "Decided" section). Inject a hardened
//!   [`DnsResolver`] if your deployment needs more.

pub mod begin;
pub mod complete;
pub mod dns;
pub mod error;
pub mod identity;
pub mod rpc;
pub mod transport;

pub use begin::{
    begin_local_login, BeginLocalLoginConfig, LocalLoginRedirect, PendingLogin,
    DEFAULT_LOGIN_REQUEST_LIFETIME, DEFAULT_REQUESTED_CLAIMS, DEFAULT_REQUIRED_CLAIMS,
};
pub use complete::{complete_local_login, CompleteLocalLoginConfig, VerifiedLocalLogin};
pub use dns::DnsResolver;
pub use error::Error;
pub use identity::{
    encryption_key_from_bytes, encryption_key_to_bytes, fingerprint_from_string,
    fingerprint_to_string, generate_local_rp_identity, local_rp_identity_from_bytes,
    local_rp_identity_to_bytes, signing_key_from_bytes, signing_key_to_bytes,
    GenerateLocalRpIdentityConfig, LocalRpKeyMaterial, DEFAULT_LIFETIME,
};
pub use transport::{AddressPolicy, StdTransport, Transport};

// Re-exported so app code doesn't need a direct `liblinkkeys` dependency just
// to name these types.
pub use liblinkkeys::generated::types::{Claim, ClaimSignature, DomainPublicKey};
pub use liblinkkeys::local_rp::{ExpirationLevel, ExpirationStatus};

use std::sync::OnceLock;

static DEFAULT_TRANSPORT: OnceLock<StdTransport> = OnceLock::new();
static DEFAULT_DNS_RESOLVER: OnceLock<dns::SystemDnsResolver> = OnceLock::new();

/// The default [`Transport`]: a permissive-by-default blocking `TcpStream`
/// dialer (see `transport` module docs for why permissive is the correct
/// default here). Memoized for the process lifetime.
pub fn default_transport() -> &'static dyn Transport {
    DEFAULT_TRANSPORT.get_or_init(StdTransport::default)
}

/// The default [`DnsResolver`]: the OS-configured system resolver. Memoized
/// for the process lifetime.
pub fn default_dns_resolver() -> &'static dyn DnsResolver {
    DEFAULT_DNS_RESOLVER.get_or_init(dns::SystemDnsResolver::new)
}

/// `check_expirations(identity, now) -> ExpirationStatus` (design doc, "SDK
/// API Shape" / "Expiration Helper"). Thin re-export of
/// `liblinkkeys::local_rp::check_expirations`, taking the identity's
/// descriptor `expires_at` directly. The SDK reports facts; the app decides
/// whether to warn admins, warn users, block login, renew, or ignore.
pub fn check_expirations(
    identity: &LocalRpKeyMaterial,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<ExpirationStatus, Error> {
    let descriptor =
        liblinkkeys::generated::decode_local_rp_descriptor(&identity.descriptor.descriptor)
            .map_err(|e| Error::Decode(format!("identity descriptor: {e}")))?;
    liblinkkeys::local_rp::check_expirations(&descriptor.expires_at, now).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn check_expirations_wraps_liblinkkeys_thresholds() {
        let identity = generate_local_rp_identity(GenerateLocalRpIdentityConfig {
            app_name: "Test App".to_string(),
            local_domain_hint: None,
            supported_suites: None,
            lifetime: Some(Duration::days(100)),
            now: Utc::now(),
        })
        .unwrap();

        let status = check_expirations(&identity, Utc::now()).unwrap();
        assert_eq!(status.level, ExpirationLevel::Notice);

        let far_future = Utc::now() + Duration::days(200);
        let expired = check_expirations(&identity, far_future).unwrap();
        assert_eq!(expired.level, ExpirationLevel::Expired);
    }

    #[test]
    fn default_seams_are_memoized_singletons() {
        let a = default_transport() as *const dyn Transport;
        let b = default_transport() as *const dyn Transport;
        assert_eq!(a, b);
    }
}
