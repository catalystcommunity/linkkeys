//! The SDK's single error type. Every fallible operation in this crate
//! returns `Result<T, Error>` — the app is expected to match on `Error`'s
//! variants only for logging/UX, per AGENTS.md's error-handling rule
//! ("Never log sensitive information"): none of these variants carry key
//! material, nonces, tokens, tickets, or claim values, only enough context
//! (domain names, field names, short messages) to explain *what* failed.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// A field the caller supplied was structurally invalid (bad key length,
    /// malformed fingerprint string, empty required list, etc).
    InvalidInput(String),
    /// CBOR decoding of a stored or wire structure failed.
    Decode(String),
    /// DNS TXT lookup or record parsing failed for a domain.
    Dns(String),
    /// The TCP transport could not reach a domain's endpoint.
    Transport(String),
    /// TLS handshake / certificate pinning failed.
    Tls(String),
    /// The CSIL-RPC envelope could not be encoded/decoded, or the wire
    /// framing was malformed.
    Protocol(String),
    /// The peer returned a non-Ok RPC status.
    ServerError { status: i32, message: String },
    /// A local-RP protocol verification step failed (signature, envelope,
    /// timestamp, nonce/state, audience, issuer, callback URL, suite
    /// negotiation — see [`liblinkkeys::local_rp::LocalRpError`]).
    Verification(liblinkkeys::local_rp::LocalRpError),
    /// A claim's signature/revocation/expiry check failed.
    Claim(liblinkkeys::claims::ClaimError),
    /// No trustworthy domain keys were established for a domain (DNS pin
    /// matched nothing, or vouch verification failed for every candidate).
    NoTrustedDomainKeys(String),
    /// A sibling-signed revocation certificate did not meet quorum.
    Revocation(String),
    /// The claim-ticket redemption response named a different identity
    /// (`user_id`/`user_domain`, or a claim's own `user_id`) than the
    /// SIGNED callback payload vouched for. Fatal, always: a
    /// compromised/malicious IDP could otherwise redeem a ticket for one
    /// user while an already domain-signed callback names another, and an
    /// SDK that trusted the (unsigned) redemption response's identity over
    /// the signed payload's would silently log the wrong user in.
    IdentityMismatch(String),
    /// One or more claim types in [`crate::begin::PendingLogin::required_claims`]
    /// (declared when the login was begun) were not present among the
    /// redemption's claims that passed signature verification. Carries the
    /// missing claim types.
    RequiredClaimsNotSatisfied(Vec<String>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            Error::Decode(msg) => write!(f, "decode error: {msg}"),
            Error::Dns(msg) => write!(f, "DNS error: {msg}"),
            Error::Transport(msg) => write!(f, "transport error: {msg}"),
            Error::Tls(msg) => write!(f, "TLS error: {msg}"),
            Error::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Error::ServerError { status, message } => {
                write!(f, "server error ({status}): {message}")
            }
            Error::Verification(e) => write!(f, "verification failed: {e}"),
            Error::Claim(e) => write!(f, "claim verification failed: {e}"),
            Error::NoTrustedDomainKeys(domain) => {
                write!(
                    f,
                    "no trusted public keys could be established for domain: {domain}"
                )
            }
            Error::Revocation(msg) => write!(f, "revocation certificate error: {msg}"),
            Error::IdentityMismatch(msg) => write!(f, "identity binding mismatch: {msg}"),
            Error::RequiredClaimsNotSatisfied(missing) => {
                write!(f, "required claims not satisfied: {}", missing.join(", "))
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<liblinkkeys::local_rp::LocalRpError> for Error {
    fn from(e: liblinkkeys::local_rp::LocalRpError) -> Self {
        Error::Verification(e)
    }
}

impl From<liblinkkeys::crypto::CryptoError> for Error {
    fn from(e: liblinkkeys::crypto::CryptoError) -> Self {
        Error::Verification(liblinkkeys::local_rp::LocalRpError::from(e))
    }
}

impl From<liblinkkeys::claims::ClaimError> for Error {
    fn from(e: liblinkkeys::claims::ClaimError) -> Self {
        Error::Claim(e)
    }
}

impl From<liblinkkeys::dns::DnsParseError> for Error {
    fn from(e: liblinkkeys::dns::DnsParseError) -> Self {
        Error::Dns(e.to_string())
    }
}

impl From<liblinkkeys::revocation::RevocationError> for Error {
    fn from(e: liblinkkeys::revocation::RevocationError) -> Self {
        Error::Revocation(e.to_string())
    }
}

impl From<crate::transport::TransportError> for Error {
    fn from(e: crate::transport::TransportError) -> Self {
        Error::Transport(e.to_string())
    }
}

impl From<crate::dns::DnsLookupError> for Error {
    fn from(e: crate::dns::DnsLookupError) -> Self {
        Error::Dns(e.to_string())
    }
}
