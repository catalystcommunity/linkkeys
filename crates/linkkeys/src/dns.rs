use std::fmt;

use liblinkkeys::dns::{linkkeys_dns_name, parse_linkkeys_txt};

#[derive(Debug)]
pub enum DnsFingerprintError {
    ResolverInit(String),
    Lookup(String),
    NoRecord,
    NoFingerprints,
}

impl fmt::Display for DnsFingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsFingerprintError::ResolverInit(msg) => {
                write!(f, "DNS resolver initialization failed: {}", msg)
            }
            DnsFingerprintError::Lookup(msg) => write!(f, "DNS lookup failed: {}", msg),
            DnsFingerprintError::NoRecord => write!(f, "no _linkkeys TXT record found"),
            DnsFingerprintError::NoFingerprints => {
                write!(f, "TXT record contains no fingerprints")
            }
        }
    }
}

impl std::error::Error for DnsFingerprintError {}

/// Resolve domain key fingerprints from DNS TXT records via the real resolver.
/// Creates a short-lived single-threaded tokio runtime for the async DNS call.
/// Fails closed: returns an error if DNS fails or no fingerprints are found.
pub fn resolve_fingerprints(domain: &str) -> Result<Vec<String>, DnsFingerprintError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| DnsFingerprintError::ResolverInit(e.to_string()))?;
    let dns = crate::net::Net::production().dns;
    resolve_fingerprints_with(&rt, dns.as_ref(), domain)
}

/// Resolve domain key fingerprints through an injected [`DnsResolver`], using an
/// existing runtime to drive the async lookup. This is the seam: the TLS client-
/// cert verifier calls it with the process `Net`'s resolver in production and a
/// static fake in tests, so the synchronous (rustls-invoked) handshake path can
/// be exercised end-to-end without real DNS. Fails closed.
pub fn resolve_fingerprints_with(
    runtime: &tokio::runtime::Runtime,
    dns: &dyn crate::net::DnsResolver,
    domain: &str,
) -> Result<Vec<String>, DnsFingerprintError> {
    let dns_name = linkkeys_dns_name(domain);
    let txts = runtime
        .block_on(dns.txt_lookup(&dns_name))
        .map_err(|e| DnsFingerprintError::Lookup(e.to_string()))?;

    for txt in &txts {
        match parse_linkkeys_txt(txt) {
            Ok(parsed) => {
                if parsed.fingerprints.is_empty() {
                    return Err(DnsFingerprintError::NoFingerprints);
                }
                return Ok(parsed.fingerprints);
            }
            Err(_) => continue,
        }
    }

    Err(DnsFingerprintError::NoRecord)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_nonexistent_domain_fails() {
        let result = resolve_fingerprints("this-domain-does-not-exist-linkkeys-test.invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_with_runtime_nonexistent_domain_fails() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let dns = crate::net::Net::production().dns;
        let result = resolve_fingerprints_with(
            &rt,
            dns.as_ref(),
            "this-domain-does-not-exist-linkkeys-test.invalid",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_error_display() {
        assert!(DnsFingerprintError::NoRecord
            .to_string()
            .contains("no _linkkeys"));
        assert!(DnsFingerprintError::NoFingerprints
            .to_string()
            .contains("no fingerprints"));
        assert!(DnsFingerprintError::Lookup("timeout".into())
            .to_string()
            .contains("timeout"));
    }
}
