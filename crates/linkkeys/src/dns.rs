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

/// Resolve domain key fingerprints from DNS TXT records.
/// Creates a short-lived single-threaded tokio runtime for the async DNS call.
/// Fails closed: returns an error if DNS fails or no fingerprints are found.
pub fn resolve_fingerprints(domain: &str) -> Result<Vec<String>, DnsFingerprintError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| DnsFingerprintError::ResolverInit(e.to_string()))?;
    resolve_fingerprints_on(&rt, domain)
}

/// Resolve domain key fingerprints using an existing tokio runtime.
/// Used by the ClientCertVerifier which keeps a runtime for its lifetime.
pub fn resolve_fingerprints_on(
    runtime: &tokio::runtime::Runtime,
    domain: &str,
) -> Result<Vec<String>, DnsFingerprintError> {
    runtime.block_on(async_resolve(domain))
}

async fn async_resolve(domain: &str) -> Result<Vec<String>, DnsFingerprintError> {
    use hickory_resolver::TokioAsyncResolver;

    let dns_name = linkkeys_dns_name(domain);
    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .map_err(|e| DnsFingerprintError::ResolverInit(e.to_string()))?;

    let response = resolver
        .txt_lookup(&dns_name)
        .await
        .map_err(|e| DnsFingerprintError::Lookup(e.to_string()))?;

    for record in response.iter() {
        let txt = record.to_string();
        match parse_linkkeys_txt(&txt) {
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
        let result = resolve_fingerprints_on(&rt, "this-domain-does-not-exist-linkkeys-test.invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_error_display() {
        assert!(DnsFingerprintError::NoRecord.to_string().contains("no _linkkeys"));
        assert!(DnsFingerprintError::NoFingerprints.to_string().contains("no fingerprints"));
        assert!(DnsFingerprintError::Lookup("timeout".into()).to_string().contains("timeout"));
    }
}
