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
///
/// Runtime-aware, because this is called from two very different contexts:
/// - TCP-backed CLI admin commands (`crates/linkkeys/src/cli/tcp_client.rs`)
///   call it from inside `#[rocket::main]`'s already-running Tokio runtime.
///   Unconditionally building and `.block_on()`-ing a second nested runtime
///   there panics ("Cannot start a runtime from within a runtime").
/// - Everything else (unit tests, or any caller with no ambient runtime) has
///   no runtime to detect and gets the original self-contained behavior.
///
/// Detection is via `Handle::try_current()`:
/// - Multi-thread ambient runtime (what `#[rocket::main]` provides —
///   `rocket::async_main` builds one with `Builder::new_multi_thread()`):
///   drive the lookup on that runtime via `block_in_place` + `Handle::
///   block_on`. `block_in_place` itself panics on a current-thread runtime,
///   which is why this branch is gated on the flavor check.
/// - Current-thread ambient runtime (e.g. a `#[tokio::test]` without
///   `flavor = "multi_thread"`): `block_in_place` would panic there too, so
///   fall back to a dedicated OS thread that builds and drives its own fresh
///   runtime — always safe, independent of what's running on the calling
///   thread.
/// - No ambient runtime: build one directly, exactly as before.
///
/// Fails closed: returns an error if DNS fails or no fingerprints are found.
pub fn resolve_fingerprints(domain: &str) -> Result<Vec<String>, DnsFingerprintError> {
    let dns = crate::net::Net::production().dns;

    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            let domain = domain.to_string();
            tokio::task::block_in_place(move || {
                handle.block_on(resolve_fingerprints_async(dns.as_ref(), &domain))
            })
        }
        Ok(_) => {
            let domain = domain.to_string();
            std::thread::spawn(move || resolve_fingerprints_blocking(dns.as_ref(), &domain))
                .join()
                .unwrap_or_else(|_| {
                    Err(DnsFingerprintError::ResolverInit(
                        "DNS resolver thread panicked".to_string(),
                    ))
                })
        }
        Err(_) => resolve_fingerprints_blocking(dns.as_ref(), domain),
    }
}

/// Build a short-lived current-thread runtime and drive the lookup on it. Only
/// safe when the calling thread is not already inside an ambient Tokio
/// runtime — callers that might be must go through `resolve_fingerprints`,
/// which picks this only when it has confirmed (or moved to a fresh OS
/// thread to guarantee) that's the case.
fn resolve_fingerprints_blocking(
    dns: &dyn crate::net::DnsResolver,
    domain: &str,
) -> Result<Vec<String>, DnsFingerprintError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| DnsFingerprintError::ResolverInit(e.to_string()))?;
    resolve_fingerprints_with(&rt, dns, domain)
}

/// Resolve domain key fingerprints through an injected [`DnsResolver`], using an
/// existing runtime to drive the async lookup. This is the seam: the TLS client-
/// cert verifier calls it with the process `Net`'s resolver in production and a
/// static fake in tests, so the synchronous (rustls-invoked) handshake path can
/// be exercised end-to-end without real DNS. The verifier drives its own
/// dedicated runtime from a plain thread-pool thread during a synchronous
/// rustls callback — never itself inside an ambient runtime — so `block_on`
/// here is always safe. Fails closed.
pub fn resolve_fingerprints_with(
    runtime: &tokio::runtime::Runtime,
    dns: &dyn crate::net::DnsResolver,
    domain: &str,
) -> Result<Vec<String>, DnsFingerprintError> {
    runtime.block_on(resolve_fingerprints_async(dns, domain))
}

/// The actual async lookup + TXT parse, shared by every driving strategy
/// above (ambient multi-thread runtime, dedicated OS thread, or a
/// purpose-built runtime).
async fn resolve_fingerprints_async(
    dns: &dyn crate::net::DnsResolver,
    domain: &str,
) -> Result<Vec<String>, DnsFingerprintError> {
    let dns_name = linkkeys_dns_name(domain);
    let txts = dns
        .txt_lookup(&dns_name)
        .await
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

    /// Regression test for the nested-runtime panic: calling
    /// `resolve_fingerprints` from a thread already inside a Tokio
    /// multi-thread runtime — exactly what happens when a TCP-backed CLI
    /// admin command runs inside `#[rocket::main]`'s runtime — must not
    /// panic with "Cannot start a runtime from within a runtime". It should
    /// still fail closed with a clean resolution error for a domain with no
    /// DNS record.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_resolve_from_within_multi_thread_runtime_does_not_panic() {
        // Call the sync fn directly on this async test's worker thread — no
        // `.await`, mirroring how `main.rs`'s sync CLI handlers call it from
        // inside `#[rocket::main]`.
        let result = resolve_fingerprints("this-domain-does-not-exist-linkkeys-test.invalid");
        assert!(result.is_err(), "must fail closed, not panic");
    }

    /// Same, but from within a current-thread runtime (e.g. a `#[tokio::
    /// test]` without `flavor = "multi_thread"`), where `block_in_place`
    /// itself would panic — must take the dedicated-OS-thread fallback
    /// instead and still not panic.
    #[tokio::test]
    async fn test_resolve_from_within_current_thread_runtime_does_not_panic() {
        let result = resolve_fingerprints("this-domain-does-not-exist-linkkeys-test.invalid");
        assert!(result.is_err(), "must fail closed, not panic");
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
