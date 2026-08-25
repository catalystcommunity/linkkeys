//! The DNS TXT lookup seam.
//!
//! `dns-less-local-rp-design.md`'s "Required Network Access" / Wire Precision
//! sections require every SDK to look up `_linkkeys.{domain}` (trust anchor
//! `fp=` pins) and `_linkkeys_apis.{domain}` (the `tcp=` endpoint) TXT
//! records, with a configurable resolver defaulting to the system resolver.
//! [`DnsResolver`] is that seam; [`SystemDnsResolver`] is the default,
//! blocking implementation.

use std::fmt;
use std::sync::OnceLock;

#[derive(Debug)]
pub enum DnsLookupError {
    ResolverInit(String),
    Lookup(String),
}

impl fmt::Display for DnsLookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsLookupError::ResolverInit(msg) => write!(f, "DNS resolver init failed: {msg}"),
            DnsLookupError::Lookup(msg) => write!(f, "DNS TXT lookup failed: {msg}"),
        }
    }
}

impl std::error::Error for DnsLookupError {}

/// Resolve TXT records for a fully-qualified name (e.g. `_linkkeys.example.com`).
/// Each returned string is one TXT record's content — the concatenation of
/// its character-strings, exactly as `crates/linkkeys/src/net.rs`'s own
/// resolver seam does it (`TXT::to_string()`), so
/// `liblinkkeys::dns::parse_linkkeys_txt`/`parse_linkkeys_apis_txt` can parse
/// it unchanged.
pub trait DnsResolver: Send + Sync {
    fn txt_lookup(&self, name: &str) -> Result<Vec<String>, DnsLookupError>;
}

/// Default [`DnsResolver`]: the OS-configured resolver
/// (`hickory_resolver::TokioResolver::builder_tokio`), lazily built and reused
/// across calls. Per the design doc's "Decided" section: resolver spoofing on
/// a LAN is an accepted, documented tradeoff for this mode; operators wanting
/// hardening can inject their own [`DnsResolver`] (e.g. a DoH client) instead.
#[derive(Default)]
pub struct SystemDnsResolver {
    state: OnceLock<ResolverState>,
}

struct ResolverState {
    runtime: tokio::runtime::Runtime,
    resolver: hickory_resolver::TokioResolver,
}

impl fmt::Debug for SystemDnsResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemDnsResolver").finish_non_exhaustive()
    }
}

impl SystemDnsResolver {
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self) -> Result<&ResolverState, DnsLookupError> {
        if let Some(state) = self.state.get() {
            return Ok(state);
        }
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| DnsLookupError::ResolverInit(e.to_string()))?;
        let resolver = runtime
            .block_on(async {
                hickory_resolver::TokioResolver::builder_tokio().and_then(|builder| builder.build())
            })
            .map_err(|e| DnsLookupError::ResolverInit(e.to_string()))?;
        Ok(self
            .state
            .get_or_init(|| ResolverState { runtime, resolver }))
    }
}

impl DnsResolver for SystemDnsResolver {
    fn txt_lookup(&self, name: &str) -> Result<Vec<String>, DnsLookupError> {
        let state = self.get()?;
        let lookup = state
            .runtime
            .block_on(state.resolver.txt_lookup(name))
            .map_err(|e| DnsLookupError::Lookup(format!("{name}: {e}")))?;
        Ok(lookup
            .answers()
            .iter()
            .map(|record| record.data.to_string())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_resolver_nonexistent_domain_fails() {
        let resolver = SystemDnsResolver::new();
        let result =
            resolver.txt_lookup("_linkkeys.this-domain-does-not-exist-linkkeys-sdk-test.invalid");
        assert!(result.is_err());
    }
}
