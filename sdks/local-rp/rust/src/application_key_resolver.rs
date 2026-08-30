//! Application-key resolution for a DNS-less RP (`signing-things-request.md`,
//! "Roles and trust boundaries" -> "DNS-less RP": "A DNS-less RP has no DNS
//! identity that a remote home domain can verify... This is not a problem for
//! public-key reads. A DNS-less RP can read the same anonymous public key
//! data as any other caller. It authenticates the home-domain server and then
//! keeps its own bounded cache."; "Public-key caches" -> "DNS-less RP cache").
//!
//! This module is the whole trust chain in one call
//! ([`resolve_application_keys`]):
//!
//! 1. Fetch the anonymous `ApplicationKeys/get-application-keys` read and the
//!    home domain's public keys, both DNS-`fp=`-pinned over TCP CSIL-RPC
//!    (`crate::rpc::fetch_application_keys`, `crate::rpc::fetch_domain_keys`
//!    — the SAME domain-key fetch+revocation-filtering path this crate
//!    already uses for local-RP logins).
//! 2. Verify every signed record with
//!    `liblinkkeys::application_keys::verify_application_key_set` — the SAME
//!    pure rules the server-side RP cache and every other peer use. This
//!    module adds no verification rule of its own; see that function's doc
//!    comment for the actual order (attestations against the home domain's
//!    pinned key set, then revocations against the attested SIBLING keys,
//!    then classification against `now`).
//! 3. Cache the RAW signed records (never a pre-classified verdict) behind a
//!    pluggable, bounded [`crate::application_key_cache::ApplicationKeyCacheStore`],
//!    keyed on the canonical subject/application/instance identity — never a
//!    handle.
//! 4. Report an explicit [`CacheFreshness`] alongside the keys on every call,
//!    so a caller cannot silently treat a stale result as current trust.

use crate::application_key_cache::{
    ApplicationKeyCacheStore, BoundedInMemoryApplicationKeyCache, CachedApplicationKeys,
    InstanceKey,
};
use crate::dns::DnsResolver;
use crate::transport::Transport;
use crate::Error;
use chrono::{DateTime, Utc};
use liblinkkeys::application_keys::{self as ak, VerifiedApplicationKeySet};
use liblinkkeys::generated::types::{DomainPublicKey, SignedApplicationKeyAttestation};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// The SDK's own ceiling on cache age when the caller supplies none (design
/// doc, "RP cache": "A caller can request a stricter maximum cache age. It
/// cannot request a weaker policy than the RP operator permits." — a
/// DNS-less RP has no separate RP server, so this SDK plays the operator's
/// role). Matches the protocol's own default attestation lifetime
/// (`ak::DEFAULT_ATTESTATION_LIFETIME_SECONDS`): there is no reason to
/// promise freshness tighter than attestations are ever refreshed on the home
/// domain's side.
pub const DEFAULT_MAX_CACHE_AGE_SECONDS: i64 = ak::DEFAULT_ATTESTATION_LIFETIME_SECONDS;

/// Refresh a cache entry once it has used up this fraction of its allowed
/// age, instead of waiting for it to actually expire (design doc: "The RP
/// should refresh frequently used entries before their allowed cache age
/// ends"). Mirrors the exact half-life idempotence threshold
/// `ak::needs_new_attestation` already uses on the home-domain renewal path
/// for the identical reason: the common case becomes "still fresh, skip the
/// network" well before a caller ever lands right on the edge of expiry.
const REFRESH_AHEAD_FRACTION: f64 = 0.5;

/// Default clock-skew tolerance for the RFC3339 timestamp checks inside
/// `verify_application_key_set`, matching this protocol's own documented
/// default (`APPLICATION_KEY_CLOCK_SKEW_SECONDS` in `docs/application-keys.md`).
pub const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 300;

/// How this result was produced (design doc, "RP cache": "explicit freshness
/// result"). A caller must handle every variant explicitly — see
/// [`ResolvedApplicationKeys`] for why there is no way to read the keys
/// without also seeing this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheFreshness {
    /// Served from cache within the allowed age; no network call was made.
    Fresh,
    /// A network fetch happened during this call and succeeded.
    Refreshed,
    /// The entry is past its allowed age and the home domain could not be
    /// reached. These are the last verified records this cache holds, not
    /// current trust (design doc: "An RP must not silently present an
    /// expired attestation as current... It must mark the current-trust
    /// result as stale or unavailable").
    Stale,
}

/// The result of [`resolve_application_keys`]. Deliberately NOT a bare key
/// list: `freshness` travels in the same struct as `keys` so a caller cannot
/// destructure only the keys and forget to check it (design doc, "Security
/// review points": "A stale cache must not hide revocation without a visible
/// freshness result").
#[derive(Debug, Clone)]
pub struct ResolvedApplicationKeys {
    /// Re-classified against the caller's `now` on every call — never a
    /// replay of a verdict computed at fetch time. Use
    /// [`VerifiedApplicationKeySet::key_for_use`] or
    /// [`VerifiedApplicationKeySet::usable_keys`] to consult it.
    pub keys: VerifiedApplicationKeySet,
    pub freshness: CacheFreshness,
    pub fetched_at: DateTime<Utc>,
    pub revocations_checked_at: DateTime<Utc>,
    /// Which home-domain signing key ids verified each attestation, keyed by
    /// application key id (design doc, "RP cache": "must record... which
    /// home-domain keys verified each attestation").
    pub verified_by_domain_keys: HashMap<String, Vec<String>>,
}

/// Input to [`resolve_application_keys`]. Every field is load-bearing.
pub struct ResolveApplicationKeysConfig<'a> {
    pub subject_user_id: &'a str,
    pub subject_domain: &'a str,
    pub application_id: &'a str,
    pub instance_id: &'a str,
    pub now: DateTime<Utc>,
    /// A STRICTER ceiling than [`DEFAULT_MAX_CACHE_AGE_SECONDS`]. This can
    /// only tighten the allowed age, never loosen it — see
    /// [`resolve_application_keys`].
    pub max_cache_age_seconds: Option<i64>,
    /// Defaults to [`DEFAULT_CLOCK_SKEW_SECONDS`] when `None`.
    pub clock_skew_seconds: Option<i64>,
    pub transport: &'a dyn Transport,
    pub dns: &'a dyn DnsResolver,
    pub store: &'a dyn ApplicationKeyCacheStore,
}

impl<'a> ResolveApplicationKeysConfig<'a> {
    /// Convenience constructor using the default network seams
    /// ([`crate::default_transport`], [`crate::default_dns_resolver`]) and
    /// the process-wide [`default_application_key_cache`]. Override any field
    /// afterward (struct-update syntax) to inject fakes in tests or a
    /// persistent store in production.
    pub fn new(
        subject_user_id: &'a str,
        subject_domain: &'a str,
        application_id: &'a str,
        instance_id: &'a str,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            subject_user_id,
            subject_domain,
            application_id,
            instance_id,
            now,
            max_cache_age_seconds: None,
            clock_skew_seconds: None,
            transport: crate::default_transport(),
            dns: crate::default_dns_resolver(),
            store: default_application_key_cache(),
        }
    }
}

static DEFAULT_CACHE: OnceLock<BoundedInMemoryApplicationKeyCache> = OnceLock::new();

/// The process-wide default [`ApplicationKeyCacheStore`]: a
/// [`BoundedInMemoryApplicationKeyCache`], memoized like
/// [`crate::default_transport`]. An application that wants a
/// restart-surviving cache supplies its own store in
/// [`ResolveApplicationKeysConfig::store`] instead.
pub fn default_application_key_cache() -> &'static dyn ApplicationKeyCacheStore {
    DEFAULT_CACHE.get_or_init(BoundedInMemoryApplicationKeyCache::default)
}

// Per-key single-flight registry so concurrent resolves for the SAME
// instance coalesce into one network fetch (design doc: "It should
// coalesce concurrent refreshes for the same entry."). Scoped to distinct
// in-flight keys only, and an entry is removed once nothing is left waiting
// on it — this is a transient synchronization aid, not a second unbounded
// cache; the actual key data lives only in the bounded
// `ApplicationKeyCacheStore`.
static REFRESH_LOCKS: OnceLock<Mutex<HashMap<InstanceKey, Arc<Mutex<()>>>>> = OnceLock::new();

fn refresh_lock_for(key: &InstanceKey) -> Arc<Mutex<()>> {
    let mut locks = REFRESH_LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    locks
        .entry(key.clone())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Remove `key`'s entry from the registry if nothing else is waiting on it.
/// `lock` must be the caller's own (still-held) clone: while the caller holds
/// it, `strong_count` is `2` exactly when the registry's own clone is the
/// only other reference (no other thread is waiting).
fn release_refresh_lock_if_unused(key: &InstanceKey, lock: &Arc<Mutex<()>>) {
    let mut locks = REFRESH_LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if Arc::strong_count(lock) <= 2 {
        locks.remove(key);
    }
}

/// Resolve `config`'s application instance's currently-usable public keys.
///
/// `config.max_cache_age_seconds` can only make the allowed age STRICTER than
/// [`DEFAULT_MAX_CACHE_AGE_SECONDS`] (`min(configured, default)`) — a caller
/// can never loosen this SDK's own ceiling.
///
/// A [`CacheFreshness::Stale`] result means the home domain could not be
/// reached and these are the last verified records this cache holds; a
/// `Fresh`/`Refreshed` result only ever crosses the allowed-age boundary set
/// above. If the home domain is unreachable AND nothing is cached yet, this
/// returns `Err` — there is nothing to fall back to.
pub fn resolve_application_keys(
    config: ResolveApplicationKeysConfig<'_>,
) -> Result<ResolvedApplicationKeys, Error> {
    let key = InstanceKey::new(
        config.subject_user_id,
        config.subject_domain,
        config.application_id,
        config.instance_id,
    );
    let max_age_seconds = match config.max_cache_age_seconds {
        Some(requested) => requested.clamp(0, DEFAULT_MAX_CACHE_AGE_SECONDS),
        None => DEFAULT_MAX_CACHE_AGE_SECONDS,
    };
    let refresh_ahead_seconds = (max_age_seconds as f64 * REFRESH_AHEAD_FRACTION) as i64;
    let skew = config
        .clock_skew_seconds
        .unwrap_or(DEFAULT_CLOCK_SKEW_SECONDS);

    if let Some(entry) = config.store.get(&key) {
        let age = (config.now - entry.fetched_at).num_seconds();
        if age <= refresh_ahead_seconds {
            return Ok(classify(
                &key,
                &entry,
                CacheFreshness::Fresh,
                config.now,
                skew,
            ));
        }
    }

    // Past the refresh-ahead threshold, or a miss: fetch, coalesced per
    // instance so concurrent callers for the same key share one round trip
    // instead of stampeding the home domain.
    let lock = refresh_lock_for(&key);
    let guard = lock.lock().unwrap_or_else(|e| e.into_inner());

    // Re-check after acquiring the lock: another thread may already have
    // refreshed this exact entry while we were waiting for it.
    if let Some(entry) = config.store.get(&key) {
        let age = (config.now - entry.fetched_at).num_seconds();
        if age <= refresh_ahead_seconds {
            drop(guard);
            release_refresh_lock_if_unused(&key, &lock);
            return Ok(classify(
                &key,
                &entry,
                CacheFreshness::Fresh,
                config.now,
                skew,
            ));
        }
    }

    let outcome = match fetch_and_verify(&config) {
        Ok(entry) => {
            config.store.put(&key, entry.clone());
            Ok(classify(
                &key,
                &entry,
                CacheFreshness::Refreshed,
                config.now,
                skew,
            ))
        }
        Err(fetch_err) => match config.store.get(&key) {
            Some(entry) => {
                let age = (config.now - entry.fetched_at).num_seconds();
                if age <= max_age_seconds {
                    // Still inside the allowed window despite the failed
                    // refresh attempt: the refresh was only a proactive
                    // optimization, not a requirement for the data to remain
                    // current by policy.
                    Ok(classify(
                        &key,
                        &entry,
                        CacheFreshness::Fresh,
                        config.now,
                        skew,
                    ))
                } else {
                    Ok(classify(
                        &key,
                        &entry,
                        CacheFreshness::Stale,
                        config.now,
                        skew,
                    ))
                }
            }
            None => Err(fetch_err),
        },
    };

    drop(guard);
    release_refresh_lock_if_unused(&key, &lock);
    outcome
}

fn fetch_and_verify(
    config: &ResolveApplicationKeysConfig<'_>,
) -> Result<CachedApplicationKeys, Error> {
    let domain_keys =
        crate::rpc::fetch_domain_keys(config.transport, config.dns, config.subject_domain)?;
    let response = crate::rpc::fetch_application_keys(
        config.transport,
        config.dns,
        config.subject_domain,
        config.subject_user_id,
        config.application_id,
        config.instance_id,
    )?;
    if response.subject_domain != config.subject_domain {
        return Err(Error::IdentityMismatch(format!(
            "get-application-keys response names subject_domain {:?}, expected {:?}",
            response.subject_domain, config.subject_domain
        )));
    }
    Ok(CachedApplicationKeys {
        signed_attestations: response.keys,
        revocations: response.revocations,
        domain_keys,
        fetched_at: config.now,
        revocations_checked_at: config.now,
    })
}

fn classify(
    key: &InstanceKey,
    entry: &CachedApplicationKeys,
    freshness: CacheFreshness,
    now: DateTime<Utc>,
    skew_seconds: i64,
) -> ResolvedApplicationKeys {
    let instance = key.as_instance_ref();
    let keys = ak::verify_application_key_set(
        &entry.signed_attestations,
        &entry.revocations,
        &entry.domain_keys,
        &instance,
        now,
        skew_seconds,
    );
    let verified_by_domain_keys = attestation_signers(
        &entry.signed_attestations,
        &entry.domain_keys,
        &key.subject_domain,
    );
    ResolvedApplicationKeys {
        keys,
        freshness,
        fetched_at: entry.fetched_at,
        revocations_checked_at: entry.revocations_checked_at,
        verified_by_domain_keys,
    }
}

/// Which home-domain signing key ids verified each attestation (design doc,
/// "RP cache": "must record... which home-domain keys verified each
/// attestation"). Pure bookkeeping over the SAME already-vetted primitives
/// `ak::verify_attestation_signature` itself uses
/// (`liblinkkeys::crypto::resolve_and_verify`,
/// `liblinkkeys::assertions::check_signing_key_valid`) — this does not
/// re-derive whether a signature is valid, only which valid signer(s)
/// produced it, information `verify_attestation_signature` itself discards
/// after finding the first match.
fn attestation_signers(
    signed_attestations: &[SignedApplicationKeyAttestation],
    domain_keys: &[DomainPublicKey],
    expected_domain: &str,
) -> HashMap<String, Vec<String>> {
    let mut out = HashMap::new();
    for signed in signed_attestations {
        let Ok(attestation) =
            liblinkkeys::generated::decode_application_key_attestation(&signed.attestation)
        else {
            continue;
        };
        if attestation.subject_domain != expected_domain {
            continue;
        }
        let message = ak::attestation_signature_input(&signed.attestation);
        let mut signers = Vec::new();
        for sig in &signed.signatures {
            if sig.domain != expected_domain {
                continue;
            }
            let Some(key) = domain_keys
                .iter()
                .find(|k| k.key_id == sig.signed_by_key_id)
            else {
                continue;
            };
            if liblinkkeys::assertions::check_signing_key_valid(key).is_err() {
                continue;
            }
            if liblinkkeys::crypto::resolve_and_verify(
                &key.algorithm,
                &message,
                &sig.signature,
                &key.public_key,
            )
            .is_ok()
            {
                signers.push(key.key_id.clone());
            }
        }
        if !signers.is_empty() {
            out.insert(attestation.key_id.clone(), signers);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application_key_cache::BoundedInMemoryApplicationKeyCache;
    use crate::dns::DnsLookupError;
    use crate::transport::{ReadWrite, TransportError};
    use chrono::Duration;

    struct AlwaysFailsTransport;
    impl Transport for AlwaysFailsTransport {
        fn dial(&self, _host_port: &str) -> Result<Box<dyn ReadWrite>, TransportError> {
            Err(TransportError::Connect(
                "test transport never dials".to_string(),
            ))
        }
    }

    struct AlwaysFailsDns;
    impl DnsResolver for AlwaysFailsDns {
        fn txt_lookup(&self, _name: &str) -> Result<Vec<String>, DnsLookupError> {
            Err(DnsLookupError::Lookup(
                "test resolver has no records".to_string(),
            ))
        }
    }

    fn empty_entry(fetched_at: DateTime<Utc>) -> CachedApplicationKeys {
        CachedApplicationKeys {
            signed_attestations: vec![],
            revocations: vec![],
            domain_keys: vec![],
            fetched_at,
            revocations_checked_at: fetched_at,
        }
    }

    fn base_config<'a>(
        now: DateTime<Utc>,
        transport: &'a dyn Transport,
        dns: &'a dyn DnsResolver,
        store: &'a dyn ApplicationKeyCacheStore,
    ) -> ResolveApplicationKeysConfig<'a> {
        ResolveApplicationKeysConfig {
            subject_user_id: "user-1",
            subject_domain: "example.test",
            application_id: "tinku",
            instance_id: "instance-1",
            now,
            max_cache_age_seconds: None,
            clock_skew_seconds: None,
            transport,
            dns,
            store,
        }
    }

    #[test]
    fn fresh_entry_never_touches_the_network() {
        let now = Utc::now();
        let store = BoundedInMemoryApplicationKeyCache::default();
        let key = InstanceKey::new("user-1", "example.test", "tinku", "instance-1");
        store.put(&key, empty_entry(now));

        let transport = AlwaysFailsTransport;
        let dns = AlwaysFailsDns;
        let config = base_config(now, &transport, &dns, &store);
        let result = resolve_application_keys(config).expect("must serve from cache");
        assert_eq!(result.freshness, CacheFreshness::Fresh);
    }

    #[test]
    fn entry_past_max_age_with_unreachable_home_domain_is_stale() {
        let now = Utc::now();
        let store = BoundedInMemoryApplicationKeyCache::default();
        let key = InstanceKey::new("user-1", "example.test", "tinku", "instance-1");
        let old = now - Duration::seconds(DEFAULT_MAX_CACHE_AGE_SECONDS + 1);
        store.put(&key, empty_entry(old));

        let transport = AlwaysFailsTransport;
        let dns = AlwaysFailsDns;
        let config = base_config(now, &transport, &dns, &store);
        let result = resolve_application_keys(config).expect("must fall back to stale cache");
        assert_eq!(result.freshness, CacheFreshness::Stale);
        assert_eq!(result.fetched_at, old);
    }

    #[test]
    fn entry_past_refresh_ahead_but_within_max_age_survives_a_failed_refresh() {
        let now = Utc::now();
        let store = BoundedInMemoryApplicationKeyCache::default();
        let key = InstanceKey::new("user-1", "example.test", "tinku", "instance-1");
        // Past the refresh-ahead threshold (half of max age) but still within
        // the full max age.
        let aging = now - Duration::seconds(DEFAULT_MAX_CACHE_AGE_SECONDS * 3 / 4);
        store.put(&key, empty_entry(aging));

        let transport = AlwaysFailsTransport;
        let dns = AlwaysFailsDns;
        let config = base_config(now, &transport, &dns, &store);
        let result = resolve_application_keys(config).expect("must fall back to fresh cache");
        assert_eq!(result.freshness, CacheFreshness::Fresh);
    }

    #[test]
    fn miss_with_unreachable_home_domain_is_an_error() {
        let now = Utc::now();
        let store = BoundedInMemoryApplicationKeyCache::default();
        let transport = AlwaysFailsTransport;
        let dns = AlwaysFailsDns;
        let config = base_config(now, &transport, &dns, &store);
        assert!(resolve_application_keys(config).is_err());
    }

    #[test]
    fn caller_supplied_max_age_can_only_tighten_never_loosen() {
        let now = Utc::now();
        let store = BoundedInMemoryApplicationKeyCache::default();
        let key = InstanceKey::new("user-1", "example.test", "tinku", "instance-1");
        // Just past the SDK's own default ceiling.
        let old = now - Duration::seconds(DEFAULT_MAX_CACHE_AGE_SECONDS + 10);
        store.put(&key, empty_entry(old));

        let transport = AlwaysFailsTransport;
        let dns = AlwaysFailsDns;
        // Ask for a WEAKER (larger) max age than the default; the SDK must
        // still treat this entry as past its (unloosenable) ceiling.
        let mut config = base_config(now, &transport, &dns, &store);
        config.max_cache_age_seconds = Some(DEFAULT_MAX_CACHE_AGE_SECONDS * 10);
        let result = resolve_application_keys(config).expect("must fall back to stale cache");
        assert_eq!(
            result.freshness,
            CacheFreshness::Stale,
            "a caller-requested weaker policy must not be honored"
        );
    }
}
