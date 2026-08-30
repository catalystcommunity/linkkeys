//! A bounded, pluggable cache for verified remote application-key material
//! (`signing-things-request.md`, "Public-key caches" -> "DNS-less RP cache":
//! "It keeps its cache in application-controlled storage through an SDK
//! interface. The SDK must provide a safe bounded default for applications
//! that do not supply a persistent store.").
//!
//! [`ApplicationKeyCacheStore`] is deliberately storage-only: get and put on
//! the canonical instance identity. Refresh coalescing, freshness
//! classification, and re-verification on every read live in
//! [`crate::application_key_resolver`], not here, so any store implementation
//! (SQLite, a KV store, or this crate's in-memory default) gets that behavior
//! for free without reimplementing it.

use chrono::{DateTime, Utc};
use liblinkkeys::application_keys::InstanceRef;
use liblinkkeys::generated::types::{
    ApplicationKeyRevocation, DomainPublicKey, SignedApplicationKeyAttestation,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// The durable cache key: the canonical subject/application/instance
/// identity, never a handle (design doc, "Peer authorization": "A handle can
/// move or be reused... Tinku must not make a permanent approval depend only
/// on `handle@domain`" — the same rule applies to any SDK cache keyed on this
/// identity, application key caches included).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InstanceKey {
    pub subject_user_id: String,
    pub subject_domain: String,
    pub application_id: String,
    pub instance_id: String,
}

impl InstanceKey {
    pub fn new(
        subject_user_id: impl Into<String>,
        subject_domain: impl Into<String>,
        application_id: impl Into<String>,
        instance_id: impl Into<String>,
    ) -> Self {
        Self {
            subject_user_id: subject_user_id.into(),
            subject_domain: subject_domain.into(),
            application_id: application_id.into(),
            instance_id: instance_id.into(),
        }
    }

    /// Borrow this key as the `liblinkkeys::application_keys` functions want
    /// it.
    pub fn as_instance_ref(&self) -> InstanceRef<'_> {
        InstanceRef {
            subject_user_id: &self.subject_user_id,
            subject_domain: &self.subject_domain,
            application_id: &self.application_id,
            instance_id: &self.instance_id,
        }
    }
}

/// Everything the resolver needs to reclassify a cache entry's key statuses
/// against a fresh `now` WITHOUT a network call (design doc, "RP cache":
/// "The RP must validate signed records before it stores them. It must
/// validate their current status again before it returns them for current
/// use."). This stores the RAW signed records exactly as fetched — never a
/// pre-classified verdict — so re-verification on every read is a real
/// re-verification against the current clock, not a replay of a stale
/// classification.
#[derive(Debug, Clone)]
pub struct CachedApplicationKeys {
    pub signed_attestations: Vec<SignedApplicationKeyAttestation>,
    pub revocations: Vec<ApplicationKeyRevocation>,
    /// The home-domain keys fetched alongside the attestations, used to
    /// re-verify their signatures on every read.
    pub domain_keys: Vec<DomainPublicKey>,
    pub fetched_at: DateTime<Utc>,
    pub revocations_checked_at: DateTime<Utc>,
}

/// Pluggable cache storage (design doc, "DNS-less RP cache"). Implement this
/// to back the cache with a database, a file, or any other
/// application-controlled store so a restart does not lose useful cache
/// state. [`BoundedInMemoryApplicationKeyCache`] is the safe bounded default
/// for applications that supply none.
pub trait ApplicationKeyCacheStore: Send + Sync {
    fn get(&self, key: &InstanceKey) -> Option<CachedApplicationKeys>;
    fn put(&self, key: &InstanceKey, entry: CachedApplicationKeys);
}

/// Default bound for [`BoundedInMemoryApplicationKeyCache::default`].
/// Generous enough for an application instance juggling a few hundred peers
/// without giving an attacker-controlled key space anywhere to grow — the
/// design doc is explicit that "an SDK that grows without limit is a defect
/// in every application that embeds it."
pub const DEFAULT_MAX_ENTRIES: usize = 512;

/// The SDK's safe bounded default [`ApplicationKeyCacheStore`]: a
/// least-recently-used cache bounded by `max_entries`. It can never grow past
/// its configured entry count — inserting past the limit evicts the
/// least-recently-used entry FIRST, so the backing map size is invariant
/// under any sequence of `put` calls, not merely bounded on average.
pub struct BoundedInMemoryApplicationKeyCache {
    max_entries: usize,
    state: Mutex<LruState>,
}

#[derive(Default)]
struct LruState {
    map: HashMap<InstanceKey, CachedApplicationKeys>,
    /// Least-recently-used at the front, most-recently-used at the back.
    order: VecDeque<InstanceKey>,
}

impl BoundedInMemoryApplicationKeyCache {
    /// `max_entries` is clamped to at least 1 — a cache that can hold nothing
    /// is not a useful "bounded default", it is a misconfiguration.
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            state: Mutex::new(LruState::default()),
        }
    }
}

impl Default for BoundedInMemoryApplicationKeyCache {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES)
    }
}

fn touch(order: &mut VecDeque<InstanceKey>, key: &InstanceKey) {
    if let Some(pos) = order.iter().position(|k| k == key) {
        order.remove(pos);
    }
    order.push_back(key.clone());
}

impl ApplicationKeyCacheStore for BoundedInMemoryApplicationKeyCache {
    fn get(&self, key: &InstanceKey) -> Option<CachedApplicationKeys> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let found = state.map.get(key).cloned();
        if found.is_some() {
            touch(&mut state.order, key);
        }
        found
    }

    fn put(&self, key: &InstanceKey, entry: CachedApplicationKeys) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !state.map.contains_key(key) && state.map.len() >= self.max_entries {
            if let Some(evicted) = state.order.pop_front() {
                state.map.remove(&evicted);
            }
        }
        state.map.insert(key.clone(), entry);
        touch(&mut state.order, key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u32) -> InstanceKey {
        InstanceKey::new(format!("user-{n}"), "example.com", "tinku", "instance-1")
    }

    fn entry() -> CachedApplicationKeys {
        CachedApplicationKeys {
            signed_attestations: vec![],
            revocations: vec![],
            domain_keys: vec![],
            fetched_at: Utc::now(),
            revocations_checked_at: Utc::now(),
        }
    }

    #[test]
    fn evicts_least_recently_used_past_the_bound() {
        let cache = BoundedInMemoryApplicationKeyCache::new(2);
        cache.put(&key(1), entry());
        cache.put(&key(2), entry());
        // Touching key(1) makes key(2) the least-recently-used entry.
        assert!(cache.get(&key(1)).is_some());
        cache.put(&key(3), entry());
        assert!(
            cache.get(&key(1)).is_some(),
            "recently touched, must survive"
        );
        assert!(
            cache.get(&key(2)).is_none(),
            "least-recently-used, must be evicted"
        );
        assert!(cache.get(&key(3)).is_some(), "just inserted, must survive");
    }

    #[test]
    fn never_grows_past_max_entries_under_heavy_insert() {
        let cache = BoundedInMemoryApplicationKeyCache::new(8);
        for n in 0..1000 {
            cache.put(&key(n), entry());
        }
        let state = cache.state.lock().unwrap();
        assert!(state.map.len() <= 8);
        assert!(state.order.len() <= 8);
    }

    #[test]
    fn repeated_put_of_the_same_key_does_not_grow_the_cache() {
        let cache = BoundedInMemoryApplicationKeyCache::new(4);
        for _ in 0..50 {
            cache.put(&key(1), entry());
        }
        let state = cache.state.lock().unwrap();
        assert_eq!(state.map.len(), 1);
        assert_eq!(state.order.len(), 1);
    }

    #[test]
    fn default_bound_matches_documented_constant() {
        let cache = BoundedInMemoryApplicationKeyCache::default();
        assert_eq!(cache.max_entries, DEFAULT_MAX_ENTRIES);
    }
}
