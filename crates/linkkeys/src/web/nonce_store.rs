use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// In-memory nonce store with TTL-based expiration.
/// Prevents replay of assertion tokens within their validity window.
pub struct NonceStore {
    nonces: RwLock<HashMap<String, Instant>>,
    ttl: Duration,
}

impl NonceStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            nonces: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Record a nonce as used. Returns false if the nonce was already used
    /// (replay detected). Returns true if this is the first time.
    pub fn record(&self, nonce: &str) -> bool {
        let mut map = self.nonces.write().expect("NonceStore lock poisoned");

        // Periodic cleanup: remove expired entries when the map grows
        if map.len() > 1000 {
            let cutoff = Instant::now() - self.ttl;
            map.retain(|_, &mut inserted| inserted > cutoff);
        }

        let now = Instant::now();

        // Check if nonce already exists and is still within TTL
        if let Some(&inserted) = map.get(nonce) {
            if now.duration_since(inserted) < self.ttl {
                return false; // Replay detected
            }
            // Expired — allow reuse (update timestamp)
        }

        map.insert(nonce.to_string(), now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_use_succeeds() {
        let store = NonceStore::new(Duration::from_secs(300));
        assert!(store.record("nonce-1"));
    }

    #[test]
    fn test_replay_detected() {
        let store = NonceStore::new(Duration::from_secs(300));
        assert!(store.record("nonce-1"));
        assert!(!store.record("nonce-1")); // Replay
    }

    #[test]
    fn test_different_nonces_independent() {
        let store = NonceStore::new(Duration::from_secs(300));
        assert!(store.record("nonce-1"));
        assert!(store.record("nonce-2"));
        assert!(!store.record("nonce-1")); // Replay of first
    }

    #[test]
    fn test_expired_nonce_allowed() {
        let store = NonceStore::new(Duration::from_millis(1));
        assert!(store.record("nonce-1"));
        std::thread::sleep(Duration::from_millis(10));
        assert!(store.record("nonce-1")); // Expired, allowed again
    }
}
