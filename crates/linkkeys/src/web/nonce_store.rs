use crate::db::DbPool;
use std::time::Duration;

/// Durable, shared replay-protection store backed by the database
/// `used_nonces` table.
///
/// Unlike a per-process in-memory map, this survives restarts and is consistent
/// across replicas, so single-use / replay-prevention guarantees actually hold
/// in production rather than only within one process's lifetime.
pub struct NonceStore {
    pool: DbPool,
    ttl: Duration,
}

impl NonceStore {
    pub fn new(pool: DbPool, ttl: Duration) -> Self {
        Self { pool, ttl }
    }

    /// Record a nonce as used. Returns `true` only on a confirmed first use.
    /// Returns `false` on replay OR if the backing store errors — i.e. it
    /// **fails closed**, so a database problem rejects logins rather than
    /// silently disabling replay protection.
    pub fn record(&self, nonce: &str) -> bool {
        match self.pool.record_nonce(nonce, self.ttl) {
            Ok(first_use) => first_use,
            Err(e) => {
                log::error!("nonce store error (failing closed): {}", e);
                false
            }
        }
    }
}
