//! Warm, in-memory cache of the home domain's active *signing* keys.
//!
//! ## Why this exists
//!
//! Every signing path decrypts a domain private key at the moment of use
//! (`crate::claim_signing::active_signers` calls
//! `liblinkkeys::crypto::decrypt_private_key`, which runs Argon2id at
//! m=19 MiB, t=3, p=1). That is roughly 50-80 ms and ~19 MiB per key, so a
//! domain with three signing keys pays ~150-250 ms and ~57 MiB for one
//! signing operation. Claim issuance and login assertions are rare, so this
//! is invisible today. Application-key attestation renewal is the first
//! *scheduled, fleet-wide* signing load (see `signing-things-request.md`,
//! "Home-domain signing cost"): at scale it is roughly 1.7 cores of Argon2id
//! and ~470 MiB of concurrent allocation. That path needs a warm signer;
//! this module is it.
//!
//! Existing claim/assertion/login signing paths are UNCHANGED by this module
//! — they keep decrypting on every use. Wiring the attestation path to this
//! cache is a separate change.
//!
//! ## What this is NOT
//!
//! **This cache is not a security boundary.** To use a key the process must
//! decrypt it, and the decryption passphrase lives in the same address
//! space. Anything that can read this process's memory can read both the
//! ciphertext-adjacent passphrase and the warm plaintext key — encrypting
//! the key again in memory would only obfuscate a core-dump scan for
//! key-shaped bytes; Linux has no `CryptProtectMemory` equivalent, so that
//! would be hand-rolled obscurity with a maintenance cost and no real
//! boundary. This module deliberately does not attempt it.
//!
//! On Linux, one process can read another's memory only with the same UID
//! or `CAP_SYS_PTRACE`. Run the server under its own UID; if the threat
//! model is a hostile co-tenant on the same host, the answer is process
//! isolation, or a PKCS#11/KMS interface that keeps the key out of this
//! address space entirely. That interface is a later, separate request —
//! this warm cache must not be allowed to stand in for it.
//!
//! ## What this module does instead
//!
//! Four bounded protections, all real given the above:
//!
//! 1. **`mlock`** the decrypted key's pages so they cannot be paged to swap
//!    or captured in a hibernation image — a real at-rest leak that survives
//!    a process restart. Best-effort: `mlock` can fail under
//!    `RLIMIT_MEMLOCK`; on failure we log once (not per key) and continue,
//!    since refusing to start would be worse than an unlocked key. No-op on
//!    non-Unix targets.
//! 2. **`Zeroizing`** wraps every decrypted key (reusing
//!    `crate::claim_signing::ActiveSigner`, whose `private_key` field is
//!    already `Zeroizing<Vec<u8>>`) so a drop clears it. The key is never
//!    copied into a bare `Vec<u8>` that outlives that guard.
//! 3. **Bounded lifetime.** An entry is evicted and re-derived after
//!    `WARM_SIGNER_TTL_SECONDS` (default 900s / 15 minutes — see
//!    `DEFAULT_TTL_SECONDS` below for the rationale) so a key is never
//!    resident for the whole life of the process. Eviction munlocks and
//!    zeroizes before the memory is freed.
//! 4. **Explicit invalidation** via [`invalidate`] for key rotation/
//!    revocation, so a revoked key is never served warm after the write
//!    that revoked it.
//!
//! Derivation is single-flight: concurrent cold callers block on one shared
//! lock and get the *same* derived set, so a cold-cache stampede (e.g. after
//! a restart) pays Argon2id once, not once per caller.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use liblinkkeys::crypto::SigningAlgorithm;
use zeroize::Zeroize;

use crate::claim_signing::{self, SignerError};
use crate::db::DbPool;

/// Default warm-signer TTL: 15 minutes.
///
/// Chosen as a middle ground: long enough that the attestation-renewal load
/// described in `signing-things-request.md` (up to ~8.3 renewals/sec
/// fleet-wide at a 1-hour attestation lifetime) amortizes the Argon2id cost
/// to effectively zero, but short enough that a decrypted key is never
/// resident for more than a small fraction of even the shortest attestation
/// lifetime under discussion (1 hour) — bounding exposure rather than
/// keeping the key warm for the life of the process.
const DEFAULT_TTL_SECONDS: u64 = 900;

/// Env var overriding [`DEFAULT_TTL_SECONDS`].
const TTL_ENV_VAR: &str = "WARM_SIGNER_TTL_SECONDS";

fn configured_ttl() -> Duration {
    let secs = std::env::var(TTL_ENV_VAR)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TTL_SECONDS);
    Duration::from_secs(secs)
}

/// Error deriving or reusing the warm signer set.
#[derive(Debug)]
pub enum WarmSignerError {
    /// Loading the domain's active keys from the database failed.
    Query(diesel::result::Error),
    /// Decrypting/parsing the active keys failed (see [`SignerError`]).
    Sign(SignerError),
    /// `DOMAIN_KEY_PASSPHRASE` was not set (only returned by
    /// [`with_active_signers`], which reads it on the caller's behalf).
    MissingPassphrase,
}

impl std::fmt::Display for WarmSignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WarmSignerError::Query(e) => write!(f, "loading active domain keys failed: {}", e),
            WarmSignerError::Sign(e) => write!(f, "{}", e),
            WarmSignerError::MissingPassphrase => write!(f, "DOMAIN_KEY_PASSPHRASE not set"),
        }
    }
}

impl std::error::Error for WarmSignerError {}

/// One warm (already-decrypted) domain signing key, borrowed out of a
/// [`WarmSignerSet`]. Never outlives the `Arc<WarmSignerSet>` it came from.
pub struct WarmSigner<'a> {
    pub key_id: &'a str,
    pub algorithm: SigningAlgorithm,
    pub private_key: &'a [u8],
}

/// A snapshot of the domain's active signing keys, decrypted once and kept
/// warm until the cache's TTL expires or [`invalidate`] is called.
///
/// Dropping the last `Arc<WarmSignerSet>` (whether because the cache
/// evicted it or a caller dropped a stray clone after eviction) munlocks and
/// zeroizes every entry's key material.
pub struct WarmSignerSet {
    entries: Vec<WarmEntry>,
    derived_at: Instant,
}

impl WarmSignerSet {
    /// Iterate the warm signers. Borrows live only as long as `self` (i.e.
    /// only as long as the caller keeps its `Arc<WarmSignerSet>` alive).
    pub fn iter(&self) -> impl Iterator<Item = WarmSigner<'_>> + '_ {
        self.entries.iter().map(|e| WarmSigner {
            key_id: &e.key_id,
            algorithm: e.algorithm,
            private_key: &e.private_key,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// One entry's decrypted key plus its mlock bookkeeping. Zeroizes and
/// munlocks on drop (eviction, cache replacement, or TTL-driven re-derive).
struct WarmEntry {
    key_id: String,
    algorithm: SigningAlgorithm,
    private_key: zeroize::Zeroizing<Vec<u8>>,
    mlocked: bool,
}

impl WarmEntry {
    fn new(signer: claim_signing::ActiveSigner) -> Self {
        let mlocked = mlock_bytes(&signer.private_key);
        if mlocked {
            STATS.mlock_successes.fetch_add(1, Ordering::Relaxed);
        } else {
            STATS.mlock_failures.fetch_add(1, Ordering::Relaxed);
            warn_mlock_failure_once();
        }
        WarmEntry {
            key_id: signer.key_id,
            algorithm: signer.algorithm,
            private_key: signer.private_key,
            mlocked,
        }
    }
}

impl Drop for WarmEntry {
    fn drop(&mut self) {
        // Zero the bytes while the pages are still locked (if they were
        // locked at all), then release the lock. Either order leaves at most
        // an instant where locked-but-stale or unlocked-but-zero data
        // exists; zero-first minimizes the window where live key material
        // is both unlocked and unzeroed.
        self.private_key.zeroize();
        if self.mlocked {
            munlock_bytes(&self.private_key);
        }
        STATS.evictions.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(unix)]
fn mlock_bytes(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    // SAFETY: `buf` is a valid, live slice for its full length for the
    // duration of this call; `mlock` only locks the pages backing it and
    // does not mutate or retain the pointer.
    let ret = unsafe { libc::mlock(buf.as_ptr() as *const c_void, buf.len()) };
    ret == 0
}

#[cfg(unix)]
fn munlock_bytes(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    // SAFETY: same validity argument as `mlock_bytes`; `munlock` on a range
    // that was never (successfully) locked is a documented no-op/error we
    // don't need to check here, since callers only invoke this when
    // `mlocked` was recorded true.
    unsafe {
        libc::munlock(buf.as_ptr() as *const c_void, buf.len());
    }
}

#[cfg(not(unix))]
fn mlock_bytes(_buf: &[u8]) -> bool {
    false
}

#[cfg(not(unix))]
fn munlock_bytes(_buf: &[u8]) {}

static MLOCK_WARNED: AtomicBool = AtomicBool::new(false);

fn warn_mlock_failure_once() {
    if MLOCK_WARNED
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        log::warn!(
            "mlock failed for a warm domain signing key; its pages may be \
             swapped to disk or captured in a hibernation image. Check this \
             process's RLIMIT_MEMLOCK. Continuing without mlock protection."
        );
    }
}

/// Process-wide cache slot. A single `Mutex` doubles as the single-flight
/// gate: the thread that finds the cache cold/expired derives while holding
/// the lock, so concurrent callers block on the lock instead of each
/// starting their own Argon2id pass, and unblock straight into a warm hit.
static CACHE: Mutex<Option<Arc<WarmSignerSet>>> = Mutex::new(None);

#[derive(Default)]
struct Counters {
    derivations: AtomicU64,
    hits: AtomicU64,
    evictions: AtomicU64,
    mlock_successes: AtomicU64,
    mlock_failures: AtomicU64,
}

static STATS: Counters = Counters {
    derivations: AtomicU64::new(0),
    hits: AtomicU64::new(0),
    evictions: AtomicU64::new(0),
    mlock_successes: AtomicU64::new(0),
    mlock_failures: AtomicU64::new(0),
};

/// Snapshot of the cache's lifetime counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WarmSignerStats {
    /// Number of times a fresh Argon2id derivation pass actually ran.
    pub derivations: u64,
    /// Number of calls served from an already-warm, unexpired cache.
    pub hits: u64,
    /// Number of individual key entries evicted (zeroized + munlocked).
    pub evictions: u64,
    /// Number of individual keys `mlock` succeeded for.
    pub mlock_successes: u64,
    /// Number of individual keys `mlock` failed for.
    pub mlock_failures: u64,
}

/// Snapshot the cache's counters. Process-wide; not scoped to a single
/// domain or caller.
pub fn stats() -> WarmSignerStats {
    WarmSignerStats {
        derivations: STATS.derivations.load(Ordering::Relaxed),
        hits: STATS.hits.load(Ordering::Relaxed),
        evictions: STATS.evictions.load(Ordering::Relaxed),
        mlock_successes: STATS.mlock_successes.load(Ordering::Relaxed),
        mlock_failures: STATS.mlock_failures.load(Ordering::Relaxed),
    }
}

/// Active signing keys for the home domain, derived once and reused warm
/// until [`DEFAULT_TTL_SECONDS`] (or `WARM_SIGNER_TTL_SECONDS`) elapses or
/// [`invalidate`] is called. Concurrent cold callers single-flight into one
/// Argon2id derivation pass.
///
/// The returned `Arc<WarmSignerSet>` keeps the underlying key material alive
/// only as long as the caller (and the cache, if still warm) holds a
/// reference; drop it when done so eviction can proceed.
pub fn active_signers(
    pool: &DbPool,
    passphrase: &[u8],
) -> Result<Arc<WarmSignerSet>, WarmSignerError> {
    active_signers_with_ttl(pool, passphrase, configured_ttl())
}

/// Same as [`active_signers`] but with an injectable TTL, so tests don't
/// have to sleep out the production default to exercise eviction.
pub fn active_signers_with_ttl(
    pool: &DbPool,
    passphrase: &[u8],
    ttl: Duration,
) -> Result<Arc<WarmSignerSet>, WarmSignerError> {
    let mut slot = CACHE.lock().unwrap_or_else(|e| e.into_inner());

    if let Some(set) = slot.as_ref() {
        if set.derived_at.elapsed() < ttl {
            STATS.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(Arc::clone(set));
        }
    }

    // Cold or expired: derive while still holding the lock. Any other
    // thread calling in concurrently blocks here until this finishes, then
    // observes the fresh, unexpired entry above and takes the hit path —
    // that's the single-flight property.
    let fresh = derive(pool, passphrase)?;
    let arc = Arc::new(fresh);
    *slot = Some(Arc::clone(&arc));
    // Dropping the previous `Option<Arc<...>>` value here (via the
    // assignment above) drops the old `WarmSignerSet` once no other caller
    // still holds a clone, which zeroizes/munlocks/counts its entries.
    Ok(arc)
}

fn derive(pool: &DbPool, passphrase: &[u8]) -> Result<WarmSignerSet, WarmSignerError> {
    let keys = pool
        .list_active_domain_keys()
        .map_err(WarmSignerError::Query)?;
    // Count the attempt here, right before the expensive Argon2id loop
    // starts, so a plain DB-query failure above isn't misreported as a paid
    // derivation.
    STATS.derivations.fetch_add(1, Ordering::Relaxed);
    let signers =
        claim_signing::active_signers(&keys, passphrase).map_err(WarmSignerError::Sign)?;
    let entries = signers.into_iter().map(WarmEntry::new).collect();
    Ok(WarmSignerSet {
        entries,
        derived_at: Instant::now(),
    })
}

/// Run `f` against the home domain's warm active signers, deriving them if
/// needed. Reads `DOMAIN_KEY_PASSPHRASE` from the environment itself (the
/// convention every other signing call site in this crate already follows —
/// see e.g. `services::attestation::mint_signing_request`), so callers don't
/// have to thread the passphrase through.
///
/// The `Arc<WarmSignerSet>` backing `f`'s argument is held only for the
/// duration of this call, so `f` should do its signing and return promptly
/// rather than stashing the reference.
pub fn with_active_signers<T>(
    pool: &DbPool,
    f: impl FnOnce(&WarmSignerSet) -> T,
) -> Result<T, WarmSignerError> {
    let passphrase =
        std::env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| WarmSignerError::MissingPassphrase)?;
    let set = active_signers(pool, passphrase.as_bytes())?;
    Ok(f(&set))
}

/// Force the next call to [`active_signers`] to re-derive from the database,
/// regardless of TTL. Call this after any write to the domain's key set
/// (rotation, revocation) so a revoked/rotated key is never served warm.
pub fn invalidate() {
    let mut slot = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *slot = None;
    // Dropping the `Some(arc)` above (if present) drops the `WarmSignerSet`
    // once no caller still holds a clone, triggering zeroize/munlock.
}
