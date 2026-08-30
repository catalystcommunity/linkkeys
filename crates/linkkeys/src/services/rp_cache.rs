//! The relying party's persistent cache of remote key material
//! (signing-things-request.md, "RP cache" / "RP-facing operations" /
//! "Public-key caches").
//!
//! An application asks ITS OWN RP server for cached peer keys. The RP does
//! the discovery, the fetch, the verification, and the caching; the
//! application never calls a remote home domain itself when it uses a
//! regular RP. That is what keeps repeated home-domain reads out of normal
//! peer message verification.
//!
//! # What this module does and does not do
//!
//! It resolves a remote domain's signing keys (backed by `db::peer_keys` plus
//! a freshness record here) and a remote application instance's signed
//! attestations + revocations (backed by `db::rp_cache`, stored verbatim). It
//! validates every signed record with [`liblinkkeys::application_keys`]
//! BEFORE it is cached or returned, and validates freshness again at every
//! read. It never invents trust: a record whose signature does not verify is
//! never stored and never returned, and a stale answer is always marked
//! `"stale"`, never presented as current trust.
//!
//! # Composition
//!
//! `resolve_application_keys` calls the SAME domain-key resolution
//! `resolve_domain_keys` uses (`resolve_domain_keys_at`) to get the
//! home-domain keys + revocations an application SDK needs to verify the
//! attestations for itself — "one call must be enough". This also means the
//! domain-key cache (`peer_keys` + `rp_domain_key_cache`) is the single
//! source of truth for a remote domain's signing keys; this module never
//! stores a second copy of them next to the application-key cache.
//!
//! # Deliberate scope decision: domain revocation certs are not persisted
//!
//! The design explicitly scopes the domain-key freshness record to "you only
//! need the freshness record" (key material stays in `peer_keys`). Following
//! that literally, this module does not add a table for peer domains'
//! `RevocationCertificate`s. `resolve_domain_keys` populates `revocations` in
//! its response only when it just performed a live fetch ("refreshed"); a
//! `"fresh"` or `"stale"` cache-served answer returns an empty revocations
//! list — honest, since the RP genuinely holds none across a restart, and
//! never a correctness problem, because the CACHED `keys` list was already
//! filtered of anything provably revoked at the time it was fetched.

use chrono::{DateTime, Duration, Utc};
use liblinkkeys::application_keys::{self as ak, ApplicationKeyRef, InstanceRef};
use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    ApplicationKeyAttestation, ApplicationKeyRevocation, DomainPublicKey,
    GetApplicationKeysRequest, GetApplicationKeysResponse, GetRevocationsRequest,
    GetRevocationsResponse, RevocationCertificate, RpResolveApplicationKeysRequest,
    RpResolveApplicationKeysResponse, RpResolveDomainKeysRequest, RpResolveDomainKeysResponse,
    SignedApplicationKeyAttestation,
};
use std::collections::HashMap;
use std::sync::{Arc, Condvar, LazyLock, Mutex};

use crate::config::{nonneg_i64_env, nonzero_u64_env};
use crate::conversions::get_domain_name;
use crate::db::models::{PeerKey, RpApplicationKeyCacheEntry};
use crate::db::DbPool;
use crate::net::Net;

// ---------------------------------------------------------------------------
// Configuration (env; read fresh each call, never cached in a LazyLock, so a
// test can set an env var before a call and see it take effect immediately —
// the same reasoning as `services::revocations`'s env helpers).
// ---------------------------------------------------------------------------

/// A floor on freshness, not a ceiling: `max_cache_age_seconds` on a request
/// may only ask for material FRESHER than this, never staler
/// ([`clamp_max_age`]).
fn max_age_seconds() -> i64 {
    nonzero_u64_env("RP_CACHE_MAX_AGE_SECONDS", 3600).unwrap_or(3600) as i64
}

/// How long before the allowed age runs out a frequently-used entry is
/// refreshed proactively, instead of waiting for a hard miss.
fn refresh_ahead_seconds() -> i64 {
    nonneg_i64_env("RP_CACHE_REFRESH_AHEAD_SECONDS", 300).unwrap_or(300)
}

/// Bound on the persisted cache: the least-recently-used domain freshness
/// records / application-key cache entries are evicted beyond this count.
fn max_entries() -> i64 {
    nonzero_u64_env("RP_CACHE_MAX_ENTRIES", 10_000).unwrap_or(10_000) as i64
}

/// A second, independently-tunable freshness bound on revocation checks
/// specifically — typically shorter than `RP_CACHE_MAX_AGE_SECONDS`, so an
/// operator can force more frequent revocation checks without shortening the
/// whole cache's lifetime.
fn revocation_check_interval_seconds() -> i64 {
    nonzero_u64_env("RP_CACHE_REVOCATION_CHECK_INTERVAL_SECONDS", 900).unwrap_or(900) as i64
}

/// Tolerated clock skew when checking attestation/key temporal validity.
/// Matches the home domain's own `APPLICATION_KEY_CLOCK_SKEW_SECONDS`
/// default; not independently configurable because this task's env surface
/// is limited to the four cache-shape knobs above.
const CLOCK_SKEW_SECONDS: i64 = 300;

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

fn bad_request(message: impl Into<String>) -> ServiceError {
    ServiceError {
        code: 400,
        message: message.into(),
    }
}

/// Internal failures are logged with their cause; the caller only ever learns
/// "internal error" — this crosses the anonymous-adjacent RP boundary and
/// must never leak database detail.
fn internal(context: &str, cause: impl std::fmt::Display) -> ServiceError {
    log::error!("rp cache: {context}: {cause}");
    ServiceError {
        code: 500,
        message: "internal error".to_string(),
    }
}

fn parse_rfc3339(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// Seconds since `then`. An unparseable timestamp (only reachable via DB
/// corruption) is treated as maximally stale — fail toward a refetch, never
/// toward silently trusting garbage as fresh.
fn age_seconds(now: DateTime<Utc>, then: &str) -> i64 {
    match parse_rfc3339(then) {
        Some(t) => (now - t).num_seconds().max(0),
        None => i64::MAX,
    }
}

/// `requested` can only make the effective age stricter (smaller) than
/// `policy`, never weaker. A missing or negative request falls back to
/// policy.
fn clamp_max_age(policy: i64, requested: Option<i64>) -> i64 {
    match requested {
        Some(r) if r >= 0 => r.min(policy),
        _ => policy,
    }
}

fn status_rank(status: &str) -> u8 {
    match status {
        "refreshed" => 2,
        "fresh" => 1,
        _ => 0, // "stale" and anything unrecognized
    }
}

/// The combined freshness of two composed answers is never better than the
/// worse of the two — never silently present a part backed by stale data as
/// an overall "fresh" or "refreshed" result.
fn combine_status(a: &str, b: &str) -> String {
    if status_rank(a) <= status_rank(b) {
        a.to_string()
    } else {
        b.to_string()
    }
}

// ---------------------------------------------------------------------------
// Single-flight coalescing: concurrent callers asking for the SAME cache key
// (domain, or subject+domain+application+instance) share one fetch. The
// leader (the caller that finds no in-flight entry) runs `f` and hands its
// result to every waiter; nobody else touches the network or the database
// for this key while a fetch is in progress. Same idea as
// `services::pubkey_cache`'s `InFlight`, kept separate because the values
// here are typed response structs, not encoded bytes.
// ---------------------------------------------------------------------------

struct InFlight<T> {
    result: Mutex<Option<Result<T, ServiceError>>>,
    cv: Condvar,
}

impl<T: Clone> InFlight<T> {
    fn new() -> Self {
        InFlight {
            result: Mutex::new(None),
            cv: Condvar::new(),
        }
    }

    fn wait(&self) -> Result<T, ServiceError> {
        let mut guard = self.result.lock().unwrap_or_else(|e| e.into_inner());
        while guard.is_none() {
            guard = self.cv.wait(guard).unwrap_or_else(|e| e.into_inner());
        }
        guard.clone().expect("checked is_none in the loop above")
    }

    fn finish(&self, result: Result<T, ServiceError>) {
        {
            let mut guard = self.result.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some(result);
        }
        self.cv.notify_all();
    }
}

/// The four identifiers that name one remote application instance.
///
/// A STRUCTURED key, not a joined string. Joining these with a separator is a
/// collision waiting to happen: none of the four is charset-restricted on this
/// path, because they name a REMOTE peer's instance rather than one this
/// domain enrolled, so `("y|z", "w")` and `("y", "z|w")` would join to the
/// same text. In a single-flight registry a collision does not merely mix up
/// a cache entry — the follower receives the LEADER's result, which is another
/// subject's key material. Deriving `Hash`/`Eq` per field makes that
/// impossible by construction.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct ApplicationFlightKey {
    subject_user_id: String,
    subject_domain: String,
    application_id: String,
    instance_id: String,
}

struct FlightRegistry<K, T> {
    inner: Mutex<HashMap<K, Arc<InFlight<T>>>>,
}

impl<K: Eq + std::hash::Hash + Clone, T: Clone> FlightRegistry<K, T> {
    fn new() -> Self {
        FlightRegistry {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Run `f` for `key`, coalescing concurrent callers. Only the leader
    /// (the first caller to observe no in-flight entry for `key`) calls `f`;
    /// every other concurrent caller for the same key blocks and receives a
    /// clone of the leader's result. The entry is removed before the leader
    /// finishes, so the NEXT call for this key always re-fetches rather than
    /// serving a memoized answer forever (durability lives in the database,
    /// not here).
    fn run<F>(&self, key: &K, f: F) -> Result<T, ServiceError>
    where
        F: FnOnce() -> Result<T, ServiceError>,
    {
        enum Action<T> {
            Wait(Arc<InFlight<T>>),
            Lead(Arc<InFlight<T>>),
        }

        let action = {
            let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(inflight) = map.get(key) {
                Action::Wait(Arc::clone(inflight))
            } else {
                let inflight = Arc::new(InFlight::new());
                map.insert(key.clone(), Arc::clone(&inflight));
                Action::Lead(inflight)
            }
        };

        match action {
            Action::Wait(inflight) => inflight.wait(),
            Action::Lead(inflight) => {
                let result = f();
                {
                    let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                    map.remove(key);
                }
                inflight.finish(result.clone());
                result
            }
        }
    }
}

static DOMAIN_FLIGHTS: LazyLock<FlightRegistry<String, RpResolveDomainKeysResponse>> =
    LazyLock::new(FlightRegistry::new);
static APPLICATION_FLIGHTS: LazyLock<
    FlightRegistry<ApplicationFlightKey, RpResolveApplicationKeysResponse>,
> = LazyLock::new(FlightRegistry::new);

// ---------------------------------------------------------------------------
// Domain keys
// ---------------------------------------------------------------------------

pub fn resolve_domain_keys(
    pool: &DbPool,
    net: &Net,
    rt: &tokio::runtime::Handle,
    request: RpResolveDomainKeysRequest,
) -> Result<RpResolveDomainKeysResponse, ServiceError> {
    let domain = request.domain.trim();
    if domain.is_empty() {
        return Err(bad_request("domain must not be empty"));
    }
    resolve_domain_keys_at(
        pool,
        net,
        rt,
        domain,
        request.max_cache_age_seconds,
        Utc::now(),
    )
}

/// The reusable core: `resolve_application_keys` calls this too, so the
/// domain-key half of "one call must be enough" is always served by the same
/// cache and freshness rules.
fn resolve_domain_keys_at(
    pool: &DbPool,
    net: &Net,
    rt: &tokio::runtime::Handle,
    domain: &str,
    requested_max_age: Option<i64>,
    now: DateTime<Utc>,
) -> Result<RpResolveDomainKeysResponse, ServiceError> {
    let effective_max_age = clamp_max_age(max_age_seconds(), requested_max_age);
    let rev_interval = revocation_check_interval_seconds();
    let ahead = refresh_ahead_seconds();

    let meta = pool
        .get_rp_domain_key_cache_meta(domain)
        .map_err(|e| internal("reading domain key cache metadata", e))?;

    if let Some(m) = &meta {
        let fetch_remaining = effective_max_age - age_seconds(now, &m.fetched_at);
        let rev_remaining = rev_interval - age_seconds(now, &m.revocations_checked_at);
        if fetch_remaining > ahead && rev_remaining > ahead {
            let _ = pool.touch_rp_domain_key_cache_meta(domain, now);
            let keys = load_domain_keys_from_cache(pool, domain)?;
            return Ok(RpResolveDomainKeysResponse {
                domain: domain.to_string(),
                keys,
                revocations: Vec::new(),
                fetched_at: m.fetched_at.clone(),
                revocations_checked_at: m.revocations_checked_at.clone(),
                cache_status: "fresh".to_string(),
            });
        }
    }

    DOMAIN_FLIGHTS.run(&domain.to_string(), || {
        match rt.block_on(do_domain_refresh(pool, net, domain, now)) {
            Ok((keys, revocations)) => Ok(RpResolveDomainKeysResponse {
                domain: domain.to_string(),
                keys,
                revocations,
                fetched_at: now.to_rfc3339(),
                revocations_checked_at: now.to_rfc3339(),
                cache_status: "refreshed".to_string(),
            }),
            Err(fetch_err) => {
                if let Some(m) = &meta {
                    log::warn!(
                        "resolve-domain-keys: {domain} unreachable, serving stale cache: {fetch_err}"
                    );
                    let keys = load_domain_keys_from_cache(pool, domain)?;
                    Ok(RpResolveDomainKeysResponse {
                        domain: domain.to_string(),
                        keys,
                        revocations: Vec::new(),
                        fetched_at: m.fetched_at.clone(),
                        revocations_checked_at: m.revocations_checked_at.clone(),
                        cache_status: "stale".to_string(),
                    })
                } else {
                    Err(ServiceError {
                        code: 502,
                        message: format!(
                            "home domain {domain} is unreachable and no cached keys are \
                             available: {fetch_err}"
                        ),
                    })
                }
            }
        }
    })
}

/// Best-effort domain-key lookup for a context that is already degraded
/// (serving a stale application-key answer): never let a secondary failure
/// here turn an otherwise-usable stale answer into a hard error.
fn domain_part_or_empty(
    pool: &DbPool,
    net: &Net,
    rt: &tokio::runtime::Handle,
    domain: &str,
    now: DateTime<Utc>,
) -> RpResolveDomainKeysResponse {
    resolve_domain_keys_at(pool, net, rt, domain, None, now).unwrap_or_else(|e| {
        log::warn!(
            "resolve-application-keys: domain key lookup for {domain} failed: {}",
            e.message
        );
        RpResolveDomainKeysResponse {
            domain: domain.to_string(),
            keys: Vec::new(),
            revocations: Vec::new(),
            fetched_at: String::new(),
            revocations_checked_at: String::new(),
            cache_status: "stale".to_string(),
        }
    })
}

fn load_domain_keys_from_cache(
    pool: &DbPool,
    domain: &str,
) -> Result<Vec<DomainPublicKey>, ServiceError> {
    if domain == get_domain_name() {
        let keys = pool
            .list_active_domain_keys()
            .map_err(|e| internal("reading local domain keys", e))?;
        return Ok(keys.iter().map(Into::into).collect());
    }
    let peers = pool
        .list_peer_keys_for_domain(domain)
        .map_err(|e| internal("reading cached peer keys", e))?;
    Ok(peers
        .iter()
        .filter(|k| k.revoked_at.is_none())
        .map(peer_key_to_domain_public_key)
        .collect())
}

/// `peer_keys` does not retain the remote key's own creation time (only
/// `first_seen`, which is not exposed on the domain-agnostic `PeerKey`), so
/// `created_at` is left empty here. This is safe: every validity check
/// (`check_signing_key_valid`, `signing_key_validity`) consults only
/// `expires_at`/`revoked_at`, never `created_at`.
fn peer_key_to_domain_public_key(k: &PeerKey) -> DomainPublicKey {
    DomainPublicKey {
        key_id: k.key_id.clone(),
        public_key: k.public_key.clone(),
        fingerprint: k.fingerprint.clone(),
        algorithm: k.algorithm.clone(),
        key_usage: k.key_usage.clone(),
        created_at: String::new(),
        expires_at: k.expires_at.clone(),
        revoked_at: k.revoked_at.clone(),
        signed_by_key_id: None,
        key_signature: None,
    }
}

/// Fetch `domain`'s current trusted signing keys (reusing
/// [`crate::web::rp::fetch_domain_keys`] for the DNS discovery, TOFU pin
/// check, and best-effort revocation application — never a second discovery
/// path) plus its revocation certs, then persist the freshness record and the
/// key material (`peer_keys`).
async fn do_domain_refresh(
    pool: &DbPool,
    net: &Net,
    domain: &str,
    now: DateTime<Utc>,
) -> Result<(Vec<DomainPublicKey>, Vec<RevocationCertificate>), String> {
    let (keys, revocations) = fetch_domain_keys_and_revocations(pool, net, domain).await?;
    persist_domain_keys(pool, domain, &keys);
    if let Err(e) = pool.upsert_rp_domain_key_cache_meta(domain, now, now, now) {
        log::error!("rp cache: recording domain key freshness for {domain} failed: {e}");
    }
    if let Err(e) = pool.evict_oldest_rp_domain_key_cache(max_entries()) {
        log::warn!("rp cache: domain key cache eviction failed: {e}");
    }
    Ok((keys, revocations))
}

async fn fetch_domain_keys_and_revocations(
    pool: &DbPool,
    net: &Net,
    domain: &str,
) -> Result<(Vec<DomainPublicKey>, Vec<RevocationCertificate>), String> {
    let keys = crate::web::rp::fetch_domain_keys(pool, net, domain)
        .await
        .map_err(|e| e.to_string())?;
    let revocations = if domain == get_domain_name() {
        crate::services::revocations::serve(pool, None)
    } else {
        fetch_remote_revocations(net, domain, &keys).await
    };
    Ok((keys, revocations))
}

fn persist_domain_keys(pool: &DbPool, domain: &str, keys: &[DomainPublicKey]) {
    if domain == get_domain_name() {
        return; // our own keys already live in `domain_keys`
    }
    for key in keys {
        let peer = PeerKey {
            domain: domain.to_string(),
            key_id: key.key_id.clone(),
            public_key: key.public_key.clone(),
            algorithm: key.algorithm.clone(),
            fingerprint: key.fingerprint.clone(),
            key_usage: key.key_usage.clone(),
            expires_at: key.expires_at.clone(),
            revoked_at: key.revoked_at.clone(),
        };
        if let Err(e) = pool.cache_peer_key(&peer) {
            log::warn!(
                "rp cache: caching peer key {} for {domain} failed: {e}",
                key.key_id
            );
        }
    }
}

/// Best-effort: a domain's revocation certs are supplementary (the `keys`
/// list [`crate::web::rp::fetch_domain_keys`] returns is already filtered of
/// anything it could provably revoke), so a failure here never fails the
/// whole domain-key resolve.
async fn fetch_remote_revocations(
    net: &Net,
    domain: &str,
    trusted_keys: &[DomainPublicKey],
) -> Vec<RevocationCertificate> {
    match fetch_remote_revocations_inner(net, domain, trusted_keys).await {
        Ok(certs) => certs,
        Err(e) => {
            log::warn!("rp cache: fetching revocations for {domain} failed (continuing): {e}");
            Vec::new()
        }
    }
}

async fn fetch_remote_revocations_inner(
    net: &Net,
    domain: &str,
    trusted_keys: &[DomainPublicKey],
) -> Result<Vec<RevocationCertificate>, String> {
    let (addr, hostname, fingerprints) = discover(net, domain).await?;
    let since = (Utc::now() - Duration::days(crate::services::revocations::fetch_default_days()))
        .to_rfc3339();
    let payload = liblinkkeys::generated::encode_get_revocations_request(&GetRevocationsRequest {
        since: Some(since),
    });
    let resp_bytes = net
        .rpc
        .call(
            &addr,
            &hostname,
            fingerprints,
            None,
            "DomainKeys",
            "get-revocations",
            payload,
            None,
        )
        .await
        .map_err(|e| e.to_string())?;
    let resp: GetRevocationsResponse =
        liblinkkeys::generated::decode_get_revocations_response(&resp_bytes)
            .map_err(|e| e.to_string())?;
    Ok(resp
        .revocations
        .into_iter()
        .filter(|c| {
            liblinkkeys::revocation::verify_revocation_certificate(c, trusted_keys, domain).is_ok()
        })
        .collect())
}

/// Resolve `domain`'s CSIL-RPC transport target and DNS-pinned fingerprint
/// set. `crate::web::rp` keeps its own copy of this lookup private and is
/// reused as-is (via `fetch_domain_keys`) for the TOFU-pinned key fetch
/// itself; this is ONLY for the supplementary calls
/// (`DomainKeys/get-revocations`, `ApplicationKeys/get-application-keys`)
/// that `fetch_domain_keys` does not expose the resolved address for.
/// Deliberately not a "second discovery path": it calls the exact same
/// public `liblinkkeys::dns` primitives `web::rp`'s private helpers do, it
/// does not re-derive the TOFU pin-check policy (trust for verification
/// always comes from `fetch_domain_keys`'s own pin-checked key set, never
/// from this), and it exists only because changing `fetch_domain_keys`'s
/// signature would ripple across its other 8 call sites, which is out of
/// scope here.
async fn discover(net: &Net, domain: &str) -> Result<(String, String, Vec<String>), String> {
    let dns_name = liblinkkeys::dns::linkkeys_dns_name(domain);
    let txts = net
        .dns
        .txt_lookup(&dns_name)
        .await
        .map_err(|e| format!("_linkkeys lookup for {domain} failed: {e}"))?;
    let record = txts
        .iter()
        .find_map(|t| liblinkkeys::dns::parse_linkkeys_txt(t).ok())
        .ok_or_else(|| format!("no valid _linkkeys record for {domain}"))?;
    let fingerprints: Vec<String> = record
        .fingerprints
        .iter()
        .filter(|f| liblinkkeys::dns::is_valid_fingerprint(f))
        .cloned()
        .collect();
    if fingerprints.is_empty() {
        return Err(format!(
            "_linkkeys record for {domain} publishes no valid fingerprints"
        ));
    }

    let apis_name = liblinkkeys::dns::linkkeys_apis_dns_name(domain);
    let apis_txts = net
        .dns
        .txt_lookup(&apis_name)
        .await
        .map_err(|e| format!("_linkkeys_apis lookup for {domain} failed: {e}"))?;
    let apis = apis_txts
        .iter()
        .find_map(|t| liblinkkeys::dns::parse_linkkeys_apis_txt(t).ok())
        .ok_or_else(|| format!("no valid _linkkeys_apis record for {domain}"))?;
    let addr = apis
        .tcp
        .ok_or_else(|| format!("_linkkeys_apis for {domain} advertises no tcp= endpoint"))?;
    let hostname = linkkeys_rpc_client::extract_hostname(&addr).to_string();
    Ok((addr, hostname, fingerprints))
}

// ---------------------------------------------------------------------------
// Application keys
// ---------------------------------------------------------------------------

pub fn resolve_application_keys(
    pool: &DbPool,
    net: &Net,
    rt: &tokio::runtime::Handle,
    request: RpResolveApplicationKeysRequest,
) -> Result<RpResolveApplicationKeysResponse, ServiceError> {
    let subject_user_id = request.subject_user_id.trim();
    let subject_domain = request.subject_domain.trim();
    let application_id = request.application_id.trim();
    let instance_id = request.instance_id.trim();
    if subject_user_id.is_empty()
        || subject_domain.is_empty()
        || application_id.is_empty()
        || instance_id.is_empty()
    {
        return Err(bad_request(
            "subject_user_id, subject_domain, application_id, and instance_id are all required",
        ));
    }
    let now = Utc::now();
    let effective_max_age = clamp_max_age(max_age_seconds(), request.max_cache_age_seconds);
    let rev_interval = revocation_check_interval_seconds();
    let ahead = refresh_ahead_seconds();

    let entry = pool
        .find_rp_application_key_cache_entry(
            subject_user_id,
            subject_domain,
            application_id,
            instance_id,
        )
        .map_err(|e| internal("reading application key cache entry", e))?;

    if let Some(e) = &entry {
        let fetch_remaining = effective_max_age - age_seconds(now, &e.fetched_at);
        let rev_remaining = rev_interval - age_seconds(now, &e.revocations_checked_at);
        if fetch_remaining > ahead && rev_remaining > ahead {
            let _ = pool.touch_rp_application_key_cache_entry(&e.id, now);
            let (attestations, revocations) = load_cached_records(pool, &e.id)?;
            let domain_part = resolve_domain_keys_at(pool, net, rt, subject_domain, None, now)?;
            return Ok(build_app_response(
                subject_user_id,
                subject_domain,
                application_id,
                instance_id,
                attestations,
                revocations,
                domain_part.keys,
                domain_part.revocations,
                e.fetched_at.clone(),
                e.revocations_checked_at.clone(),
                combine_status("fresh", &domain_part.cache_status),
            ));
        }
    }

    let identity_key = ApplicationFlightKey {
        subject_user_id: subject_user_id.to_string(),
        subject_domain: subject_domain.to_string(),
        application_id: application_id.to_string(),
        instance_id: instance_id.to_string(),
    };
    let entry_for_stale_fallback = entry.clone();

    APPLICATION_FLIGHTS.run(&identity_key, || {
        match rt.block_on(fetch_and_verify_application_keys(
            pool,
            net,
            subject_user_id,
            subject_domain,
            application_id,
            instance_id,
            now,
        )) {
            Ok(fetched) => {
                persist_application_keys(
                    pool,
                    subject_user_id,
                    subject_domain,
                    application_id,
                    instance_id,
                    &fetched,
                    now,
                );
                let attestations = fetched
                    .attestations
                    .iter()
                    .map(|r| r.signed.clone())
                    .collect();
                Ok(build_app_response(
                    subject_user_id,
                    subject_domain,
                    application_id,
                    instance_id,
                    attestations,
                    fetched.revocations,
                    fetched.domain_keys,
                    fetched.domain_revocations,
                    now.to_rfc3339(),
                    now.to_rfc3339(),
                    combine_status("refreshed", &fetched.domain_status),
                ))
            }
            Err(fetch_err) => {
                if let Some(e) = &entry_for_stale_fallback {
                    log::warn!(
                        "resolve-application-keys: {subject_domain} unreachable, serving stale \
                         cache for {application_id}/{instance_id}: {fetch_err}"
                    );
                    let (attestations, revocations) = load_cached_records(pool, &e.id)?;
                    let domain_part = domain_part_or_empty(pool, net, rt, subject_domain, now);
                    Ok(build_app_response(
                        subject_user_id,
                        subject_domain,
                        application_id,
                        instance_id,
                        attestations,
                        revocations,
                        domain_part.keys,
                        domain_part.revocations,
                        e.fetched_at.clone(),
                        e.revocations_checked_at.clone(),
                        "stale".to_string(),
                    ))
                } else {
                    Err(ServiceError {
                        code: 502,
                        message: format!(
                            "home domain {subject_domain} is unreachable and no cached \
                             application keys exist for this instance: {fetch_err}"
                        ),
                    })
                }
            }
        }
    })
}

struct VerifiedAttestationRecord {
    key_id: String,
    signed: SignedApplicationKeyAttestation,
    attestation_expires_at: String,
    verified_by_key_ids: String,
}

struct FetchedApplicationKeys {
    attestations: Vec<VerifiedAttestationRecord>,
    revocations: Vec<ApplicationKeyRevocation>,
    domain_keys: Vec<DomainPublicKey>,
    domain_revocations: Vec<RevocationCertificate>,
    /// Always `"refreshed"` today (this struct is only built after a live
    /// fetch); kept as a field rather than a literal so a future push-update
    /// path (design: "must update the same cache records") can report
    /// something other than "refreshed" without changing every call site.
    domain_status: String,
}

/// Fetch, verify, and classify one remote application instance's keys.
/// Nothing here writes to the database — see [`persist_application_keys`].
/// Verification is entirely delegated to
/// [`liblinkkeys::application_keys::verify_application_key_set`] and
/// [`liblinkkeys::application_keys::verify_revocation`]; this function only
/// decides WHICH already-verified records to keep (attaching the original
/// signed bytes and the verifying home-domain key ids) and never re-derives
/// a quorum, temporal, or signature rule itself.
#[allow(clippy::too_many_arguments)]
async fn fetch_and_verify_application_keys(
    pool: &DbPool,
    net: &Net,
    subject_user_id: &str,
    subject_domain: &str,
    application_id: &str,
    instance_id: &str,
    now: DateTime<Utc>,
) -> Result<FetchedApplicationKeys, String> {
    let (domain_keys, domain_revocations) =
        do_domain_refresh(pool, net, subject_domain, now).await?;

    let resp: GetApplicationKeysResponse = if subject_domain == get_domain_name() {
        crate::services::application_keys::get_application_keys(
            pool,
            GetApplicationKeysRequest {
                subject_user_id: subject_user_id.to_string(),
                application_id: application_id.to_string(),
                instance_id: instance_id.to_string(),
            },
            now,
        )
        .map_err(|e| e.message)?
    } else {
        fetch_remote_application_keys(
            net,
            subject_domain,
            subject_user_id,
            application_id,
            instance_id,
        )
        .await?
    };

    if resp.subject_domain != subject_domain {
        return Err(format!(
            "{subject_domain} answered with a different subject_domain ({})",
            resp.subject_domain
        ));
    }

    let instance = InstanceRef {
        subject_user_id,
        subject_domain,
        application_id,
        instance_id,
    };
    let verified = ak::verify_application_key_set(
        &resp.keys,
        &resp.revocations,
        &domain_keys,
        &instance,
        now,
        CLOCK_SKEW_SECONDS,
    );
    for rejected in &verified.rejected {
        log::warn!(
            "rp cache: rejected {} for {subject_user_id}@{subject_domain}/{application_id}/{instance_id}: {}",
            rejected.what, rejected.reason
        );
    }

    // Only a record whose signature actually verified reaches here (never a
    // rejected one) — `verify_application_key_set` guarantees that.
    let mut originals: HashMap<String, &SignedApplicationKeyAttestation> = HashMap::new();
    for signed in &resp.keys {
        if let Ok(a) =
            liblinkkeys::generated::decode_application_key_attestation(&signed.attestation)
        {
            originals.insert(a.key_id.clone(), signed);
        }
    }

    let mut attestations = Vec::with_capacity(verified.keys.len());
    for vk in &verified.keys {
        let Some(signed) = originals.get(&vk.attestation.key_id) else {
            continue;
        };
        attestations.push(VerifiedAttestationRecord {
            key_id: vk.attestation.key_id.clone(),
            signed: (*signed).clone(),
            attestation_expires_at: vk.attestation.attestation_expires_at.clone(),
            verified_by_key_ids: verifying_domain_key_ids(signed, &domain_keys, subject_domain),
        });
    }

    // Mirror `verify_application_key_set`'s own acceptance test for
    // revocations (same pure function, same inputs) to learn WHICH original
    // records verified, so only those are cached/returned verbatim.
    let key_refs: Vec<ApplicationKeyRef> = verified
        .keys
        .iter()
        .map(|vk| attested_key_ref(&vk.attestation))
        .collect();
    let mut revocations = Vec::new();
    for rev in &resp.revocations {
        if ak::verify_revocation(rev, &key_refs, &instance).is_ok() {
            revocations.push(rev.clone());
        }
    }

    Ok(FetchedApplicationKeys {
        attestations,
        revocations,
        domain_keys,
        domain_revocations,
        domain_status: "refreshed".to_string(),
    })
}

fn attested_key_ref(a: &ApplicationKeyAttestation) -> ApplicationKeyRef {
    ApplicationKeyRef {
        key_id: a.key_id.clone(),
        key_usage: a.key_usage.clone(),
        algorithm: a.algorithm.clone(),
        public_key: a.public_key.clone(),
        fingerprint: a.fingerprint.clone(),
        created_at: a.key_created_at.clone(),
        expires_at: a.key_expires_at.clone(),
        revoked_at: None,
    }
}

/// Which of `domain_keys` actually produced a valid signature over
/// `signed`'s attestation bytes — the design's "which home-domain keys
/// verified each attestation" record. Uses the exact same primitives
/// `verify_attestation_signature` does (`check_signing_key_valid`,
/// `crypto::resolve_and_verify`) so this never disagrees with the real
/// verification decision; it only collects every match instead of stopping
/// at the first.
fn verifying_domain_key_ids(
    signed: &SignedApplicationKeyAttestation,
    domain_keys: &[DomainPublicKey],
    expected_domain: &str,
) -> String {
    let message = ak::attestation_signature_input(&signed.attestation);
    let mut ids = Vec::new();
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
            ids.push(key.key_id.clone());
        }
    }
    ids.join(",")
}

async fn fetch_remote_application_keys(
    net: &Net,
    domain: &str,
    subject_user_id: &str,
    application_id: &str,
    instance_id: &str,
) -> Result<GetApplicationKeysResponse, String> {
    let (addr, hostname, fingerprints) = discover(net, domain).await?;
    let payload =
        liblinkkeys::generated::encode_get_application_keys_request(&GetApplicationKeysRequest {
            subject_user_id: subject_user_id.to_string(),
            application_id: application_id.to_string(),
            instance_id: instance_id.to_string(),
        });
    let resp_bytes = net
        .rpc
        .call(
            &addr,
            &hostname,
            fingerprints,
            None,
            "ApplicationKeys",
            "get-application-keys",
            payload,
            None,
        )
        .await
        .map_err(|e| e.to_string())?;
    liblinkkeys::generated::decode_get_application_keys_response(&resp_bytes)
        .map_err(|e| e.to_string())
}

/// Persist a freshly-verified fetch. Best-effort per row: a write failure is
/// logged and skipped rather than turning an already-verified, in-memory
/// answer into a hard error for this call — durability is a "next restart"
/// concern, not a "this response" concern.
fn persist_application_keys(
    pool: &DbPool,
    subject_user_id: &str,
    subject_domain: &str,
    application_id: &str,
    instance_id: &str,
    fetched: &FetchedApplicationKeys,
    now: DateTime<Utc>,
) {
    let entry: RpApplicationKeyCacheEntry = match pool.upsert_rp_application_key_cache_entry(
        subject_user_id,
        subject_domain,
        application_id,
        instance_id,
        now,
        now,
        now,
    ) {
        Ok(entry) => entry,
        Err(e) => {
            log::error!(
                "rp cache: upserting cache entry for {subject_user_id}@{subject_domain}/\
                 {application_id}/{instance_id} failed: {e}"
            );
            return;
        }
    };

    for rec in &fetched.attestations {
        let expires = parse_rfc3339(&rec.attestation_expires_at).unwrap_or(now);
        let bytes = liblinkkeys::generated::encode_signed_application_key_attestation(&rec.signed);
        if let Err(e) = pool.upsert_rp_application_key_attestation(
            &entry.id,
            &rec.key_id,
            &bytes,
            expires,
            &rec.verified_by_key_ids,
            now,
        ) {
            log::warn!("rp cache: caching attestation {} failed: {e}", rec.key_id);
        }
    }

    for rev in &fetched.revocations {
        let revoked_at = parse_rfc3339(&rev.revoked_at).unwrap_or(now);
        let bytes = liblinkkeys::generated::encode_application_key_revocation(rev);
        if let Err(e) = pool.upsert_rp_application_key_revocation(
            &entry.id,
            &rev.target_key_id,
            &bytes,
            revoked_at,
        ) {
            log::warn!(
                "rp cache: caching revocation of {} failed: {e}",
                rev.target_key_id
            );
        }
    }

    if let Err(e) = pool.evict_oldest_rp_application_key_cache_entries(max_entries()) {
        log::warn!("rp cache: application key cache eviction failed: {e}");
    }
}

fn load_cached_records(
    pool: &DbPool,
    entry_id: &str,
) -> Result<
    (
        Vec<SignedApplicationKeyAttestation>,
        Vec<ApplicationKeyRevocation>,
    ),
    ServiceError,
> {
    let att_rows = pool
        .list_rp_application_key_attestations(entry_id)
        .map_err(|e| internal("reading cached attestations", e))?;
    let mut attestations = Vec::with_capacity(att_rows.len());
    for row in &att_rows {
        match liblinkkeys::generated::decode_signed_application_key_attestation(
            &row.signed_attestation,
        ) {
            Ok(a) => attestations.push(a),
            Err(e) => log::error!("rp cache: corrupt cached attestation {}: {e}", row.key_id),
        }
    }

    let rev_rows = pool
        .list_rp_application_key_revocations(entry_id)
        .map_err(|e| internal("reading cached revocations", e))?;
    let mut revocations = Vec::with_capacity(rev_rows.len());
    for row in &rev_rows {
        match liblinkkeys::generated::decode_application_key_revocation(&row.revocation) {
            Ok(r) => revocations.push(r),
            Err(e) => log::error!(
                "rp cache: corrupt cached revocation {}: {e}",
                row.target_key_id
            ),
        }
    }

    Ok((attestations, revocations))
}

#[allow(clippy::too_many_arguments)]
fn build_app_response(
    subject_user_id: &str,
    subject_domain: &str,
    application_id: &str,
    instance_id: &str,
    application_keys: Vec<SignedApplicationKeyAttestation>,
    application_key_revocations: Vec<ApplicationKeyRevocation>,
    home_domain_keys: Vec<DomainPublicKey>,
    home_domain_key_revocations: Vec<RevocationCertificate>,
    fetched_at: String,
    revocations_checked_at: String,
    cache_status: String,
) -> RpResolveApplicationKeysResponse {
    RpResolveApplicationKeysResponse {
        subject_user_id: subject_user_id.to_string(),
        subject_domain: subject_domain.to_string(),
        application_id: application_id.to_string(),
        instance_id: instance_id.to_string(),
        application_keys,
        application_key_revocations,
        home_domain_keys,
        home_domain_key_revocations,
        fetched_at,
        revocations_checked_at,
        cache_status,
    }
}
