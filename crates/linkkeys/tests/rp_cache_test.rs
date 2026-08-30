//! End-to-end tests for `services::rp_cache`: the RP's persistent cache of
//! remote domain keys and remote application-key attestations
//! (signing-things-request.md, "RP cache" / "RP-facing operations"). No real
//! sockets — DNS and CSIL-RPC are served by the canned `Net` seam
//! (`tests/common/net.rs`), each fake remote domain gets its own Ed25519
//! signing key, and every attestation/revocation is built and signed with
//! `liblinkkeys::application_keys`'s own pure signing helpers so this test
//! exercises the exact same wire shapes a real home domain would produce.
//!
//! Every test uses its own, never-reused fake domain name: `resolve_*` are
//! backed by process-global coalescing registries (by design — the whole
//! point of coalescing is one fetch per SERVER, not per caller), and `cargo
//! test` runs the tests in this binary on multiple threads, so a shared
//! domain name between two tests could let one test's fetch answer another
//! test's call.

mod common;

use chrono::{Duration, Utc};
use common::net::{CannedRpc, StaticDns};
use liblinkkeys::application_keys::{self as ak, ApplicationKeyRef, InstanceRef};
use liblinkkeys::claims::ClaimSigner;
use liblinkkeys::crypto::{self, SigningAlgorithm};
use liblinkkeys::generated::types::{
    ApplicationKeyRevocation, DomainPublicKey, GetApplicationKeysResponse, GetDomainKeysResponse,
    RpResolveApplicationKeysRequest, RpResolveDomainKeysRequest, SignedApplicationKeyAttestation,
};
use linkkeys::net::{DomainRpc, HttpResponse, Net, NetError};
use linkkeys::services::rp_cache;
use std::sync::Arc;

const APP: &str = "tinku";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("test runtime")
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

struct DomainFixture {
    domain: String,
    key_id: String,
    public: DomainPublicKey,
    private_key: Vec<u8>,
}

fn domain_fixture(domain: &str) -> DomainFixture {
    let (vk, sk) = crypto::generate_ed25519_keypair();
    let pk = vk.as_bytes().to_vec();
    let fp = crypto::fingerprint(&pk);
    let now = Utc::now();
    let key_id = format!("{domain}-sign-1");
    DomainFixture {
        domain: domain.to_string(),
        key_id: key_id.clone(),
        public: DomainPublicKey {
            key_id,
            public_key: pk,
            fingerprint: fp,
            algorithm: "ed25519".to_string(),
            key_usage: "sign".to_string(),
            created_at: now.to_rfc3339(),
            expires_at: (now + Duration::days(365)).to_rfc3339(),
            revoked_at: None,
            signed_by_key_id: None,
            key_signature: None,
        },
        private_key: sk.to_bytes().to_vec(),
    }
}

fn dns_for(domain: &DomainFixture) -> StaticDns {
    StaticDns::new()
        .with(
            &liblinkkeys::dns::linkkeys_dns_name(&domain.domain),
            &[&format!("v=lk1 fp={}", domain.public.fingerprint)],
        )
        .with(
            &liblinkkeys::dns::linkkeys_apis_dns_name(&domain.domain),
            &[&format!("v=lk1 tcp={}", domain.domain)],
        )
}

fn domain_keys_response_bytes(domain: &DomainFixture) -> Vec<u8> {
    liblinkkeys::generated::encode_get_domain_keys_response(&GetDomainKeysResponse {
        domain: domain.domain.clone(),
        keys: vec![domain.public.clone()],
        recent_revocations_available: None,
    })
}

struct AppKeyFixture {
    key_ref: ApplicationKeyRef,
    private_key: Vec<u8>,
}

fn app_signing_key(id: &str) -> AppKeyFixture {
    let (vk, sk) = crypto::generate_ed25519_keypair();
    let pk = vk.as_bytes().to_vec();
    let fp = crypto::fingerprint(&pk);
    let now = Utc::now();
    AppKeyFixture {
        key_ref: ApplicationKeyRef {
            key_id: id.to_string(),
            key_usage: ak::KEY_USAGE_SIGN.to_string(),
            algorithm: "ed25519".to_string(),
            public_key: pk,
            fingerprint: fp,
            created_at: now.to_rfc3339(),
            expires_at: (now + Duration::days(365)).to_rfc3339(),
            revoked_at: None,
        },
        private_key: sk.to_bytes().to_vec(),
    }
}

fn attest(
    domain: &DomainFixture,
    instance: &InstanceRef<'_>,
    key: &AppKeyFixture,
    attested_at: chrono::DateTime<Utc>,
) -> SignedApplicationKeyAttestation {
    let attestation = ak::build_attestation(instance, &key.key_ref, attested_at, 86_400);
    ak::sign_attestation(
        &attestation,
        &[ClaimSigner {
            domain: &domain.domain,
            key_id: &domain.key_id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &domain.private_key,
        }],
    )
    .expect("sign attestation")
}

fn revoke(
    instance: &InstanceRef<'_>,
    target: &AppKeyFixture,
    siblings: &[&AppKeyFixture],
    revoked_at: chrono::DateTime<Utc>,
) -> ApplicationKeyRevocation {
    let signers: Vec<ak::ApplicationSigner<'_>> = siblings
        .iter()
        .map(|s| ak::ApplicationSigner {
            key_id: &s.key_ref.key_id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &s.private_key,
        })
        .collect();
    ak::sign_revocation(
        instance,
        &target.key_ref.key_id,
        &target.key_ref.fingerprint,
        &revoked_at.to_rfc3339(),
        &signers,
    )
    .expect("sign revocation")
}

fn app_keys_response_bytes(
    subject_user_id: &str,
    subject_domain: &str,
    keys: Vec<SignedApplicationKeyAttestation>,
    revocations: Vec<ApplicationKeyRevocation>,
) -> Vec<u8> {
    liblinkkeys::generated::encode_get_application_keys_response(&GetApplicationKeysResponse {
        subject_user_id: subject_user_id.to_string(),
        subject_domain: subject_domain.to_string(),
        application_id: APP.to_string(),
        instance_id: "instance-1".to_string(),
        keys,
        revocations,
    })
}

/// A `DomainRpc` that counts every call it serves (keyed the same way
/// `CannedRpc` is) before delegating to an inner `CannedRpc`. Lets a test
/// assert "no home-domain call happened" / "exactly one call happened".
#[derive(Debug)]
struct CountingRpc {
    inner: CannedRpc,
    op_calls: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
}

impl CountingRpc {
    fn new(inner: CannedRpc) -> Self {
        CountingRpc {
            inner,
            op_calls: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    fn count_for(&self, service: &str, op: &str) -> usize {
        let map = self.op_calls.lock().unwrap();
        *map.get(&format!("{service}/{op}")).unwrap_or(&0)
    }
}

#[rocket::async_trait]
impl DomainRpc for CountingRpc {
    async fn call(
        &self,
        addr: &str,
        hostname: &str,
        fingerprints: Vec<String>,
        client_cert: Option<(Vec<u8>, Vec<u8>)>,
        service: &str,
        op: &str,
        payload: Vec<u8>,
        auth: Option<String>,
    ) -> Result<Vec<u8>, NetError> {
        {
            let mut map = self.op_calls.lock().unwrap();
            *map.entry(format!("{service}/{op}")).or_insert(0) += 1;
        }
        self.inner
            .call(
                addr,
                hostname,
                fingerprints,
                client_cert,
                service,
                op,
                payload,
                auth,
            )
            .await
    }
}

/// Errors on every DNS/RPC call — the "home domain unreachable" seam.
#[derive(Debug, Default)]
struct DeadDns;
#[rocket::async_trait]
impl linkkeys::net::DnsResolver for DeadDns {
    async fn txt_lookup(&self, name: &str) -> Result<Vec<String>, NetError> {
        Err(NetError(format!("no route to {name}")))
    }
}
#[derive(Debug, Default)]
struct DeadRpc;
#[rocket::async_trait]
impl DomainRpc for DeadRpc {
    async fn call(
        &self,
        _addr: &str,
        hostname: &str,
        _fingerprints: Vec<String>,
        _client_cert: Option<(Vec<u8>, Vec<u8>)>,
        service: &str,
        op: &str,
        _payload: Vec<u8>,
        _auth: Option<String>,
    ) -> Result<Vec<u8>, NetError> {
        Err(NetError(format!(
            "{hostname} unreachable for {service}/{op}"
        )))
    }
}
#[derive(Debug, Default)]
struct DeadHttp;
#[rocket::async_trait]
impl linkkeys::net::DomainFetcher for DeadHttp {
    async fn get(&self, url: &str) -> Result<HttpResponse, NetError> {
        Err(NetError(format!("no route to {url}")))
    }
    async fn post_cbor(&self, url: &str, _body: Vec<u8>) -> Result<HttpResponse, NetError> {
        Err(NetError(format!("no route to {url}")))
    }
}

fn dead_net() -> Net {
    Net {
        dns: Arc::new(DeadDns),
        http: Arc::new(DeadHttp),
        rpc: Arc::new(DeadRpc),
    }
}

// ---------------------------------------------------------------------------
// Domain-key resolve
// ---------------------------------------------------------------------------

#[test]
fn domain_key_cache_miss_fetches_verifies_stores_and_returns_refreshed() {
    let pool = common::create_test_pool();
    let rt = runtime();
    let d = domain_fixture("miss.example");
    let dns = dns_for(&d);
    let rpc = CannedRpc::new().with(
        &d.domain,
        "DomainKeys",
        "get-domain-keys",
        domain_keys_response_bytes(&d),
    );
    let net = Net {
        dns: Arc::new(dns),
        http: Arc::new(common::net::CannedHttp::new()),
        rpc: Arc::new(rpc),
    };

    let resp = rp_cache::resolve_domain_keys(
        &pool,
        &net,
        rt.handle(),
        RpResolveDomainKeysRequest {
            domain: d.domain.clone(),
            max_cache_age_seconds: None,
        },
    )
    .expect("resolve domain keys");

    assert_eq!(resp.cache_status, "refreshed");
    assert_eq!(resp.keys.len(), 1);
    assert_eq!(resp.keys[0].key_id, d.key_id);
    assert!(!resp.fetched_at.is_empty());
}

#[test]
fn domain_key_cache_hit_returns_fresh_with_no_home_domain_call() {
    let pool = common::create_test_pool();
    let rt = runtime();
    let d = domain_fixture("hit.example");
    let dns = dns_for(&d);
    let canned = CannedRpc::new().with(
        &d.domain,
        "DomainKeys",
        "get-domain-keys",
        domain_keys_response_bytes(&d),
    );
    let counting = Arc::new(CountingRpc::new(canned));
    let net = Net {
        dns: Arc::new(dns),
        http: Arc::new(common::net::CannedHttp::new()),
        rpc: counting.clone(),
    };

    let req = || RpResolveDomainKeysRequest {
        domain: d.domain.clone(),
        max_cache_age_seconds: None,
    };
    let first =
        rp_cache::resolve_domain_keys(&pool, &net, rt.handle(), req()).expect("first resolve");
    assert_eq!(first.cache_status, "refreshed");
    let after_first = counting.count_for("DomainKeys", "get-domain-keys");
    assert_eq!(after_first, 1);

    let second =
        rp_cache::resolve_domain_keys(&pool, &net, rt.handle(), req()).expect("second resolve");
    assert_eq!(second.cache_status, "fresh");
    assert_eq!(
        counting.count_for("DomainKeys", "get-domain-keys"),
        after_first,
        "a fresh cache hit must not call the home domain"
    );
    // A cache-served answer (fresh or stale) re-derives `keys` from the
    // durable `peer_keys` table, which does not retain `created_at` (see
    // `peer_key_to_domain_public_key`) -- compare on the fields that matter.
    assert_eq!(second.keys.len(), first.keys.len());
    assert_eq!(second.keys[0].key_id, first.keys[0].key_id);
    assert_eq!(second.keys[0].fingerprint, first.keys[0].fingerprint);
    assert_eq!(second.keys[0].public_key, first.keys[0].public_key);
}

#[test]
fn domain_key_unreachable_with_valid_cache_returns_stale() {
    let pool = common::create_test_pool();
    let rt = runtime();
    let d = domain_fixture("stale.example");
    let dns = dns_for(&d);
    let rpc = CannedRpc::new().with(
        &d.domain,
        "DomainKeys",
        "get-domain-keys",
        domain_keys_response_bytes(&d),
    );
    let net = Net {
        dns: Arc::new(dns),
        http: Arc::new(common::net::CannedHttp::new()),
        rpc: Arc::new(rpc),
    };

    let req = |max_age: Option<i64>| RpResolveDomainKeysRequest {
        domain: d.domain.clone(),
        max_cache_age_seconds: max_age,
    };
    let first =
        rp_cache::resolve_domain_keys(&pool, &net, rt.handle(), req(None)).expect("first resolve");
    assert_eq!(first.cache_status, "refreshed");

    // Now the home domain is unreachable (DNS and RPC both dead -- the fetch
    // fails regardless of which layer trips first), but a stricter
    // max_cache_age forces an attempted refetch, and the cache falls back to
    // the last verified, explicitly-marked-stale keys.
    let dead = dead_net();
    let second = rp_cache::resolve_domain_keys(&pool, &dead, rt.handle(), req(Some(0)))
        .expect("stale fallback still succeeds");
    assert_eq!(second.cache_status, "stale");
    // The stale path re-derives `keys` from the durable `peer_keys` cache,
    // which (by design -- see `peer_key_to_domain_public_key`) does not carry
    // the key's own `created_at`, only `expires_at`/`revoked_at`, which are
    // what every validity check actually consults. Compare on identity and
    // security-relevant fields, not the whole struct.
    assert_eq!(second.keys.len(), first.keys.len());
    assert_eq!(second.keys[0].key_id, first.keys[0].key_id);
    assert_eq!(second.keys[0].fingerprint, first.keys[0].fingerprint);
    assert_eq!(second.keys[0].public_key, first.keys[0].public_key);
    assert_eq!(second.keys[0].expires_at, first.keys[0].expires_at);
    assert_eq!(second.keys[0].revoked_at, first.keys[0].revoked_at);
}

#[test]
fn domain_key_unreachable_without_cache_returns_explicit_error() {
    let pool = common::create_test_pool();
    let rt = runtime();
    let net = dead_net();

    let result = rp_cache::resolve_domain_keys(
        &pool,
        &net,
        rt.handle(),
        RpResolveDomainKeysRequest {
            domain: "nocache.example".to_string(),
            max_cache_age_seconds: None,
        },
    );
    assert!(
        result.is_err(),
        "no cache + unreachable home domain must be an explicit error"
    );
}

#[test]
fn domain_key_stricter_max_age_forces_refetch_weaker_does_not_get_staler_data() {
    let pool = common::create_test_pool();
    let rt = runtime();
    let d = domain_fixture("policy.example");
    let dns = dns_for(&d);
    let canned = CannedRpc::new().with(
        &d.domain,
        "DomainKeys",
        "get-domain-keys",
        domain_keys_response_bytes(&d),
    );
    let counting = Arc::new(CountingRpc::new(canned));
    let net = Net {
        dns: Arc::new(dns),
        http: Arc::new(common::net::CannedHttp::new()),
        rpc: counting.clone(),
    };
    let count = || counting.count_for("DomainKeys", "get-domain-keys");

    let first = rp_cache::resolve_domain_keys(
        &pool,
        &net,
        rt.handle(),
        RpResolveDomainKeysRequest {
            domain: d.domain.clone(),
            max_cache_age_seconds: None,
        },
    )
    .expect("first resolve");
    assert_eq!(first.cache_status, "refreshed");
    assert_eq!(count(), 1);

    // A weaker (larger) requested max age than policy must not serve staler
    // data than policy allows -- it is clamped, so this is still a fresh hit.
    let weaker = rp_cache::resolve_domain_keys(
        &pool,
        &net,
        rt.handle(),
        RpResolveDomainKeysRequest {
            domain: d.domain.clone(),
            max_cache_age_seconds: Some(999_999),
        },
    )
    .expect("weaker request still resolves");
    assert_eq!(weaker.cache_status, "fresh");
    assert_eq!(count(), 1, "a weaker request must not force a refetch");

    // A stricter (max_cache_age_seconds=0) request forces a refetch.
    let stricter = rp_cache::resolve_domain_keys(
        &pool,
        &net,
        rt.handle(),
        RpResolveDomainKeysRequest {
            domain: d.domain.clone(),
            max_cache_age_seconds: Some(0),
        },
    )
    .expect("stricter request still resolves");
    assert_eq!(stricter.cache_status, "refreshed");
    assert_eq!(count(), 2, "a stricter request must force a refetch");
}

// ---------------------------------------------------------------------------
// Application-key resolve
// ---------------------------------------------------------------------------

fn app_net(d: &DomainFixture, app_bytes: Vec<u8>) -> Net {
    let dns = dns_for(d);
    let rpc = CannedRpc::new()
        .with(
            &d.domain,
            "DomainKeys",
            "get-domain-keys",
            domain_keys_response_bytes(d),
        )
        .with(
            &d.domain,
            "ApplicationKeys",
            "get-application-keys",
            app_bytes,
        );
    Net {
        dns: Arc::new(dns),
        http: Arc::new(common::net::CannedHttp::new()),
        rpc: Arc::new(rpc),
    }
}

fn app_net_counting(d: &DomainFixture, app_bytes: Vec<u8>) -> (Net, Arc<CountingRpc>) {
    let dns = dns_for(d);
    let rpc = CannedRpc::new()
        .with(
            &d.domain,
            "DomainKeys",
            "get-domain-keys",
            domain_keys_response_bytes(d),
        )
        .with(
            &d.domain,
            "ApplicationKeys",
            "get-application-keys",
            app_bytes,
        );
    let counting = Arc::new(CountingRpc::new(rpc));
    (
        Net {
            dns: Arc::new(dns),
            http: Arc::new(common::net::CannedHttp::new()),
            rpc: counting.clone(),
        },
        counting,
    )
}

#[test]
fn application_key_cache_miss_fetches_verifies_stores_and_returns_refreshed() {
    let pool = common::create_test_pool();
    let rt = runtime();
    let d = domain_fixture("appmiss.example");
    let subject = uuid::Uuid::now_v7().to_string();
    let instance = InstanceRef {
        subject_user_id: &subject,
        subject_domain: &d.domain,
        application_id: APP,
        instance_id: "instance-1",
    };
    let key = app_signing_key("k1");
    let signed = attest(&d, &instance, &key, Utc::now());
    let net = app_net(
        &d,
        app_keys_response_bytes(&subject, &d.domain, vec![signed.clone()], vec![]),
    );

    let resp = rp_cache::resolve_application_keys(
        &pool,
        &net,
        rt.handle(),
        RpResolveApplicationKeysRequest {
            subject_user_id: subject.clone(),
            subject_domain: d.domain.clone(),
            application_id: APP.to_string(),
            instance_id: "instance-1".to_string(),
            max_cache_age_seconds: None,
        },
    )
    .expect("resolve application keys");

    assert_eq!(resp.cache_status, "refreshed");
    assert_eq!(resp.application_keys.len(), 1);
    assert_eq!(resp.application_keys[0].attestation, signed.attestation);
    assert_eq!(
        resp.home_domain_keys.len(),
        1,
        "one call must be enough: home domain keys are included"
    );
    assert_eq!(resp.home_domain_keys[0].key_id, d.key_id);
}

#[test]
fn application_key_cache_hit_returns_fresh_with_no_home_domain_call() {
    let pool = common::create_test_pool();
    let rt = runtime();
    let d = domain_fixture("apphit.example");
    let subject = uuid::Uuid::now_v7().to_string();
    let instance = InstanceRef {
        subject_user_id: &subject,
        subject_domain: &d.domain,
        application_id: APP,
        instance_id: "instance-1",
    };
    let key = app_signing_key("k1");
    let signed = attest(&d, &instance, &key, Utc::now());
    let (net, counting) = app_net_counting(
        &d,
        app_keys_response_bytes(&subject, &d.domain, vec![signed], vec![]),
    );
    let count = || counting.count_for("ApplicationKeys", "get-application-keys");

    let req = || RpResolveApplicationKeysRequest {
        subject_user_id: subject.clone(),
        subject_domain: d.domain.clone(),
        application_id: APP.to_string(),
        instance_id: "instance-1".to_string(),
        max_cache_age_seconds: None,
    };
    let first =
        rp_cache::resolve_application_keys(&pool, &net, rt.handle(), req()).expect("first resolve");
    assert_eq!(first.cache_status, "refreshed");
    assert_eq!(count(), 1);

    let second = rp_cache::resolve_application_keys(&pool, &net, rt.handle(), req())
        .expect("second resolve");
    assert_eq!(second.cache_status, "fresh");
    assert_eq!(
        count(),
        1,
        "a fresh cache hit must not call the home domain"
    );
    assert_eq!(second.application_keys, first.application_keys);
}

#[test]
fn application_key_restart_persists_cached_signed_records() {
    let pool = common::create_test_pool();
    let rt = runtime();
    let d = domain_fixture("apprestart.example");
    let subject = uuid::Uuid::now_v7().to_string();
    let instance = InstanceRef {
        subject_user_id: &subject,
        subject_domain: &d.domain,
        application_id: APP,
        instance_id: "instance-1",
    };
    let key = app_signing_key("k1");
    let signed = attest(&d, &instance, &key, Utc::now());
    let net = app_net(
        &d,
        app_keys_response_bytes(&subject, &d.domain, vec![signed.clone()], vec![]),
    );

    let first = rp_cache::resolve_application_keys(
        &pool,
        &net,
        rt.handle(),
        RpResolveApplicationKeysRequest {
            subject_user_id: subject.clone(),
            subject_domain: d.domain.clone(),
            application_id: APP.to_string(),
            instance_id: "instance-1".to_string(),
            max_cache_age_seconds: None,
        },
    )
    .expect("first resolve");
    assert_eq!(first.cache_status, "refreshed");

    // "Restart": build a new service view over the SAME pool (no in-process
    // struct to reconstruct -- the database is the persistence layer) and a
    // dead network, forcing a hard refetch attempt that must fail over to
    // the durably-stored signed records rather than losing them.
    let dead = dead_net();
    let after_restart = rp_cache::resolve_application_keys(
        &pool,
        &dead,
        rt.handle(),
        RpResolveApplicationKeysRequest {
            subject_user_id: subject.clone(),
            subject_domain: d.domain.clone(),
            application_id: APP.to_string(),
            instance_id: "instance-1".to_string(),
            max_cache_age_seconds: Some(0),
        },
    )
    .expect("stale fallback after restart");
    assert_eq!(after_restart.cache_status, "stale");
    assert_eq!(after_restart.application_keys.len(), 1);
    assert_eq!(
        after_restart.application_keys[0].attestation,
        signed.attestation
    );
}

#[test]
fn application_key_unreachable_with_valid_cache_returns_stale_not_current() {
    let pool = common::create_test_pool();
    let rt = runtime();
    let d = domain_fixture("appstale.example");
    let subject = uuid::Uuid::now_v7().to_string();
    let instance = InstanceRef {
        subject_user_id: &subject,
        subject_domain: &d.domain,
        application_id: APP,
        instance_id: "instance-1",
    };
    let key = app_signing_key("k1");
    let signed = attest(&d, &instance, &key, Utc::now());
    let net = app_net(
        &d,
        app_keys_response_bytes(&subject, &d.domain, vec![signed.clone()], vec![]),
    );

    let req = |max_age| RpResolveApplicationKeysRequest {
        subject_user_id: subject.clone(),
        subject_domain: d.domain.clone(),
        application_id: APP.to_string(),
        instance_id: "instance-1".to_string(),
        max_cache_age_seconds: max_age,
    };
    rp_cache::resolve_application_keys(&pool, &net, rt.handle(), req(None)).expect("first resolve");

    let dead = dead_net();
    let stale = rp_cache::resolve_application_keys(&pool, &dead, rt.handle(), req(Some(0)))
        .expect("stale fallback");
    assert_eq!(stale.cache_status, "stale");
    assert_ne!(stale.cache_status, "fresh");
    assert_eq!(stale.application_keys.len(), 1);
    assert_eq!(stale.application_keys[0].attestation, signed.attestation);
}

#[test]
fn application_key_unreachable_without_cache_returns_explicit_error() {
    let pool = common::create_test_pool();
    let rt = runtime();
    let net = dead_net();

    let result = rp_cache::resolve_application_keys(
        &pool,
        &net,
        rt.handle(),
        RpResolveApplicationKeysRequest {
            subject_user_id: uuid::Uuid::now_v7().to_string(),
            subject_domain: "appnocache.example".to_string(),
            application_id: APP.to_string(),
            instance_id: "instance-1".to_string(),
            max_cache_age_seconds: None,
        },
    );
    assert!(
        result.is_err(),
        "no cache + unreachable home domain must be an explicit error, never an empty ok answer"
    );
}

#[test]
fn attestation_that_does_not_verify_is_never_cached_or_returned() {
    let pool = common::create_test_pool();
    let rt = runtime();
    let real_domain = domain_fixture("appbadsig.example");
    let attacker_domain = domain_fixture("appbadsig-attacker.example");
    let subject = uuid::Uuid::now_v7().to_string();
    let instance = InstanceRef {
        subject_user_id: &subject,
        subject_domain: &real_domain.domain,
        application_id: APP,
        instance_id: "instance-1",
    };

    let good_key = app_signing_key("good");
    let good = attest(&real_domain, &instance, &good_key, Utc::now());

    // "Signed" by a domain key the home domain does NOT publish -- this must
    // never verify, never be cached, and never be returned.
    let bad_key = app_signing_key("bad");
    let bad = attest(&attacker_domain, &instance, &bad_key, Utc::now());

    let net = app_net(
        &real_domain,
        app_keys_response_bytes(
            &subject,
            &real_domain.domain,
            vec![good.clone(), bad],
            vec![],
        ),
    );

    let resp = rp_cache::resolve_application_keys(
        &pool,
        &net,
        rt.handle(),
        RpResolveApplicationKeysRequest {
            subject_user_id: subject.clone(),
            subject_domain: real_domain.domain.clone(),
            application_id: APP.to_string(),
            instance_id: "instance-1".to_string(),
            max_cache_age_seconds: None,
        },
    )
    .expect("resolve still succeeds using only the verifying record");

    assert_eq!(
        resp.application_keys.len(),
        1,
        "only the verifying attestation is returned"
    );
    assert_eq!(resp.application_keys[0].attestation, good.attestation);

    // And a subsequent cache-only read never surfaces it either.
    let cached = rp_cache::resolve_application_keys(
        &pool,
        &net,
        rt.handle(),
        RpResolveApplicationKeysRequest {
            subject_user_id: subject,
            subject_domain: real_domain.domain,
            application_id: APP.to_string(),
            instance_id: "instance-1".to_string(),
            max_cache_age_seconds: None,
        },
    )
    .expect("cached read");
    assert_eq!(cached.application_keys.len(), 1);
}

#[test]
fn revocation_refresh_marks_key_revoked_and_later_read_reflects_it() {
    let pool = common::create_test_pool();
    let rt = runtime();
    let d = domain_fixture("apprevoke.example");
    let subject = uuid::Uuid::now_v7().to_string();
    let instance = InstanceRef {
        subject_user_id: &subject,
        subject_domain: &d.domain,
        application_id: APP,
        instance_id: "instance-1",
    };

    let target = app_signing_key("target");
    let sibling_a = app_signing_key("sibling-a");
    let sibling_b = app_signing_key("sibling-b");
    let now = Utc::now();
    let attestations = vec![
        attest(&d, &instance, &target, now),
        attest(&d, &instance, &sibling_a, now),
        attest(&d, &instance, &sibling_b, now),
    ];

    let req = |max_age| RpResolveApplicationKeysRequest {
        subject_user_id: subject.clone(),
        subject_domain: d.domain.clone(),
        application_id: APP.to_string(),
        instance_id: "instance-1".to_string(),
        max_cache_age_seconds: max_age,
    };

    let net1 = app_net(
        &d,
        app_keys_response_bytes(&subject, &d.domain, attestations.clone(), vec![]),
    );
    let first = rp_cache::resolve_application_keys(&pool, &net1, rt.handle(), req(None))
        .expect("first resolve");
    assert_eq!(first.application_key_revocations.len(), 0);

    let revocation = revoke(&instance, &target, &[&sibling_a, &sibling_b], Utc::now());
    let net2 = app_net(
        &d,
        app_keys_response_bytes(&subject, &d.domain, attestations, vec![revocation.clone()]),
    );
    let second = rp_cache::resolve_application_keys(&pool, &net2, rt.handle(), req(Some(0)))
        .expect("forced refetch sees the revocation");
    assert_eq!(second.cache_status, "refreshed");
    assert_eq!(second.application_key_revocations.len(), 1);
    assert_eq!(
        second.application_key_revocations[0].target_key_id,
        target.key_ref.key_id
    );

    // A later cache-only read reflects it too (durably stored, not just
    // returned once).
    let third = rp_cache::resolve_application_keys(&pool, &net2, rt.handle(), req(None))
        .expect("cached read reflects the revocation");
    assert_eq!(third.application_key_revocations.len(), 1);
}

#[test]
fn application_key_stricter_max_age_forces_refetch_weaker_does_not_get_staler_data() {
    let pool = common::create_test_pool();
    let rt = runtime();
    let d = domain_fixture("apppolicy.example");
    let subject = uuid::Uuid::now_v7().to_string();
    let instance = InstanceRef {
        subject_user_id: &subject,
        subject_domain: &d.domain,
        application_id: APP,
        instance_id: "instance-1",
    };
    let key = app_signing_key("k1");
    let signed = attest(&d, &instance, &key, Utc::now());
    let (net, counting) = app_net_counting(
        &d,
        app_keys_response_bytes(&subject, &d.domain, vec![signed], vec![]),
    );
    let count = || counting.count_for("ApplicationKeys", "get-application-keys");

    let req = |max_age| RpResolveApplicationKeysRequest {
        subject_user_id: subject.clone(),
        subject_domain: d.domain.clone(),
        application_id: APP.to_string(),
        instance_id: "instance-1".to_string(),
        max_cache_age_seconds: max_age,
    };

    rp_cache::resolve_application_keys(&pool, &net, rt.handle(), req(None)).expect("first resolve");
    assert_eq!(count(), 1);

    let weaker = rp_cache::resolve_application_keys(&pool, &net, rt.handle(), req(Some(999_999)))
        .expect("weaker request still resolves");
    assert_eq!(weaker.cache_status, "fresh");
    assert_eq!(count(), 1, "a weaker request must not force a refetch");

    let stricter = rp_cache::resolve_application_keys(&pool, &net, rt.handle(), req(Some(0)))
        .expect("stricter request still resolves");
    assert_eq!(stricter.cache_status, "refreshed");
    assert_eq!(count(), 2, "a stricter request must force a refetch");
}

#[test]
fn concurrent_refreshes_for_one_entry_coalesce_into_a_single_fetch() {
    let pool = common::create_test_pool();
    let rt = runtime();
    let d = domain_fixture("appconcurrent.example");
    let subject = uuid::Uuid::now_v7().to_string();
    let instance = InstanceRef {
        subject_user_id: &subject,
        subject_domain: &d.domain,
        application_id: APP,
        instance_id: "instance-1",
    };
    let key = app_signing_key("k1");
    let signed = attest(&d, &instance, &key, Utc::now());
    let dns = dns_for(&d);
    let rpc = CannedRpc::new()
        .with(
            &d.domain,
            "DomainKeys",
            "get-domain-keys",
            domain_keys_response_bytes(&d),
        )
        .with(
            &d.domain,
            "ApplicationKeys",
            "get-application-keys",
            app_keys_response_bytes(&subject, &d.domain, vec![signed], vec![]),
        );
    let counting = Arc::new(CountingRpc::new(rpc));
    let net = Arc::new(Net {
        dns: Arc::new(dns),
        http: Arc::new(common::net::CannedHttp::new()),
        rpc: counting.clone(),
    });

    const THREADS: usize = 8;
    let pool = Arc::new(pool);
    let rt = Arc::new(rt);
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let pool = Arc::clone(&pool);
            let net = Arc::clone(&net);
            let rt = Arc::clone(&rt);
            let subject = subject.clone();
            let domain = d.domain.clone();
            std::thread::spawn(move || {
                rp_cache::resolve_application_keys(
                    &pool,
                    &net,
                    rt.handle(),
                    RpResolveApplicationKeysRequest {
                        subject_user_id: subject,
                        subject_domain: domain,
                        application_id: APP.to_string(),
                        instance_id: "instance-1".to_string(),
                        max_cache_age_seconds: None,
                    },
                )
            })
        })
        .collect();

    for h in handles {
        let resp = h
            .join()
            .expect("thread panicked")
            .expect("resolve succeeds");
        assert_eq!(resp.application_keys.len(), 1);
    }

    assert_eq!(
        counting.count_for("ApplicationKeys", "get-application-keys"),
        1,
        "N concurrent callers for the same entry must coalesce into one fetch"
    );
}

#[test]
fn cache_entries_do_not_bleed_across_instances_or_subjects() {
    let pool = common::create_test_pool();
    let rt = runtime();
    let d = domain_fixture("appbleed.example");
    let subject_a = uuid::Uuid::now_v7().to_string();
    let subject_b = uuid::Uuid::now_v7().to_string();

    let instance_a1 = InstanceRef {
        subject_user_id: &subject_a,
        subject_domain: &d.domain,
        application_id: APP,
        instance_id: "instance-a",
    };
    let instance_a2 = InstanceRef {
        subject_user_id: &subject_a,
        subject_domain: &d.domain,
        application_id: APP,
        instance_id: "instance-b",
    };
    let instance_b1 = InstanceRef {
        subject_user_id: &subject_b,
        subject_domain: &d.domain,
        application_id: APP,
        instance_id: "instance-a",
    };

    let key_a1 = app_signing_key("a1");
    let key_a2 = app_signing_key("a2");
    let key_b1 = app_signing_key("b1");

    let now = Utc::now();
    let signed_a1 = attest(&d, &instance_a1, &key_a1, now);
    let signed_a2 = attest(&d, &instance_a2, &key_a2, now);
    let signed_b1 = attest(&d, &instance_b1, &key_b1, now);

    // One canned RPC endpoint per (subject, instance) request would collide on
    // hostname, so resolve each instance against its own Net -- the point of
    // this test is DB-level isolation, not transport plumbing.
    let resolve = |pool: &linkkeys::db::DbPool, subject: &str, iid: &str, bytes: Vec<u8>| {
        let net = app_net(&d, bytes);
        rp_cache::resolve_application_keys(
            pool,
            &net,
            rt.handle(),
            RpResolveApplicationKeysRequest {
                subject_user_id: subject.to_string(),
                subject_domain: d.domain.clone(),
                application_id: APP.to_string(),
                instance_id: iid.to_string(),
                max_cache_age_seconds: None,
            },
        )
        .expect("resolve")
    };

    let resp_a1 = resolve(
        &pool,
        &subject_a,
        "instance-a",
        app_keys_response_bytes(&subject_a, &d.domain, vec![signed_a1.clone()], vec![]),
    );
    let resp_a2 = resolve(
        &pool,
        &subject_a,
        "instance-b",
        app_keys_response_bytes(&subject_a, &d.domain, vec![signed_a2.clone()], vec![]),
    );
    let resp_b1 = resolve(
        &pool,
        &subject_b,
        "instance-a",
        app_keys_response_bytes(&subject_b, &d.domain, vec![signed_b1.clone()], vec![]),
    );

    assert_eq!(
        resp_a1.application_keys[0].attestation,
        signed_a1.attestation
    );
    assert_eq!(
        resp_a2.application_keys[0].attestation,
        signed_a2.attestation
    );
    assert_eq!(
        resp_b1.application_keys[0].attestation,
        signed_b1.attestation
    );

    // Same subject, two instances: distinct entries.
    assert_ne!(
        resp_a1.application_keys[0].attestation,
        resp_a2.application_keys[0].attestation
    );
    // Two subjects, same application id and instance id: distinct entries.
    assert_ne!(
        resp_a1.application_keys[0].attestation,
        resp_b1.application_keys[0].attestation
    );
}

#[test]
fn a_handle_change_does_not_move_the_cache_entry() {
    // The RP-facing resolve request has no "handle" field at all -- only the
    // canonical (subject_user_id, subject_domain, application_id,
    // instance_id) tuple. This test demonstrates the structural guarantee:
    // resolving the SAME canonical identity twice (as if reached via two
    // different handles a peer approval might have used) always returns the
    // SAME cache entry, never a duplicate or a moved one.
    let pool = common::create_test_pool();
    let rt = runtime();
    let d = domain_fixture("apphandle.example");
    let subject = uuid::Uuid::now_v7().to_string();
    let instance = InstanceRef {
        subject_user_id: &subject,
        subject_domain: &d.domain,
        application_id: APP,
        instance_id: "instance-1",
    };
    let key = app_signing_key("k1");
    let signed = attest(&d, &instance, &key, Utc::now());
    let net = app_net(
        &d,
        app_keys_response_bytes(&subject, &d.domain, vec![signed.clone()], vec![]),
    );

    let req = || RpResolveApplicationKeysRequest {
        subject_user_id: subject.clone(),
        subject_domain: d.domain.clone(),
        application_id: APP.to_string(),
        instance_id: "instance-1".to_string(),
        max_cache_age_seconds: None,
    };
    rp_cache::resolve_application_keys(&pool, &net, rt.handle(), req()).expect("first lookup");
    rp_cache::resolve_application_keys(&pool, &net, rt.handle(), req()).expect("second lookup");

    let entry = pool
        .find_rp_application_key_cache_entry(&subject, &d.domain, APP, "instance-1")
        .expect("query")
        .expect("entry exists");
    let attestations = pool
        .list_rp_application_key_attestations(&entry.id)
        .expect("list attestations");
    assert_eq!(
        attestations.len(),
        1,
        "no duplicate entry was created for the same canonical identity"
    );
}
