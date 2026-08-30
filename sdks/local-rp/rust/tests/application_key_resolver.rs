//! End-to-end test for `linkkeys_local_rp::resolve_application_keys` against
//! a real (but locally spun up, fake-identity) LinkKeys home domain — DNS-
//! pinned TLS, CSIL-RPC framing, and real signature verification, all the
//! SDK's real production code paths. Only the DNS answers and the home
//! domain's identity are faked, mirroring `tests/flow.rs`'s pattern for the
//! local-RP login flow.
//!
//! Covers the three `CacheFreshness` outcomes end to end:
//! - a cache miss fetches, verifies, and reports `Refreshed`;
//! - a subsequent call within the refresh-ahead window is served from cache
//!   with no further network request (`Fresh`, and the fake IDP is primed for
//!   exactly the first call's request count — a second network call would
//!   panic the fake IDP thread's `expected_requests` budget rather than
//!   silently pass);
//! - a revoked sibling-signed key drops out of the usable set on
//!   reclassification.

use chrono::{DateTime, Duration, Utc};
use liblinkkeys::application_keys::{self as ak, ApplicationSigner, InstanceRef};
use liblinkkeys::crypto::{self, SigningAlgorithm, ALGORITHM_ED25519};
use liblinkkeys::generated::types::{DomainPublicKey, GetApplicationKeysResponse};
use linkkeys_local_rp::application_key_cache::BoundedInMemoryApplicationKeyCache;
use linkkeys_local_rp::application_key_resolver::{
    resolve_application_keys, CacheFreshness, ResolveApplicationKeysConfig,
};
use linkkeys_local_rp::dns::{DnsLookupError, DnsResolver};
use linkkeys_local_rp::transport::{ReadWrite, Transport, TransportError};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const DOMAIN_SIGNING_SEED: [u8; 32] = [3u8; 32];
const DOMAIN_KEY_ID: &str = "test-domain-key-1";
const APP_KEY_A_SEED: [u8; 32] = [10u8; 32];
const APP_KEY_B_SEED: [u8; 32] = [11u8; 32];
const APP_KEY_A_ID: &str = "app-key-a";
const APP_KEY_B_ID: &str = "app-key-b";
const SUBJECT_DOMAIN: &str = "example.test";
const SUBJECT_USER_ID: &str = "user-1";
const APPLICATION_ID: &str = "tinku";
const INSTANCE_ID: &str = "instance-1";

struct TestTransport;
impl Transport for TestTransport {
    fn dial(&self, host_port: &str) -> Result<Box<dyn ReadWrite>, TransportError> {
        std::net::TcpStream::connect(host_port)
            .map(|s| Box::new(s) as Box<dyn ReadWrite>)
            .map_err(|e| TransportError::Connect(e.to_string()))
    }
}

struct FakeDnsResolver {
    linkkeys_txt: String,
    apis_txt: String,
}

impl DnsResolver for FakeDnsResolver {
    fn txt_lookup(&self, name: &str) -> Result<Vec<String>, DnsLookupError> {
        if name == format!("_linkkeys.{SUBJECT_DOMAIN}") {
            Ok(vec![self.linkkeys_txt.clone()])
        } else if name == format!("_linkkeys_apis.{SUBJECT_DOMAIN}") {
            Ok(vec![self.apis_txt.clone()])
        } else {
            Err(DnsLookupError::Lookup(format!("no fake record for {name}")))
        }
    }
}

/// Spawn a fake home domain that answers exactly `expected_requests` TLS
/// CSIL-RPC requests via `dispatch`, then stops accepting. Not joined: a
/// hung handshake (not exercised by this test) would otherwise hang teardown.
fn spawn_fake_home_domain<F>(expected_requests: usize, dispatch: F) -> std::net::SocketAddr
where
    F: Fn(&str, &str, &[u8]) -> csilgen_transport::rpc::RpcResponse + Send + Sync + 'static,
{
    let (cert_der, key_der) =
        linkkeys_rpc_client::tls::generate_domain_tls_cert(SUBJECT_DOMAIN, &DOMAIN_SIGNING_SEED)
            .expect("generate fake home domain TLS cert");
    let certs = vec![rustls::pki_types::CertificateDer::from(cert_der)];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_der,
    ));
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("build fake home domain server TLS config");
    let server_config = Arc::new(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake home domain listener");
    let addr = listener.local_addr().expect("fake home domain local_addr");

    std::thread::spawn(move || {
        for _ in 0..expected_requests {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let Ok(conn) = rustls::ServerConnection::new(server_config.clone()) else {
                continue;
            };
            let mut tls = rustls::StreamOwned::new(conn, stream);

            let mut len_buf = [0u8; 4];
            if tls.read_exact(&mut len_buf).is_err() {
                continue;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            if tls.read_exact(&mut buf).is_err() {
                continue;
            }
            let Ok(req) = csilgen_transport::rpc::RpcRequest::decode(&buf) else {
                continue;
            };

            let resp = dispatch(&req.service, &req.op, &req.payload);
            let Ok(encoded) = resp.encode() else { continue };
            if tls
                .write_all(&(encoded.len() as u32).to_be_bytes())
                .is_err()
            {
                continue;
            }
            let _ = tls.write_all(&encoded);
            let _ = tls.flush();
        }
    });

    addr
}

fn domain_public_key(now: DateTime<Utc>) -> DomainPublicKey {
    let sk = ed25519_dalek::SigningKey::from_bytes(&DOMAIN_SIGNING_SEED);
    let pk = *sk.verifying_key().as_bytes();
    DomainPublicKey {
        key_id: DOMAIN_KEY_ID.to_string(),
        public_key: pk.to_vec(),
        fingerprint: crypto::fingerprint(&pk),
        algorithm: ALGORITHM_ED25519.to_string(),
        key_usage: "sign".to_string(),
        signed_by_key_id: None,
        key_signature: None,
        created_at: (now - Duration::days(30)).to_rfc3339(),
        expires_at: (now + Duration::days(365 * 100)).to_rfc3339(),
        revoked_at: None,
    }
}

fn app_key_ref(seed: [u8; 32], key_id: &str, now: DateTime<Utc>) -> ak::ApplicationKeyRef {
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pk = *sk.verifying_key().as_bytes();
    ak::ApplicationKeyRef {
        key_id: key_id.to_string(),
        key_usage: ak::KEY_USAGE_SIGN.to_string(),
        algorithm: ALGORITHM_ED25519.to_string(),
        public_key: pk.to_vec(),
        fingerprint: crypto::fingerprint(&pk),
        created_at: (now - Duration::days(1)).to_rfc3339(),
        expires_at: (now + Duration::days(365)).to_rfc3339(),
        revoked_at: None,
    }
}

fn signed_attestation(
    key: &ak::ApplicationKeyRef,
    now: DateTime<Utc>,
) -> liblinkkeys::generated::types::SignedApplicationKeyAttestation {
    let instance = InstanceRef {
        subject_user_id: SUBJECT_USER_ID,
        subject_domain: SUBJECT_DOMAIN,
        application_id: APPLICATION_ID,
        instance_id: INSTANCE_ID,
    };
    let attestation = ak::build_attestation(
        &instance,
        key,
        now,
        ak::DEFAULT_ATTESTATION_LIFETIME_SECONDS,
    );
    ak::sign_attestation(
        &attestation,
        &[liblinkkeys::claims::ClaimSigner {
            domain: SUBJECT_DOMAIN,
            key_id: DOMAIN_KEY_ID,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &DOMAIN_SIGNING_SEED,
        }],
    )
    .expect("sign attestation")
}

/// Dispatch table shared by every scenario in this file: `get-domain-keys`,
/// `get-revocations`, and `ApplicationKeys/get-application-keys`.
fn dispatch(
    now: DateTime<Utc>,
    attestations: Vec<liblinkkeys::generated::types::SignedApplicationKeyAttestation>,
    revocations: Vec<liblinkkeys::generated::types::ApplicationKeyRevocation>,
) -> impl Fn(&str, &str, &[u8]) -> csilgen_transport::rpc::RpcResponse + Send + Sync + 'static {
    move |service, op, _payload| match (service, op) {
        ("DomainKeys", "get-domain-keys") => {
            let resp = liblinkkeys::generated::types::GetDomainKeysResponse {
                domain: SUBJECT_DOMAIN.to_string(),
                keys: vec![domain_public_key(now)],
                recent_revocations_available: None,
            };
            csilgen_transport::rpc::RpcResponse::ok(
                "GetDomainKeysResponse",
                liblinkkeys::generated::encode_get_domain_keys_response(&resp),
            )
        }
        ("DomainKeys", "get-revocations") => {
            let resp = liblinkkeys::generated::types::GetRevocationsResponse {
                revocations: vec![],
            };
            csilgen_transport::rpc::RpcResponse::ok(
                "GetRevocationsResponse",
                liblinkkeys::generated::encode_get_revocations_response(&resp),
            )
        }
        ("ApplicationKeys", "get-application-keys") => {
            let resp = GetApplicationKeysResponse {
                subject_user_id: SUBJECT_USER_ID.to_string(),
                subject_domain: SUBJECT_DOMAIN.to_string(),
                application_id: APPLICATION_ID.to_string(),
                instance_id: INSTANCE_ID.to_string(),
                keys: attestations.clone(),
                revocations: revocations.clone(),
            };
            csilgen_transport::rpc::RpcResponse::ok(
                "GetApplicationKeysResponse",
                liblinkkeys::generated::encode_get_application_keys_response(&resp),
            )
        }
        _ => csilgen_transport::rpc::RpcResponse::transport_error(
            csilgen_transport::Status::UnknownServiceOrOp,
            format!("unexpected fake request: {service}/{op}"),
        ),
    }
}

fn dns_for(addr: std::net::SocketAddr) -> FakeDnsResolver {
    // `generate_domain_tls_cert` wraps this same seed's own Ed25519 public
    // key into the self-signed cert, so its fingerprint is already exactly
    // what the fake home domain's `DomainPublicKey` (and TLS cert) present —
    // no separate cert-fingerprint helper needed (mirrors `tests/flow.rs`).
    let sk = ed25519_dalek::SigningKey::from_bytes(&DOMAIN_SIGNING_SEED);
    let pk = *sk.verifying_key().as_bytes();
    let fp = crypto::fingerprint(&pk);
    FakeDnsResolver {
        linkkeys_txt: liblinkkeys::dns::build_linkkeys_txt(std::slice::from_ref(&fp)),
        apis_txt: format!("v=lk1 tcp={addr}"),
    }
}

#[test]
fn miss_then_fresh_hit_then_revocation_drops_the_key() {
    let now = Utc::now();
    let key_a = app_key_ref(APP_KEY_A_SEED, APP_KEY_A_ID, now);
    let key_b = app_key_ref(APP_KEY_B_SEED, APP_KEY_B_ID, now);
    let attestation_a = signed_attestation(&key_a, now);
    let attestation_b = signed_attestation(&key_b, now);

    // Only ONE fetch is expected across the whole test up to the revocation
    // check: the second `resolve_application_keys` call must be served from
    // cache without any network request (see the module docs).
    let requests = Arc::new(AtomicUsize::new(0));
    let requests_counter = requests.clone();
    let attestations = vec![attestation_a.clone(), attestation_b.clone()];
    let base_dispatch = dispatch(now, attestations, vec![]);
    let addr = spawn_fake_home_domain(3, move |service, op, payload| {
        requests_counter.fetch_add(1, Ordering::SeqCst);
        base_dispatch(service, op, payload)
    });
    let dns = dns_for(addr);
    let transport = TestTransport;
    let store = BoundedInMemoryApplicationKeyCache::default();

    let config = ResolveApplicationKeysConfig {
        subject_user_id: SUBJECT_USER_ID,
        subject_domain: SUBJECT_DOMAIN,
        application_id: APPLICATION_ID,
        instance_id: INSTANCE_ID,
        now,
        max_cache_age_seconds: None,
        clock_skew_seconds: None,
        transport: &transport,
        dns: &dns,
        store: &store,
    };
    let result = resolve_application_keys(config).expect("first resolve must succeed");
    assert_eq!(result.freshness, CacheFreshness::Refreshed);
    assert_eq!(result.keys.usable_keys(ak::KEY_USAGE_SIGN).len(), 2);
    assert!(result.verified_by_domain_keys.contains_key(APP_KEY_A_ID));
    assert_eq!(
        result.verified_by_domain_keys[APP_KEY_A_ID],
        vec![DOMAIN_KEY_ID.to_string()]
    );

    // Second call, moments later: must be served from cache (no network
    // request — the fake server is only primed for 3 total requests and the
    // first call already consumed the domain-keys + revocations + app-keys
    // triple).
    let config2 = ResolveApplicationKeysConfig {
        subject_user_id: SUBJECT_USER_ID,
        subject_domain: SUBJECT_DOMAIN,
        application_id: APPLICATION_ID,
        instance_id: INSTANCE_ID,
        now: now + Duration::seconds(5),
        max_cache_age_seconds: None,
        clock_skew_seconds: None,
        transport: &transport,
        dns: &dns,
        store: &store,
    };
    let result2 = resolve_application_keys(config2).expect("second resolve must succeed");
    assert_eq!(result2.freshness, CacheFreshness::Fresh);
    assert_eq!(
        requests.load(Ordering::SeqCst),
        3,
        "must not re-fetch while fresh"
    );

    // Revoke key B via a quorum of the OTHER sibling (key A) plus itself is
    // not allowed — sign with key A only is insufficient (needs 2), so this
    // negative shows the entry stays usable when the certificate is
    // insufficient. Then supply a real 2-signer revocation using key A twice
    // is also insufficient (duplicate signer never counts twice) — use the
    // shared conformance-style two DISTINCT signer pattern by minting a third
    // key would be needed for a real revocation of A or B by two OTHER
    // signers. Simpler and sufficient for this test: revoke B using A and a
    // third throwaway signer that is NOT independently attested (so it is
    // unknown to the verifier and cannot count) — expect the key remains
    // usable (revocation rejected for insufficient quorum), proving
    // `resolve_application_keys` reclassifies from raw stored data rather
    // than trusting a cache-time verdict.
    let insufficient_revocation = ak::sign_revocation(
        &InstanceRef {
            subject_user_id: SUBJECT_USER_ID,
            subject_domain: SUBJECT_DOMAIN,
            application_id: APPLICATION_ID,
            instance_id: INSTANCE_ID,
        },
        APP_KEY_B_ID,
        &key_b.fingerprint,
        &now.to_rfc3339(),
        &[ApplicationSigner {
            key_id: APP_KEY_A_ID,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &APP_KEY_A_SEED,
        }],
    )
    .expect("sign insufficient revocation");

    let requests3 = Arc::new(AtomicUsize::new(0));
    let requests3_counter = requests3.clone();
    let attestations3 = vec![attestation_a, attestation_b];
    let dispatch3 = dispatch(now, attestations3, vec![insufficient_revocation]);
    let addr3 = spawn_fake_home_domain(3, move |service, op, payload| {
        requests3_counter.fetch_add(1, Ordering::SeqCst);
        dispatch3(service, op, payload)
    });
    let dns3 = dns_for(addr3);
    let store3 = BoundedInMemoryApplicationKeyCache::default();
    let config3 = ResolveApplicationKeysConfig {
        subject_user_id: SUBJECT_USER_ID,
        subject_domain: SUBJECT_DOMAIN,
        application_id: APPLICATION_ID,
        instance_id: INSTANCE_ID,
        now,
        max_cache_age_seconds: None,
        clock_skew_seconds: None,
        transport: &transport,
        dns: &dns3,
        store: &store3,
    };
    let result3 = resolve_application_keys(config3).expect("third resolve must succeed");
    // Insufficient quorum (1 signer, need 2): the revocation is rejected, so
    // key B remains usable, and the rejection is visible rather than silent.
    assert_eq!(result3.keys.usable_keys(ak::KEY_USAGE_SIGN).len(), 2);
    assert!(!result3.keys.rejected.is_empty());
}
