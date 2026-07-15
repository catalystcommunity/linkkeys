//! Flow tests: `complete_local_login`'s full verification chain, end to end,
//! against a real (but locally spun up, fake-identity) LinkKeys IDP —
//! DNS-pinned TLS, CSIL-RPC framing, and all. Only two things are faked: the
//! DNS TXT answers ([`FakeDnsResolver`], so no real network/DNS is touched)
//! and the IDP's identity itself (a throwaway domain signing key generated
//! per test, not a real LinkKeys deployment). The [`Transport`] seam is also
//! exercised via a small custom impl ([`TestTransport`]) rather than the
//! crate's default, demonstrating the seam is genuinely injectable — the TLS
//! handshake, certificate-pinning, and RPC wire format underneath it are all
//! the SDK's real production code paths.
//!
//! Canned callback/ticket-redemption/domain-keys responses are built with
//! `liblinkkeys` directly (the same library `linkkeys_local_rp` wraps),
//! using the same fixed, publicly-known test key seeds as
//! `sdks/local-rp/conformance/keys.json` (`local_rp.signing` = 0x01 repeated,
//! `local_rp.encryption` = 0x02 repeated, `domain_signing_key` = 0x03
//! repeated) so this test suite and the conformance vectors describe the
//! same identities.
//!
//! Every scenario's fake IDP unconditionally serves `GetDomainKeysResponse`
//! with `recent_revocations_available: None` — deliberately never setting
//! the flag — and every scenario's fake IDP must handle
//! `DomainKeys/get-revocations` regardless. This is itself a standing
//! regression test for the "revocation fail-open" security fix: the old
//! implementation only fetched revocations when the flag was `Some(true)`,
//! so with the flag always absent here, a reverted fix would silently skip
//! `get-revocations` entirely and every request-count assertion in this file
//! would go stale (the fake IDP would receive one fewer request than
//! `expected_requests` primes it for, which is harmless by itself, but the
//! dedicated hostile-IDP tests below — especially
//! `revocation_certificate_drops_signing_key_and_login_fails_closed` — would
//! fail outright).

use chrono::{DateTime, Duration, Utc};
use liblinkkeys::claims::{sign_claim, ClaimSigner, ClaimSpec};
use liblinkkeys::crypto::{self, AeadSuite, ALGORITHM_ED25519};
use liblinkkeys::generated::types::{
    Claim, DomainPublicKey, GetRevocationsResponse, LocalRpCallbackPayload,
    LocalRpTicketRedemptionResponse, RevocationCertificate,
};
use liblinkkeys::local_rp;
use liblinkkeys::revocation::{build_revocation_certificate, RevocationSpec};
use linkkeys_local_rp::transport::{ReadWrite, Transport, TransportError};
use linkkeys_local_rp::{
    begin_local_login, complete_local_login, dns::DnsLookupError, dns::DnsResolver,
    BeginLocalLoginConfig, CompleteLocalLoginConfig, Error, LocalRpKeyMaterial, PendingLogin,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

// Same fixed seeds as sdks/local-rp/conformance/keys.json.
const LOCAL_RP_SIGNING_SEED: [u8; 32] = [1u8; 32];
const LOCAL_RP_ENCRYPTION_PRIVATE: [u8; 32] = [2u8; 32];
const DOMAIN_SIGNING_SEED: [u8; 32] = [3u8; 32];
const DOMAIN_KEY_ID: &str = "test-domain-key-1";
const USER_DOMAIN: &str = "example.test";
const CALLBACK_URL: &str = "http://localhost/callback";

// Sibling domain signing keys used only by the certificate-revocation test —
// distinct, unrelated seeds so a quorum of two DISTINCT signers is genuinely
// available (`liblinkkeys::revocation::REVOCATION_QUORUM`), never the target
// key itself (which can never authorize its own revocation).
const SIBLING_A_SEED: [u8; 32] = [4u8; 32];
const SIBLING_B_SEED: [u8; 32] = [5u8; 32];
const SIBLING_A_KEY_ID: &str = "sibling-key-a";
const SIBLING_B_KEY_ID: &str = "sibling-key-b";

// ---------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------

/// A `Transport` the test provides itself (rather than the crate's default
/// `StdTransport`), proving the seam is genuinely injectable. It still dials
/// a real loopback socket — only the DNS answer steering it there is faked.
struct TestTransport;

impl Transport for TestTransport {
    fn dial(&self, host_port: &str) -> Result<Box<dyn ReadWrite>, TransportError> {
        std::net::TcpStream::connect(host_port)
            .map(|s| Box::new(s) as Box<dyn ReadWrite>)
            .map_err(|e| TransportError::Connect(e.to_string()))
    }
}

/// Canned DNS answers for exactly one domain.
struct FakeDnsResolver {
    linkkeys_txt: String,
    apis_txt: String,
}

impl DnsResolver for FakeDnsResolver {
    fn txt_lookup(&self, name: &str) -> Result<Vec<String>, DnsLookupError> {
        if name == format!("_linkkeys.{USER_DOMAIN}") {
            Ok(vec![self.linkkeys_txt.clone()])
        } else if name == format!("_linkkeys_apis.{USER_DOMAIN}") {
            Ok(vec![self.apis_txt.clone()])
        } else {
            Err(DnsLookupError::Lookup(format!("no fake record for {name}")))
        }
    }
}

// ---------------------------------------------------------------------
// Fake IDP: a real TCP+TLS(fp-pinned)+CSIL-RPC server for exactly N requests
// ---------------------------------------------------------------------

/// Spawns a background thread that accepts `expected_requests` TLS
/// connections on a fresh loopback port, presenting a certificate derived
/// from `domain_seed` (so its SPKI fingerprint is whatever the test's DNS
/// answer pins to), and answers each with `dispatch(service, op, payload)`.
/// Returns the bound address. The thread is deliberately not joined: a
/// connection that never completes its TLS handshake (the "bad pin" test)
/// would otherwise hang the test on join.
fn spawn_fake_idp<F>(
    domain_seed: [u8; 32],
    expected_requests: usize,
    dispatch: F,
) -> std::net::SocketAddr
where
    F: Fn(&str, &str, &[u8]) -> csilgen_transport::rpc::RpcResponse + Send + Sync + 'static,
{
    let (cert_der, key_der) =
        linkkeys_rpc_client::tls::generate_domain_tls_cert(USER_DOMAIN, &domain_seed)
            .expect("generate fake IDP TLS cert");
    let certs = vec![rustls::pki_types::CertificateDer::from(cert_der)];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_der,
    ));
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("build fake IDP server TLS config");
    let server_config = Arc::new(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake IDP listener");
    let addr = listener.local_addr().expect("fake IDP local_addr");

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

// ---------------------------------------------------------------------
// Scenario construction
// ---------------------------------------------------------------------

fn fixed_key_material(now: DateTime<Utc>) -> LocalRpKeyMaterial {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&LOCAL_RP_SIGNING_SEED);
    let signing_public_key = *signing_key.verifying_key().as_bytes();
    let enc_secret = x25519_dalek::StaticSecret::from(LOCAL_RP_ENCRYPTION_PRIVATE);
    let encryption_public_key = *x25519_dalek::PublicKey::from(&enc_secret).as_bytes();

    let created_at = (now - Duration::days(1)).to_rfc3339();
    let expires_at = (now + Duration::days(3650)).to_rfc3339();
    let descriptor = local_rp::build_local_rp_descriptor(
        "Flow Test App",
        None,
        &signing_public_key,
        &encryption_public_key,
        vec!["aes-256-gcm".to_string(), "chacha20-poly1305".to_string()],
        &created_at,
        &expires_at,
    );
    let fingerprint = descriptor.fingerprint.clone();
    let signed_descriptor =
        local_rp::sign_local_rp_descriptor(&descriptor, &LOCAL_RP_SIGNING_SEED).unwrap();

    LocalRpKeyMaterial {
        signing_private_key: LOCAL_RP_SIGNING_SEED,
        signing_public_key,
        encryption_private_key: LOCAL_RP_ENCRYPTION_PRIVATE,
        encryption_public_key,
        descriptor: signed_descriptor,
        fingerprint,
    }
}

/// Build a domain signing `DomainPublicKey` for an arbitrary seed/key_id —
/// used both for the primary domain key (`domain_public_key`, below) and for
/// the sibling keys the certificate-revocation test needs a quorum from.
fn keyed_domain_public_key(now: DateTime<Utc>, seed: [u8; 32], key_id: &str) -> DomainPublicKey {
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pk = *sk.verifying_key().as_bytes();
    DomainPublicKey {
        key_id: key_id.to_string(),
        public_key: pk.to_vec(),
        fingerprint: crypto::fingerprint(&pk),
        algorithm: ALGORITHM_ED25519.to_string(),
        key_usage: "sign".to_string(),
        signed_by_key_id: None,
        key_signature: None,
        created_at: (now - Duration::days(30)).to_rfc3339(),
        expires_at: (now + Duration::days(365)).to_rfc3339(),
        revoked_at: None,
    }
}

fn domain_public_key(now: DateTime<Utc>) -> DomainPublicKey {
    keyed_domain_public_key(now, DOMAIN_SIGNING_SEED, DOMAIN_KEY_ID)
}

/// Every knob a failure-case test can turn, applied in this order: build the
/// correct payload/domain key/claim/redemption, then apply these mutators,
/// then sign + seal + serve. Defaults are all no-ops (the happy path).
struct Scenario {
    mutate_payload: Box<dyn Fn(&mut LocalRpCallbackPayload)>,
    mutate_domain_key: Box<dyn Fn(&mut DomainPublicKey)>,
    mutate_claim: Box<dyn Fn(&mut Claim)>,
    /// Applied to the ticket-redemption response after it's built from the
    /// (already claim-signed) fixture claim — lets a test make the
    /// UNSIGNED redemption response disagree with the SIGNED callback
    /// payload, which is exactly the class of attack Fix A closes.
    mutate_redemption: Box<dyn Fn(&mut LocalRpTicketRedemptionResponse)>,
    /// Additional domain signing keys the fake IDP serves alongside the
    /// primary one (only used by the certificate-revocation test, which
    /// needs a quorum of sibling signers distinct from the target key).
    extra_domain_keys: Vec<DomainPublicKey>,
    /// Revocation certificates the fake IDP's `get-revocations` returns.
    revocations: Vec<RevocationCertificate>,
    /// When true, the fake IDP answers `get-revocations` with a transport
    /// error instead of a certificate list — proves a revocation-fetch
    /// failure is fatal (fail-closed), not swallowed.
    fail_revocations: bool,
    dns_fingerprint_override: Option<String>,
    expected_requests: usize,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            mutate_payload: Box::new(|_| {}),
            mutate_domain_key: Box::new(|_| {}),
            mutate_claim: Box::new(|_| {}),
            mutate_redemption: Box::new(|_| {}),
            extra_domain_keys: Vec::new(),
            revocations: Vec::new(),
            fail_revocations: false,
            dns_fingerprint_override: None,
            // get-domain-keys + get-revocations (always fetched, see module
            // docs) + redeem-claim-ticket.
            expected_requests: 3,
        }
    }
}

fn run_scenario(scenario: Scenario) -> Result<linkkeys_local_rp::VerifiedLocalLogin, Error> {
    let now = Utc::now();
    let key_material = fixed_key_material(now);

    let (_redirect, pending): (_, PendingLogin) = begin_local_login(BeginLocalLoginConfig::new(
        &key_material,
        CALLBACK_URL,
        USER_DOMAIN,
        now,
    ))
    .unwrap();

    let mut domain_key = domain_public_key(now);
    (scenario.mutate_domain_key)(&mut domain_key);
    let mut all_domain_keys = vec![domain_key.clone()];
    all_domain_keys.extend(scenario.extra_domain_keys.iter().cloned());

    let claim_ticket = vec![7u8; 32];
    let mut payload = local_rp::build_local_rp_callback_payload(
        "user-1",
        USER_DOMAIN,
        claim_ticket.clone(),
        &key_material.fingerprint,
        CALLBACK_URL,
        pending.nonce.clone(),
        pending.state.clone(),
        &now.to_rfc3339(),
        &(now + Duration::minutes(5)).to_rfc3339(),
    );
    (scenario.mutate_payload)(&mut payload);

    let signed_payload = local_rp::sign_local_rp_callback_payload(
        &payload,
        DOMAIN_KEY_ID,
        crypto::SigningAlgorithm::Ed25519,
        &DOMAIN_SIGNING_SEED,
    )
    .unwrap();

    let encrypted = local_rp::seal_local_rp_callback(
        &signed_payload,
        AeadSuite::Aes256Gcm,
        &key_material.encryption_public_key,
        &payload.audience_fingerprint,
        payload.nonce.clone(),
        payload.state.clone(),
        &payload.issued_at,
        &payload.expires_at,
    )
    .unwrap();
    let encrypted_token =
        liblinkkeys::encoding::local_rp_encrypted_callback_to_url_param(&encrypted).unwrap();
    let arrived_url = format!("{CALLBACK_URL}?encrypted_token={encrypted_token}");

    let mut claim = sign_claim(
        &ClaimSpec {
            claim_id: "claim-1",
            claim_type: "handle",
            claim_value: b"flowtestuser",
            user_id: "user-1",
            subject_domain: USER_DOMAIN,
            expires_at: None,
            attested_at: &now.to_rfc3339(),
        },
        &[ClaimSigner {
            domain: USER_DOMAIN,
            key_id: DOMAIN_KEY_ID,
            algorithm: crypto::SigningAlgorithm::Ed25519,
            private_key_bytes: &DOMAIN_SIGNING_SEED,
        }],
    )
    .unwrap();
    (scenario.mutate_claim)(&mut claim);

    let ticket_expires_at = (now + Duration::hours(1)).to_rfc3339();
    let mut redemption_response = LocalRpTicketRedemptionResponse {
        user_id: "user-1".to_string(),
        user_domain: USER_DOMAIN.to_string(),
        claims: vec![claim],
        ticket_expires_at,
    };
    (scenario.mutate_redemption)(&mut redemption_response);

    let domain_keys_for_wire = all_domain_keys.clone();
    let revocations_for_wire = scenario.revocations.clone();
    let fail_revocations = scenario.fail_revocations;
    let redemption_for_wire = redemption_response.clone();
    let addr = spawn_fake_idp(
        DOMAIN_SIGNING_SEED,
        scenario.expected_requests,
        move |service, op, _payload| match (service, op) {
            ("DomainKeys", "get-domain-keys") => {
                let resp = liblinkkeys::generated::types::GetDomainKeysResponse {
                    domain: USER_DOMAIN.to_string(),
                    keys: domain_keys_for_wire.clone(),
                    // Deliberately never set — see module docs: every
                    // scenario proves get-revocations is fetched
                    // unconditionally, not gated on this hint.
                    recent_revocations_available: None,
                };
                csilgen_transport::rpc::RpcResponse::ok(
                    "GetDomainKeysResponse",
                    liblinkkeys::generated::encode_get_domain_keys_response(&resp),
                )
            }
            ("DomainKeys", "get-revocations") => {
                if fail_revocations {
                    csilgen_transport::rpc::RpcResponse::transport_error(
                        csilgen_transport::Status::Unavailable,
                        "revocations temporarily unavailable (hostile IDP simulation)".to_string(),
                    )
                } else {
                    csilgen_transport::rpc::RpcResponse::ok(
                        "GetRevocationsResponse",
                        liblinkkeys::generated::encode_get_revocations_response(
                            &GetRevocationsResponse {
                                revocations: revocations_for_wire.clone(),
                            },
                        ),
                    )
                }
            }
            ("LocalRp", "redeem-claim-ticket") => csilgen_transport::rpc::RpcResponse::ok(
                "LocalRpTicketRedemptionResponse",
                liblinkkeys::generated::encode_local_rp_ticket_redemption_response(
                    &redemption_for_wire,
                ),
            ),
            _ => csilgen_transport::rpc::RpcResponse::transport_error(
                csilgen_transport::Status::UnknownServiceOrOp,
                format!("fake IDP has no handler for {service}/{op}"),
            ),
        },
    );

    let real_fingerprints: Vec<String> = all_domain_keys
        .iter()
        .map(|k| crypto::fingerprint(&k.public_key))
        .collect();
    let linkkeys_txt = match &scenario.dns_fingerprint_override {
        Some(fp) => liblinkkeys::dns::build_linkkeys_txt(std::slice::from_ref(fp)),
        None => liblinkkeys::dns::build_linkkeys_txt(&real_fingerprints),
    };
    let dns = FakeDnsResolver {
        linkkeys_txt,
        apis_txt: format!("v=lk1 tcp={}", addr),
    };
    let transport = TestTransport;

    let mut config =
        CompleteLocalLoginConfig::new(&key_material, &pending, &encrypted_token, &arrived_url, now);
    config.transport = &transport;
    config.dns = &dns;
    complete_local_login(config)
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[test]
fn happy_path_returns_verified_login() {
    let result = run_scenario(Scenario::default());
    let verified = result.unwrap_or_else(|e| panic!("expected success, got {e}"));
    assert_eq!(verified.user_id, "user-1");
    assert_eq!(verified.user_domain, USER_DOMAIN);
    assert_eq!(verified.claims.len(), 1);
    assert_eq!(verified.claims[0].claim_type, "handle");
    assert_eq!(verified.local_rp_fingerprint.len(), 64);
    assert_eq!(verified.domain_public_keys.len(), 1);
}

#[test]
fn wrong_audience_fingerprint_is_rejected() {
    let scenario = Scenario {
        mutate_payload: Box::new(|p| {
            p.audience_fingerprint = "b".repeat(64);
        }),
        expected_requests: 2,
        ..Scenario::default()
    };
    assert!(matches!(
        run_scenario(scenario),
        Err(Error::Verification(_))
    ));
}

#[test]
fn wrong_issuer_domain_is_rejected() {
    let scenario = Scenario {
        mutate_payload: Box::new(|p| {
            p.user_domain = "attacker.test".to_string();
        }),
        expected_requests: 2,
        ..Scenario::default()
    };
    assert!(matches!(
        run_scenario(scenario),
        Err(Error::Verification(_))
    ));
}

#[test]
fn nonce_mismatch_is_rejected() {
    let scenario = Scenario {
        mutate_payload: Box::new(|p| {
            p.nonce = vec![0xEE; 32];
        }),
        expected_requests: 2,
        ..Scenario::default()
    };
    assert!(matches!(
        run_scenario(scenario),
        Err(Error::Verification(_))
    ));
}

#[test]
fn expired_callback_payload_is_rejected() {
    let scenario = Scenario {
        mutate_payload: Box::new(|p| {
            let n = Utc::now();
            p.issued_at = (n - Duration::hours(2)).to_rfc3339();
            p.expires_at = (n - Duration::hours(1)).to_rfc3339();
        }),
        expected_requests: 2,
        ..Scenario::default()
    };
    assert!(matches!(
        run_scenario(scenario),
        Err(Error::Verification(_))
    ));
}

#[test]
fn dns_fingerprint_pin_mismatch_is_rejected() {
    let scenario = Scenario {
        dns_fingerprint_override: Some("c".repeat(64)),
        expected_requests: 1,
        ..Scenario::default()
    };
    // Fails during the TLS handshake (the fake IDP's real cert fingerprint
    // no longer matches the pinned set) or, if it somehow connects, during
    // trust_keys — either way it must never reach a verified result.
    assert!(run_scenario(scenario).is_err());
}

#[test]
fn revoked_signing_key_is_rejected() {
    let scenario = Scenario {
        mutate_domain_key: Box::new(|k| {
            k.revoked_at = Some(Utc::now().to_rfc3339());
        }),
        expected_requests: 2,
        ..Scenario::default()
    };
    assert!(matches!(
        run_scenario(scenario),
        Err(Error::Verification(_))
    ));
}

#[test]
fn tampered_claim_signature_is_rejected() {
    let scenario = Scenario {
        mutate_claim: Box::new(|c| {
            if let Some(sig) = c.signatures.first_mut() {
                if let Some(b) = sig.signature.first_mut() {
                    *b ^= 0xff;
                }
            }
        }),
        expected_requests: 3,
        ..Scenario::default()
    };
    assert!(matches!(run_scenario(scenario), Err(Error::Claim(_))));
}

// ---------------------------------------------------------------------
// Hostile-IDP tests (security review fix-up): a compromised/malicious IDP
// controls every network response this SDK receives. Each test proves one
// specific lie the IDP might tell is caught and rejected — FATAL, never a
// silent fallback to unverified data.
// ---------------------------------------------------------------------

/// (1) The claim-ticket redemption response — which carries no signature of
/// its own — names a different user than the domain-SIGNED callback
/// payload. A pre-fix SDK trusted the redemption response's identity
/// outright; this must be fatal.
#[test]
fn redemption_user_id_mismatch_with_signed_payload_is_rejected() {
    let scenario = Scenario {
        mutate_redemption: Box::new(|r| {
            r.user_id = "attacker-user".to_string();
        }),
        expected_requests: 3,
        ..Scenario::default()
    };
    assert!(matches!(
        run_scenario(scenario),
        Err(Error::IdentityMismatch(_))
    ));
}

/// (1, continued) Same lie, on the domain field instead of the user id.
#[test]
fn redemption_user_domain_mismatch_with_signed_payload_is_rejected() {
    let scenario = Scenario {
        mutate_redemption: Box::new(|r| {
            r.user_domain = "attacker.test".to_string();
        }),
        expected_requests: 3,
        ..Scenario::default()
    };
    assert!(matches!(
        run_scenario(scenario),
        Err(Error::IdentityMismatch(_))
    ));
}

/// (2) An individual claim inside an otherwise-correctly-signed redemption
/// response names a different `user_id` than the signed callback payload —
/// a malicious IDP splicing another user's claim into this login's
/// response. The claim's own signature only proves ITS issuing domain
/// signed that claim, not that it belongs to this login's subject, so this
/// must be checked and rejected independently of signature validity.
#[test]
fn claim_user_id_mismatch_with_signed_payload_is_rejected() {
    let scenario = Scenario {
        mutate_claim: Box::new(|c| {
            c.user_id = "attacker-user".to_string();
        }),
        expected_requests: 3,
        ..Scenario::default()
    };
    assert!(matches!(
        run_scenario(scenario),
        Err(Error::IdentityMismatch(_))
    ));
}

/// (3) `begin_local_login`'s default `required_claims` (["handle"]) demands
/// a claim the redemption response doesn't actually return. A pre-fix SDK
/// never checked `required_claims` at all, so a malicious/degraded IDP
/// could silently drop a required claim and completion would still succeed.
#[test]
fn required_claims_not_satisfied_when_redemption_returns_no_claims_is_rejected() {
    let scenario = Scenario {
        mutate_redemption: Box::new(|r| {
            r.claims = Vec::new();
        }),
        expected_requests: 3,
        ..Scenario::default()
    };
    match run_scenario(scenario) {
        Err(Error::RequiredClaimsNotSatisfied(missing)) => {
            assert_eq!(missing, vec!["handle".to_string()]);
        }
        other => panic!("expected RequiredClaimsNotSatisfied, got {other:?}"),
    }
}

/// (4) The fake IDP answers `get-domain-keys` normally but fails
/// `get-revocations` outright. A pre-fix SDK treated revocation delivery as
/// best-effort and silently proceeded with an unfiltered (possibly
/// containing revoked signers) key set; this must fail closed instead.
#[test]
fn get_revocations_transport_error_fails_closed() {
    let scenario = Scenario {
        fail_revocations: true,
        expected_requests: 2,
        ..Scenario::default()
    };
    assert!(matches!(
        run_scenario(scenario),
        Err(Error::ServerError { .. })
    ));
}

/// (5) A genuine, quorum-valid sibling-signed revocation certificate
/// targets the exact domain signing key that signed both the callback
/// envelope and the claim. Because the fixture never sets
/// `recent_revocations_available` (see module docs), this also proves
/// revocations are fetched unconditionally: a pre-fix SDK gated the
/// `get-revocations` call on that flag and would never have learned of this
/// certificate at all, so the envelope would still verify against the
/// (now-revoked) signing key.
#[test]
fn revocation_certificate_drops_signing_key_and_login_fails_closed() {
    let now = Utc::now();
    let sibling_a = keyed_domain_public_key(now, SIBLING_A_SEED, SIBLING_A_KEY_ID);
    let sibling_b = keyed_domain_public_key(now, SIBLING_B_SEED, SIBLING_B_KEY_ID);
    let target_fingerprint = domain_public_key(now).fingerprint;

    let spec = RevocationSpec {
        target_key_id: DOMAIN_KEY_ID,
        target_fingerprint: &target_fingerprint,
        revoked_at: &now.to_rfc3339(),
    };
    let cert = build_revocation_certificate(
        &spec,
        &[
            ClaimSigner {
                domain: USER_DOMAIN,
                key_id: SIBLING_A_KEY_ID,
                algorithm: crypto::SigningAlgorithm::Ed25519,
                private_key_bytes: &SIBLING_A_SEED,
            },
            ClaimSigner {
                domain: USER_DOMAIN,
                key_id: SIBLING_B_KEY_ID,
                algorithm: crypto::SigningAlgorithm::Ed25519,
                private_key_bytes: &SIBLING_B_SEED,
            },
        ],
    )
    .unwrap();

    let scenario = Scenario {
        extra_domain_keys: vec![sibling_a, sibling_b],
        revocations: vec![cert],
        // get-domain-keys + get-revocations only: the envelope fails to
        // verify (its signing key was just dropped) before any ticket is
        // ever redeemed.
        expected_requests: 2,
        ..Scenario::default()
    };
    assert!(matches!(
        run_scenario(scenario),
        Err(Error::Verification(_))
    ));
}
