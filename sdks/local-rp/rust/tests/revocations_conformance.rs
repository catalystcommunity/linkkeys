//! Conformance coverage for `sdks/local-rp/conformance/revocations.json` —
//! sibling-signed key revocation certificates (see that directory's README,
//! "revocations.json" section, for the schema and the nine certificate
//! cases).
//!
//! Two layers, matching how this SDK actually uses revocations:
//!
//! - `certificate_cases[]` exercise
//!   `liblinkkeys::revocation::verify_revocation_certificate` — the exact
//!   call `linkkeys_local_rp::rpc::fetch_domain_keys` makes for every
//!   fetched certificate — asserting both the overall valid/invalid outcome
//!   and, for failures, the distinct-counted-signer number the error
//!   reports (`expected_counted_signers`), which pinpoints which filtering
//!   rule an implementation got wrong.
//!
//! - `application_case` runs the flow `complete_local_login` actually
//!   performs, through the SDK's own network path: a fake TLS+TCP CSIL-RPC
//!   IDP serves the fixture's five domain keys (where the target key
//!   carries NO `revoked_at` and looks perfectly valid) plus the valid
//!   quorum certificate; `linkkeys_local_rp::rpc::fetch_domain_keys` must
//!   verify the certificate and drop its target from the trusted set, so
//!   the fixture's callback-payload envelope (signed by the target key)
//!   flips from verifying (against the pre-revocation key list) to failing
//!   (against the SDK's post-revocation trusted set). An SDK that verifies
//!   certificates but forgets to *apply* them fails this case.

use liblinkkeys::generated::types::{
    ClaimSignature, DomainPublicKey, GetDomainKeysResponse, GetRevocationsResponse,
    RevocationCertificate, SignedLocalRpCallbackPayload,
};
use liblinkkeys::revocation::{verify_revocation_certificate, RevocationError, REVOCATION_QUORUM};
use linkkeys_local_rp::dns::{DnsLookupError, DnsResolver};
use linkkeys_local_rp::transport::{ReadWrite, Transport, TransportError};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;

fn load_revocations() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../conformance/revocations.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {} (run the generator?)", path.display(), e));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e))
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd-length hex string: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .unwrap_or_else(|e| panic!("bad hex byte at {i} in {s:?}: {e}"))
        })
        .collect()
}

/// Build the fixture's five `DomainPublicKey` wire entries from
/// `domain_keys[]`.
fn fixture_domain_keys(d: &Value) -> Vec<DomainPublicKey> {
    d["domain_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| DomainPublicKey {
            key_id: k["key_id"].as_str().unwrap().to_string(),
            public_key: hex_decode(k["public_key_hex"].as_str().unwrap()),
            fingerprint: k["fingerprint_hex"].as_str().unwrap().to_string(),
            algorithm: k["algorithm"].as_str().unwrap().to_string(),
            key_usage: k["key_usage"].as_str().unwrap().to_string(),
            created_at: k["created_at"].as_str().unwrap().to_string(),
            expires_at: k["expires_at"].as_str().unwrap().to_string(),
            revoked_at: k["revoked_at"].as_str().map(|s| s.to_string()),
            signed_by_key_id: None,
            key_signature: None,
        })
        .collect()
}

/// Build a `RevocationCertificate` from a case's expanded `certificate`
/// fields.
fn certificate_from_case(case: &Value) -> RevocationCertificate {
    let cert = &case["certificate"];
    RevocationCertificate {
        target_key_id: cert["target_key_id"].as_str().unwrap().to_string(),
        target_fingerprint: cert["target_fingerprint"].as_str().unwrap().to_string(),
        revoked_at: cert["revoked_at"].as_str().unwrap().to_string(),
        signatures: cert["signatures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| ClaimSignature {
                domain: s["domain"].as_str().unwrap().to_string(),
                signed_by_key_id: s["signed_by_key_id"].as_str().unwrap().to_string(),
                signature: hex_decode(s["signature_hex"].as_str().unwrap()),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------
// certificate_cases[]
// ---------------------------------------------------------------------

#[test]
fn revocations_quorum_constant_matches_fixture() {
    let d = load_revocations();
    assert_eq!(d["quorum"].as_u64().unwrap() as usize, REVOCATION_QUORUM);
}

#[test]
fn revocations_certificate_cbor_round_trips() {
    // The wire encoding in every case must decode to exactly the expanded
    // fields (and re-encode byte-identically), independent of verification.
    let d = load_revocations();
    for case in d["certificate_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let expected = certificate_from_case(case);
        let cbor = hex_decode(case["certificate_cbor_hex"].as_str().unwrap());
        let decoded = liblinkkeys::generated::decode_revocation_certificate(&cbor)
            .unwrap_or_else(|e| panic!("{name}: decode certificate_cbor_hex: {e}"));
        assert_eq!(decoded, expected, "{name}: wire/expanded field mismatch");
        assert_eq!(
            liblinkkeys::generated::encode_revocation_certificate(&expected),
            cbor,
            "{name}: re-encode is not byte-identical"
        );
    }
}

#[test]
fn revocations_certificate_cases_verify_with_expected_outcome_and_signer_count() {
    let d = load_revocations();
    let keys = fixture_domain_keys(&d);
    let cases = d["certificate_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 9, "expected the nine documented cases");

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let verify_domain = case["verify_domain"].as_str().unwrap();
        let expected_valid = case["expected_valid"].as_bool().unwrap();
        let expected_counted = case["expected_counted_signers"].as_u64().unwrap() as usize;

        // Verify from the decoded wire bytes (what an SDK actually receives
        // over get-revocations), exactly as fetch_domain_keys does.
        let cbor = hex_decode(case["certificate_cbor_hex"].as_str().unwrap());
        let cert = liblinkkeys::generated::decode_revocation_certificate(&cbor).unwrap();

        let result = verify_revocation_certificate(&cert, &keys, verify_domain);
        assert_eq!(
            result.is_ok(),
            expected_valid,
            "{name}: expected_valid={expected_valid}, got {result:?}"
        );
        match result {
            Ok(()) => {
                // A valid certificate means the counted signers reached
                // quorum; the fixture states the exact count for clarity.
                assert!(
                    expected_counted >= REVOCATION_QUORUM,
                    "{name}: fixture claims valid with fewer than quorum signers"
                );
            }
            Err(RevocationError::InsufficientSignatures { got, need }) => {
                assert_eq!(
                    got, expected_counted,
                    "{name}: counted signers mismatch (which filtering rule differed?)"
                );
                assert_eq!(need, REVOCATION_QUORUM, "{name}: quorum mismatch");
            }
        }
    }
}

// ---------------------------------------------------------------------
// application_case — through the SDK's own fetch_domain_keys path
// ---------------------------------------------------------------------

const FIXTURE_DOMAIN_SEED: [u8; 32] = [9u8; 32]; // sibling-key-1's seed_hex

struct TestTransport;

impl Transport for TestTransport {
    fn dial(&self, host_port: &str) -> Result<Box<dyn ReadWrite>, TransportError> {
        std::net::TcpStream::connect(host_port)
            .map(|s| Box::new(s) as Box<dyn ReadWrite>)
            .map_err(|e| TransportError::Connect(e.to_string()))
    }
}

struct FakeDnsResolver {
    domain: String,
    linkkeys_txt: String,
    apis_txt: String,
}

impl DnsResolver for FakeDnsResolver {
    fn txt_lookup(&self, name: &str) -> Result<Vec<String>, DnsLookupError> {
        if name == format!("_linkkeys.{}", self.domain) {
            Ok(vec![self.linkkeys_txt.clone()])
        } else if name == format!("_linkkeys_apis.{}", self.domain) {
            Ok(vec![self.apis_txt.clone()])
        } else {
            Err(DnsLookupError::Lookup(format!("no fake record for {name}")))
        }
    }
}

/// Minimal fake IDP: answers `expected_requests` CSIL-RPC requests over TLS
/// on a fresh loopback port, presenting a cert derived from `domain_seed`
/// (same shape as `tests/flow.rs`'s fake IDP).
fn spawn_fake_idp<F>(
    domain: &str,
    domain_seed: [u8; 32],
    expected_requests: usize,
    dispatch: F,
) -> std::net::SocketAddr
where
    F: Fn(&str, &str) -> csilgen_transport::rpc::RpcResponse + Send + Sync + 'static,
{
    let (cert_der, key_der) =
        linkkeys_rpc_client::tls::generate_domain_tls_cert(domain, &domain_seed)
            .expect("generate fake IDP TLS cert");
    let certs = vec![rustls::pki_types::CertificateDer::from(cert_der)];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_der,
    ));
    let server_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("build fake IDP server TLS config"),
    );

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

            let resp = dispatch(&req.service, &req.op);
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

#[test]
fn revocations_application_case_flips_envelope_from_valid_to_invalid() {
    let d = load_revocations();
    let domain = d["domain"].as_str().unwrap().to_string();
    let keys = fixture_domain_keys(&d);
    let app = &d["application_case"];

    // Sanity: the fixture's first key really is the seed this test derives
    // the fake IDP's TLS cert from.
    {
        let sk = ed25519_dalek::SigningKey::from_bytes(&FIXTURE_DOMAIN_SEED);
        assert_eq!(
            sk.verifying_key().as_bytes().to_vec(),
            keys[0].public_key,
            "FIXTURE_DOMAIN_SEED no longer matches domain_keys[0] — fixture changed?"
        );
    }

    // The envelope: a SignedLocalRpCallbackPayload signed by the revocation
    // TARGET key (sibling-key-3).
    let envelope = &app["envelope"];
    assert_eq!(envelope["structure"].as_str().unwrap(), "callback_payload");
    let signed_payload = SignedLocalRpCallbackPayload {
        payload: hex_decode(envelope["payload_cbor_hex"].as_str().unwrap()),
        signing_key_id: envelope["signing_key_id"].as_str().unwrap().to_string(),
        signature: hex_decode(envelope["signature_hex"].as_str().unwrap()),
    };
    let verify_now = chrono::DateTime::parse_from_rfc3339(app["verify_now"].as_str().unwrap())
        .unwrap()
        .with_timezone(&chrono::Utc);
    let skew = app["clock_skew_seconds"].as_i64().unwrap();

    // BEFORE revocation: against the raw fetched key list (target key carries
    // no revoked_at and looks perfectly valid), the envelope verifies. This
    // is the same `verify_local_rp_callback_payload` call
    // `complete_local_login` makes.
    assert!(app["expected_valid_before_revocation"].as_bool().unwrap());
    liblinkkeys::local_rp::verify_local_rp_callback_payload(
        &signed_payload,
        &keys,
        verify_now,
        skew,
    )
    .expect("envelope must verify against the pre-revocation key list");

    // AFTER: run the SDK's own fetch path. The fake IDP serves the five
    // fixture keys with recent_revocations_available=true, then the valid
    // quorum certificate; `fetch_domain_keys` must verify it and drop the
    // target key from the returned trusted set.
    let cert_case = d["certificate_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"].as_str() == Some("valid_quorum_two_siblings"))
        .expect("certificate_ref target must exist");
    let cert_cbor = hex_decode(cert_case["certificate_cbor_hex"].as_str().unwrap());
    let cert = liblinkkeys::generated::decode_revocation_certificate(&cert_cbor).unwrap();
    let target_key_id = cert.target_key_id.clone();

    let keys_for_wire = keys.clone();
    let domain_for_wire = domain.clone();
    let addr = spawn_fake_idp(&domain, FIXTURE_DOMAIN_SEED, 2, move |service, op| {
        match (service, op) {
            ("DomainKeys", "get-domain-keys") => csilgen_transport::rpc::RpcResponse::ok(
                "GetDomainKeysResponse",
                liblinkkeys::generated::encode_get_domain_keys_response(&GetDomainKeysResponse {
                    domain: domain_for_wire.clone(),
                    keys: keys_for_wire.clone(),
                    recent_revocations_available: Some(true),
                }),
            ),
            ("DomainKeys", "get-revocations") => csilgen_transport::rpc::RpcResponse::ok(
                "GetRevocationsResponse",
                liblinkkeys::generated::encode_get_revocations_response(&GetRevocationsResponse {
                    revocations: vec![cert.clone()],
                }),
            ),
            _ => csilgen_transport::rpc::RpcResponse::transport_error(
                csilgen_transport::Status::UnknownServiceOrOp,
                format!("fake IDP has no handler for {service}/{op}"),
            ),
        }
    });

    // Pin every fixture signing key's fingerprint so trust_keys keeps them
    // all (the point of this case is revocation dropping a PINNED key, not
    // pin filtering).
    let fp_parts: Vec<String> = keys
        .iter()
        .map(|k| format!("fp={}", k.fingerprint))
        .collect();
    let dns = FakeDnsResolver {
        domain: domain.clone(),
        linkkeys_txt: format!("v=lk1 {}", fp_parts.join(" ")),
        apis_txt: format!("v=lk1 tcp={addr}"),
    };
    let transport = TestTransport;

    let trusted = linkkeys_local_rp::rpc::fetch_domain_keys(&transport, &dns, &domain)
        .expect("fetch_domain_keys must succeed (siblings remain trusted)");
    assert!(
        !trusted.iter().any(|k| k.key_id == target_key_id),
        "the revocation target must be dropped from the SDK's trusted set"
    );
    assert!(
        trusted.iter().any(|k| k.key_id == "sibling-key-1")
            && trusted.iter().any(|k| k.key_id == "sibling-key-2"),
        "non-target siblings must remain trusted"
    );

    // The same envelope must now FAIL against the SDK's post-revocation
    // trusted set (the target key is simply gone).
    assert!(!app["expected_valid_after_revocation"].as_bool().unwrap());
    let result = liblinkkeys::local_rp::verify_local_rp_callback_payload(
        &signed_payload,
        &trusted,
        verify_now,
        skew,
    );
    assert!(
        result.is_err(),
        "envelope signed by the revoked key must fail after applying the certificate"
    );
}
