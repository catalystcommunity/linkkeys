//! Act-as grantee tests: the `local_rp_grantee` case of
//! `sdks/regular-rp/conformance/act_as_grantee_signing.json` (exact bytes),
//! begin with a fake DNS resolver, and refresh against a loopback fake home
//! domain (real TLS pin and CSIL-RPC framing; only DNS is faked). No test
//! touches the live network.

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use csilgen_transport::rpc::RpcResponse;
use liblinkkeys::act_as::{self, REFRESH_REQUEST_TAG};
use liblinkkeys::generated::{self, types::ApplicationRef};
use liblinkkeys::local_rp::envelope_signature_input;
use linkkeys_local_rp::dns::{DnsLookupError, DnsResolver};
use linkkeys_local_rp::transport::{ReadWrite, Transport, TransportError};
use linkkeys_local_rp::{
    act_as_grant_request_url_param, begin_act_as, complete_act_as_callback, local_rp_grantee,
    present_act_as, refresh_act_as_grant, sign_act_as_grant_request, sign_act_as_refresh_request,
    ActAsGrantRequest, ActAsRefreshRequest, BeginActAsConfig, Error, LocalRpKeyMaterial,
    RefreshActAsGrantConfig,
};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const HOME_DOMAIN: &str = "home.conformance.example";
const TLS_SEED: [u8; 32] = [7u8; 32];

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../regular-rp/conformance/act_as_grantee_signing.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_string()
}

fn time(v: &Value) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(v.as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc)
}

fn local_case(v: &Value) -> &Value {
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "local_rp_grantee")
        .expect("local_rp_grantee case")
}

/// Key material from the vector's published descriptor seed. The encryption
/// key is unused by act-as, so a fixed placeholder fills it.
fn vector_key_material(v: &Value) -> LocalRpKeyMaterial {
    let local = &v["local_rp_grantee"];
    let seed: [u8; 32] = unhex(local["signing_private_key_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let signing_public_key = *ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .as_bytes();
    let descriptor = generated::decode_signed_local_rp_descriptor(&unhex(
        local["signed_descriptor_cbor_hex"].as_str().unwrap(),
    ))
    .unwrap();
    LocalRpKeyMaterial {
        signing_private_key: seed,
        signing_public_key,
        encryption_private_key: [0u8; 32],
        encryption_public_key: [0u8; 32],
        descriptor,
        fingerprint: s(&local["fingerprint"]),
    }
}

fn app_ref(v: &Value) -> ApplicationRef {
    ApplicationRef {
        subject_user_id: s(&v["subject_user_id"]),
        subject_domain: s(&v["subject_domain"]),
        application_id: s(&v["application_id"]),
    }
}

// ---------------------------------------------------------------------
// Conformance: exact bytes
// ---------------------------------------------------------------------

#[test]
fn local_rp_grantee_vector_bytes_match() {
    let v = vectors();
    let m = vector_key_material(&v);
    let case = local_case(&v);
    assert_eq!(
        local_rp_grantee(&m).local_rp_descriptor_fingerprint,
        case["grantee"]["local_rp_descriptor_fingerprint"]
            .as_str()
            .map(str::to_string)
    );

    let g = &case["grant_request"];
    let i = &g["inputs"];
    let request = ActAsGrantRequest {
        grantee: local_rp_grantee(&m),
        scope_set: generated::decode_signed_act_as_scope_set(&unhex(
            i["scope_set_signed_cbor_hex"].as_str().unwrap(),
        ))
        .unwrap(),
        requested_lifetime_seconds: i["requested_lifetime_seconds"].as_i64(),
        requested_renewal_window_seconds: i["requested_renewal_window_seconds"].as_i64(),
        grantee_handle_claim: None,
        callback_url: s(&i["callback_url"]),
        nonce: s(&i["nonce"]),
        requested_at: s(&i["requested_at"]),
        expires_at: s(&i["expires_at"]),
    };
    let signed = sign_act_as_grant_request(&m, &request).unwrap();
    assert_eq!(
        signed.request,
        unhex(g["request_cbor_hex"].as_str().unwrap())
    );
    assert_eq!(
        generated::encode_signed_act_as_grant_request(&signed),
        unhex(g["signed_cbor_hex"].as_str().unwrap())
    );
    assert_eq!(act_as_grant_request_url_param(&signed), s(&g["url_param"]));

    let r = &case["refresh_request"];
    let i = &r["inputs"];
    let refresh = ActAsRefreshRequest {
        grant_id: s(&i["grant_id"]),
        grantee: local_rp_grantee(&m),
        requested_at: s(&i["requested_at"]),
        expires_at: s(&i["expires_at"]),
        nonce: s(&i["nonce"]),
    };
    let signed = sign_act_as_refresh_request(&m, &refresh).unwrap();
    assert_eq!(
        signed.request,
        unhex(r["request_cbor_hex"].as_str().unwrap())
    );
    assert_eq!(
        generated::encode_signed_act_as_refresh_request(&signed),
        unhex(r["signed_cbor_hex"].as_str().unwrap())
    );

    let p = &case["presentation"];
    let i = &p["inputs"];
    let grant =
        generated::decode_signed_act_as_grant(&unhex(i["grant_signed_cbor_hex"].as_str().unwrap()))
            .unwrap();
    let presented = present_act_as(
        &grant,
        &app_ref(&i["audience"]),
        &unhex(i["request_digest_hex"].as_str().unwrap()),
        time(&i["presented_at"]),
        &unhex(i["nonce_hex"].as_str().unwrap()),
        &m,
    )
    .unwrap();
    assert_eq!(
        presented.credential.presentation.presentation,
        unhex(p["presentation_cbor_hex"].as_str().unwrap())
    );
    assert_eq!(
        act_as::grant_hash(&grant.grant),
        unhex(p["grant_hash_hex"].as_str().unwrap())
    );
    assert_eq!(
        presented.credential_cbor,
        unhex(p["credential_cbor_hex"].as_str().unwrap())
    );
}

// ---------------------------------------------------------------------
// begin_act_as with a fake DNS resolver
// ---------------------------------------------------------------------

struct MapDns(HashMap<String, Vec<String>>);

impl MapDns {
    fn empty() -> Self {
        Self(HashMap::new())
    }
    fn with(mut self, name: &str, txts: &[&str]) -> Self {
        self.0.insert(
            name.to_string(),
            txts.iter().map(|t| t.to_string()).collect(),
        );
        self
    }
}

impl DnsResolver for MapDns {
    fn txt_lookup(&self, name: &str) -> Result<Vec<String>, DnsLookupError> {
        self.0
            .get(name)
            .cloned()
            .ok_or_else(|| DnsLookupError::Lookup(format!("no fake record for {name}")))
    }
}

fn scope_set_bytes(v: &Value) -> Vec<u8> {
    unhex(
        local_case(v)["grant_request"]["inputs"]["scope_set_signed_cbor_hex"]
            .as_str()
            .unwrap(),
    )
}

fn signed_request_param(redirect_url: &str) -> String {
    url::Url::parse(redirect_url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "signed_request")
        .map(|(_, v)| v.into_owned())
        .expect("signed_request parameter")
}

#[test]
fn begin_act_as_uses_discovered_host_and_signs_a_verifiable_request() {
    let v = vectors();
    let m = vector_key_material(&v);
    let scope_set = scope_set_bytes(&v);
    let dns = MapDns::empty().with(
        &format!("_linkkeys_apis.{HOME_DOMAIN}"),
        &["v=lk1 tcp=tcp.home.example:4987 https=login.home.example/linkkeys"],
    );
    let now = time(&local_case(&v)["grant_request"]["inputs"]["requested_at"]);
    let mut config = BeginActAsConfig::new(
        &m,
        format!("alice@{HOME_DOMAIN}"),
        &scope_set,
        "http://app.lan:8080/act-as/callback",
        now,
    );
    config.dns = Some(&dns);
    config.requested_lifetime_seconds = Some(1800);
    config.requested_renewal_window_seconds = Some(600);
    let (redirect, pending) = begin_act_as(config).unwrap();

    assert!(
        redirect
            .redirect_url
            .starts_with("https://login.home.example/linkkeys/auth/act-as?signed_request="),
        "{}",
        redirect.redirect_url
    );
    assert_eq!(pending.user_domain, HOME_DOMAIN);
    assert_eq!(pending.callback_url, "http://app.lan:8080/act-as/callback");
    assert_eq!(
        Base64UrlUnpadded::decode_vec(&pending.nonce).unwrap().len(),
        32
    );

    let cbor =
        Base64UrlUnpadded::decode_vec(&signed_request_param(&redirect.redirect_url)).unwrap();
    let signed = generated::decode_signed_act_as_grant_request(&cbor).unwrap();
    // The home domain's own verifier accepts it (descriptor proof, window).
    let request = act_as::verify_grant_request(&signed, &[], now, 0).unwrap();
    assert_eq!(request.nonce, pending.nonce);
    assert_eq!(request.grantee, local_rp_grantee(&m));
    assert_eq!(request.requested_lifetime_seconds, Some(1800));
    assert_eq!(request.requested_renewal_window_seconds, Some(600));
    assert_eq!(request.requested_at, "2026-10-06T11:59:00Z");
    assert_eq!(request.expires_at, "2026-10-06T12:04:00Z");
    // The scope set rides unchanged.
    assert_eq!(
        generated::encode_signed_act_as_scope_set(&request.scope_set),
        scope_set
    );
}

#[test]
fn begin_act_as_falls_back_to_identity_domain() {
    let v = vectors();
    let m = vector_key_material(&v);
    let scope_set = scope_set_bytes(&v);
    for dns in [
        MapDns::empty(),
        MapDns::empty().with(
            &format!("_linkkeys_apis.{HOME_DOMAIN}"),
            &["v=lk1 tcp=t.example"],
        ),
    ] {
        let mut config =
            BeginActAsConfig::new(&m, HOME_DOMAIN, &scope_set, "https://app/cb", Utc::now());
        config.dns = Some(&dns);
        let (redirect, _) = begin_act_as(config).unwrap();
        assert!(redirect.redirect_url.starts_with(&format!(
            "https://{HOME_DOMAIN}/auth/act-as?signed_request="
        )));
    }
}

#[test]
fn begin_act_as_rejects_bad_inputs_and_never_reuses_nonces() {
    let v = vectors();
    let m = vector_key_material(&v);
    let scope_set: &'static [u8] = scope_set_bytes(&v).leak();
    let dns = MapDns::empty();
    let config = |window: Option<Duration>, callback: &str, scope: &'static [u8]| {
        let mut c = BeginActAsConfig::new(&m, HOME_DOMAIN, scope, callback, Utc::now());
        c.dns = Some(&dns);
        c.request_window = window;
        c
    };
    let ok = |window| begin_act_as(config(window, "https://app/cb", scope_set));
    assert!(ok(Some(Duration::seconds(900))).is_ok());
    assert!(matches!(
        ok(Some(Duration::seconds(901))),
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        ok(Some(Duration::zero())),
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        begin_act_as(config(None, "myapp://cb", scope_set)),
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        begin_act_as(config(None, "https://app/cb", b"not cbor")),
        Err(Error::Decode(_))
    ));
    let mut c = config(None, "https://app/cb", scope_set);
    c.requested_lifetime_seconds = Some(0);
    assert!(matches!(begin_act_as(c), Err(Error::InvalidInput(_))));

    let (_, a) = ok(None).unwrap();
    let (_, b) = ok(None).unwrap();
    assert_ne!(a.nonce, b.nonce);
}

#[test]
fn callback_round_trip_with_begin_nonce() {
    let v = vectors();
    let m = vector_key_material(&v);
    let scope_set = scope_set_bytes(&v);
    let dns = MapDns::empty();
    let mut config =
        BeginActAsConfig::new(&m, HOME_DOMAIN, &scope_set, "https://app/cb", Utc::now());
    config.dns = Some(&dns);
    let (_, pending) = begin_act_as(config).unwrap();

    let good = format!(
        "https://app/cb?act_as_grant_id=grant-9&nonce={}",
        pending.nonce
    );
    assert_eq!(
        complete_act_as_callback(&pending, &good).unwrap(),
        "grant-9"
    );
    let bad = "https://app/cb?act_as_grant_id=grant-9&nonce=someone-elses-nonce";
    assert!(matches!(
        complete_act_as_callback(&pending, bad),
        Err(Error::Verification(_))
    ));
}

// ---------------------------------------------------------------------
// refresh_act_as_grant against a loopback fake home domain
// ---------------------------------------------------------------------

struct LoopbackTransport;

impl Transport for LoopbackTransport {
    fn dial(&self, host_port: &str) -> Result<Box<dyn ReadWrite>, TransportError> {
        std::net::TcpStream::connect(host_port)
            .map(|s| Box::new(s) as Box<dyn ReadWrite>)
            .map_err(|e| TransportError::Connect(e.to_string()))
    }
}

type Seen = Arc<Mutex<Vec<(String, String, Vec<u8>)>>>;

/// Serves one TLS CSIL-RPC call on loopback with a certificate from
/// `TLS_SEED`, records it, and answers with `reply`. Returns the address,
/// the pinned fingerprint, and the record.
fn spawn_home(reply: RpcResponse) -> (std::net::SocketAddr, String, Seen) {
    let (cert_der, key_der) =
        linkkeys_rpc_client::tls::generate_domain_tls_cert(HOME_DOMAIN, &TLS_SEED).unwrap();
    let fingerprint = liblinkkeys::crypto::fingerprint(
        ed25519_dalek::SigningKey::from_bytes(&TLS_SEED)
            .verifying_key()
            .as_bytes(),
    );
    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(cert_der)],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
                ),
            )
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let record = seen.clone();
    std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let conn = rustls::ServerConnection::new(config).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, stream);
        let mut len = [0u8; 4];
        if tls.read_exact(&mut len).is_err() {
            return;
        }
        let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
        if tls.read_exact(&mut buf).is_err() {
            return;
        }
        let req = csilgen_transport::rpc::RpcRequest::decode(&buf).unwrap();
        record
            .lock()
            .unwrap()
            .push((req.service.clone(), req.op.clone(), req.payload.clone()));
        let encoded = reply.encode().unwrap();
        let _ = tls.write_all(&(encoded.len() as u32).to_be_bytes());
        let _ = tls.write_all(&encoded);
        let _ = tls.flush();
    });
    (addr, fingerprint, seen)
}

fn home_dns(addr: std::net::SocketAddr, fingerprint: &str) -> MapDns {
    MapDns::empty()
        .with(
            &format!("_linkkeys.{HOME_DOMAIN}"),
            &[&format!("v=lk1 fp={fingerprint}")],
        )
        .with(
            &format!("_linkkeys_apis.{HOME_DOMAIN}"),
            &[&format!("v=lk1 tcp={addr}")],
        )
}

fn vector_grant(v: &Value) -> liblinkkeys::generated::types::SignedActAsGrant {
    generated::decode_signed_act_as_grant(&unhex(
        local_case(v)["presentation"]["inputs"]["grant_signed_cbor_hex"]
            .as_str()
            .unwrap(),
    ))
    .unwrap()
}

fn ok_reply(grant: &liblinkkeys::generated::types::SignedActAsGrant, signed: bool) -> RpcResponse {
    RpcResponse::ok(
        "RefreshActAsGrantResponse",
        generated::encode_refresh_act_as_grant_response(
            &liblinkkeys::generated::types::RefreshActAsGrantResponse {
                grant: grant.clone(),
                signed,
            },
        ),
    )
}

#[test]
fn refresh_calls_act_as_refresh_grant_with_a_verifiable_request() {
    let v = vectors();
    let m = vector_key_material(&v);
    let grant = vector_grant(&v);
    let (addr, fp, seen) = spawn_home(ok_reply(&grant, true));
    let dns = home_dns(addr, &fp);
    let now = time(&local_case(&v)["refresh_request"]["inputs"]["requested_at"]);

    let mut config = RefreshActAsGrantConfig::new(&m, HOME_DOMAIN, "grant-1", now);
    config.transport = &LoopbackTransport;
    config.dns = &dns;
    let refreshed = refresh_act_as_grant(config).unwrap();
    assert!(refreshed.signed);
    assert_eq!(refreshed.grant, grant);

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let (service, op, payload) = &seen[0];
    assert_eq!((service.as_str(), op.as_str()), ("ActAs", "refresh-grant"));
    let wire = generated::decode_refresh_act_as_grant_request(payload).unwrap();
    let request =
        act_as::verify_refresh_request(&wire.request, &local_rp_grantee(&m), &[], now, 0).unwrap();
    assert_eq!(request.grant_id, "grant-1");
    assert_eq!(request.grantee, local_rp_grantee(&m));
    assert_eq!(request.requested_at, "2026-10-06T12:40:00Z");
    assert_eq!(request.expires_at, "2026-10-06T12:45:00Z");
    // Independent of liblinkkeys' verifier: the descriptor key signed
    // CBOR([refresh tag, request bytes]).
    let key = ed25519_dalek::VerifyingKey::from_bytes(&m.signing_public_key).unwrap();
    let sig =
        ed25519_dalek::Signature::from_slice(&wire.request.proof.signature.signature).unwrap();
    key.verify_strict(
        &envelope_signature_input(REFRESH_REQUEST_TAG, &wire.request.request),
        &sig,
    )
    .unwrap();
}

#[test]
fn refresh_surfaces_transport_errors() {
    let v = vectors();
    let m = vector_key_material(&v);
    let (addr, fp, _) = spawn_home(RpcResponse::transport_error(
        csilgen_transport::Status::UnknownServiceOrOp,
        "no such op",
    ));
    let dns = home_dns(addr, &fp);
    let mut config = RefreshActAsGrantConfig::new(&m, HOME_DOMAIN, "grant-1", Utc::now());
    config.transport = &LoopbackTransport;
    config.dns = &dns;
    match refresh_act_as_grant(config) {
        Err(Error::ServerError { message, .. }) => assert_eq!(message, "no such op"),
        other => panic!("expected ServerError, got {other:?}"),
    }
}

#[test]
fn refresh_rejects_a_grant_for_another_grant_id() {
    let v = vectors();
    let m = vector_key_material(&v);
    let (addr, fp, _) = spawn_home(ok_reply(&vector_grant(&v), false));
    let dns = home_dns(addr, &fp);
    let mut config = RefreshActAsGrantConfig::new(&m, HOME_DOMAIN, "grant-2", Utc::now());
    config.transport = &LoopbackTransport;
    config.dns = &dns;
    assert!(matches!(
        refresh_act_as_grant(config),
        Err(Error::ActAs(act_as::ActAsError::Mismatch("grant_id")))
    ));
}
