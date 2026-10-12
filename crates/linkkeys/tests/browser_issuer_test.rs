//! `BrowserIssuer`: this domain signs claims for a signing request that a user
//! of another domain brings. The subject domain's DNS, keys, and deposit
//! endpoint are faked through the network seam, so no socket is used.

mod common;

use base64ct::{Base64UrlUnpadded, Encoding};
use common::data_factory::{
    create_auth_credential, create_domain_key, create_relation, create_user, DataMap,
};
use common::net::{net_with_rpc, CannedRpc, StaticDns};
use csilgen_transport::rpc::{RpcRequest, RpcResponse};
use csilgen_transport::Status as RpcStatus;
use liblinkkeys::claims::ClaimSigner;
use liblinkkeys::crypto::{self, SigningAlgorithm};
use liblinkkeys::generated::types::{
    DepositClaimResponse, DomainPublicKey, GetDomainKeysResponse, InspectSigningRequestRequest,
    IssueForSigningRequestRequest, SessionPasswordLoginRequest,
};
use liblinkkeys::signing_request::{sign_signing_request, SigningRequestSpec};
use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

const ISSUER: &str = "issuer.test";
const SUBJECT: &str = "subject.example";
const PASSWORD: &str = "correct horse battery staple";

struct SubjectDomain {
    key_id: String,
    signing_key: Vec<u8>,
    net_keys: Vec<u8>,
    fingerprint: String,
}

fn subject_domain() -> SubjectDomain {
    let (vk, sk) = crypto::generate_ed25519_keypair();
    let public_key = vk.as_bytes().to_vec();
    let fingerprint = crypto::fingerprint(&public_key);
    let key = DomainPublicKey {
        key_id: "subject-1".to_string(),
        public_key,
        fingerprint: fingerprint.clone(),
        algorithm: "ed25519".to_string(),
        key_usage: "sign".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        expires_at: (chrono::Utc::now() + chrono::Duration::days(365)).to_rfc3339(),
        revoked_at: None,
        signed_by_key_id: None,
        key_signature: None,
    };
    SubjectDomain {
        key_id: "subject-1".to_string(),
        signing_key: sk.to_bytes().to_vec(),
        net_keys: liblinkkeys::generated::encode_get_domain_keys_response(&GetDomainKeysResponse {
            domain: SUBJECT.to_string(),
            keys: vec![key],
            recent_revocations_available: None,
        }),
        fingerprint,
    }
}

fn net(subject: &SubjectDomain, accept_deposit: bool) -> linkkeys::net::Net {
    let dns = StaticDns::new()
        .with(
            &liblinkkeys::dns::linkkeys_dns_name(SUBJECT),
            &[&format!("v=lk1 fp={}", subject.fingerprint)],
        )
        .with(
            &liblinkkeys::dns::linkkeys_apis_dns_name(SUBJECT),
            &["v=lk1 tcp=subject.example"],
        );
    let mut rpc = CannedRpc::new().with(
        "subject.example",
        "DomainKeys",
        "get-domain-keys",
        subject.net_keys.clone(),
    );
    if accept_deposit {
        rpc = rpc.with(
            "subject.example",
            "Attestation",
            "deposit-claim",
            liblinkkeys::generated::encode_deposit_claim_response(&DepositClaimResponse {
                stored: true,
            }),
        );
    }
    net_with_rpc(dns, rpc)
}

/// A signing request from `subject-user@SUBJECT`, addressed to `issuer`.
fn signing_request(subject: &SubjectDomain, issuer: &str, types: &[&str]) -> String {
    let types: Vec<String> = types.iter().map(|t| t.to_string()).collect();
    let now = chrono::Utc::now();
    let signed = sign_signing_request(
        &SigningRequestSpec {
            request_id: "request-1",
            subject_user_id: "subject-user",
            subject_domain: SUBJECT,
            issuer_domain: issuer,
            requested_claim_types: &types,
            nonce: "nonce-1",
            issued_at: &now.to_rfc3339(),
            expires_at: &(now + chrono::Duration::days(2)).to_rfc3339(),
            callback: None,
        },
        &[ClaimSigner {
            domain: SUBJECT,
            key_id: &subject.key_id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &subject.signing_key,
        }],
    )
    .expect("sign request");
    Base64UrlUnpadded::encode_string(&liblinkkeys::generated::encode_signed_signing_request(
        &signed,
    ))
}

async fn rpc(client: &Client, service: &str, op: &str, payload: Vec<u8>) -> RpcResponse {
    let response = client
        .post("/csil/v1/rpc")
        .header(ContentType::new("application", "cbor"))
        .header(Header::new("Host", ISSUER))
        .header(Header::new("Origin", format!("https://{ISSUER}")))
        .body(RpcRequest::new(service, op, payload).encode().unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    RpcResponse::decode(&response.into_bytes().await.unwrap()).unwrap()
}

/// Build the issuer domain with a signed-in operator. `relation` is the
/// operator's grant on the domain, if any.
async fn signed_in_client(net: linkkeys::net::Net, relation: Option<&str>) -> Client {
    std::env::set_var("DOMAIN_NAME", ISSUER);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("ENABLE_PASSWORD_AUTH", "true");
    let pool = common::create_test_pool();
    create_domain_key(&pool);
    let mut overrides = DataMap::new();
    overrides.insert("username".to_string(), serde_json::json!("operator"));
    let operator = create_user(&pool, &overrides);
    let hash = linkkeys::services::password::hash_for_storage(PASSWORD).unwrap();
    create_auth_credential(&pool, &operator.id, "password", &hash);
    if let Some(relation) = relation {
        create_relation(&pool, "user", &operator.id, relation, "domain", ISSUER);
    }
    let rocket = linkkeys::web::build_rocket(
        pool,
        Arc::new(AtomicBool::new(true)),
        net,
        rocket::Config {
            secret_key: rocket::config::SecretKey::derive_from(&[5_u8; 64]),
            ..rocket::Config::debug_default()
        },
    );
    let client = Client::tracked(rocket).await.expect("rocket client");
    let login = rpc(
        &client,
        "Session",
        "login-password",
        liblinkkeys::generated::encode_session_password_login_request(
            &SessionPasswordLoginRequest {
                username: format!("operator@{ISSUER}"),
                password: PASSWORD.to_string(),
            },
        ),
    )
    .await;
    assert_eq!(login.status, RpcStatus::Ok);
    client
}

fn inspect_payload(signed_request: &str) -> Vec<u8> {
    liblinkkeys::generated::encode_inspect_signing_request_request(&InspectSigningRequestRequest {
        signed_request: signed_request.to_string(),
    })
}

fn issue_payload(signed_request: &str, values: &[(&str, &str)]) -> Vec<u8> {
    liblinkkeys::generated::encode_issue_for_signing_request_request(
        &IssueForSigningRequestRequest {
            signed_request: signed_request.to_string(),
            claim_types: values.iter().map(|(t, _)| t.to_string()).collect(),
            claim_values: values.iter().map(|(_, v)| v.to_string()).collect(),
        },
    )
}

#[rocket::async_test]
async fn an_operator_verifies_signs_and_deposits_requested_claims() {
    let subject = subject_domain();
    let client = signed_in_client(net(&subject, true), Some("manage_claims")).await;
    let request = signing_request(&subject, ISSUER, &["over_21", "legal_name"]);

    let response = rpc(
        &client,
        "BrowserIssuer",
        "inspect-signing-request",
        inspect_payload(&request),
    )
    .await;
    assert_eq!(response.status, RpcStatus::Ok);
    let inspected =
        liblinkkeys::generated::decode_inspect_signing_request_response(&response.payload).unwrap();
    assert_eq!(inspected.subject_user_id, "subject-user");
    assert_eq!(inspected.subject_domain, SUBJECT);
    assert_eq!(inspected.issuable_claim_types.len(), 2);

    let response = rpc(
        &client,
        "BrowserIssuer",
        "issue-for-signing-request",
        issue_payload(&request, &[("over_21", "true"), ("favorite_color", "blue")]),
    )
    .await;
    assert_eq!(response.status, RpcStatus::Ok);
    let issued =
        liblinkkeys::generated::decode_issue_for_signing_request_response(&response.payload)
            .unwrap();
    let outcome = |claim_type: &str| {
        issued
            .results
            .iter()
            .find(|r| r.claim_type == claim_type)
            .map(|r| r.outcome.clone())
    };
    assert_eq!(outcome("over_21").as_deref(), Some("deposited"));
    assert_eq!(
        outcome("favorite_color").as_deref(),
        Some("skipped"),
        "a type the request did not ask for is never signed"
    );
}

#[rocket::async_test]
async fn an_unreachable_subject_domain_gets_a_handoff_code() {
    let subject = subject_domain();
    let client = signed_in_client(net(&subject, false), Some("manage_claims")).await;
    let request = signing_request(&subject, ISSUER, &["over_21"]);
    let response = rpc(
        &client,
        "BrowserIssuer",
        "issue-for-signing-request",
        issue_payload(&request, &[("over_21", "true")]),
    )
    .await;
    assert_eq!(response.status, RpcStatus::Ok);
    let issued =
        liblinkkeys::generated::decode_issue_for_signing_request_response(&response.payload)
            .unwrap();
    assert_eq!(issued.results[0].outcome, "handoff");
    let code = issued.results[0].claim_code.as_deref().expect("claim code");
    let claim = liblinkkeys::generated::decode_claim(
        &Base64UrlUnpadded::decode_vec(code).expect("base64url"),
    )
    .expect("the code is a signed claim");
    assert_eq!(claim.claim_type, "over_21");
    assert_eq!(claim.user_id, "subject-user");
}

#[rocket::async_test]
async fn a_user_without_issue_rights_is_refused() {
    let subject = subject_domain();
    let client = signed_in_client(net(&subject, true), None).await;
    let request = signing_request(&subject, ISSUER, &["over_21"]);
    for (op, payload) in [
        ("inspect-signing-request", inspect_payload(&request)),
        (
            "issue-for-signing-request",
            issue_payload(&request, &[("over_21", "true")]),
        ),
    ] {
        let response = rpc(&client, "BrowserIssuer", op, payload).await;
        assert_ne!(response.status, RpcStatus::Ok, "{op} must be refused");
    }
}

#[rocket::async_test]
async fn a_request_for_another_issuer_or_a_damaged_request_is_refused() {
    let subject = subject_domain();
    let client = signed_in_client(net(&subject, true), Some("manage_claims")).await;
    let elsewhere = signing_request(&subject, "other-issuer.test", &["over_21"]);
    let mut tampered = signing_request(&subject, ISSUER, &["over_21"]);
    let swap = if &tampered[10..12] == "AA" {
        "BB"
    } else {
        "AA"
    };
    tampered.replace_range(10..12, swap);
    for request in [elsewhere.as_str(), tampered.as_str(), "not a request"] {
        let response = rpc(
            &client,
            "BrowserIssuer",
            "issue-for-signing-request",
            issue_payload(request, &[("over_21", "true")]),
        )
        .await;
        assert_ne!(response.status, RpcStatus::Ok);
    }
}
