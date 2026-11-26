//! `Rp/verify-claims` through the TCP dispatch: the RP server gets each
//! signing domain's keys (canned DNS and CSIL-RPC, no sockets) and reports a
//! result for the claim and for each signing domain.
//!
//! Each test uses its own fake domain names, because the domain-key cache and
//! its fetch coalescing are process-wide.

mod common;

use common::data_factory::{create_auth_credential, create_relation};
use common::net::{net_with_rpc, CannedRpc, StaticDns};
use liblinkkeys::claims::{sign_claim, ClaimSigner, ClaimSpec};
use liblinkkeys::crypto::{self, SigningAlgorithm};
use liblinkkeys::generated::types::{
    Claim, ClaimCheck, ClaimCheckStatus, DomainPublicKey, GetDomainKeysResponse, KeyAlgorithm,
    KeyUsage, RpVerifyClaimsRequest, RpVerifyClaimsResponse,
};
use linkkeys::net::Net;
use linkkeys::services::auth;
use time::Duration;

const RP_DOMAIN: &str = "rp.test";
/// The wire status of a refused request (`MalformedEnvelope`).
const BAD_REQUEST: i32 = 1;
const USER_ID: &str = "0b6f2f0e-3a51-4c1e-9d7e-1f2a3b4c5d6e";

struct Domain {
    name: String,
    key: DomainPublicKey,
    private_key: Vec<u8>,
}

fn domain(name: &str) -> Domain {
    let (vk, sk) = crypto::generate_ed25519_keypair();
    let public_key = vk.as_bytes().to_vec();
    let now = liblinkkeys::timestamp::now_whole_seconds();
    Domain {
        name: name.to_string(),
        key: DomainPublicKey {
            key_id: format!("{name}-sign-1"),
            fingerprint: crypto::fingerprint(&public_key),
            public_key,
            algorithm: KeyAlgorithm::Ed25519,
            key_usage: KeyUsage::Sign,
            signed_by_key_id: None,
            key_signature: None,
            created_at: now - Duration::days(30),
            expires_at: now + Duration::days(365),
            revoked_at: None,
        },
        private_key: sk.to_bytes().to_vec(),
    }
}

/// A net that serves the keys of each domain in `domains`.
fn net_for(domains: &[&Domain]) -> Net {
    let mut dns = StaticDns::new();
    let mut rpc = CannedRpc::new();
    for d in domains {
        dns = dns
            .with(
                &liblinkkeys::dns::linkkeys_dns_name(&d.name),
                &[&format!("v=lk1 fp={}", d.key.fingerprint)],
            )
            .with(
                &liblinkkeys::dns::linkkeys_apis_dns_name(&d.name),
                &[&format!("v=lk1 tcp={}", d.name)],
            );
        rpc = rpc.with(
            &d.name,
            "DomainKeys",
            "get-domain-keys",
            liblinkkeys::generated::encode_get_domain_keys_response(&GetDomainKeysResponse {
                domain: d.name.clone(),
                keys: vec![d.key.clone()],
                recent_revocations_available: None,
            })
            .unwrap(),
        );
    }
    net_with_rpc(dns, rpc)
}

/// A claim about `USER_ID@subject_domain`, signed by each of `signers`.
fn claim(
    claim_id: &str,
    claim_type: &str,
    value: &[u8],
    subject_domain: &str,
    signers: &[&Domain],
) -> Claim {
    let claim_signers: Vec<ClaimSigner<'_>> = signers
        .iter()
        .map(|d| ClaimSigner {
            domain: &d.name,
            key_id: &d.key.key_id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &d.private_key,
        })
        .collect();
    sign_claim(
        &ClaimSpec {
            claim_id,
            claim_type,
            claim_value: value,
            user_id: USER_ID,
            subject_domain,
            expires_at: None,
            attested_at: liblinkkeys::timestamp::now_whole_seconds() - Duration::days(1),
        },
        &claim_signers,
    )
    .unwrap()
}

/// An application account with an API key and the `api_access` relation.
fn rp_app() -> (linkkeys::db::DbPool, String) {
    std::env::set_var("DOMAIN_NAME", RP_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    let pool = common::create_test_pool();
    let user = pool
        .create_account("claims-app", "Claims App", Some("claims-app"))
        .expect("create application account");
    let (api_key, hash) = auth::generate_api_key(&user.id);
    create_auth_credential(&pool, &user.id, auth::CREDENTIAL_TYPE_API_KEY, &hash);
    create_relation(&pool, "user", &user.id, "api_access", "domain", RP_DOMAIN);
    (pool, api_key)
}

fn request(subject_domain: &str, user_id: &str, claims: Vec<Claim>) -> Vec<u8> {
    liblinkkeys::generated::encode_rp_verify_claims_request(&RpVerifyClaimsRequest {
        subject_domain: subject_domain.to_string(),
        user_id: user_id.to_string(),
        claims,
    })
    .unwrap()
}

/// Call `Rp/verify-claims`. Returns the transport status, and the response
/// when the status is 0.
fn verify(
    pool: &linkkeys::db::DbPool,
    api_key: &str,
    net: &Net,
    payload: Vec<u8>,
) -> (i32, Option<RpVerifyClaimsResponse>) {
    let reply = linkkeys::tcp::dispatch_for_test_with_net(
        "Rp",
        "verify-claims",
        payload,
        Some(api_key),
        pool,
        net,
    );
    if reply.status != 0 {
        return (reply.status, None);
    }
    let response = liblinkkeys::generated::decode_rp_verify_claims_response(&reply.payload)
        .expect("decode RpVerifyClaimsResponse");
    (0, Some(response))
}

fn domains_of(check: &ClaimCheck) -> Vec<(String, ClaimCheckStatus)> {
    check
        .signing_domains
        .iter()
        .map(|d| (d.domain.clone(), d.status))
        .collect()
}

/// The application's policy for a required, home-verified claim.
fn verified_by(check: &ClaimCheck, domain: &str) -> bool {
    check.claim_status == ClaimCheckStatus::Valid
        && check
            .signing_domains
            .iter()
            .any(|d| d.domain == domain && d.status == ClaimCheckStatus::Valid)
}

#[test]
fn home_domain_signed_email_claims_verify() {
    let (pool, api_key) = rp_app();
    let home = domain("vc-home.example");
    let claims = vec![
        claim(
            "c-email",
            "email",
            b"me@vc-home.example",
            &home.name,
            &[&home],
        ),
        claim(
            "c-verified",
            "email_verified",
            b"true",
            &home.name,
            &[&home],
        ),
    ];
    let (status, response) = verify(
        &pool,
        &api_key,
        &net_for(&[&home]),
        request(&home.name, USER_ID, claims),
    );
    assert_eq!(status, 0);
    let checks = response.unwrap().checks;
    assert_eq!(checks.len(), 2);
    assert_eq!(checks[0].claim_id, "c-email");
    assert_eq!(checks[0].claim_type, "email");
    assert_eq!(checks[1].claim_type, "email_verified");
    for check in &checks {
        assert_eq!(check.claim_status, ClaimCheckStatus::Valid);
        assert_eq!(
            domains_of(check),
            vec![(home.name.clone(), ClaimCheckStatus::Valid)]
        );
        assert!(check.verified);
        assert!(verified_by(check, &home.name));
    }
}

#[test]
fn a_claim_signed_only_by_another_domain_is_not_home_verified() {
    let (pool, api_key) = rp_app();
    let home = domain("vc-home2.example");
    let other = domain("vc-other2.example");
    let claims = vec![claim(
        "c-email",
        "email",
        b"me@vc-home2.example",
        &home.name,
        &[&other],
    )];
    let (status, response) = verify(
        &pool,
        &api_key,
        &net_for(&[&home, &other]),
        request(&home.name, USER_ID, claims),
    );
    assert_eq!(status, 0);
    let check = &response.unwrap().checks[0];
    // The signature is good, but it is not the home domain's.
    assert!(check.verified);
    assert_eq!(
        domains_of(check),
        vec![(other.name.clone(), ClaimCheckStatus::Valid)]
    );
    assert!(!verified_by(check, &home.name));
}

#[test]
fn each_signing_domain_gets_its_own_result() {
    let (pool, api_key) = rp_app();
    let home = domain("vc-home3.example");
    let unreachable = domain("vc-gone3.example");
    let claims = vec![claim(
        "c-email",
        "email",
        b"me@vc-home3.example",
        &home.name,
        &[&home, &unreachable],
    )];
    // Only the home domain's keys can be fetched.
    let (status, response) = verify(
        &pool,
        &api_key,
        &net_for(&[&home]),
        request(&home.name, USER_ID, claims),
    );
    assert_eq!(status, 0);
    let check = &response.unwrap().checks[0];
    assert_eq!(
        domains_of(check),
        // Ascending order of domain.
        vec![
            (unreachable.name.clone(), ClaimCheckStatus::KeysUnavailable),
            (home.name.clone(), ClaimCheckStatus::Valid),
        ]
    );
    assert!(!check.verified, "the full verification needs every domain");
    assert!(verified_by(check, &home.name));
}

#[test]
fn a_tampered_or_foreign_claim_fails() {
    let (pool, api_key) = rp_app();
    let home = domain("vc-home4.example");
    let mut tampered = claim(
        "c-email",
        "email",
        b"me@vc-home4.example",
        &home.name,
        &[&home],
    );
    tampered.claim_value = b"eve@vc-home4.example".to_vec();
    let foreign = claim("c-handle", "handle", b"me", &home.name, &[&home]);
    let net = net_for(&[&home]);

    let (_, response) = verify(
        &pool,
        &api_key,
        &net,
        request(&home.name, USER_ID, vec![tampered, foreign.clone()]),
    );
    let checks = response.unwrap().checks;
    assert_eq!(
        domains_of(&checks[0]),
        vec![(home.name.clone(), ClaimCheckStatus::BadSignature)]
    );
    assert!(!verified_by(&checks[0], &home.name));
    assert!(checks[1].verified);

    // The same good claim checked for another user.
    let (_, response) = verify(
        &pool,
        &api_key,
        &net,
        request(&home.name, "another-user", vec![foreign]),
    );
    let check = &response.unwrap().checks[0];
    assert_eq!(check.claim_status, ClaimCheckStatus::WrongSubject);
    assert!(!check.verified);
    assert!(!verified_by(check, &home.name));
}

#[test]
fn request_bounds_are_enforced() {
    let (pool, api_key) = rp_app();
    let home = domain("vc-home5.example");
    let net = net_for(&[&home]);
    let one = claim("c-1", "handle", b"me", &home.name, &[&home]);

    let (status, _) = verify(&pool, &api_key, &net, request(&home.name, USER_ID, vec![]));
    assert_eq!(status, BAD_REQUEST, "no claims");

    let too_many = vec![one.clone(); 65];
    let (status, _) = verify(
        &pool,
        &api_key,
        &net,
        request(&home.name, USER_ID, too_many),
    );
    assert_eq!(status, BAD_REQUEST, "more than 64 claims");

    let (status, _) = verify(
        &pool,
        &api_key,
        &net,
        request(" ", USER_ID, vec![one.clone()]),
    );
    assert_eq!(status, BAD_REQUEST, "empty subject domain");

    let (status, _) = verify(
        &pool,
        &api_key,
        &net,
        request(&home.name, "", vec![one.clone()]),
    );
    assert_eq!(status, BAD_REQUEST, "empty user id");

    let mut many_domains = one.clone();
    let template = many_domains.signatures[0].clone();
    many_domains.signatures = (0..17)
        .map(|i| {
            let mut s = template.clone();
            s.domain = format!("vc-many{i}.example");
            s
        })
        .collect();
    let (status, _) = verify(
        &pool,
        &api_key,
        &net,
        request(&home.name, USER_ID, vec![many_domains]),
    );
    assert_eq!(status, BAD_REQUEST, "more than 16 signing domains");

    let (status, response) = verify(
        &pool,
        &api_key,
        &net,
        request(&home.name, USER_ID, vec![one]),
    );
    assert_eq!(status, 0);
    assert!(response.unwrap().checks[0].verified);
}

#[test]
fn verify_claims_needs_an_api_key_and_the_outbound_context() {
    let (pool, api_key) = rp_app();
    let home = domain("vc-home6.example");
    let payload = request(
        &home.name,
        USER_ID,
        vec![claim("c-1", "handle", b"me", &home.name, &[&home])],
    );

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Rp",
        "verify-claims",
        payload.clone(),
        None,
        &pool,
        None,
    );
    assert_ne!(status, 0, "Rp ops need an API key");

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Rp",
        "verify-claims",
        payload,
        Some(&api_key),
        &pool,
        None,
    );
    // error_response(4) is the wire status Internal (6).
    assert_eq!(status, 6, "unavailable without the outbound context");
}

// ---------------------------------------------------------------------------
// `RequestedClaim.verified_by` at sign-in. This server is the user's IDP and
// the app's RP (`API_HOSTNAME` = `RP_DOMAIN`), so `userinfo-fetch` redeems
// locally and the RP checks the claims against its own domain keys.
// ---------------------------------------------------------------------------

use common::data_factory::{create_domain_key, create_user, DataMap};
use liblinkkeys::generated::types::{
    ApplicationRef, ClaimRequest, ClaimValueType, RequestedClaim, RpErrorCode, RpSignRequest,
    RpUserInfoRequest, UserInfo, VerifyingParty,
};

struct Login {
    pool: linkkeys::db::DbPool,
    api_key: String,
    app: ApplicationRef,
    domain_key: linkkeys::db::models::DomainKey,
    user_id: String,
}

fn local_login() -> Login {
    let (pool, api_key) = rp_app();
    std::env::set_var("API_HOSTNAME", RP_DOMAIN);
    let domain_key = create_domain_key(&pool);
    let app_account = pool
        .find_user_by_username("claims-app")
        .expect("find the app account");
    let user = create_user(&pool, &DataMap::new());
    Login {
        app: ApplicationRef {
            subject_user_id: app_account.id,
            subject_domain: RP_DOMAIN.to_string(),
            application_id: "claims-app".to_string(),
        },
        pool,
        api_key,
        domain_key,
        user_id: user.id,
    }
}

fn requested(claim_type: &str, verified_by: Option<VerifyingParty>) -> RequestedClaim {
    RequestedClaim {
        claim_type: claim_type.to_string(),
        datatype: ClaimValueType::Text,
        verified_by,
    }
}

/// Store a claim for the user, signed by this domain when `signed`.
fn store_claim(login: &Login, claim_type: &str, value: &[u8], signed: bool) {
    let claim_id = uuid::Uuid::now_v7().to_string();
    let attested_at = liblinkkeys::timestamp::now_whole_seconds();
    let signatures = if signed {
        let sk = crypto::decrypt_private_key(
            &login.domain_key.private_key_encrypted,
            b"test-passphrase",
        )
        .unwrap();
        sign_claim(
            &ClaimSpec {
                claim_id: &claim_id,
                claim_type,
                claim_value: value,
                user_id: &login.user_id,
                subject_domain: RP_DOMAIN,
                expires_at: None,
                attested_at,
            },
            &[ClaimSigner {
                domain: RP_DOMAIN,
                key_id: &login.domain_key.id,
                algorithm: SigningAlgorithm::Ed25519,
                private_key_bytes: &sk,
            }],
        )
        .unwrap()
        .signatures
    } else {
        Vec::new()
    };
    login
        .pool
        .create_claim(
            &claim_id,
            &login.user_id,
            claim_type,
            value,
            &signatures,
            None,
            attested_at,
        )
        .expect("create claim");
}

/// Start a login with `claims` through `Rp/sign-request`, then build the
/// token that the IDP would return for it, releasing `authorized`.
fn start(login: &Login, claims: ClaimRequest, authorized: &[&str]) -> String {
    let nonce = uuid::Uuid::now_v7().to_string();
    let payload = liblinkkeys::generated::encode_rp_sign_request(&RpSignRequest {
        callback_url: "https://claims-app.example/callback".to_string(),
        nonce: nonce.clone(),
        requested_claims: Some(claims),
        authentication_requirements: None,
        flow_context: None,
    })
    .unwrap();
    let reply = linkkeys::tcp::dispatch_for_test_with_net(
        "Rp",
        "sign-request",
        payload,
        Some(&login.api_key),
        &login.pool,
        &common::net::offline_net(),
    );
    assert_eq!(reply.status, 0);
    assert_eq!(reply.variant.as_deref(), Some("RpSignResponse"));

    let sk =
        crypto::decrypt_private_key(&login.domain_key.private_key_encrypted, b"test-passphrase")
            .unwrap();
    let assertion = liblinkkeys::assertions::build_assertion(
        &login.user_id,
        RP_DOMAIN,
        RP_DOMAIN,
        &nonce,
        None,
        300,
        authorized.iter().map(|t| t.to_string()).collect(),
        login.app.clone(),
    );
    let signed = liblinkkeys::assertions::sign_assertion(
        &assertion,
        &login.domain_key.id,
        SigningAlgorithm::Ed25519,
        &sk,
    )
    .unwrap();
    liblinkkeys::encoding::assertion_to_url_param(&signed).unwrap()
}

/// Call `Rp/userinfo-fetch`: the UserInfo, or the RpError code.
fn userinfo(login: &Login, token: String) -> Result<UserInfo, RpErrorCode> {
    let payload = liblinkkeys::generated::encode_rp_user_info_request(&RpUserInfoRequest {
        token,
        api_base: format!("https://{RP_DOMAIN}"),
        domain: RP_DOMAIN.to_string(),
    })
    .unwrap();
    let reply = linkkeys::tcp::dispatch_for_test_with_net(
        "Rp",
        "userinfo-fetch",
        payload,
        Some(&login.api_key),
        &login.pool,
        &common::net::offline_net(),
    );
    assert_eq!(reply.status, 0, "userinfo-fetch transport status");
    match reply.variant.as_deref() {
        Some("UserInfo") => Ok(liblinkkeys::generated::decode_user_info(&reply.payload).unwrap()),
        Some("RpError") => Err(liblinkkeys::generated::decode_rp_error(&reply.payload)
            .unwrap()
            .code),
        other => panic!("unexpected variant {other:?}"),
    }
}

fn types_of(info: &UserInfo) -> Vec<String> {
    let mut types: Vec<String> = info.claims.iter().map(|c| c.claim_type.clone()).collect();
    types.sort();
    types
}

fn email_request(verified_by: Option<VerifyingParty>) -> ClaimRequest {
    ClaimRequest {
        required: vec![
            requested("email", verified_by),
            requested("email_verified", verified_by),
        ],
        optional: vec![requested("display_name", verified_by)],
    }
}

#[test]
fn sign_in_releases_home_verified_required_claims() {
    let login = local_login();
    store_claim(&login, "email", b"me@rp.test", true);
    store_claim(&login, "email_verified", b"true", true);
    let token = start(
        &login,
        email_request(Some(VerifyingParty::HomeDomain)),
        &["email", "email_verified"],
    );
    let info = userinfo(&login, token).expect("the login passes");
    assert_eq!(types_of(&info), vec!["email", "email_verified"]);
}

#[test]
fn sign_in_refuses_a_required_claim_the_home_domain_did_not_sign() {
    let login = local_login();
    // An unconfirmed address: stored, but not signed by the home domain.
    store_claim(&login, "email", b"me@rp.test", false);
    store_claim(&login, "email_verified", b"true", true);
    let token = start(
        &login,
        email_request(Some(VerifyingParty::HomeDomain)),
        &["email", "email_verified"],
    );
    assert_eq!(
        userinfo(&login, token).err(),
        Some(RpErrorCode::RequiredClaimUnverified)
    );
}

#[test]
fn sign_in_refuses_a_missing_required_claim() {
    let login = local_login();
    store_claim(&login, "email", b"me@rp.test", true);
    // email_verified is requested but not released.
    let token = start(
        &login,
        email_request(Some(VerifyingParty::HomeDomain)),
        &["email"],
    );
    assert_eq!(
        userinfo(&login, token).err(),
        Some(RpErrorCode::RequiredClaimUnverified)
    );
}

#[test]
fn sign_in_drops_an_unverified_optional_claim() {
    let login = local_login();
    store_claim(&login, "email", b"me@rp.test", true);
    store_claim(&login, "email_verified", b"true", true);
    store_claim(&login, "display_name", b"Me", false);
    let token = start(
        &login,
        email_request(Some(VerifyingParty::HomeDomain)),
        &["email", "email_verified", "display_name"],
    );
    let info = userinfo(&login, token).expect("the login passes");
    assert_eq!(types_of(&info), vec!["email", "email_verified"]);
}

#[test]
fn sign_in_without_verified_by_is_unchanged() {
    let login = local_login();
    store_claim(&login, "email", b"me@rp.test", false);
    store_claim(&login, "display_name", b"Me", false);
    let token = start(&login, email_request(None), &["email", "display_name"]);
    // No requirement was recorded, so the RP passes the IDP's reply through.
    let info = userinfo(&login, token).expect("the login passes");
    assert_eq!(types_of(&info), vec!["display_name", "email"]);
}
