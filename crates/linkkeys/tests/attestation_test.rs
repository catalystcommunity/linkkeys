// Attested (lane-C) claims: a third-party issuer signs a claim about one of our
// accounts; we keep & store the issuer's signature and can verify it against the
// issuer's (cached) public key. Exercises the FK-relaxed claim_signatures +
// peer-key cache + the attestation service, against a real DB.

mod common;

use common::data_factory::{create_domain_key, create_relation, create_user, DataMap};
use linkkeys::db::models::PeerKey;
use linkkeys::services::attestation;

const OUR_DOMAIN: &str = "test.com";
const ISSUER: &str = "dmv.test";

/// Mint an issuer keypair + an issuer-signed claim about `subject_id`, and return
/// the claim plus the issuer's public key (to cache as a peer key).
fn issuer_signed_claim(
    subject_id: &str,
    claim_type: &str,
    value: &[u8],
) -> (liblinkkeys::generated::types::Claim, PeerKey) {
    let (vk, sk) = liblinkkeys::crypto::generate_ed25519_keypair();
    let pk_bytes = vk.as_bytes().to_vec();
    let key_id = format!("issuer-key-{}", &uuid::Uuid::now_v7().to_string()[..8]);
    let claim_id = uuid::Uuid::now_v7().to_string();

    let claim = liblinkkeys::claims::sign_claim(
        &liblinkkeys::claims::ClaimSpec {
            claim_id: &claim_id,
            claim_type,
            claim_value: value,
            user_id: subject_id,
            subject_domain: OUR_DOMAIN,
            expires_at: None,
        },
        &[liblinkkeys::claims::ClaimSigner {
            domain: ISSUER,
            key_id: &key_id,
            algorithm: liblinkkeys::crypto::SigningAlgorithm::parse_str("ed25519").unwrap(),
            private_key_bytes: &sk.to_bytes(),
        }],
    )
    .expect("sign issuer claim");

    let peer = PeerKey {
        domain: ISSUER.to_string(),
        key_id,
        public_key: pk_bytes.clone(),
        algorithm: "ed25519".to_string(),
        fingerprint: liblinkkeys::crypto::fingerprint(&pk_bytes),
        key_usage: "sign".to_string(),
        expires_at: (chrono::Utc::now() + chrono::Duration::days(365)).to_rfc3339(),
        revoked_at: None,
    };
    (claim, peer)
}

fn setup() -> (linkkeys::db::DbPool, String) {
    std::env::set_var("DOMAIN_NAME", OUR_DOMAIN);
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());
    (pool, user.id)
}

#[test]
fn trusted_issuer_claim_is_stored_and_verifies() {
    let (pool, uid) = setup();
    let (claim, peer) = issuer_signed_claim(&uid, "age_over_21", b"true");

    pool.cache_peer_key(&peer).expect("cache issuer key");
    pool.add_trusted_issuer("age_over_21", ISSUER)
        .expect("trust issuer");

    attestation::verify_and_store_attested(&pool, &uid, &claim).expect("accept attested claim");

    // Stored verbatim, with the EXTERNAL signature (issuer domain + key id) intact.
    let stored = pool.list_active_claims(&uid).unwrap();
    let c = stored
        .iter()
        .find(|c| c.claim_type == "age_over_21")
        .expect("claim stored");
    assert_eq!(c.claim_value, b"true");
    assert_eq!(c.signatures.len(), 1);
    assert_eq!(c.signatures[0].domain, ISSUER);

    // One-click verify resolves the issuer's cached key and checks out.
    let v = attestation::verify_stored_claim(&pool, &claim);
    assert!(v.verified, "should verify against the cached issuer key");
    assert_eq!(v.signed_by, vec![ISSUER.to_string()]);
}

#[test]
fn deposit_via_rpc_dispatch_stores_claim() {
    let (pool, uid) = setup();
    let (claim, peer) = issuer_signed_claim(&uid, "age_over_21", b"true");
    pool.cache_peer_key(&peer).unwrap();
    pool.add_trusted_issuer("age_over_21", ISSUER).unwrap();

    // Deposit over the CBOR-RPC dispatch (the server-to-server API), not a REST
    // route — issuer's server -> subject's domain.
    let req = liblinkkeys::generated::types::DepositClaimRequest { claim };
    let payload = liblinkkeys::generated::encode_deposit_claim_request(&req);
    let (status, resp) =
        linkkeys::tcp::dispatch_for_test("Attestation", "deposit-claim", payload, &pool, None);
    assert_eq!(status, 0, "deposit should succeed");
    let r = liblinkkeys::generated::decode_deposit_claim_response(&resp).unwrap();
    assert!(r.stored);
    assert!(pool
        .list_active_claims(&uid)
        .unwrap()
        .iter()
        .any(|c| c.claim_type == "age_over_21"));
}

#[test]
fn untrusted_issuer_is_rejected() {
    let (pool, uid) = setup();
    let (claim, peer) = issuer_signed_claim(&uid, "age_over_21", b"true");
    pool.cache_peer_key(&peer).unwrap();
    // No add_trusted_issuer → the signature is valid but the issuer isn't trusted.
    let err = attestation::verify_and_store_attested(&pool, &uid, &claim).unwrap_err();
    assert_eq!(err.code, 403);
}

#[test]
fn tampered_value_fails_verification() {
    let (pool, uid) = setup();
    let (mut claim, peer) = issuer_signed_claim(&uid, "age_over_21", b"true");
    pool.cache_peer_key(&peer).unwrap();
    pool.add_trusted_issuer("age_over_21", ISSUER).unwrap();
    // Flip the value after signing — signature no longer matches.
    claim.claim_value = b"false".to_vec();

    let err = attestation::verify_and_store_attested(&pool, &uid, &claim).unwrap_err();
    assert_eq!(err.code, 400);
    assert!(!attestation::verify_stored_claim(&pool, &claim).verified);
}

#[test]
fn minted_signing_request_verifies_against_domain_keys() {
    std::env::set_var("DOMAIN_NAME", OUR_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    let pool = common::create_test_pool();
    common::data_factory::create_domain_key(&pool);
    let user = create_user(&pool, &DataMap::new());

    let types = vec!["age_over_21".to_string()];
    let signed =
        linkkeys::services::attestation::mint_signing_request(&pool, &user.id, ISSUER, &types)
            .expect("mint signing request");

    // An issuer would verify it against our DNS-pinned domain keys.
    let keys: Vec<liblinkkeys::generated::types::DomainPublicKey> = pool
        .list_active_domain_keys()
        .unwrap()
        .iter()
        .map(Into::into)
        .collect();
    let keysets = vec![liblinkkeys::claims::DomainKeySet {
        domain: OUR_DOMAIN.to_string(),
        keys,
    }];
    let req =
        liblinkkeys::signing_request::verify_signing_request(&signed, OUR_DOMAIN, ISSUER, &keysets)
            .expect("issuer verifies the request");
    assert_eq!(req.subject_user_id, user.id);
    assert_eq!(req.issuer_domain, ISSUER);
    assert_eq!(req.requested_claim_types, types);
    assert!(req.callback.is_some());
}

#[test]
fn verify_without_cached_key_is_unverified() {
    let (pool, uid) = setup();
    let (claim, _peer) = issuer_signed_claim(&uid, "age_over_21", b"true");
    // Issuer key never cached → cannot resolve → unverified (fail closed).
    assert!(!attestation::verify_stored_claim(&pool, &claim).verified);
}

#[test]
fn issuer_policy_denies_subject_tld_and_issued_claims_expire() {
    std::env::set_var("DOMAIN_NAME", "issuer.test");
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("ATTESTATION_DENY_SUBJECT_TLDS", "ru");
    let pool = common::create_test_pool();
    create_domain_key(&pool);

    let denied = attestation::issue_attested_claim(
        &pool,
        "remote-user",
        "example.ru",
        "linkidspec_signed",
        b"2026-06-30",
    )
    .unwrap_err();
    assert_eq!(denied.code, 403);

    std::env::remove_var("ATTESTATION_DENY_SUBJECT_TLDS");
    let claim = attestation::issue_attested_claim(
        &pool,
        "remote-user",
        "home.test",
        "linkidspec_signed",
        b"2026-06-30",
    )
    .expect("claim issued");
    assert_eq!(claim.claim_type, "linkidspec_signed");
    assert!(claim.expires_at.is_some(), "issued attestations expire");
}

#[test]
fn subject_domain_policy_can_be_evaluated_with_temporary_denies() {
    let exact = attestation::subject_domain_policy_decision_with_denies(
        "Blocked.Example.",
        &["blocked.example".to_string()],
        &[],
    );
    assert!(!exact.allowed);
    assert!(exact.reason.contains("explicitly denied"));

    let tld =
        attestation::subject_domain_policy_decision_with_denies("news.ru", &[], &[".ru".into()]);
    assert!(!tld.allowed);
    assert!(tld.reason.contains(".ru"));

    let allowed =
        attestation::subject_domain_policy_decision_with_denies("partner.example", &[], &[]);
    assert!(allowed.allowed);
}

#[test]
fn per_claim_issue_relation_authorizes_without_manage_claims() {
    std::env::set_var("DOMAIN_NAME", OUR_DOMAIN);
    let pool = common::create_test_pool();
    let user = create_user(&pool, &DataMap::new());

    assert!(!attestation::user_can_issue_claim(
        &pool,
        &user.id,
        "linkidspec_signed"
    ));
    create_relation(
        &pool,
        "user",
        &user.id,
        "issue_claims",
        "claim_type",
        "linkidspec_signed",
    );
    assert!(attestation::user_can_issue_claim(
        &pool,
        &user.id,
        "linkidspec_signed"
    ));
    assert!(!attestation::user_can_issue_claim(
        &pool,
        &user.id,
        "age_over_21"
    ));
}
