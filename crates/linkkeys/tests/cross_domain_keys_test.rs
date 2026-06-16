//! End-to-end test of the cross-domain key-fetch path through the network seam:
//! a third party's keys are resolved via mocked DNS (`_linkkeys` fp= +
//! `_linkkeys_apis` https=) and mocked HTTPS (`domain-keys.json`), with NO
//! socket. This is the path an IDP uses to verify a third-party-attested domain
//! claim, and it exercises both the `DnsResolver` and `DomainFetcher` seams.

mod common;

use common::net::{net_with, CannedHttp, StaticDns};
use liblinkkeys::crypto;
use liblinkkeys::generated::types::{DomainPublicKey, GetDomainKeysResponse};

const THIRD: &str = "third.example";

#[rocket::async_test]
async fn fetch_domain_keys_resolves_via_dns_and_http_seam() {
    // DOMAIN_NAME must differ from THIRD so the fetch path runs (a domain is
    // authoritative for its own keys via the local DB).
    std::env::set_var("DOMAIN_NAME", "idp.local");
    let pool = common::create_test_pool();

    // The third party's published signing key. trust_keys recomputes the
    // fingerprint from the bytes and pins it against the DNS fp= set.
    let (vk, _sk) = crypto::generate_ed25519_keypair();
    let pk = vk.as_bytes().to_vec();
    let fp = crypto::fingerprint(&pk);
    let key = DomainPublicKey {
        key_id: "third-1".to_string(),
        public_key: pk,
        fingerprint: fp.clone(),
        algorithm: "ed25519".to_string(),
        key_usage: "sign".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        expires_at: (chrono::Utc::now() + chrono::Duration::days(365)).to_rfc3339(),
        revoked_at: None,
        signed_by_key_id: None,
        key_signature: None,
    };
    let response = GetDomainKeysResponse {
        domain: THIRD.to_string(),
        keys: vec![key],
    };
    let body = serde_json::to_vec(&response).unwrap();

    let dns = StaticDns::new()
        .with(
            &liblinkkeys::dns::linkkeys_dns_name(THIRD),
            &[&format!("v=lk1 fp={}", fp)],
        )
        .with(
            &liblinkkeys::dns::linkkeys_apis_dns_name(THIRD),
            &["v=lk1 https=third.example"],
        );
    let http = CannedHttp::new().with("https://third.example/v1alpha/domain-keys.json", body);
    let net = net_with(dns, http);

    let keys = linkkeys::web::rp::fetch_domain_keys(&pool, &net, THIRD)
        .await
        .expect("third-party keys resolve through the DNS + HTTP seam");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key_id, "third-1");
    assert_eq!(keys[0].fingerprint, fp);
}

#[rocket::async_test]
async fn fetch_domain_keys_fails_closed_without_dns() {
    std::env::set_var("DOMAIN_NAME", "idp.local");
    let pool = common::create_test_pool();
    // Empty DNS: the _linkkeys lookup fails, so key resolution fails closed.
    let net = common::net::offline_net();
    let result = linkkeys::web::rp::fetch_domain_keys(&pool, &net, THIRD).await;
    assert!(result.is_err(), "no DNS record => no keys");
}
