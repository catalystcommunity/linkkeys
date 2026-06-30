//! End-to-end test of the cross-domain key-fetch path through the network seam:
//! a third party's keys are resolved via mocked DNS (`_linkkeys` fp= +
//! `_linkkeys_apis` tcp=) and a mocked CSIL-RPC response
//! (`DomainKeys/get-domain-keys`), with NO socket. This is the path an IDP uses
//! to verify a third-party-attested domain claim, and it exercises both the
//! `DnsResolver` and `DomainRpc` seams.

mod common;

use common::net::{net_with_rpc, CannedRpc, StaticDns};
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
    let body = liblinkkeys::generated::encode_get_domain_keys_response(&response);

    let dns = StaticDns::new()
        .with(
            &liblinkkeys::dns::linkkeys_dns_name(THIRD),
            &[&format!("v=lk1 fp={}", fp)],
        )
        .with(
            &liblinkkeys::dns::linkkeys_apis_dns_name(THIRD),
            &["v=lk1 tcp=third.example"],
        );
    // The pinned host is the `tcp=` host (port normalized to the default), and
    // the CSIL-RPC fake answers the `DomainKeys/get-domain-keys` op for it.
    let rpc = CannedRpc::new().with("third.example", "DomainKeys", "get-domain-keys", body);
    let net = net_with_rpc(dns, rpc);

    let keys = linkkeys::web::rp::fetch_domain_keys(&pool, &net, THIRD)
        .await
        .expect("third-party keys resolve through the DNS + RPC seam");
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
