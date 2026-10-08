//! The RP forwarding operations for act-as grants: an application behind a
//! regular RP refreshes its grant and reads grant revocations through its own
//! RP, which calls the user's home domain. No real sockets: DNS and CSIL-RPC
//! are canned (`tests/common/net.rs`).

mod common;

use common::net::{net_with_rpc, CannedRpc, StaticDns};
use liblinkkeys::generated::types::{
    ApplicationKeySignature, GetActAsGrantRevocationsResponse, GranteeProof,
    RefreshActAsGrantResponse, RpActAsRefreshRequest, RpResolveActAsRevocationsRequest,
    SignedActAsGrant, SignedActAsGrantRevocation, SignedActAsRefreshRequest,
};
use linkkeys::services::act_as as svc;

const REMOTE: &str = "remote-home.test";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn dns() -> StaticDns {
    StaticDns::new()
        .with(
            &liblinkkeys::dns::linkkeys_dns_name(REMOTE),
            &[&format!("v=lk1 fp={}", "a".repeat(64))],
        )
        .with(
            &liblinkkeys::dns::linkkeys_apis_dns_name(REMOTE),
            &[&format!("v=lk1 tcp={REMOTE}")],
        )
}

fn refresh_request(domain: &str) -> RpActAsRefreshRequest {
    RpActAsRefreshRequest {
        subject_domain: domain.into(),
        request: SignedActAsRefreshRequest {
            request: vec![0xa0],
            proof: GranteeProof {
                application_instance_id: Some("i".into()),
                local_rp_descriptor: None,
                signature: ApplicationKeySignature {
                    signed_by_key_id: "k".into(),
                    signature: vec![],
                },
            },
        },
    }
}

#[test]
fn refresh_is_forwarded_to_a_remote_home_domain() {
    let pool = common::create_test_pool();
    let canned = RefreshActAsGrantResponse {
        grant: SignedActAsGrant {
            grant: vec![1, 2, 3],
            signatures: vec![],
        },
        signed: true,
    };
    let net = net_with_rpc(
        dns(),
        CannedRpc::new().with(
            REMOTE,
            "ActAs",
            "refresh-grant",
            liblinkkeys::generated::encode_refresh_act_as_grant_response(&canned),
        ),
    );
    let rt = runtime();
    let handle = rt.handle().clone();
    let result = std::thread::spawn(move || {
        svc::rp_forward_refresh(&pool, &net, &handle, refresh_request(REMOTE))
    })
    .join()
    .unwrap()
    .unwrap();
    assert_eq!(result, canned);
}

#[test]
fn revocations_are_fetched_from_a_remote_home_domain() {
    let pool = common::create_test_pool();
    let canned = GetActAsGrantRevocationsResponse {
        revocations: vec![SignedActAsGrantRevocation {
            revocation: vec![9],
            signatures: vec![],
        }],
    };
    let net = net_with_rpc(
        dns(),
        CannedRpc::new().with(
            REMOTE,
            "ActAs",
            "get-grant-revocations",
            liblinkkeys::generated::encode_get_act_as_grant_revocations_response(&canned),
        ),
    );
    let rt = runtime();
    let handle = rt.handle().clone();
    let result = std::thread::spawn(move || {
        svc::rp_resolve_revocations(
            &pool,
            &net,
            &handle,
            RpResolveActAsRevocationsRequest {
                subject_domain: REMOTE.into(),
                grant_ids: vec!["g".into()],
            },
        )
    })
    .join()
    .unwrap()
    .unwrap();
    assert_eq!(result, canned);
}

#[test]
fn an_unreachable_home_domain_is_a_gateway_error() {
    let pool = common::create_test_pool();
    let net = net_with_rpc(StaticDns::new(), CannedRpc::new());
    let rt = runtime();
    let handle = rt.handle().clone();
    let err = std::thread::spawn(move || {
        svc::rp_forward_refresh(&pool, &net, &handle, refresh_request("nowhere.test"))
    })
    .join()
    .unwrap()
    .unwrap_err();
    assert_eq!(err.code, 502);
}

#[test]
fn the_revocation_lookup_is_bounded_before_any_network_call() {
    let pool = common::create_test_pool();
    let net = common::net::offline_net();
    let rt = runtime();
    let handle = rt.handle().clone();
    let err = std::thread::spawn(move || {
        svc::rp_resolve_revocations(
            &pool,
            &net,
            &handle,
            RpResolveActAsRevocationsRequest {
                subject_domain: REMOTE.into(),
                grant_ids: (0..=liblinkkeys::act_as::MAX_REVOCATION_LOOKUP_IDS)
                    .map(|i| i.to_string())
                    .collect(),
            },
        )
    })
    .join()
    .unwrap()
    .unwrap_err();
    assert_eq!(err.code, 400);
}

#[test]
fn the_own_domain_answers_locally() {
    let pool = common::create_test_pool();
    let own = linkkeys::conversions::get_domain_name();
    let net = common::net::offline_net();
    let rt = runtime();
    let handle = rt.handle().clone();
    let result = std::thread::spawn(move || {
        svc::rp_resolve_revocations(
            &pool,
            &net,
            &handle,
            RpResolveActAsRevocationsRequest {
                subject_domain: own,
                grant_ids: vec![uuid::Uuid::now_v7().to_string()],
            },
        )
    })
    .join()
    .unwrap()
    .unwrap();
    assert!(result.revocations.is_empty());
}
