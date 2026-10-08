//! Dispatch-level tests for act-as grants: the ActAs and Account operations
//! are routed, decode their payloads, and keep their carrier and
//! authentication rules. Protocol and storage behavior is covered by
//! `act_as_service_test` and `act_as_db_test`.

mod common;

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard};

use common::data_factory::{create_act_as_grant, DataMap};
use csilgen_transport::rpc::{RpcRequest, RpcResponse};
use csilgen_transport::Status;
use liblinkkeys::generated::types::{
    EmptyRequest, GetActAsGrantRevocationsRequest, RevokeActAsGrantRequest,
};
use serde_json::json;

static SIGNING: Mutex<()> = Mutex::new(());

fn signing_guard() -> MutexGuard<'static, ()> {
    let guard = SIGNING.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    linkkeys::services::warm_signer::invalidate();
    guard
}

fn envelope(service: &str, op: &str, payload: Vec<u8>) -> Vec<u8> {
    RpcRequest {
        service: service.into(),
        op: op.into(),
        id: Some(1),
        payload,
        auth: None,
    }
    .encode()
    .unwrap()
}

fn call(pool: &linkkeys::db::DbPool, service: &str, op: &str, payload: Vec<u8>) -> RpcResponse {
    let ready = Arc::new(AtomicBool::new(true));
    RpcResponse::decode(&linkkeys::tcp::dispatch_envelope(
        &envelope(service, op, payload),
        &ready,
        pool,
        None,
    ))
    .unwrap()
}

#[test]
fn revocations_are_served_over_dispatch() {
    let _g = signing_guard();
    let pool = common::create_test_pool();
    common::data_factory::create_domain_key(&pool);
    let grant = create_act_as_grant(&pool, &DataMap::new());
    let user = pool.find_user_by_id(&grant.user_id).unwrap();
    linkkeys::services::act_as::revoke_for_user(
        &pool,
        &user,
        &RevokeActAsGrantRequest {
            grant_id: grant.grant_id.clone(),
        },
        chrono::Utc::now(),
    )
    .unwrap();

    let response = call(
        &pool,
        "ActAs",
        "get-grant-revocations",
        liblinkkeys::generated::encode_get_act_as_grant_revocations_request(
            &GetActAsGrantRevocationsRequest {
                grant_ids: vec![grant.grant_id.clone()],
            },
        ),
    );
    assert_eq!(response.status, Status::Ok, "{:?}", response.error);
    let body =
        liblinkkeys::generated::decode_get_act_as_grant_revocations_response(&response.payload)
            .unwrap();
    assert_eq!(body.revocations.len(), 1);
}

#[test]
fn refresh_needs_the_tcp_carrier() {
    let pool = common::create_test_pool();
    let request = liblinkkeys::generated::types::RefreshActAsGrantRequest {
        request: liblinkkeys::generated::types::SignedActAsRefreshRequest {
            request: vec![],
            proof: liblinkkeys::generated::types::GranteeProof {
                application_instance_id: Some("i".into()),
                local_rp_descriptor: None,
                signature: liblinkkeys::generated::types::ApplicationKeySignature {
                    signed_by_key_id: "k".into(),
                    signature: vec![],
                },
            },
        },
    };
    let response = call(
        &pool,
        "ActAs",
        "refresh-grant",
        liblinkkeys::generated::encode_refresh_act_as_grant_request(&request),
    );
    assert_ne!(response.status, Status::Ok);
    assert!(
        response
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("unavailable on this carrier"),
        "{:?}",
        response.error
    );
}

#[test]
fn unknown_act_as_operations_are_refused() {
    let pool = common::create_test_pool();
    let response = call(&pool, "ActAs", "list-everything", vec![]);
    assert_ne!(response.status, Status::Ok);
}

#[test]
fn account_act_as_operations_require_authentication() {
    let pool = common::create_test_pool();
    let response = call(
        &pool,
        "Account",
        "list-act-as-grants",
        liblinkkeys::generated::encode_empty_request(&EmptyRequest {}),
    );
    assert_ne!(response.status, Status::Ok);
}

#[test]
fn account_lists_only_the_callers_grants() {
    let pool = common::create_test_pool();
    let grant = create_act_as_grant(&pool, &DataMap::new());
    create_act_as_grant(
        &pool,
        &[("approved_scope".to_string(), json!(["other"]))]
            .into_iter()
            .collect(),
    );
    let user = pool.find_user_by_id(&grant.user_id).unwrap();
    let ready = Arc::new(AtomicBool::new(true));
    let response = RpcResponse::decode(&linkkeys::tcp::dispatch_envelope_with_browser(
        &envelope(
            "Account",
            "list-act-as-grants",
            liblinkkeys::generated::encode_empty_request(&EmptyRequest {}),
        ),
        &ready,
        &pool,
        Some(&user),
        "test-source",
    ))
    .unwrap();
    assert_eq!(response.status, Status::Ok, "{:?}", response.error);
    let body =
        liblinkkeys::generated::decode_list_act_as_grants_response(&response.payload).unwrap();
    assert_eq!(body.grants.len(), 1);
    assert_eq!(body.grants[0].grant_id, grant.grant_id);
}
