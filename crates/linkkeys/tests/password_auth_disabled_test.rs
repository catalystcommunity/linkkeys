mod common;

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use csilgen_transport::rpc::{RpcRequest, RpcResponse};
use csilgen_transport::Status as RpcStatus;
use rocket::http::{ContentType, Header};
use rocket::local::asynchronous::Client;

fn envelope(service: &str, operation: &str, payload: Vec<u8>) -> Vec<u8> {
    RpcRequest::new(service, operation, payload)
        .encode()
        .expect("encode request")
}

#[rocket::async_test]
async fn disabled_password_auth_is_not_advertised_or_accepted() {
    std::env::set_var("ENABLE_PASSWORD_AUTH", "false");
    std::env::set_var("DOMAIN_NAME", "disabled-auth.example.test");
    let pool = common::create_test_pool();
    let user = common::data_factory::create_user(&pool, &HashMap::new());
    let hash = linkkeys::services::password::hash_for_storage("correct-password").unwrap();
    common::data_factory::create_auth_credential(&pool, &user.id, "password", &hash);

    let rocket = linkkeys::web::build_rocket(
        pool,
        Arc::new(AtomicBool::new(true)),
        common::net::offline_net(),
        rocket::Config {
            secret_key: rocket::config::SecretKey::derive_from(&[9_u8; 64]),
            ..rocket::Config::debug_default()
        },
    );
    let client = Client::tracked(rocket).await.expect("Rocket client");
    let origin = Header::new("Origin", "https://disabled-auth.example.test");

    let response = client
        .post("/account/login")
        .header(ContentType::Form)
        .header(Header::new("Host", "disabled-auth.example.test"))
        .header(origin.clone())
        .body(format!(
            "username={}&password=correct-password",
            user.username
        ))
        .dispatch()
        .await;
    assert_eq!(response.status(), rocket::http::Status::NotFound);

    let login = liblinkkeys::generated::types::SessionPasswordLoginRequest {
        username: user.username,
        password: "correct-password".to_string(),
    };
    let response = client
        .post("/csil/v1/rpc")
        .header(ContentType::new("application", "cbor"))
        .header(Header::new("Host", "disabled-auth.example.test"))
        .header(origin.clone())
        .body(envelope(
            "Session",
            "login-password",
            liblinkkeys::generated::encode_session_password_login_request(&login),
        ))
        .dispatch()
        .await;
    let response = RpcResponse::decode(&response.into_bytes().await.unwrap()).unwrap();
    assert_eq!(response.status, RpcStatus::Forbidden);

    let response = client
        .post("/csil/v1/rpc")
        .header(ContentType::new("application", "cbor"))
        .header(Header::new("Host", "disabled-auth.example.test"))
        .body(envelope(
            "Ui",
            "get-configuration",
            liblinkkeys::generated::encode_empty_request(
                &liblinkkeys::generated::types::EmptyRequest {},
            ),
        ))
        .dispatch()
        .await;
    let response = RpcResponse::decode(&response.into_bytes().await.unwrap()).unwrap();
    let configuration =
        liblinkkeys::generated::decode_get_ui_configuration_response(&response.payload).unwrap();
    assert!(!configuration
        .capabilities
        .iter()
        .any(|value| value == "password_login" || value == "reset_password"));
}
