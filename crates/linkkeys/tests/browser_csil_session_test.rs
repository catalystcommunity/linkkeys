mod common;

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use csilgen_transport::rpc::{RpcRequest, RpcResponse};
use csilgen_transport::Status as RpcStatus;
use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;

const DOMAIN: &str = "browser-csil.example.test";

fn envelope(service: &str, operation: &str, payload: Vec<u8>) -> Vec<u8> {
    RpcRequest::new(service, operation, payload)
        .encode()
        .unwrap()
}

/// The web UI decodes these replies with the generated TypeScript codec, which
/// rejects a timestamp finer than a millisecond. A stored time with
/// microseconds once made every sign-in fail in the browser.
fn assert_millisecond_times(info: &liblinkkeys::generated::types::BrowserSessionInfo) {
    let times = [
        ("issued_at", info.issued_at),
        ("authenticated_at", info.authenticated_at),
        ("expires_at", info.expires_at),
        ("user.created_at", info.user.created_at),
        ("user.updated_at", info.user.updated_at),
    ];
    for (name, value) in times {
        assert_eq!(
            value.nanosecond() % 1_000_000,
            0,
            "{name} is finer than milliseconds: {value}"
        );
    }
}

#[rocket::async_test]
async fn browser_csil_login_current_and_account_dispatch_share_one_session() {
    std::env::set_var("DOMAIN_NAME", DOMAIN);
    let pool = common::create_test_pool();
    let mut values = HashMap::new();
    values.insert("username".to_string(), "browser-user".into());
    let user = common::data_factory::create_user(&pool, &values);
    let hash = linkkeys::services::password::hash_for_storage("correct-password").unwrap();
    common::data_factory::create_auth_credential(&pool, &user.id, "password", &hash);

    let config = rocket::Config {
        secret_key: rocket::config::SecretKey::derive_from(&[7_u8; 64]),
        ..rocket::Config::debug_default()
    };
    let rocket = linkkeys::web::build_rocket(
        pool,
        Arc::new(AtomicBool::new(true)),
        common::net::offline_net(),
        config,
    );
    let client = Client::tracked(rocket).await.expect("Rocket client");

    let foreign_login = liblinkkeys::generated::types::SessionPasswordLoginRequest {
        username: "browser-user@another.example".to_string(),
        password: "correct-password".to_string(),
    };
    let response = client
        .post("/csil/v1/rpc")
        .header(ContentType::new("application", "cbor"))
        .header(Header::new("Host", DOMAIN))
        .header(Header::new("Origin", format!("https://{DOMAIN}")))
        .body(envelope(
            "Session",
            "login-password",
            liblinkkeys::generated::encode_session_password_login_request(&foreign_login).unwrap(),
        ))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let response = RpcResponse::decode(&response.into_bytes().await.unwrap()).unwrap();
    assert_eq!(response.status, RpcStatus::Forbidden);

    let login = liblinkkeys::generated::types::SessionPasswordLoginRequest {
        username: format!("browser-user@{DOMAIN}"),
        password: "correct-password".to_string(),
    };
    let response = client
        .post("/csil/v1/rpc")
        .header(ContentType::new("application", "cbor"))
        .header(Header::new("Host", DOMAIN))
        .header(Header::new("Origin", format!("https://{DOMAIN}")))
        .body(envelope(
            "Session",
            "login-password",
            liblinkkeys::generated::encode_session_password_login_request(&login).unwrap(),
        ))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let response = RpcResponse::decode(&response.into_bytes().await.unwrap()).unwrap();
    assert_eq!(response.status, RpcStatus::Ok);
    let login = liblinkkeys::generated::decode_session_password_login_response(&response.payload)
        .expect("decode login response");
    assert_eq!(login.session.user.id, user.id);
    assert_millisecond_times(&login.session);

    let response = client
        .post("/csil/v1/rpc")
        .header(ContentType::new("application", "cbor"))
        .header(Header::new("Host", DOMAIN))
        .header(Header::new("Origin", format!("https://{DOMAIN}")))
        .body(envelope(
            "Session",
            "get-current",
            liblinkkeys::generated::encode_empty_request(
                &liblinkkeys::generated::types::EmptyRequest {},
            )
            .unwrap(),
        ))
        .dispatch()
        .await;
    let response = RpcResponse::decode(&response.into_bytes().await.unwrap()).unwrap();
    assert_eq!(response.status, RpcStatus::Ok);
    let current = liblinkkeys::generated::decode_session_current_response(&response.payload)
        .expect("decode current session");
    assert_millisecond_times(&current.session);

    let response = client
        .post("/csil/v1/rpc")
        .header(ContentType::new("application", "cbor"))
        .header(Header::new("Host", DOMAIN))
        .header(Header::new("Origin", format!("https://{DOMAIN}")))
        .body(envelope(
            "Account",
            "get-my-info",
            liblinkkeys::generated::encode_empty_request(
                &liblinkkeys::generated::types::EmptyRequest {},
            )
            .unwrap(),
        ))
        .dispatch()
        .await;
    let response = RpcResponse::decode(&response.into_bytes().await.unwrap()).unwrap();
    assert_eq!(response.status, RpcStatus::Ok);
    let account = liblinkkeys::generated::decode_get_my_info_response(&response.payload).unwrap();
    assert_eq!(account.user.id, user.id);

    let response = client
        .post("/csil/v1/rpc")
        .header(ContentType::new("application", "cbor"))
        .header(Header::new("Host", DOMAIN))
        .header(Header::new("Origin", format!("https://{DOMAIN}")))
        .body(envelope(
            "Account",
            "change-password",
            liblinkkeys::generated::encode_change_password_request(
                &liblinkkeys::generated::types::ChangePasswordRequest {
                    current_password: "wrong-password".to_string(),
                    new_password: "new-password-value".to_string(),
                },
            )
            .unwrap(),
        ))
        .dispatch()
        .await;
    let response = RpcResponse::decode(&response.into_bytes().await.unwrap()).unwrap();
    assert_eq!(response.status, RpcStatus::Forbidden);
    assert_eq!(
        response.error.as_deref(),
        Some("The current password is incorrect")
    );

    let response = client
        .post("/csil/v1/rpc")
        .header(ContentType::new("application", "cbor"))
        .header(Header::new("Host", DOMAIN))
        .body(envelope(
            "Account",
            "get-my-info",
            liblinkkeys::generated::encode_empty_request(
                &liblinkkeys::generated::types::EmptyRequest {},
            )
            .unwrap(),
        ))
        .dispatch()
        .await;
    let response = RpcResponse::decode(&response.into_bytes().await.unwrap()).unwrap();
    assert_eq!(response.status, RpcStatus::Forbidden);

    let response = client
        .post("/csil/v1/rpc")
        .header(ContentType::new("application", "cbor"))
        .header(Header::new("Host", DOMAIN))
        .header(Header::new("Origin", format!("https://{DOMAIN}")))
        .body(envelope(
            "Session",
            "logout",
            liblinkkeys::generated::encode_empty_request(
                &liblinkkeys::generated::types::EmptyRequest {},
            )
            .unwrap(),
        ))
        .dispatch()
        .await;
    let response = RpcResponse::decode(&response.into_bytes().await.unwrap()).unwrap();
    assert_eq!(response.status, RpcStatus::Ok);

    let response = client
        .post("/csil/v1/rpc")
        .header(ContentType::new("application", "cbor"))
        .header(Header::new("Host", DOMAIN))
        .header(Header::new("Origin", format!("https://{DOMAIN}")))
        .body(envelope(
            "Session",
            "get-current",
            liblinkkeys::generated::encode_empty_request(
                &liblinkkeys::generated::types::EmptyRequest {},
            )
            .unwrap(),
        ))
        .dispatch()
        .await;
    let response = RpcResponse::decode(&response.into_bytes().await.unwrap()).unwrap();
    assert_eq!(response.status, RpcStatus::Forbidden);
}
