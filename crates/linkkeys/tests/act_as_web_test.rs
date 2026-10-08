//! The `/auth/act-as` entry route hands a decodable request to the consent
//! page and refuses anything else with an error page, never a login form.

mod common;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use base64ct::{Base64UrlUnpadded, Encoding};
use rocket::http::Status;
use rocket::local::asynchronous::Client;

fn rocket(pool: linkkeys::db::DbPool) -> rocket::Rocket<rocket::Build> {
    linkkeys::web::build_rocket(
        pool,
        Arc::new(AtomicBool::new(true)),
        common::net::offline_net(),
        rocket::Config {
            secret_key: rocket::config::SecretKey::derive_from(&[12_u8; 64]),
            ..rocket::Config::debug_default()
        },
    )
}

fn sample_request() -> String {
    use liblinkkeys::generated::types::*;
    let signed = SignedActAsGrantRequest {
        request: vec![0xa0],
        proof: GranteeProof {
            application_instance_id: Some("i".into()),
            local_rp_descriptor: None,
            signature: ApplicationKeySignature {
                signed_by_key_id: "k".into(),
                signature: vec![1, 2, 3],
            },
        },
    };
    Base64UrlUnpadded::encode_string(&liblinkkeys::generated::encode_signed_act_as_grant_request(
        &signed,
    ))
}

#[rocket::async_test]
async fn a_decodable_request_is_handed_to_the_consent_page() {
    let client = Client::tracked(rocket(common::create_test_pool()))
        .await
        .unwrap();
    let sr = sample_request();
    let response = client
        .get(format!("/auth/act-as?signed_request={sr}"))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Found);
    let location = response.headers().get_one("Location").unwrap();
    assert_eq!(location, format!("/app/act-as#request={sr}"));
}

#[rocket::async_test]
async fn a_missing_or_damaged_request_gets_an_error_page() {
    let client = Client::tracked(rocket(common::create_test_pool()))
        .await
        .unwrap();
    for path in ["/auth/act-as", "/auth/act-as?signed_request=not-cbor!!"] {
        let response = client.get(path).dispatch().await;
        assert_eq!(response.status(), Status::Ok, "{path}");
        let body = response.into_string().await.unwrap();
        assert!(body.contains("missing or damaged"), "{path}");
        assert!(!body.to_lowercase().contains("password"), "{path}");
    }
}
