//! Password-manager metadata on the built-in account and administration UI.

mod common;

use common::data_factory::{create_auth_credential, create_relation, create_user, DataMap};
use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

const DOMAIN: &str = "password-manager.test";
const USERNAME: &str = "password_manager_user";
const PASSWORD: &str = "correct-horse-battery-staple";

#[rocket::async_test]
async fn account_and_admin_password_forms_describe_their_credentials() {
    std::env::set_var("DOMAIN_NAME", DOMAIN);
    std::env::set_var("ENABLE_PASSWORD_AUTH", "true");

    let pool = common::create_test_pool();
    let mut overrides = DataMap::new();
    overrides.insert("username".to_string(), serde_json::json!(USERNAME));
    let user = create_user(&pool, &overrides);
    let hash = linkkeys::services::password::hash_for_storage(PASSWORD).unwrap();
    create_auth_credential(&pool, &user.id, "password", &hash);
    create_relation(&pool, "user", &user.id, "admin", "domain", DOMAIN);

    let config = rocket::Config {
        secret_key: rocket::config::SecretKey::derive_from(&[9u8; 64]),
        ..rocket::Config::debug_default()
    };
    let rocket = linkkeys::web::build_rocket(
        pool,
        Arc::new(AtomicBool::new(true)),
        common::net::offline_net(),
        config,
    );
    let client = Client::tracked(rocket).await.expect("rocket client");

    let response = client.get("/account/login").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let body = response.into_string().await.unwrap();
    assert!(body.contains(r#"name="username" autocomplete="username""#));
    assert!(body.contains(r#"name="password" autocomplete="current-password""#));

    let response = client
        .post("/account/login")
        .header(ContentType::Form)
        .header(Header::new("Host", DOMAIN))
        .header(Header::new("Origin", format!("https://{DOMAIN}")))
        .body(format!(
            "username={USERNAME}%40{DOMAIN}&password={PASSWORD}"
        ))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Found);

    let response = client.get("/account/change-password").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let body = response.into_string().await.unwrap();
    assert!(body.contains(&format!(
        r#"name="username" value="{USERNAME}" autocomplete="username""#
    )));
    assert!(body.contains(r#"name="current_password" autocomplete="current-password""#));
    assert_eq!(body.matches(r#"autocomplete="new-password""#).count(), 2);

    let response = client.get("/user-admin/users/create").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let body = response.into_string().await.unwrap();
    assert!(body.contains(r#"name="username" autocomplete="username""#));
    assert!(body.contains(r#"name="password" autocomplete="new-password""#));

    let response = client
        .get(format!("/user-admin/users/{}", user.id))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let body = response.into_string().await.unwrap();
    assert!(body.contains(&format!(
        r#"name="username" value="{USERNAME}" autocomplete="username""#
    )));
    assert!(body.contains(r#"name="new_password" autocomplete="new-password""#));
}
