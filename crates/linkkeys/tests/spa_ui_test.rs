mod common;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use rocket::http::Status;
use rocket::local::asynchronous::Client;

fn rocket(pool: linkkeys::db::DbPool) -> rocket::Rocket<rocket::Build> {
    linkkeys::web::build_rocket(
        pool,
        Arc::new(AtomicBool::new(true)),
        common::net::offline_net(),
        rocket::Config {
            secret_key: rocket::config::SecretKey::derive_from(&[11_u8; 64]),
            ..rocket::Config::debug_default()
        },
    )
}

#[rocket::async_test]
async fn embedded_spa_and_runtime_assets_are_served_with_security_headers() {
    std::env::remove_var("UI_CONFIG_FILE");
    std::env::remove_var("UI_DIST_DIR");
    let client = Client::tracked(rocket(common::create_test_pool()))
        .await
        .expect("embedded UI client");

    let response = client
        .get("/app/password/reset?token=secret")
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let csp = response
        .headers()
        .get_one("Content-Security-Policy")
        .expect("content security policy");
    assert!(csp.contains("script-src 'self'"));
    assert!(csp.contains("style-src 'self'"));
    assert!(!csp.contains("unsafe-inline"));
    assert_eq!(
        response.headers().get_one("X-Content-Type-Options"),
        Some("nosniff")
    );
    let body = response.into_string().await.unwrap();
    assert!(body.contains(r#"src="/_linkkeys/assets/app.js""#));
    assert!(body.contains(r#"href="/_linkkeys/assets/app.css""#));

    let response = client.get("/_linkkeys/assets/app.js").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert!(response.into_bytes().await.unwrap().len() > 10_000);

    let root = std::env::temp_dir().join(format!("linkkeys-ui-{}", uuid::Uuid::now_v7()));
    let dist = root.join("dist");
    let theme = root.join("theme");
    let extension = root.join("extension");
    std::fs::create_dir_all(&dist).unwrap();
    std::fs::create_dir_all(&theme).unwrap();
    std::fs::create_dir_all(&extension).unwrap();
    std::fs::write(
        dist.join("index.html"),
        "<!doctype html><p>replacement-ui</p>",
    )
    .unwrap();
    std::fs::write(dist.join("custom.js"), "export const replacement = true;").unwrap();
    std::fs::write(theme.join("theme.css"), ":root { --accent: pink; }").unwrap();
    std::fs::write(
        extension.join("extension.js"),
        "export function activate() {}",
    )
    .unwrap();
    let config_path = root.join("ui.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
[theme]
asset_dir = "{}"
stylesheet_url = "/_linkkeys/themes/operator/theme.css"

[[extensions]]
id = "product"
asset_dir = "{}"
module_url = "/_linkkeys/extensions/product/extension.js"
api_version = 1
"#,
            theme.display(),
            extension.display()
        ),
    )
    .unwrap();
    std::env::set_var("UI_DIST_DIR", &dist);
    std::env::set_var("UI_CONFIG_FILE", &config_path);

    let runtime_client = Client::tracked(rocket(common::create_test_pool()))
        .await
        .expect("runtime UI client");
    let body = runtime_client
        .get("/app/product")
        .dispatch()
        .await
        .into_string()
        .await
        .unwrap();
    assert!(body.contains("replacement-ui"));
    assert_eq!(
        runtime_client
            .get("/_linkkeys/assets/custom.js")
            .dispatch()
            .await
            .status(),
        Status::Ok
    );
    assert_eq!(
        runtime_client
            .get("/_linkkeys/themes/operator/theme.css")
            .dispatch()
            .await
            .status(),
        Status::Ok
    );
    assert_eq!(
        runtime_client
            .get("/_linkkeys/extensions/product/extension.js")
            .dispatch()
            .await
            .status(),
        Status::Ok
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/proc/self/environ", extension.join("outside.txt")).unwrap();
        assert_eq!(
            runtime_client
                .get("/_linkkeys/extensions/product/outside.txt")
                .dispatch()
                .await
                .status(),
            Status::NotFound
        );
    }

    std::env::remove_var("UI_CONFIG_FILE");
    std::env::remove_var("UI_DIST_DIR");
    std::fs::remove_dir_all(root).unwrap();
}
