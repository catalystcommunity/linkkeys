//! Application accounts on a relying party (request-app-management.md):
//! account kind and application id, renames, named API keys with a maximum,
//! account limits, usage counts, the enrollment rule, and the migration that
//! turned API-key-only accounts into application accounts.

mod common;

use std::collections::HashMap;

use liblinkkeys::generated::types::{
    AccountKind, AccountLimits, CreateApiKeyRequest, CreateUserRequest, GetAccountLimitsRequest,
    GetApplicationUsageRequest, ListApiKeysRequest, RenameUserRequest, RevokeApiKeyRequest,
    SetAccountLimitsRequest, SetApplicationIdRequest,
};
use linkkeys::services::{admin, applications, auth::ApiKeyAuthenticator};

fn setup() -> linkkeys::db::DbPool {
    std::env::set_var("DOMAIN_NAME", "rp.test");
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    common::create_test_pool()
}

fn create_application(pool: &linkkeys::db::DbPool, username: &str, app: &str) -> (String, String) {
    let resp = admin::create_user(
        pool,
        CreateUserRequest {
            username: username.to_string(),
            display_name: "An App".to_string(),
            password: None,
            application_id: Some(app.to_string()),
        },
    )
    .expect("create application account");
    assert_eq!(resp.user.kind, AccountKind::Application);
    assert_eq!(resp.user.application_id.as_deref(), Some(app));
    (resp.user.id, resp.api_key.expect("first API key"))
}

#[test]
fn an_application_account_has_no_password_and_a_valid_id() {
    let pool = setup();
    for (password, app) in [
        (Some("correct horse battery staple".to_string()), "app"),
        (None, "not valid!"),
    ] {
        assert!(admin::create_user(
            &pool,
            CreateUserRequest {
                username: "x".to_string(),
                display_name: "X".to_string(),
                password,
                application_id: Some(app.to_string()),
            },
        )
        .is_err());
    }
    let human = admin::create_user(
        &pool,
        CreateUserRequest {
            username: "person".to_string(),
            display_name: "Person".to_string(),
            password: Some("correct horse battery staple".to_string()),
            application_id: None,
        },
    )
    .unwrap();
    assert_eq!(human.user.kind, AccountKind::Human);
    assert_eq!(human.user.application_id, None);
}

#[test]
fn rename_keeps_the_account_and_refuses_a_taken_name() {
    let pool = setup();
    let (id, key) = create_application(&pool, "old-name", "app");
    create_application(&pool, "taken", "other");
    let renamed = applications::rename_user(
        &pool,
        RenameUserRequest {
            user_id: id.clone(),
            username: "new-name".to_string(),
        },
    )
    .unwrap();
    assert_eq!(renamed.user.id, id);
    assert_eq!(renamed.user.username, "new-name");
    // The API key still works: credentials belong to the account id.
    let auth = ApiKeyAuthenticator::new(pool.clone())
        .authenticate_key_with_credential(&key)
        .unwrap();
    assert_eq!(auth.user.id, id);

    for name in ["taken", "has space", "a@b", ""] {
        assert!(
            applications::rename_user(
                &pool,
                RenameUserRequest {
                    user_id: id.clone(),
                    username: name.to_string(),
                },
            )
            .is_err(),
            "{name:?}"
        );
    }
}

#[test]
fn only_an_application_account_has_an_application_id() {
    let pool = setup();
    let (id, _) = create_application(&pool, "app-account", "first");
    let resp = applications::set_application_id(
        &pool,
        SetApplicationIdRequest {
            user_id: id.clone(),
            application_id: "second".to_string(),
        },
    )
    .unwrap();
    assert_eq!(resp.user.application_id.as_deref(), Some("second"));

    let human = common::data_factory::create_user(&pool, &HashMap::new());
    assert!(applications::set_application_id(
        &pool,
        SetApplicationIdRequest {
            user_id: human.id,
            application_id: "stolen".to_string(),
        },
    )
    .is_err());
}

#[test]
fn named_api_keys_are_listed_capped_and_revoked() {
    let pool = setup();
    let (id, first_key) = create_application(&pool, "keys", "keys");
    applications::set_account_limits(
        &pool,
        SetAccountLimitsRequest {
            user_id: id.clone(),
            limits: AccountLimits {
                max_api_keys: Some(2),
                max_distinct_users: None,
                distinct_user_window_days: 30,
                requests_per_minute: None,
                request_burst: None,
            },
        },
    )
    .unwrap();
    let second = applications::create_api_key(
        &pool,
        CreateApiKeyRequest {
            user_id: id.clone(),
            name: "ci".to_string(),
        },
    )
    .unwrap();
    assert_eq!(second.key.name, "ci");
    assert!(second.api_key.ends_with(&second.key.hint));
    assert!(
        applications::create_api_key(
            &pool,
            CreateApiKeyRequest {
                user_id: id.clone(),
                name: "third".to_string(),
            },
        )
        .is_err(),
        "the account is at its maximum of 2 keys"
    );

    let listed = applications::list_api_keys(
        &pool,
        ListApiKeysRequest {
            user_id: id.clone(),
        },
    )
    .unwrap()
    .keys;
    let names: Vec<&str> = listed.iter().map(|k| k.name.as_str()).collect();
    assert_eq!(names, ["default", "ci"]);
    assert!(listed.iter().all(|k| k.hint.len() == 4));

    // A key that authenticates records when it was last used.
    let auth = ApiKeyAuthenticator::new(pool.clone());
    auth.authenticate_key_with_credential(&first_key).unwrap();
    let listed = applications::list_api_keys(
        &pool,
        ListApiKeysRequest {
            user_id: id.clone(),
        },
    )
    .unwrap()
    .keys;
    assert!(listed[0].last_used_at.is_some());

    applications::revoke_api_key(
        &pool,
        RevokeApiKeyRequest {
            user_id: id.clone(),
            key_id: listed[0].key_id.clone(),
        },
    )
    .unwrap();
    assert!(auth.authenticate_key_with_credential(&first_key).is_err());
    assert!(auth
        .authenticate_key_with_credential(&second.api_key)
        .is_ok());
    // A key of another account cannot be revoked through this one.
    let (other, _) = create_application(&pool, "other", "other");
    assert!(applications::revoke_api_key(
        &pool,
        RevokeApiKeyRequest {
            user_id: other,
            key_id: second.key.key_id.clone(),
        },
    )
    .is_err());
}

#[test]
fn limits_round_trip_and_default_to_none() {
    let pool = setup();
    let (id, _) = create_application(&pool, "limits", "limits");
    let defaults = applications::get_account_limits(
        &pool,
        GetAccountLimitsRequest {
            user_id: id.clone(),
        },
    )
    .unwrap()
    .limits;
    assert_eq!(defaults.max_distinct_users, None);
    assert_eq!(defaults.distinct_user_window_days, 30);

    let limits = AccountLimits {
        max_api_keys: Some(3),
        max_distinct_users: Some(100),
        distinct_user_window_days: 30,
        requests_per_minute: Some(600),
        request_burst: Some(50),
    };
    applications::set_account_limits(
        &pool,
        SetAccountLimitsRequest {
            user_id: id.clone(),
            limits: limits.clone(),
        },
    )
    .unwrap();
    let read = applications::get_account_limits(&pool, GetAccountLimitsRequest { user_id: id })
        .unwrap()
        .limits;
    assert_eq!(read, limits);
}

#[test]
fn usage_is_counted_by_day_and_operation() {
    let pool = setup();
    let (id, _) = create_application(&pool, "usage", "usage");
    applications::record_usage(&id, "sign-request", true);
    applications::record_usage(&id, "sign-request", true);
    applications::record_usage(&id, "decrypt-token", false);
    let today = liblinkkeys::timestamp::now_whole_milliseconds().date();
    let usage = applications::get_application_usage(
        &pool,
        GetApplicationUsageRequest {
            user_id: id,
            first_day: today,
            last_day: today,
        },
    )
    .unwrap();
    let find = |op: &str| usage.days.iter().find(|d| d.operation == op).unwrap();
    assert_eq!(find("sign-request").succeeded, 2);
    assert_eq!(find("decrypt-token").failed, 1);
    assert_eq!(usage.distinct_users, 0);
}

#[test]
fn an_application_account_enrolls_only_under_its_own_id() {
    let pool = setup();
    let (id, _) = create_application(&pool, "enroller", "mine");
    let request = liblinkkeys::generated::types::EnrollApplicationInstanceRequest {
        application_id: "someone-else".to_string(),
        instance_id: "i1".to_string(),
        keys: Vec::new(),
    };
    let err = linkkeys::services::application_keys::enroll_instance(
        &pool,
        &id,
        request,
        liblinkkeys::timestamp::now_whole_milliseconds(),
    )
    .unwrap_err();
    assert!(
        err.message.contains("own application_id"),
        "{}",
        err.message
    );
}

/// The migration makes an account with an API key and no password an
/// application account named by its username, and leaves the others human.
#[cfg(feature = "sqlite")]
#[test]
fn the_migration_classifies_existing_accounts() {
    use diesel::prelude::*;
    use diesel_migrations::MigrationHarness;

    let mut conn = diesel::SqliteConnection::establish(":memory:").unwrap();
    diesel::sql_query("PRAGMA foreign_keys = ON")
        .execute(&mut conn)
        .unwrap();
    loop {
        let pending = conn
            .pending_migrations(linkkeys::db::sqlite_migrations())
            .unwrap();
        let Some(next) = pending.first() else {
            panic!("the application accounts migration was not found");
        };
        if next
            .name()
            .version()
            .to_string()
            .starts_with("20261122000001")
        {
            break;
        }
        conn.run_next_migration(linkkeys::db::sqlite_migrations())
            .unwrap();
    }
    for (id, name, credentials) in [
        ("u-app", "grafana", &["api_key"][..]),
        ("u-human", "alice", &["password", "api_key"][..]),
        ("u-pw", "bob", &["password"][..]),
    ] {
        diesel::sql_query(format!(
            "INSERT INTO users (id, username, display_name) VALUES ('{id}', '{name}', '{name}')"
        ))
        .execute(&mut conn)
        .unwrap();
        for (n, kind) in credentials.iter().enumerate() {
            diesel::sql_query(format!(
                "INSERT INTO auth_credentials (id, user_id, credential_type, credential_hash) \
                 VALUES ('{id}-{n}', '{id}', '{kind}', 'h')"
            ))
            .execute(&mut conn)
            .unwrap();
        }
    }
    conn.run_next_migration(linkkeys::db::sqlite_migrations())
        .unwrap();

    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Text)]
        id: String,
        #[diesel(sql_type = diesel::sql_types::Text)]
        kind: String,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        application_id: Option<String>,
    }
    let rows: Vec<Row> =
        diesel::sql_query("SELECT id, kind, application_id FROM users ORDER BY id")
            .load(&mut conn)
            .unwrap();
    let got: Vec<(String, String, Option<String>)> = rows
        .into_iter()
        .map(|r| (r.id, r.kind, r.application_id))
        .collect();
    assert_eq!(
        got,
        vec![
            ("u-app".into(), "application".into(), Some("grafana".into())),
            ("u-human".into(), "human".into(), None),
            ("u-pw".into(), "human".into(), None),
        ]
    );
}
