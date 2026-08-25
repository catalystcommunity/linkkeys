mod common;

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use liblinkkeys::generated::types::{
    IntrospectBrowserSessionRequest, RequestPasswordRecoveryRequest,
};
use linkkeys::services::auth::{AuthenticationEvidence, Authenticator, PasswordAuthenticator};

#[test]
fn verified_contact_and_recovery_are_single_use_and_revoke_sessions() {
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("SMTP_HOST", "smtp.example.test");
    std::env::set_var("SMTP_FROM", "noreply@example.test");
    std::env::set_var("PUBLIC_ORIGIN", "https://localhost:8443");
    std::env::set_var("OUTBOX_ENCRYPTION_KEY", "00".repeat(32));
    assert!(linkkeys::services::notification::capabilities()
        .capabilities
        .is_empty());
    let pool = common::create_test_pool();
    let user = common::data_factory::create_user(&pool, &HashMap::new());
    common::data_factory::create_domain_key(&pool);

    for (claim_type, value_type) in [("email", "email"), ("email_verified", "bool")] {
        let mut policy = HashMap::new();
        policy.insert("claim_type".to_string(), claim_type.into());
        policy.insert("value_type".to_string(), value_type.into());
        policy.insert("set_rule".to_string(), "verified".into());
        policy.insert("signing_rule".to_string(), "self_signed".into());
        common::data_factory::create_claim_policy(&pool, &policy);
    }

    let superseded_verification_token = "superseded-verification-secret";
    let stored_verification = pool
        .create_account_challenge_and_outbox(
            &user.id,
            "verify_contact",
            "email",
            "person@example.test",
            &linkkeys::services::verification::token_digest(superseded_verification_token),
            vec![1, 2, 3],
            chrono::Utc::now() + chrono::Duration::hours(24),
            None,
        )
        .expect("create verification challenge");
    assert_ne!(
        stored_verification.token_digest,
        superseded_verification_token
    );
    assert_eq!(stored_verification.token_digest.len(), 64);
    let first_outbox = pool
        .find_latest_notification_outbox(&user.id, "verify_contact")
        .unwrap()
        .unwrap();

    let verification_token = "verification-secret";
    pool.create_account_challenge_and_outbox(
        &user.id,
        "verify_contact",
        "email",
        "person@example.test",
        &linkkeys::services::verification::token_digest(verification_token),
        vec![1, 2, 3],
        chrono::Utc::now() + chrono::Duration::hours(24),
        None,
    )
    .expect("replace verification challenge");
    let superseded_outbox = pool
        .find_notification_outbox(&first_outbox.id)
        .expect("find superseded outbox")
        .expect("superseded outbox exists");
    assert_eq!(superseded_outbox.state, "superseded");
    assert!(superseded_outbox.encrypted_payload.is_none());
    assert!(
        linkkeys::services::verification::confirm_contact_verification(
            &pool,
            &user.id,
            superseded_verification_token,
        )
        .is_err()
    );

    let confirmed = linkkeys::services::verification::confirm_contact_verification(
        &pool,
        &user.id,
        verification_token,
    )
    .expect("confirm contact");
    assert_eq!(confirmed.contact_method.destination, "person@example.test");
    assert_eq!(confirmed.claims.len(), 2);
    assert!(
        linkkeys::services::verification::confirm_contact_verification(
            &pool,
            &user.id,
            verification_token,
        )
        .is_err()
    );

    let repeated_verification_token = "repeated-verification-secret";
    pool.create_account_challenge_and_outbox(
        &user.id,
        "verify_contact",
        "email",
        "person@example.test",
        &linkkeys::services::verification::token_digest(repeated_verification_token),
        vec![1, 2, 3],
        chrono::Utc::now() + chrono::Duration::hours(24),
        None,
    )
    .expect("create repeated verification challenge");
    linkkeys::services::verification::confirm_contact_verification(
        &pool,
        &user.id,
        repeated_verification_token,
    )
    .expect("confirm repeated contact");
    let active_contacts = pool
        .list_verified_contacts(&user.id)
        .expect("list contacts");
    assert_eq!(active_contacts.len(), 1);
    assert_eq!(active_contacts[0].destination, "person@example.test");

    let worker_ready = Arc::new(AtomicBool::new(false));
    let _email_worker = linkkeys::services::notification::start_worker(pool.clone(), worker_ready)
        .expect("start email worker")
        .expect("email worker is configured");
    assert!(linkkeys::services::notification::capabilities()
        .capabilities
        .iter()
        .any(|capability| capability.channel == "email"));

    let mut recovery_responses = Vec::new();
    for identifier in [&user.username, "unknown-account"] {
        let payload = liblinkkeys::generated::encode_request_password_recovery_request(
            &RequestPasswordRecoveryRequest {
                identifier: identifier.to_string(),
            },
        );
        let (status, response) = linkkeys::tcp::dispatch_for_test(
            "Recovery",
            "request-password-recovery",
            payload,
            &pool,
            None,
        );
        assert_eq!(status, 0);
        liblinkkeys::generated::decode_request_password_recovery_response(&response)
            .expect("decode generic recovery response");
        recovery_responses.push(response);
    }
    assert_eq!(recovery_responses[0], recovery_responses[1]);
    let recovery_outbox = pool
        .find_latest_notification_outbox(&user.id, "reset_password")
        .expect("find recovery outbox")
        .expect("known account queues recovery");
    assert!(recovery_outbox.encrypted_payload.is_some());

    let old_password = "old-password-value";
    let old_hash = linkkeys::services::password::hash_for_storage(old_password).unwrap();
    common::data_factory::create_auth_credential(&pool, &user.id, "password", &old_hash);
    let (session_token, stored_session) = linkkeys::services::browser_session::create(
        &pool,
        &user.id,
        &AuthenticationEvidence::single("password"),
    )
    .expect("create browser session");
    assert_ne!(stored_session.token_digest, session_token);
    assert_eq!(stored_session.token_digest.len(), 64);

    let extension = common::data_factory::create_user(&pool, &HashMap::new());
    let (api_key, api_hash) = linkkeys::services::auth::generate_api_key(&extension.id);
    common::data_factory::create_auth_credential(&pool, &extension.id, "api_key", &api_hash);
    let payload = liblinkkeys::generated::encode_introspect_browser_session_request(
        &IntrospectBrowserSessionRequest {
            session_cookie: session_token.clone(),
        },
    );
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Session",
        "introspect",
        payload.clone(),
        Some(&api_key),
        &pool,
        None,
    );
    assert_ne!(status, 0);
    common::data_factory::create_relation(
        &pool,
        "user",
        &extension.id,
        "ui_extension",
        "domain",
        &linkkeys::conversions::get_domain_name(),
    );
    let (status, response) = linkkeys::tcp::dispatch_for_test_authed(
        "Session",
        "introspect",
        payload,
        Some(&api_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let introspection =
        liblinkkeys::generated::decode_introspect_browser_session_response(&response).unwrap();
    assert_eq!(introspection.user_id, user.id);

    let recovery_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    pool.create_account_challenge_and_outbox(
        &user.id,
        "reset_password",
        "email",
        "person@example.test",
        &linkkeys::services::verification::token_digest(recovery_token),
        vec![4, 5, 6],
        chrono::Utc::now() + chrono::Duration::hours(1),
        None,
    )
    .expect("create recovery challenge");

    linkkeys::services::recovery::complete(&pool, recovery_token, "new-password-value")
        .expect("complete recovery");
    assert!(
        linkkeys::services::browser_session::get(&pool, &session_token, false)
            .unwrap()
            .is_none()
    );

    let authenticator = PasswordAuthenticator::new(pool.clone());
    assert!(authenticator
        .authenticate(&user.username, old_password)
        .is_err());
    assert!(authenticator
        .authenticate(&user.username, "new-password-value")
        .is_ok());
    assert!(linkkeys::services::recovery::complete(
        &pool,
        recovery_token,
        "another-password-value",
    )
    .is_err());

    let active_password = pool
        .find_credentials_for_user(&user.id, "password")
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let stale_step_up_token = "stale-password-step-up-token";
    pool.create_account_challenge_and_outbox(
        &user.id,
        "verify_contact",
        "email",
        "replacement@example.test",
        &linkkeys::services::verification::token_digest(stale_step_up_token),
        vec![7, 8, 9],
        chrono::Utc::now() + chrono::Duration::hours(24),
        Some(&active_password.id),
    )
    .unwrap();
    let replacement_hash =
        linkkeys::services::password::hash_for_storage("replacement-password-value").unwrap();
    pool.replace_password(&user.id, &replacement_hash).unwrap();
    assert!(
        linkkeys::services::verification::confirm_contact_verification(
            &pool,
            &user.id,
            stale_step_up_token,
        )
        .is_err()
    );

    let expiring_password = pool
        .find_credentials_for_user(&user.id, "password")
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let expired_step_up_token = "expired-password-step-up-token";
    pool.create_account_challenge_and_outbox(
        &user.id,
        "verify_contact",
        "email",
        "expiring@example.test",
        &linkkeys::services::verification::token_digest(expired_step_up_token),
        vec![10, 11, 12],
        chrono::Utc::now() + chrono::Duration::hours(24),
        Some(&expiring_password.id),
    )
    .unwrap();
    pool.set_credential_expires_at(
        &expiring_password.id,
        &(chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339(),
    )
    .unwrap();
    assert!(
        linkkeys::services::verification::confirm_contact_verification(
            &pool,
            &user.id,
            expired_step_up_token,
        )
        .is_err()
    );
    assert!(pool
        .create_account_challenge_and_outbox(
            &user.id,
            "verify_contact",
            "email",
            "already-expired@example.test",
            &linkkeys::services::verification::token_digest("already-expired-token"),
            vec![13, 14, 15],
            chrono::Utc::now() + chrono::Duration::hours(24),
            Some(&expiring_password.id),
        )
        .is_err());
    pool.replace_password(&user.id, &replacement_hash).unwrap();

    assert!(linkkeys::services::verification::revoke_verified_contact(
        &pool,
        &user.id,
        &active_contacts[0].id,
        "wrong-password",
    )
    .is_err());
    assert_eq!(pool.list_verified_contacts(&user.id).unwrap().len(), 1);
    linkkeys::services::verification::revoke_verified_contact(
        &pool,
        &user.id,
        &active_contacts[0].id,
        "replacement-password-value",
    )
    .expect("revoke verified contact");
    assert!(pool.list_verified_contacts(&user.id).unwrap().is_empty());
    assert!(pool
        .find_recovery_contact("person@example.test")
        .unwrap()
        .is_none());
    assert!(pool
        .list_active_claims(&user.id)
        .unwrap()
        .iter()
        .all(|claim| claim.claim_type != "email" && claim.claim_type != "email_verified"));
    let reset_outbox = pool
        .find_latest_notification_outbox(&user.id, "reset_password")
        .unwrap()
        .expect("reset outbox exists");
    assert_eq!(reset_outbox.state, "superseded");
    assert!(reset_outbox.encrypted_payload.is_none());
}
