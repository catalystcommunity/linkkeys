use liblinkkeys::generated::{self, types::*};

#[test]
fn ui_configuration_round_trips_through_generated_codec() {
    let config = GetUiConfigurationResponse {
        host_api_version: 1,
        domain: "id.example".to_string(),
        public_origin: Some("https://id.example".to_string()),
        capabilities: vec![
            "password_login".to_string(),
            "runtime_extensions".to_string(),
        ],
        display: UiDisplaySettings {
            site_name: "Example LinkKeys".to_string(),
            support_url: Some("https://help.example/linkkeys".to_string()),
        },
        theme: Some(UiTheme {
            stylesheet_url: Some("/_linkkeys/themes/example/theme.css".to_string()),
            logo_url: Some("/_linkkeys/themes/example/logo.svg".to_string()),
            favicon_url: None,
        }),
        extensions: vec![UiExtension {
            id: "catalyst".to_string(),
            module_url: "/_linkkeys/extensions/catalyst/extension.js".to_string(),
            api_version: 1,
            stylesheet_url: Some("/_linkkeys/extensions/catalyst/extension.css".to_string()),
        }],
        password_policy: Some(PasswordPolicy {
            min_length: 12,
            max_length: 1024,
        }),
    };

    let encoded = generated::encode_get_ui_configuration_response(&config);
    let decoded = generated::decode_get_ui_configuration_response(&encoded)
        .expect("decode generated UI configuration");

    assert_eq!(decoded, config);
}

#[test]
fn notification_capabilities_round_trip_through_generated_codec() {
    let capabilities = GetNotificationCapabilitiesResponse {
        capabilities: vec![
            NotificationCapability {
                purpose: "verify_contact".to_string(),
                channel: "email".to_string(),
                destination_kind: "email_address".to_string(),
            },
            NotificationCapability {
                purpose: "reset_password".to_string(),
                channel: "email".to_string(),
                destination_kind: "email_address".to_string(),
            },
        ],
    };

    let encoded = generated::encode_get_notification_capabilities_response(&capabilities);
    let decoded = generated::decode_get_notification_capabilities_response(&encoded)
        .expect("decode generated notification capabilities");

    assert_eq!(decoded, capabilities);
}

#[test]
fn secret_bearing_request_codecs_round_trip() {
    let login = SessionPasswordLoginRequest {
        username: "alice".to_string(),
        password: "correct horse battery staple".to_string(),
    };
    let encoded = generated::encode_session_password_login_request(&login);
    assert_eq!(
        generated::decode_session_password_login_request(&encoded).expect("decode login request"),
        login
    );

    let confirm = ConfirmContactVerificationRequest {
        token: "verification-secret".to_string(),
    };
    let encoded = generated::encode_confirm_contact_verification_request(&confirm);
    assert_eq!(
        generated::decode_confirm_contact_verification_request(&encoded)
            .expect("decode contact verification request"),
        confirm
    );

    let recovery = CompletePasswordRecoveryRequest {
        token: "recovery-secret".to_string(),
        new_password: "new correct horse battery staple".to_string(),
    };
    let encoded = generated::encode_complete_password_recovery_request(&recovery);
    assert_eq!(
        generated::decode_complete_password_recovery_request(&encoded)
            .expect("decode password recovery request"),
        recovery
    );

    let revoke = RevokeVerifiedContactMethodRequest {
        contact_method_id: "contact-id".to_string(),
        current_password: "correct horse battery staple".to_string(),
    };
    let encoded = generated::encode_revoke_verified_contact_method_request(&revoke);
    assert_eq!(
        generated::decode_revoke_verified_contact_method_request(&encoded)
            .expect("decode contact revocation request"),
        revoke
    );
}
