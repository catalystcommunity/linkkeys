//! Generated transport-agnostic service clients from CSIL specification

#![allow(async_fn_in_trait)]

use super::client::ClientError;
use super::codec::*;
use super::types::*;

/// The caller-supplied byte carrier: it performs the call named by `(service, op)`
/// with the already-encoded request bytes and returns the response bytes, or an
/// error. The generated client owns (de)serialization via the codec; the carrier
/// only moves bytes, so it can be HTTP, a queue, or an in-process loop.
pub trait AsyncTransport {
    async fn call(&self, service: &str, op: &str, req: &[u8]) -> Result<Vec<u8>, ClientError>;
}

/// Typed client for the Ops service.
pub struct OpsAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> OpsAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// healthcheck (request/response).
    pub async fn healthcheck(&self, req: EmptyRequest) -> Result<CheckResult, ClientError> {
        let csil_resp = self
            .transport
            .call("Ops", "healthcheck", &encode_empty_request(&req))
            .await?;
        decode_check_result(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// readiness (request/response).
    pub async fn readiness(&self, req: EmptyRequest) -> Result<CheckResult, ClientError> {
        let csil_resp = self
            .transport
            .call("Ops", "readiness", &encode_empty_request(&req))
            .await?;
        decode_check_result(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the Hello service.
pub struct HelloAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> HelloAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// hello (request/response).
    pub async fn hello(&self, req: HelloRequest) -> Result<HelloResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Hello", "hello", &encode_hello_request(&req))
            .await?;
        decode_hello_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the Guestbook service.
pub struct GuestbookAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> GuestbookAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// create-entry (request/response).
    pub async fn create_entry(
        &self,
        req: CreateGuestbookRequest,
    ) -> Result<GuestbookEntry, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Guestbook",
                "create-entry",
                &encode_create_guestbook_request(&req),
            )
            .await?;
        decode_guestbook_entry(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// list-entries (request/response).
    pub async fn list_entries(
        &self,
        req: GuestbookListRequest,
    ) -> Result<GuestbookListResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Guestbook",
                "list-entries",
                &encode_guestbook_list_request(&req),
            )
            .await?;
        decode_guestbook_list_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// update-entry (request/response).
    pub async fn update_entry(
        &self,
        req: UpdateGuestbookRequest,
    ) -> Result<GuestbookEntry, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Guestbook",
                "update-entry",
                &encode_update_guestbook_request(&req),
            )
            .await?;
        decode_guestbook_entry(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// delete-entry (request/response).
    pub async fn delete_entry(
        &self,
        req: DeleteGuestbookRequest,
    ) -> Result<DeleteGuestbookResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Guestbook",
                "delete-entry",
                &encode_delete_guestbook_request(&req),
            )
            .await?;
        decode_delete_guestbook_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the DomainKeys service.
pub struct DomainKeysAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> DomainKeysAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// get-domain-keys (request/response).
    pub async fn get_domain_keys(
        &self,
        req: EmptyRequest,
    ) -> Result<GetDomainKeysResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("DomainKeys", "get-domain-keys", &encode_empty_request(&req))
            .await?;
        decode_get_domain_keys_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// get-revocations (request/response).
    pub async fn get_revocations(
        &self,
        req: GetRevocationsRequest,
    ) -> Result<GetRevocationsResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "DomainKeys",
                "get-revocations",
                &encode_get_revocations_request(&req),
            )
            .await?;
        decode_get_revocations_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the UserKeys service.
pub struct UserKeysAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> UserKeysAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// get-user-keys (request/response).
    pub async fn get_user_keys(
        &self,
        req: GetUserKeysRequest,
    ) -> Result<GetUserKeysResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "UserKeys",
                "get-user-keys",
                &encode_get_user_keys_request(&req),
            )
            .await?;
        decode_get_user_keys_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the Identity service.
pub struct IdentityAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> IdentityAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// get-user-info (request/response).
    pub async fn get_user_info(&self, req: SignedUserInfoRequest) -> Result<UserInfo, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Identity",
                "get-user-info",
                &encode_signed_user_info_request(&req),
            )
            .await?;
        decode_user_info(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the Handshake service.
pub struct HandshakeAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> HandshakeAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// handshake (request/response).
    pub async fn handshake(&self, req: HandshakeRequest) -> Result<HandshakeResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Handshake", "handshake", &encode_handshake_request(&req))
            .await?;
        decode_handshake_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the I18n service.
pub struct I18nAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> I18nAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// get-translations (request/response).
    pub async fn get_translations(
        &self,
        req: TranslationsRequest,
    ) -> Result<TranslationsResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "I18n",
                "get-translations",
                &encode_translations_request(&req),
            )
            .await?;
        decode_translations_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// list-locales (request/response).
    pub async fn list_locales(
        &self,
        req: EmptyRequest,
    ) -> Result<ListLocalesResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("I18n", "list-locales", &encode_empty_request(&req))
            .await?;
        decode_list_locales_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the Ui service.
pub struct UiAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> UiAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// get-configuration (request/response).
    pub async fn get_configuration(
        &self,
        req: EmptyRequest,
    ) -> Result<GetUiConfigurationResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Ui", "get-configuration", &encode_empty_request(&req))
            .await?;
        decode_get_ui_configuration_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the Notification service.
pub struct NotificationAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> NotificationAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// get-capabilities (request/response).
    pub async fn get_capabilities(
        &self,
        req: EmptyRequest,
    ) -> Result<GetNotificationCapabilitiesResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Notification",
                "get-capabilities",
                &encode_empty_request(&req),
            )
            .await?;
        decode_get_notification_capabilities_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the Session service.
pub struct SessionAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> SessionAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// login-password (request/response).
    pub async fn login_password(
        &self,
        req: SessionPasswordLoginRequest,
    ) -> Result<SessionPasswordLoginResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Session",
                "login-password",
                &encode_session_password_login_request(&req),
            )
            .await?;
        decode_session_password_login_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// get-current (request/response).
    pub async fn get_current(
        &self,
        req: EmptyRequest,
    ) -> Result<SessionCurrentResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Session", "get-current", &encode_empty_request(&req))
            .await?;
        decode_session_current_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// logout (request/response).
    pub async fn logout(&self, req: EmptyRequest) -> Result<SessionLogoutResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Session", "logout", &encode_empty_request(&req))
            .await?;
        decode_session_logout_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// introspect (request/response).
    pub async fn introspect(
        &self,
        req: IntrospectBrowserSessionRequest,
    ) -> Result<IntrospectBrowserSessionResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Session",
                "introspect",
                &encode_introspect_browser_session_request(&req),
            )
            .await?;
        decode_introspect_browser_session_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the Recovery service.
pub struct RecoveryAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> RecoveryAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// request-password-recovery (request/response).
    pub async fn request_password_recovery(
        &self,
        req: RequestPasswordRecoveryRequest,
    ) -> Result<RequestPasswordRecoveryResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Recovery",
                "request-password-recovery",
                &encode_request_password_recovery_request(&req),
            )
            .await?;
        decode_request_password_recovery_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// validate-password-recovery (request/response).
    pub async fn validate_password_recovery(
        &self,
        req: ValidatePasswordRecoveryRequest,
    ) -> Result<ValidatePasswordRecoveryResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Recovery",
                "validate-password-recovery",
                &encode_validate_password_recovery_request(&req),
            )
            .await?;
        decode_validate_password_recovery_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// complete-password-recovery (request/response).
    pub async fn complete_password_recovery(
        &self,
        req: CompletePasswordRecoveryRequest,
    ) -> Result<CompletePasswordRecoveryResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Recovery",
                "complete-password-recovery",
                &encode_complete_password_recovery_request(&req),
            )
            .await?;
        decode_complete_password_recovery_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the BrowserAuthorization service.
pub struct BrowserAuthorizationAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> BrowserAuthorizationAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// inspect (request/response).
    pub async fn inspect(
        &self,
        req: BrowserAuthorizationInspectRequest,
    ) -> Result<BrowserAuthorizationInspectResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "BrowserAuthorization",
                "inspect",
                &encode_browser_authorization_inspect_request(&req),
            )
            .await?;
        decode_browser_authorization_inspect_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// complete (request/response).
    pub async fn complete(
        &self,
        req: BrowserAuthorizationCompleteRequest,
    ) -> Result<BrowserAuthorizationCompleteResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "BrowserAuthorization",
                "complete",
                &encode_browser_authorization_complete_request(&req),
            )
            .await?;
        decode_browser_authorization_complete_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the Admin service.
pub struct AdminAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> AdminAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// list-users (request/response).
    pub async fn list_users(
        &self,
        req: ListUsersRequest,
    ) -> Result<ListUsersResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Admin", "list-users", &encode_list_users_request(&req))
            .await?;
        decode_list_users_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// get-user (request/response).
    pub async fn get_user(&self, req: GetUserRequest) -> Result<GetUserResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Admin", "get-user", &encode_get_user_request(&req))
            .await?;
        decode_get_user_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// create-user (request/response).
    pub async fn create_user(
        &self,
        req: CreateUserRequest,
    ) -> Result<CreateUserResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Admin", "create-user", &encode_create_user_request(&req))
            .await?;
        decode_create_user_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// update-user (request/response).
    pub async fn update_user(
        &self,
        req: UpdateUserRequest,
    ) -> Result<UpdateUserResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Admin", "update-user", &encode_update_user_request(&req))
            .await?;
        decode_update_user_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// deactivate-user (request/response).
    pub async fn deactivate_user(
        &self,
        req: DeactivateUserRequest,
    ) -> Result<DeactivateUserResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "deactivate-user",
                &encode_deactivate_user_request(&req),
            )
            .await?;
        decode_deactivate_user_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// activate-user (request/response).
    pub async fn activate_user(
        &self,
        req: ActivateUserRequest,
    ) -> Result<ActivateUserResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "activate-user",
                &encode_activate_user_request(&req),
            )
            .await?;
        decode_activate_user_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// purge-user (request/response).
    pub async fn purge_user(
        &self,
        req: PurgeUserRequest,
    ) -> Result<PurgeUserResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Admin", "purge-user", &encode_purge_user_request(&req))
            .await?;
        decode_purge_user_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// revoke-domain-key (request/response).
    pub async fn revoke_domain_key(
        &self,
        req: RevokeDomainKeyRequest,
    ) -> Result<RevokeDomainKeyResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "revoke-domain-key",
                &encode_revoke_domain_key_request(&req),
            )
            .await?;
        decode_revoke_domain_key_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// reset-password (request/response).
    pub async fn reset_password(
        &self,
        req: ResetPasswordRequest,
    ) -> Result<ResetPasswordResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "reset-password",
                &encode_reset_password_request(&req),
            )
            .await?;
        decode_reset_password_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// authenticate (request/response).
    pub async fn authenticate(
        &self,
        req: AuthenticateRequest,
    ) -> Result<AuthenticateResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Admin", "authenticate", &encode_authenticate_request(&req))
            .await?;
        decode_authenticate_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// remove-credential (request/response).
    pub async fn remove_credential(
        &self,
        req: RemoveCredentialRequest,
    ) -> Result<RemoveCredentialResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "remove-credential",
                &encode_remove_credential_request(&req),
            )
            .await?;
        decode_remove_credential_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// set-claim (request/response).
    pub async fn set_claim(&self, req: SetClaimRequest) -> Result<SetClaimResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Admin", "set-claim", &encode_set_claim_request(&req))
            .await?;
        decode_set_claim_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// remove-claim (request/response).
    pub async fn remove_claim(
        &self,
        req: RemoveClaimRequest,
    ) -> Result<RemoveClaimResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Admin", "remove-claim", &encode_remove_claim_request(&req))
            .await?;
        decode_remove_claim_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// list-user-claims (request/response).
    pub async fn list_user_claims(
        &self,
        req: ListUserClaimsRequest,
    ) -> Result<ListUserClaimsResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "list-user-claims",
                &encode_list_user_claims_request(&req),
            )
            .await?;
        decode_list_user_claims_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// get-user-claims (request/response).
    pub async fn get_user_claims(
        &self,
        req: AdminUserClaimsRequest,
    ) -> Result<AdminUserClaimsResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "get-user-claims",
                &encode_admin_user_claims_request(&req),
            )
            .await?;
        decode_admin_user_claims_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// set-user-claim (request/response).
    pub async fn set_user_claim(
        &self,
        req: SetUserClaimRequest,
    ) -> Result<SetUserClaimResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "set-user-claim",
                &encode_set_user_claim_request(&req),
            )
            .await?;
        decode_set_user_claim_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// list-settable-policies (request/response).
    pub async fn list_settable_policies(
        &self,
        req: EmptyRequest,
    ) -> Result<ListSettablePoliciesResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "list-settable-policies",
                &encode_empty_request(&req),
            )
            .await?;
        decode_list_settable_policies_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// list-claim-types (request/response).
    pub async fn list_claim_types(
        &self,
        req: EmptyRequest,
    ) -> Result<ListClaimTypesResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Admin", "list-claim-types", &encode_empty_request(&req))
            .await?;
        decode_list_claim_types_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// set-claim-type (request/response).
    pub async fn set_claim_type(
        &self,
        req: SetClaimTypeRequest,
    ) -> Result<SetClaimTypeResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "set-claim-type",
                &encode_set_claim_type_request(&req),
            )
            .await?;
        decode_set_claim_type_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// remove-claim-type (request/response).
    pub async fn remove_claim_type(
        &self,
        req: RemoveClaimTypeRequest,
    ) -> Result<RemoveClaimTypeResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "remove-claim-type",
                &encode_remove_claim_type_request(&req),
            )
            .await?;
        decode_remove_claim_type_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// set-claim-type-label (request/response).
    pub async fn set_claim_type_label(
        &self,
        req: SetClaimTypeLabelRequest,
    ) -> Result<SetClaimTypeLabelResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "set-claim-type-label",
                &encode_set_claim_type_label_request(&req),
            )
            .await?;
        decode_set_claim_type_label_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// remove-claim-type-label (request/response).
    pub async fn remove_claim_type_label(
        &self,
        req: RemoveClaimTypeLabelRequest,
    ) -> Result<RemoveClaimTypeLabelResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "remove-claim-type-label",
                &encode_remove_claim_type_label_request(&req),
            )
            .await?;
        decode_remove_claim_type_label_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// list-trusted-issuers (request/response).
    pub async fn list_trusted_issuers(
        &self,
        req: EmptyRequest,
    ) -> Result<ListTrustedIssuersResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Admin", "list-trusted-issuers", &encode_empty_request(&req))
            .await?;
        decode_list_trusted_issuers_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// add-trusted-issuer (request/response).
    pub async fn add_trusted_issuer(
        &self,
        req: AddTrustedIssuerRequest,
    ) -> Result<AddTrustedIssuerResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "add-trusted-issuer",
                &encode_add_trusted_issuer_request(&req),
            )
            .await?;
        decode_add_trusted_issuer_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// remove-trusted-issuer (request/response).
    pub async fn remove_trusted_issuer(
        &self,
        req: RemoveTrustedIssuerRequest,
    ) -> Result<RemoveTrustedIssuerResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "remove-trusted-issuer",
                &encode_remove_trusted_issuer_request(&req),
            )
            .await?;
        decode_remove_trusted_issuer_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// list-release-rules (request/response).
    pub async fn list_release_rules(
        &self,
        req: EmptyRequest,
    ) -> Result<ListReleaseRulesResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Admin", "list-release-rules", &encode_empty_request(&req))
            .await?;
        decode_list_release_rules_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// set-release-rule (request/response).
    pub async fn set_release_rule(
        &self,
        req: SetReleaseRuleRequest,
    ) -> Result<SetReleaseRuleResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "set-release-rule",
                &encode_set_release_rule_request(&req),
            )
            .await?;
        decode_set_release_rule_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// remove-release-rule (request/response).
    pub async fn remove_release_rule(
        &self,
        req: RemoveReleaseRuleRequest,
    ) -> Result<RemoveReleaseRuleResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "remove-release-rule",
                &encode_remove_release_rule_request(&req),
            )
            .await?;
        decode_remove_release_rule_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// list-pending-claim-approvals (request/response).
    pub async fn list_pending_claim_approvals(
        &self,
        req: EmptyRequest,
    ) -> Result<ListPendingClaimApprovalsResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "list-pending-claim-approvals",
                &encode_empty_request(&req),
            )
            .await?;
        decode_list_pending_claim_approvals_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// approve-claim (request/response).
    pub async fn approve_claim(
        &self,
        req: ApproveClaimRequest,
    ) -> Result<ApproveClaimResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "approve-claim",
                &encode_approve_claim_request(&req),
            )
            .await?;
        decode_approve_claim_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// reject-claim (request/response).
    pub async fn reject_claim(
        &self,
        req: RejectClaimRequest,
    ) -> Result<RejectClaimResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Admin", "reject-claim", &encode_reject_claim_request(&req))
            .await?;
        decode_reject_claim_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// admin-issue-attestation (request/response).
    pub async fn admin_issue_attestation(
        &self,
        req: AdminIssueAttestationRequest,
    ) -> Result<AdminIssueAttestationResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "admin-issue-attestation",
                &encode_admin_issue_attestation_request(&req),
            )
            .await?;
        decode_admin_issue_attestation_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// grant-relation (request/response).
    pub async fn grant_relation(
        &self,
        req: GrantRelationRequest,
    ) -> Result<GrantRelationResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "grant-relation",
                &encode_grant_relation_request(&req),
            )
            .await?;
        decode_grant_relation_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// remove-relation (request/response).
    pub async fn remove_relation(
        &self,
        req: RemoveRelationRequest,
    ) -> Result<RemoveRelationResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "remove-relation",
                &encode_remove_relation_request(&req),
            )
            .await?;
        decode_remove_relation_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// list-relations (request/response).
    pub async fn list_relations(
        &self,
        req: ListRelationsRequest,
    ) -> Result<ListRelationsResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "list-relations",
                &encode_list_relations_request(&req),
            )
            .await?;
        decode_list_relations_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// check-permission (request/response).
    pub async fn check_permission(
        &self,
        req: CheckPermissionRequest,
    ) -> Result<CheckPermissionResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "check-permission",
                &encode_check_permission_request(&req),
            )
            .await?;
        decode_check_permission_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// recheck-pins (request/response).
    pub async fn recheck_pins(
        &self,
        req: RecheckPinsRequest,
    ) -> Result<RecheckPinsResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Admin", "recheck-pins", &encode_recheck_pins_request(&req))
            .await?;
        decode_recheck_pins_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// list-local-rps (request/response).
    pub async fn list_local_rps(
        &self,
        req: ListLocalRpsRequest,
    ) -> Result<ListLocalRpsResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "list-local-rps",
                &encode_list_local_rps_request(&req),
            )
            .await?;
        decode_list_local_rps_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// get-local-rp (request/response).
    pub async fn get_local_rp(
        &self,
        req: GetLocalRpRequest,
    ) -> Result<GetLocalRpResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Admin", "get-local-rp", &encode_get_local_rp_request(&req))
            .await?;
        decode_get_local_rp_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// approve-local-rp (request/response).
    pub async fn approve_local_rp(
        &self,
        req: ApproveLocalRpRequest,
    ) -> Result<ApproveLocalRpResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "approve-local-rp",
                &encode_approve_local_rp_request(&req),
            )
            .await?;
        decode_approve_local_rp_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// deny-local-rp (request/response).
    pub async fn deny_local_rp(
        &self,
        req: DenyLocalRpRequest,
    ) -> Result<DenyLocalRpResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "deny-local-rp",
                &encode_deny_local_rp_request(&req),
            )
            .await?;
        decode_deny_local_rp_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// revoke-local-rp (request/response).
    pub async fn revoke_local_rp(
        &self,
        req: RevokeLocalRpRequest,
    ) -> Result<RevokeLocalRpResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "revoke-local-rp",
                &encode_revoke_local_rp_request(&req),
            )
            .await?;
        decode_revoke_local_rp_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// get-local-rp-policy (request/response).
    pub async fn get_local_rp_policy(
        &self,
        req: GetLocalRpPolicyRequest,
    ) -> Result<GetLocalRpPolicyResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "get-local-rp-policy",
                &encode_get_local_rp_policy_request(&req),
            )
            .await?;
        decode_get_local_rp_policy_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// set-local-rp-policy (request/response).
    pub async fn set_local_rp_policy(
        &self,
        req: SetLocalRpPolicyRequest,
    ) -> Result<SetLocalRpPolicyResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "set-local-rp-policy",
                &encode_set_local_rp_policy_request(&req),
            )
            .await?;
        decode_set_local_rp_policy_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// purge-local-rp-tickets (request/response).
    pub async fn purge_local_rp_tickets(
        &self,
        req: PurgeLocalRpTicketsRequest,
    ) -> Result<PurgeLocalRpTicketsResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Admin",
                "purge-local-rp-tickets",
                &encode_purge_local_rp_tickets_request(&req),
            )
            .await?;
        decode_purge_local_rp_tickets_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the Account service.
pub struct AccountAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> AccountAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// change-password (request/response).
    pub async fn change_password(
        &self,
        req: ChangePasswordRequest,
    ) -> Result<ChangePasswordResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Account",
                "change-password",
                &encode_change_password_request(&req),
            )
            .await?;
        decode_change_password_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// get-my-info (request/response).
    pub async fn get_my_info(&self, req: EmptyRequest) -> Result<GetMyInfoResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Account", "get-my-info", &encode_empty_request(&req))
            .await?;
        decode_get_my_info_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// list-settable-policies (request/response).
    pub async fn list_settable_policies(
        &self,
        req: EmptyRequest,
    ) -> Result<ListSettablePoliciesResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Account",
                "list-settable-policies",
                &encode_empty_request(&req),
            )
            .await?;
        decode_list_settable_policies_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// set-my-claim (request/response).
    pub async fn set_my_claim(
        &self,
        req: SetMyClaimRequest,
    ) -> Result<SetMyClaimResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Account",
                "set-my-claim",
                &encode_set_my_claim_request(&req),
            )
            .await?;
        decode_set_my_claim_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// remove-my-claim (request/response).
    pub async fn remove_my_claim(
        &self,
        req: RemoveMyClaimRequest,
    ) -> Result<RemoveMyClaimResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Account",
                "remove-my-claim",
                &encode_remove_my_claim_request(&req),
            )
            .await?;
        decode_remove_my_claim_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// set-my-claim-sharing (request/response).
    pub async fn set_my_claim_sharing(
        &self,
        req: SetMyClaimSharingRequest,
    ) -> Result<SetMyClaimSharingResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Account",
                "set-my-claim-sharing",
                &encode_set_my_claim_sharing_request(&req),
            )
            .await?;
        decode_set_my_claim_sharing_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// create-profile (request/response).
    pub async fn create_profile(
        &self,
        req: CreateProfileRequest,
    ) -> Result<CreateProfileResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Account",
                "create-profile",
                &encode_create_profile_request(&req),
            )
            .await?;
        decode_create_profile_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// request-verification (request/response).
    pub async fn request_verification(
        &self,
        req: RequestVerificationRequest,
    ) -> Result<RequestVerificationResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Account",
                "request-verification",
                &encode_request_verification_request(&req),
            )
            .await?;
        decode_request_verification_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// list-verified-contact-methods (request/response).
    pub async fn list_verified_contact_methods(
        &self,
        req: EmptyRequest,
    ) -> Result<ListVerifiedContactMethodsResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Account",
                "list-verified-contact-methods",
                &encode_empty_request(&req),
            )
            .await?;
        decode_list_verified_contact_methods_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// revoke-verified-contact-method (request/response).
    pub async fn revoke_verified_contact_method(
        &self,
        req: RevokeVerifiedContactMethodRequest,
    ) -> Result<RevokeVerifiedContactMethodResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Account",
                "revoke-verified-contact-method",
                &encode_revoke_verified_contact_method_request(&req),
            )
            .await?;
        decode_revoke_verified_contact_method_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// request-contact-verification (request/response).
    pub async fn request_contact_verification(
        &self,
        req: RequestContactVerificationRequest,
    ) -> Result<RequestContactVerificationResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Account",
                "request-contact-verification",
                &encode_request_contact_verification_request(&req),
            )
            .await?;
        decode_request_contact_verification_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// confirm-contact-verification (request/response).
    pub async fn confirm_contact_verification(
        &self,
        req: ConfirmContactVerificationRequest,
    ) -> Result<ConfirmContactVerificationResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Account",
                "confirm-contact-verification",
                &encode_confirm_contact_verification_request(&req),
            )
            .await?;
        decode_confirm_contact_verification_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the Attestation service.
pub struct AttestationAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> AttestationAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// deposit-claim (request/response).
    pub async fn deposit_claim(
        &self,
        req: DepositClaimRequest,
    ) -> Result<DepositClaimResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Attestation",
                "deposit-claim",
                &encode_deposit_claim_request(&req),
            )
            .await?;
        decode_deposit_claim_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the Rp service.
pub struct RpAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> RpAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// sign-request (request/response).
    pub async fn sign_request(&self, req: RpSignRequest) -> Result<RpSignResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Rp", "sign-request", &encode_rp_sign_request(&req))
            .await?;
        decode_rp_sign_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// decrypt-token (request/response).
    pub async fn decrypt_token(
        &self,
        req: RpDecryptRequest,
    ) -> Result<RpDecryptResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Rp", "decrypt-token", &encode_rp_decrypt_request(&req))
            .await?;
        decode_rp_decrypt_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// verify-assertion (request/response).
    pub async fn verify_assertion(
        &self,
        req: RpVerifyRequest,
    ) -> Result<RpVerifyResponse, ClientError> {
        let csil_resp = self
            .transport
            .call("Rp", "verify-assertion", &encode_rp_verify_request(&req))
            .await?;
        decode_rp_verify_response(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// userinfo-fetch (request/response).
    pub async fn userinfo_fetch(&self, req: RpUserInfoRequest) -> Result<UserInfo, ClientError> {
        let csil_resp = self
            .transport
            .call("Rp", "userinfo-fetch", &encode_rp_user_info_request(&req))
            .await?;
        decode_user_info(&csil_resp).map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// issue-attestation (request/response).
    pub async fn issue_attestation(
        &self,
        req: RpIssueAttestationRequest,
    ) -> Result<RpIssueAttestationResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "Rp",
                "issue-attestation",
                &encode_rp_issue_attestation_request(&req),
            )
            .await?;
        decode_rp_issue_attestation_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }
}

/// Typed client for the LocalRp service.
pub struct LocalRpAsyncClient<T: AsyncTransport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: AsyncTransport> LocalRpAsyncClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// redeem-claim-ticket (request/response).
    pub async fn redeem_claim_ticket(
        &self,
        req: SignedLocalRpTicketRedemptionRequest,
    ) -> Result<LocalRpTicketRedemptionResponse, ClientError> {
        let csil_resp = self
            .transport
            .call(
                "LocalRp",
                "redeem-claim-ticket",
                &encode_signed_local_rp_ticket_redemption_request(&req),
            )
            .await?;
        decode_local_rp_ticket_redemption_response(&csil_resp)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }
}
