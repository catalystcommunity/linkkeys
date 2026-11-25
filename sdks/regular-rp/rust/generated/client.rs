//! Generated transport-agnostic service clients from CSIL specification

use super::codec::*;
use super::types::*;

/// Error from a generated client call: a structured error the service returned,
/// or a transport-level failure. The caller-supplied `Transport` decides how an
/// error response maps onto `Service`. `Encode` means the request has no valid
/// wire form, so the client did not call the transport.
#[derive(Debug, Clone)]
pub enum ClientError {
    Service { code: i64, message: String },
    Transport(String),
    Encode(String),
    ApplicationRpError(Box<RpError>),
    Decode(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Service { code, message } => write!(f, "service error {code}: {message}"),
            Self::Encode(msg) => write!(f, "invalid request: {msg}"),
            Self::ApplicationRpError(e) => write!(f, "application error: {e:?}"),
            Self::Decode(msg) => write!(f, "invalid reply: {msg}"),
            ClientError::Transport(msg) => write!(f, "transport error: {msg}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// A status-zero CSIL-RPC reply: `variant` names the declared output arm that
/// `payload` encodes. A transport returns it from `call_reply`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireReply {
    pub variant: Option<String>,
    pub payload: Vec<u8>,
}

/// The caller-supplied byte carrier: it performs the call named by `(service, op)`
/// with the already-encoded request bytes and returns the response bytes, or an
/// error. The generated client owns (de)serialization via the codec; the carrier
/// only moves bytes, so it can be HTTP, a queue, or an in-process loop.
pub trait Transport {
    fn call(&self, service: &str, op: &str, req: &[u8]) -> Result<Vec<u8>, ClientError>;

    /// Perform a call whose operation declares several reply arms and return
    /// the status-zero reply `variant` with its payload, so the client can
    /// return the success arm or the declared error arm.
    fn call_reply(&self, service: &str, op: &str, req: &[u8]) -> Result<WireReply, ClientError>;
}
impl From<CsilCborError> for ClientError {
    fn from(error: CsilCborError) -> Self {
        Self::Decode(error.0)
    }
}

/// Resolve a status-zero RPC reply into its success payload or its declared error
/// arm. Generated clients call it with the reply from `Transport::call_reply`.
pub fn resolve_rpc_reply(
    service: &str,
    op: &str,
    variant: Option<&str>,
    payload: Vec<u8>,
) -> Result<Vec<u8>, ClientError> {
    match (service, op) {
        ("Rp", "sign-request") => match variant {
            Some("RpSignResponse") => Ok(payload),
            Some("RpError") => {
                let value = decode_rp_error(&payload)?;
                let value = Box::new(value);
                let error = ClientError::ApplicationRpError(value);
                Err(error)
            }
            _ => Err(ClientError::Decode(format!(
                "invalid reply variant {variant:?}"
            ))),
        },
        ("Rp", "decrypt-token") => match variant {
            Some("RpDecryptResponse") => Ok(payload),
            Some("RpError") => {
                let value = decode_rp_error(&payload)?;
                let value = Box::new(value);
                let error = ClientError::ApplicationRpError(value);
                Err(error)
            }
            _ => Err(ClientError::Decode(format!(
                "invalid reply variant {variant:?}"
            ))),
        },
        ("Rp", "verify-assertion") => match variant {
            Some("RpVerifyResponse") => Ok(payload),
            Some("RpError") => {
                let value = decode_rp_error(&payload)?;
                let value = Box::new(value);
                let error = ClientError::ApplicationRpError(value);
                Err(error)
            }
            _ => Err(ClientError::Decode(format!(
                "invalid reply variant {variant:?}"
            ))),
        },
        ("Rp", "userinfo-fetch") => match variant {
            Some("UserInfo") => Ok(payload),
            Some("RpError") => {
                let value = decode_rp_error(&payload)?;
                let value = Box::new(value);
                let error = ClientError::ApplicationRpError(value);
                Err(error)
            }
            _ => Err(ClientError::Decode(format!(
                "invalid reply variant {variant:?}"
            ))),
        },
        _ => Ok(payload),
    }
}

/// Typed client for the Ops service.
pub struct OpsClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> OpsClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// healthcheck (request/response).
    pub fn healthcheck(&self, req: EmptyRequest) -> Result<CheckResult, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Ops", "healthcheck", &csil_req)?;
        decode_check_result(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// readiness (request/response).
    pub fn readiness(&self, req: EmptyRequest) -> Result<CheckResult, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Ops", "readiness", &csil_req)?;
        decode_check_result(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the Hello service.
pub struct HelloClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> HelloClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// hello (request/response).
    pub fn hello(&self, req: HelloRequest) -> Result<HelloResponse, ClientError> {
        let csil_req = match encode_hello_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Hello", "hello", &csil_req)?;
        decode_hello_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the Guestbook service.
pub struct GuestbookClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> GuestbookClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// create-entry (request/response).
    pub fn create_entry(&self, req: CreateGuestbookRequest) -> Result<GuestbookEntry, ClientError> {
        let csil_req = match encode_create_guestbook_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Guestbook", "create-entry", &csil_req)?;
        decode_guestbook_entry(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// list-entries (request/response).
    pub fn list_entries(
        &self,
        req: GuestbookListRequest,
    ) -> Result<GuestbookListResponse, ClientError> {
        let csil_req = match encode_guestbook_list_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Guestbook", "list-entries", &csil_req)?;
        decode_guestbook_list_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// update-entry (request/response).
    pub fn update_entry(&self, req: UpdateGuestbookRequest) -> Result<GuestbookEntry, ClientError> {
        let csil_req = match encode_update_guestbook_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Guestbook", "update-entry", &csil_req)?;
        decode_guestbook_entry(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// delete-entry (request/response).
    pub fn delete_entry(
        &self,
        req: DeleteGuestbookRequest,
    ) -> Result<DeleteGuestbookResponse, ClientError> {
        let csil_req = match encode_delete_guestbook_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Guestbook", "delete-entry", &csil_req)?;
        decode_delete_guestbook_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the DomainKeys service.
pub struct DomainKeysClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> DomainKeysClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// get-domain-keys (request/response).
    pub fn get_domain_keys(&self, req: EmptyRequest) -> Result<GetDomainKeysResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("DomainKeys", "get-domain-keys", &csil_req)?;
        decode_get_domain_keys_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// get-revocations (request/response).
    pub fn get_revocations(
        &self,
        req: GetRevocationsRequest,
    ) -> Result<GetRevocationsResponse, ClientError> {
        let csil_req = match encode_get_revocations_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("DomainKeys", "get-revocations", &csil_req)?;
        decode_get_revocations_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the UserKeys service.
pub struct UserKeysClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> UserKeysClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// get-user-keys (request/response).
    pub fn get_user_keys(
        &self,
        req: GetUserKeysRequest,
    ) -> Result<GetUserKeysResponse, ClientError> {
        let csil_req = match encode_get_user_keys_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("UserKeys", "get-user-keys", &csil_req)?;
        decode_get_user_keys_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the ApplicationKeys service.
pub struct ApplicationKeysClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> ApplicationKeysClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// get-application-keys (request/response).
    pub fn get_application_keys(
        &self,
        req: GetApplicationKeysRequest,
    ) -> Result<GetApplicationKeysResponse, ClientError> {
        let csil_req = match encode_get_application_keys_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp =
            self.transport
                .call("ApplicationKeys", "get-application-keys", &csil_req)?;
        decode_get_application_keys_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// start-key-challenge (request/response).
    pub fn start_key_challenge(
        &self,
        req: StartApplicationKeyChallengeRequest,
    ) -> Result<StartApplicationKeyChallengeResponse, ClientError> {
        let csil_req = match encode_start_application_key_challenge_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("ApplicationKeys", "start-key-challenge", &csil_req)?;
        decode_start_application_key_challenge_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// add-key (request/response).
    pub fn add_key(
        &self,
        req: AddApplicationKeyRequest,
    ) -> Result<AddApplicationKeyResponse, ClientError> {
        let csil_req = match encode_add_application_key_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("ApplicationKeys", "add-key", &csil_req)?;
        decode_add_application_key_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// renew-attestation (request/response).
    pub fn renew_attestation(
        &self,
        req: RenewApplicationKeyAttestationRequest,
    ) -> Result<RenewApplicationKeyAttestationResponse, ClientError> {
        let csil_req = match encode_renew_application_key_attestation_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("ApplicationKeys", "renew-attestation", &csil_req)?;
        decode_renew_application_key_attestation_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// revoke-key (request/response).
    pub fn revoke_key(
        &self,
        req: RevokeApplicationKeyRequest,
    ) -> Result<RevokeApplicationKeyResponse, ClientError> {
        let csil_req = match encode_revoke_application_key_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("ApplicationKeys", "revoke-key", &csil_req)?;
        decode_revoke_application_key_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the Identity service.
pub struct IdentityClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> IdentityClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// get-user-info (request/response).
    pub fn get_user_info(&self, req: SignedUserInfoRequest) -> Result<UserInfo, ClientError> {
        let csil_req = match encode_signed_user_info_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Identity", "get-user-info", &csil_req)?;
        decode_user_info(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the Handshake service.
pub struct HandshakeClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> HandshakeClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// handshake (request/response).
    pub fn handshake(&self, req: HandshakeRequest) -> Result<HandshakeResponse, ClientError> {
        let csil_req = match encode_handshake_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Handshake", "handshake", &csil_req)?;
        decode_handshake_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the I18n service.
pub struct I18nClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> I18nClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// get-translations (request/response).
    pub fn get_translations(
        &self,
        req: TranslationsRequest,
    ) -> Result<TranslationsResponse, ClientError> {
        let csil_req = match encode_translations_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("I18n", "get-translations", &csil_req)?;
        decode_translations_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// list-locales (request/response).
    pub fn list_locales(&self, req: EmptyRequest) -> Result<ListLocalesResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("I18n", "list-locales", &csil_req)?;
        decode_list_locales_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the Ui service.
pub struct UiClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> UiClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// get-configuration (request/response).
    pub fn get_configuration(
        &self,
        req: EmptyRequest,
    ) -> Result<GetUiConfigurationResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Ui", "get-configuration", &csil_req)?;
        decode_get_ui_configuration_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the Notification service.
pub struct NotificationClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> NotificationClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// get-capabilities (request/response).
    pub fn get_capabilities(
        &self,
        req: EmptyRequest,
    ) -> Result<GetNotificationCapabilitiesResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Notification", "get-capabilities", &csil_req)?;
        decode_get_notification_capabilities_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the Session service.
pub struct SessionClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> SessionClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// login-password (request/response).
    pub fn login_password(
        &self,
        req: SessionPasswordLoginRequest,
    ) -> Result<SessionPasswordLoginResponse, ClientError> {
        let csil_req = match encode_session_password_login_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Session", "login-password", &csil_req)?;
        decode_session_password_login_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// get-current (request/response).
    pub fn get_current(&self, req: EmptyRequest) -> Result<SessionCurrentResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Session", "get-current", &csil_req)?;
        decode_session_current_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// logout (request/response).
    pub fn logout(&self, req: EmptyRequest) -> Result<SessionLogoutResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Session", "logout", &csil_req)?;
        decode_session_logout_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// introspect (request/response).
    pub fn introspect(
        &self,
        req: IntrospectBrowserSessionRequest,
    ) -> Result<IntrospectBrowserSessionResponse, ClientError> {
        let csil_req = match encode_introspect_browser_session_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Session", "introspect", &csil_req)?;
        decode_introspect_browser_session_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the Recovery service.
pub struct RecoveryClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> RecoveryClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// request-password-recovery (request/response).
    pub fn request_password_recovery(
        &self,
        req: RequestPasswordRecoveryRequest,
    ) -> Result<RequestPasswordRecoveryResponse, ClientError> {
        let csil_req = match encode_request_password_recovery_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Recovery", "request-password-recovery", &csil_req)?;
        decode_request_password_recovery_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// validate-password-recovery (request/response).
    pub fn validate_password_recovery(
        &self,
        req: ValidatePasswordRecoveryRequest,
    ) -> Result<ValidatePasswordRecoveryResponse, ClientError> {
        let csil_req = match encode_validate_password_recovery_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Recovery", "validate-password-recovery", &csil_req)?;
        decode_validate_password_recovery_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// complete-password-recovery (request/response).
    pub fn complete_password_recovery(
        &self,
        req: CompletePasswordRecoveryRequest,
    ) -> Result<CompletePasswordRecoveryResponse, ClientError> {
        let csil_req = match encode_complete_password_recovery_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Recovery", "complete-password-recovery", &csil_req)?;
        decode_complete_password_recovery_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the BrowserAuthorization service.
pub struct BrowserAuthorizationClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> BrowserAuthorizationClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// inspect (request/response).
    pub fn inspect(
        &self,
        req: BrowserAuthorizationInspectRequest,
    ) -> Result<BrowserAuthorizationInspectResponse, ClientError> {
        let csil_req = match encode_browser_authorization_inspect_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("BrowserAuthorization", "inspect", &csil_req)?;
        decode_browser_authorization_inspect_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// complete (request/response).
    pub fn complete(
        &self,
        req: BrowserAuthorizationCompleteRequest,
    ) -> Result<BrowserAuthorizationCompleteResponse, ClientError> {
        let csil_req = match encode_browser_authorization_complete_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("BrowserAuthorization", "complete", &csil_req)?;
        decode_browser_authorization_complete_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// inspect-act-as (request/response).
    pub fn inspect_act_as(
        &self,
        req: BrowserActAsInspectRequest,
    ) -> Result<BrowserActAsInspectResponse, ClientError> {
        let csil_req = match encode_browser_act_as_inspect_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("BrowserAuthorization", "inspect-act-as", &csil_req)?;
        decode_browser_act_as_inspect_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// complete-act-as (request/response).
    pub fn complete_act_as(
        &self,
        req: BrowserActAsCompleteRequest,
    ) -> Result<BrowserActAsCompleteResponse, ClientError> {
        let csil_req = match encode_browser_act_as_complete_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp =
            self.transport
                .call("BrowserAuthorization", "complete-act-as", &csil_req)?;
        decode_browser_act_as_complete_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// inspect-local-rp (request/response).
    pub fn inspect_local_rp(
        &self,
        req: BrowserLocalRpInspectRequest,
    ) -> Result<BrowserLocalRpInspectResponse, ClientError> {
        let csil_req = match encode_browser_local_rp_inspect_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp =
            self.transport
                .call("BrowserAuthorization", "inspect-local-rp", &csil_req)?;
        decode_browser_local_rp_inspect_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// complete-local-rp (request/response).
    pub fn complete_local_rp(
        &self,
        req: BrowserLocalRpCompleteRequest,
    ) -> Result<BrowserLocalRpCompleteResponse, ClientError> {
        let csil_req = match encode_browser_local_rp_complete_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp =
            self.transport
                .call("BrowserAuthorization", "complete-local-rp", &csil_req)?;
        decode_browser_local_rp_complete_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the BrowserIssuer service.
pub struct BrowserIssuerClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> BrowserIssuerClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// inspect-signing-request (request/response).
    pub fn inspect_signing_request(
        &self,
        req: InspectSigningRequestRequest,
    ) -> Result<InspectSigningRequestResponse, ClientError> {
        let csil_req = match encode_inspect_signing_request_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp =
            self.transport
                .call("BrowserIssuer", "inspect-signing-request", &csil_req)?;
        decode_inspect_signing_request_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// issue-for-signing-request (request/response).
    pub fn issue_for_signing_request(
        &self,
        req: IssueForSigningRequestRequest,
    ) -> Result<IssueForSigningRequestResponse, ClientError> {
        let csil_req = match encode_issue_for_signing_request_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp =
            self.transport
                .call("BrowserIssuer", "issue-for-signing-request", &csil_req)?;
        decode_issue_for_signing_request_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the Admin service.
pub struct AdminClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> AdminClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// list-users (request/response).
    pub fn list_users(&self, req: ListUsersRequest) -> Result<ListUsersResponse, ClientError> {
        let csil_req = match encode_list_users_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "list-users", &csil_req)?;
        decode_list_users_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// get-user (request/response).
    pub fn get_user(&self, req: GetUserRequest) -> Result<GetUserResponse, ClientError> {
        let csil_req = match encode_get_user_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "get-user", &csil_req)?;
        decode_get_user_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// get-user-authentication-activity (request/response).
    pub fn get_user_authentication_activity(
        &self,
        req: GetUserAuthenticationActivityRequest,
    ) -> Result<GetUserAuthenticationActivityResponse, ClientError> {
        let csil_req = match encode_get_user_authentication_activity_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp =
            self.transport
                .call("Admin", "get-user-authentication-activity", &csil_req)?;
        decode_get_user_authentication_activity_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// create-user (request/response).
    pub fn create_user(&self, req: CreateUserRequest) -> Result<CreateUserResponse, ClientError> {
        let csil_req = match encode_create_user_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "create-user", &csil_req)?;
        decode_create_user_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// update-user (request/response).
    pub fn update_user(&self, req: UpdateUserRequest) -> Result<UpdateUserResponse, ClientError> {
        let csil_req = match encode_update_user_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "update-user", &csil_req)?;
        decode_update_user_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// deactivate-user (request/response).
    pub fn deactivate_user(
        &self,
        req: DeactivateUserRequest,
    ) -> Result<DeactivateUserResponse, ClientError> {
        let csil_req = match encode_deactivate_user_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "deactivate-user", &csil_req)?;
        decode_deactivate_user_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// activate-user (request/response).
    pub fn activate_user(
        &self,
        req: ActivateUserRequest,
    ) -> Result<ActivateUserResponse, ClientError> {
        let csil_req = match encode_activate_user_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "activate-user", &csil_req)?;
        decode_activate_user_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// purge-user (request/response).
    pub fn purge_user(&self, req: PurgeUserRequest) -> Result<PurgeUserResponse, ClientError> {
        let csil_req = match encode_purge_user_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "purge-user", &csil_req)?;
        decode_purge_user_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// revoke-domain-key (request/response).
    pub fn revoke_domain_key(
        &self,
        req: RevokeDomainKeyRequest,
    ) -> Result<RevokeDomainKeyResponse, ClientError> {
        let csil_req = match encode_revoke_domain_key_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "revoke-domain-key", &csil_req)?;
        decode_revoke_domain_key_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// reset-password (request/response).
    pub fn reset_password(
        &self,
        req: ResetPasswordRequest,
    ) -> Result<ResetPasswordResponse, ClientError> {
        let csil_req = match encode_reset_password_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "reset-password", &csil_req)?;
        decode_reset_password_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// authenticate (request/response).
    pub fn authenticate(
        &self,
        req: AuthenticateRequest,
    ) -> Result<AuthenticateResponse, ClientError> {
        let csil_req = match encode_authenticate_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "authenticate", &csil_req)?;
        decode_authenticate_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// remove-credential (request/response).
    pub fn remove_credential(
        &self,
        req: RemoveCredentialRequest,
    ) -> Result<RemoveCredentialResponse, ClientError> {
        let csil_req = match encode_remove_credential_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "remove-credential", &csil_req)?;
        decode_remove_credential_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// set-claim (request/response).
    pub fn set_claim(&self, req: SetClaimRequest) -> Result<SetClaimResponse, ClientError> {
        let csil_req = match encode_set_claim_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "set-claim", &csil_req)?;
        decode_set_claim_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// remove-claim (request/response).
    pub fn remove_claim(
        &self,
        req: RemoveClaimRequest,
    ) -> Result<RemoveClaimResponse, ClientError> {
        let csil_req = match encode_remove_claim_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "remove-claim", &csil_req)?;
        decode_remove_claim_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// list-user-claims (request/response).
    pub fn list_user_claims(
        &self,
        req: ListUserClaimsRequest,
    ) -> Result<ListUserClaimsResponse, ClientError> {
        let csil_req = match encode_list_user_claims_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "list-user-claims", &csil_req)?;
        decode_list_user_claims_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// get-user-claims (request/response).
    pub fn get_user_claims(
        &self,
        req: AdminUserClaimsRequest,
    ) -> Result<AdminUserClaimsResponse, ClientError> {
        let csil_req = match encode_admin_user_claims_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "get-user-claims", &csil_req)?;
        decode_admin_user_claims_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// set-user-claim (request/response).
    pub fn set_user_claim(
        &self,
        req: SetUserClaimRequest,
    ) -> Result<SetUserClaimResponse, ClientError> {
        let csil_req = match encode_set_user_claim_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "set-user-claim", &csil_req)?;
        decode_set_user_claim_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// list-settable-policies (request/response).
    pub fn list_settable_policies(
        &self,
        req: EmptyRequest,
    ) -> Result<ListSettablePoliciesResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "list-settable-policies", &csil_req)?;
        decode_list_settable_policies_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// list-claim-types (request/response).
    pub fn list_claim_types(
        &self,
        req: EmptyRequest,
    ) -> Result<ListClaimTypesResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "list-claim-types", &csil_req)?;
        decode_list_claim_types_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// set-claim-type (request/response).
    pub fn set_claim_type(
        &self,
        req: SetClaimTypeRequest,
    ) -> Result<SetClaimTypeResponse, ClientError> {
        let csil_req = match encode_set_claim_type_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "set-claim-type", &csil_req)?;
        decode_set_claim_type_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// remove-claim-type (request/response).
    pub fn remove_claim_type(
        &self,
        req: RemoveClaimTypeRequest,
    ) -> Result<RemoveClaimTypeResponse, ClientError> {
        let csil_req = match encode_remove_claim_type_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "remove-claim-type", &csil_req)?;
        decode_remove_claim_type_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// list-claim-type-labels (request/response).
    pub fn list_claim_type_labels(
        &self,
        req: EmptyRequest,
    ) -> Result<ListClaimTypeLabelsResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "list-claim-type-labels", &csil_req)?;
        decode_list_claim_type_labels_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// set-claim-type-label (request/response).
    pub fn set_claim_type_label(
        &self,
        req: SetClaimTypeLabelRequest,
    ) -> Result<SetClaimTypeLabelResponse, ClientError> {
        let csil_req = match encode_set_claim_type_label_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "set-claim-type-label", &csil_req)?;
        decode_set_claim_type_label_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// remove-claim-type-label (request/response).
    pub fn remove_claim_type_label(
        &self,
        req: RemoveClaimTypeLabelRequest,
    ) -> Result<RemoveClaimTypeLabelResponse, ClientError> {
        let csil_req = match encode_remove_claim_type_label_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "remove-claim-type-label", &csil_req)?;
        decode_remove_claim_type_label_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// list-trusted-issuers (request/response).
    pub fn list_trusted_issuers(
        &self,
        req: EmptyRequest,
    ) -> Result<ListTrustedIssuersResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "list-trusted-issuers", &csil_req)?;
        decode_list_trusted_issuers_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// add-trusted-issuer (request/response).
    pub fn add_trusted_issuer(
        &self,
        req: AddTrustedIssuerRequest,
    ) -> Result<AddTrustedIssuerResponse, ClientError> {
        let csil_req = match encode_add_trusted_issuer_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "add-trusted-issuer", &csil_req)?;
        decode_add_trusted_issuer_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// remove-trusted-issuer (request/response).
    pub fn remove_trusted_issuer(
        &self,
        req: RemoveTrustedIssuerRequest,
    ) -> Result<RemoveTrustedIssuerResponse, ClientError> {
        let csil_req = match encode_remove_trusted_issuer_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "remove-trusted-issuer", &csil_req)?;
        decode_remove_trusted_issuer_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// list-release-rules (request/response).
    pub fn list_release_rules(
        &self,
        req: EmptyRequest,
    ) -> Result<ListReleaseRulesResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "list-release-rules", &csil_req)?;
        decode_list_release_rules_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// set-release-rule (request/response).
    pub fn set_release_rule(
        &self,
        req: SetReleaseRuleRequest,
    ) -> Result<SetReleaseRuleResponse, ClientError> {
        let csil_req = match encode_set_release_rule_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "set-release-rule", &csil_req)?;
        decode_set_release_rule_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// remove-release-rule (request/response).
    pub fn remove_release_rule(
        &self,
        req: RemoveReleaseRuleRequest,
    ) -> Result<RemoveReleaseRuleResponse, ClientError> {
        let csil_req = match encode_remove_release_rule_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "remove-release-rule", &csil_req)?;
        decode_remove_release_rule_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// list-pending-claim-approvals (request/response).
    pub fn list_pending_claim_approvals(
        &self,
        req: EmptyRequest,
    ) -> Result<ListPendingClaimApprovalsResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "list-pending-claim-approvals", &csil_req)?;
        decode_list_pending_claim_approvals_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// approve-claim (request/response).
    pub fn approve_claim(
        &self,
        req: ApproveClaimRequest,
    ) -> Result<ApproveClaimResponse, ClientError> {
        let csil_req = match encode_approve_claim_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "approve-claim", &csil_req)?;
        decode_approve_claim_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// reject-claim (request/response).
    pub fn reject_claim(
        &self,
        req: RejectClaimRequest,
    ) -> Result<RejectClaimResponse, ClientError> {
        let csil_req = match encode_reject_claim_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "reject-claim", &csil_req)?;
        decode_reject_claim_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// admin-issue-attestation (request/response).
    pub fn admin_issue_attestation(
        &self,
        req: AdminIssueAttestationRequest,
    ) -> Result<AdminIssueAttestationResponse, ClientError> {
        let csil_req = match encode_admin_issue_attestation_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "admin-issue-attestation", &csil_req)?;
        decode_admin_issue_attestation_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// preview-release-policy (request/response).
    pub fn preview_release_policy(
        &self,
        req: PreviewReleasePolicyRequest,
    ) -> Result<PreviewReleasePolicyResponse, ClientError> {
        let csil_req = match encode_preview_release_policy_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "preview-release-policy", &csil_req)?;
        decode_preview_release_policy_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// preview-issuer-policy (request/response).
    pub fn preview_issuer_policy(
        &self,
        req: PreviewIssuerPolicyRequest,
    ) -> Result<PreviewIssuerPolicyResponse, ClientError> {
        let csil_req = match encode_preview_issuer_policy_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "preview-issuer-policy", &csil_req)?;
        decode_preview_issuer_policy_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// grant-relation (request/response).
    pub fn grant_relation(
        &self,
        req: GrantRelationRequest,
    ) -> Result<GrantRelationResponse, ClientError> {
        let csil_req = match encode_grant_relation_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "grant-relation", &csil_req)?;
        decode_grant_relation_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// remove-relation (request/response).
    pub fn remove_relation(
        &self,
        req: RemoveRelationRequest,
    ) -> Result<RemoveRelationResponse, ClientError> {
        let csil_req = match encode_remove_relation_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "remove-relation", &csil_req)?;
        decode_remove_relation_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// list-relations (request/response).
    pub fn list_relations(
        &self,
        req: ListRelationsRequest,
    ) -> Result<ListRelationsResponse, ClientError> {
        let csil_req = match encode_list_relations_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "list-relations", &csil_req)?;
        decode_list_relations_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// check-permission (request/response).
    pub fn check_permission(
        &self,
        req: CheckPermissionRequest,
    ) -> Result<CheckPermissionResponse, ClientError> {
        let csil_req = match encode_check_permission_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "check-permission", &csil_req)?;
        decode_check_permission_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// recheck-pins (request/response).
    pub fn recheck_pins(
        &self,
        req: RecheckPinsRequest,
    ) -> Result<RecheckPinsResponse, ClientError> {
        let csil_req = match encode_recheck_pins_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "recheck-pins", &csil_req)?;
        decode_recheck_pins_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// list-local-rps (request/response).
    pub fn list_local_rps(
        &self,
        req: ListLocalRpsRequest,
    ) -> Result<ListLocalRpsResponse, ClientError> {
        let csil_req = match encode_list_local_rps_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "list-local-rps", &csil_req)?;
        decode_list_local_rps_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// get-local-rp (request/response).
    pub fn get_local_rp(&self, req: GetLocalRpRequest) -> Result<GetLocalRpResponse, ClientError> {
        let csil_req = match encode_get_local_rp_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "get-local-rp", &csil_req)?;
        decode_get_local_rp_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// approve-local-rp (request/response).
    pub fn approve_local_rp(
        &self,
        req: ApproveLocalRpRequest,
    ) -> Result<ApproveLocalRpResponse, ClientError> {
        let csil_req = match encode_approve_local_rp_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "approve-local-rp", &csil_req)?;
        decode_approve_local_rp_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// deny-local-rp (request/response).
    pub fn deny_local_rp(
        &self,
        req: DenyLocalRpRequest,
    ) -> Result<DenyLocalRpResponse, ClientError> {
        let csil_req = match encode_deny_local_rp_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "deny-local-rp", &csil_req)?;
        decode_deny_local_rp_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// revoke-local-rp (request/response).
    pub fn revoke_local_rp(
        &self,
        req: RevokeLocalRpRequest,
    ) -> Result<RevokeLocalRpResponse, ClientError> {
        let csil_req = match encode_revoke_local_rp_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "revoke-local-rp", &csil_req)?;
        decode_revoke_local_rp_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// get-local-rp-policy (request/response).
    pub fn get_local_rp_policy(
        &self,
        req: GetLocalRpPolicyRequest,
    ) -> Result<GetLocalRpPolicyResponse, ClientError> {
        let csil_req = match encode_get_local_rp_policy_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "get-local-rp-policy", &csil_req)?;
        decode_get_local_rp_policy_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// set-local-rp-policy (request/response).
    pub fn set_local_rp_policy(
        &self,
        req: SetLocalRpPolicyRequest,
    ) -> Result<SetLocalRpPolicyResponse, ClientError> {
        let csil_req = match encode_set_local_rp_policy_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "set-local-rp-policy", &csil_req)?;
        decode_set_local_rp_policy_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// purge-local-rp-tickets (request/response).
    pub fn purge_local_rp_tickets(
        &self,
        req: PurgeLocalRpTicketsRequest,
    ) -> Result<PurgeLocalRpTicketsResponse, ClientError> {
        let csil_req = match encode_purge_local_rp_tickets_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "purge-local-rp-tickets", &csil_req)?;
        decode_purge_local_rp_tickets_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// get-sign-in-policy (request/response).
    pub fn get_sign_in_policy(&self, req: EmptyRequest) -> Result<SignInPolicy, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "get-sign-in-policy", &csil_req)?;
        decode_sign_in_policy(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// set-sign-in-policy (request/response).
    pub fn set_sign_in_policy(
        &self,
        req: SetSignInPolicyRequest,
    ) -> Result<SignInPolicy, ClientError> {
        let csil_req = match encode_set_sign_in_policy_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "set-sign-in-policy", &csil_req)?;
        decode_sign_in_policy(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// set-user-password-lock (request/response).
    pub fn set_user_password_lock(
        &self,
        req: SetUserPasswordLockRequest,
    ) -> Result<SetUserPasswordLockResponse, ClientError> {
        let csil_req = match encode_set_user_password_lock_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "set-user-password-lock", &csil_req)?;
        decode_set_user_password_lock_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// list-app-access-policies (request/response).
    pub fn list_app_access_policies(
        &self,
        req: EmptyRequest,
    ) -> Result<ListAppAccessPoliciesResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "list-app-access-policies", &csil_req)?;
        decode_list_app_access_policies_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// set-app-access-policy (request/response).
    pub fn set_app_access_policy(
        &self,
        req: SetAppAccessPolicyRequest,
    ) -> Result<SetAppAccessPolicyResponse, ClientError> {
        let csil_req = match encode_set_app_access_policy_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "set-app-access-policy", &csil_req)?;
        decode_set_app_access_policy_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// remove-app-access-policy (request/response).
    pub fn remove_app_access_policy(
        &self,
        req: RemoveAppAccessPolicyRequest,
    ) -> Result<RemoveAppAccessPolicyResponse, ClientError> {
        let csil_req = match encode_remove_app_access_policy_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "remove-app-access-policy", &csil_req)?;
        decode_remove_app_access_policy_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// preview-app-access (request/response).
    pub fn preview_app_access(
        &self,
        req: PreviewAppAccessRequest,
    ) -> Result<PreviewAppAccessResponse, ClientError> {
        let csil_req = match encode_preview_app_access_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "preview-app-access", &csil_req)?;
        decode_preview_app_access_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// rename-user (request/response).
    pub fn rename_user(&self, req: RenameUserRequest) -> Result<RenameUserResponse, ClientError> {
        let csil_req = match encode_rename_user_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "rename-user", &csil_req)?;
        decode_rename_user_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// set-application-id (request/response).
    pub fn set_application_id(
        &self,
        req: SetApplicationIdRequest,
    ) -> Result<SetApplicationIdResponse, ClientError> {
        let csil_req = match encode_set_application_id_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "set-application-id", &csil_req)?;
        decode_set_application_id_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// create-api-key (request/response).
    pub fn create_api_key(
        &self,
        req: CreateApiKeyRequest,
    ) -> Result<CreateApiKeyResponse, ClientError> {
        let csil_req = match encode_create_api_key_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "create-api-key", &csil_req)?;
        decode_create_api_key_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// list-api-keys (request/response).
    pub fn list_api_keys(
        &self,
        req: ListApiKeysRequest,
    ) -> Result<ListApiKeysResponse, ClientError> {
        let csil_req = match encode_list_api_keys_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "list-api-keys", &csil_req)?;
        decode_list_api_keys_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// revoke-api-key (request/response).
    pub fn revoke_api_key(
        &self,
        req: RevokeApiKeyRequest,
    ) -> Result<RevokeApiKeyResponse, ClientError> {
        let csil_req = match encode_revoke_api_key_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Admin", "revoke-api-key", &csil_req)?;
        decode_revoke_api_key_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// get-account-limits (request/response).
    pub fn get_account_limits(
        &self,
        req: GetAccountLimitsRequest,
    ) -> Result<GetAccountLimitsResponse, ClientError> {
        let csil_req = match encode_get_account_limits_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "get-account-limits", &csil_req)?;
        decode_get_account_limits_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// set-account-limits (request/response).
    pub fn set_account_limits(
        &self,
        req: SetAccountLimitsRequest,
    ) -> Result<SetAccountLimitsResponse, ClientError> {
        let csil_req = match encode_set_account_limits_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "set-account-limits", &csil_req)?;
        decode_set_account_limits_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// get-application-usage (request/response).
    pub fn get_application_usage(
        &self,
        req: GetApplicationUsageRequest,
    ) -> Result<GetApplicationUsageResponse, ClientError> {
        let csil_req = match encode_get_application_usage_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Admin", "get-application-usage", &csil_req)?;
        decode_get_application_usage_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the Account service.
pub struct AccountClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> AccountClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// change-password (request/response).
    pub fn change_password(
        &self,
        req: ChangePasswordRequest,
    ) -> Result<ChangePasswordResponse, ClientError> {
        let csil_req = match encode_change_password_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Account", "change-password", &csil_req)?;
        decode_change_password_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// get-my-info (request/response).
    pub fn get_my_info(&self, req: EmptyRequest) -> Result<GetMyInfoResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Account", "get-my-info", &csil_req)?;
        decode_get_my_info_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// list-settable-policies (request/response).
    pub fn list_settable_policies(
        &self,
        req: EmptyRequest,
    ) -> Result<ListSettablePoliciesResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Account", "list-settable-policies", &csil_req)?;
        decode_list_settable_policies_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// set-my-claim (request/response).
    pub fn set_my_claim(&self, req: SetMyClaimRequest) -> Result<SetMyClaimResponse, ClientError> {
        let csil_req = match encode_set_my_claim_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Account", "set-my-claim", &csil_req)?;
        decode_set_my_claim_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// remove-my-claim (request/response).
    pub fn remove_my_claim(
        &self,
        req: RemoveMyClaimRequest,
    ) -> Result<RemoveMyClaimResponse, ClientError> {
        let csil_req = match encode_remove_my_claim_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Account", "remove-my-claim", &csil_req)?;
        decode_remove_my_claim_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// set-my-claim-sharing (request/response).
    pub fn set_my_claim_sharing(
        &self,
        req: SetMyClaimSharingRequest,
    ) -> Result<SetMyClaimSharingResponse, ClientError> {
        let csil_req = match encode_set_my_claim_sharing_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Account", "set-my-claim-sharing", &csil_req)?;
        decode_set_my_claim_sharing_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// create-profile (request/response).
    pub fn create_profile(
        &self,
        req: CreateProfileRequest,
    ) -> Result<CreateProfileResponse, ClientError> {
        let csil_req = match encode_create_profile_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Account", "create-profile", &csil_req)?;
        decode_create_profile_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// get-my-claim-settings (request/response).
    pub fn get_my_claim_settings(
        &self,
        req: EmptyRequest,
    ) -> Result<MyClaimSettingsResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Account", "get-my-claim-settings", &csil_req)?;
        decode_my_claim_settings_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// set-my-claim-keep-verified (request/response).
    pub fn set_my_claim_keep_verified(
        &self,
        req: SetMyClaimKeepVerifiedRequest,
    ) -> Result<SetMyClaimKeepVerifiedResponse, ClientError> {
        let csil_req = match encode_set_my_claim_keep_verified_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Account", "set-my-claim-keep-verified", &csil_req)?;
        decode_set_my_claim_keep_verified_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// request-verification (request/response).
    pub fn request_verification(
        &self,
        req: RequestVerificationRequest,
    ) -> Result<RequestVerificationResponse, ClientError> {
        let csil_req = match encode_request_verification_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Account", "request-verification", &csil_req)?;
        decode_request_verification_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// list-verified-contact-methods (request/response).
    pub fn list_verified_contact_methods(
        &self,
        req: EmptyRequest,
    ) -> Result<ListVerifiedContactMethodsResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp =
            self.transport
                .call("Account", "list-verified-contact-methods", &csil_req)?;
        decode_list_verified_contact_methods_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// revoke-verified-contact-method (request/response).
    pub fn revoke_verified_contact_method(
        &self,
        req: RevokeVerifiedContactMethodRequest,
    ) -> Result<RevokeVerifiedContactMethodResponse, ClientError> {
        let csil_req = match encode_revoke_verified_contact_method_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp =
            self.transport
                .call("Account", "revoke-verified-contact-method", &csil_req)?;
        decode_revoke_verified_contact_method_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// request-contact-verification (request/response).
    pub fn request_contact_verification(
        &self,
        req: RequestContactVerificationRequest,
    ) -> Result<RequestContactVerificationResponse, ClientError> {
        let csil_req = match encode_request_contact_verification_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp =
            self.transport
                .call("Account", "request-contact-verification", &csil_req)?;
        decode_request_contact_verification_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// confirm-contact-verification (request/response).
    pub fn confirm_contact_verification(
        &self,
        req: ConfirmContactVerificationRequest,
    ) -> Result<ConfirmContactVerificationResponse, ClientError> {
        let csil_req = match encode_confirm_contact_verification_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp =
            self.transport
                .call("Account", "confirm-contact-verification", &csil_req)?;
        decode_confirm_contact_verification_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// enroll-application-instance (request/response).
    pub fn enroll_application_instance(
        &self,
        req: EnrollApplicationInstanceRequest,
    ) -> Result<EnrollApplicationInstanceResponse, ClientError> {
        let csil_req = match encode_enroll_application_instance_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Account", "enroll-application-instance", &csil_req)?;
        decode_enroll_application_instance_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// list-act-as-grants (request/response).
    pub fn list_act_as_grants(
        &self,
        req: EmptyRequest,
    ) -> Result<ListActAsGrantsResponse, ClientError> {
        let csil_req = match encode_empty_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Account", "list-act-as-grants", &csil_req)?;
        decode_list_act_as_grants_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// revoke-act-as-grant (request/response).
    pub fn revoke_act_as_grant(
        &self,
        req: RevokeActAsGrantRequest,
    ) -> Result<RevokeActAsGrantResponse, ClientError> {
        let csil_req = match encode_revoke_act_as_grant_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Account", "revoke-act-as-grant", &csil_req)?;
        decode_revoke_act_as_grant_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the Attestation service.
pub struct AttestationClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> AttestationClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// deposit-claim (request/response).
    pub fn deposit_claim(
        &self,
        req: DepositClaimRequest,
    ) -> Result<DepositClaimResponse, ClientError> {
        let csil_req = match encode_deposit_claim_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Attestation", "deposit-claim", &csil_req)?;
        decode_deposit_claim_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the Rp service.
pub struct RpClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> RpClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// sign-request (request/response).
    pub fn sign_request(&self, req: RpSignRequest) -> Result<RpSignResponse, ClientError> {
        let csil_req = match encode_rp_sign_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_reply = self.transport.call_reply("Rp", "sign-request", &csil_req)?;
        let csil_resp = resolve_rpc_reply(
            "Rp",
            "sign-request",
            csil_reply.variant.as_deref(),
            csil_reply.payload,
        )?;
        decode_rp_sign_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// decrypt-token (request/response).
    pub fn decrypt_token(&self, req: RpDecryptRequest) -> Result<RpDecryptResponse, ClientError> {
        let csil_req = match encode_rp_decrypt_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_reply = self
            .transport
            .call_reply("Rp", "decrypt-token", &csil_req)?;
        let csil_resp = resolve_rpc_reply(
            "Rp",
            "decrypt-token",
            csil_reply.variant.as_deref(),
            csil_reply.payload,
        )?;
        decode_rp_decrypt_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// verify-assertion (request/response).
    pub fn verify_assertion(&self, req: RpVerifyRequest) -> Result<RpVerifyResponse, ClientError> {
        let csil_req = match encode_rp_verify_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_reply = self
            .transport
            .call_reply("Rp", "verify-assertion", &csil_req)?;
        let csil_resp = resolve_rpc_reply(
            "Rp",
            "verify-assertion",
            csil_reply.variant.as_deref(),
            csil_reply.payload,
        )?;
        decode_rp_verify_response(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// userinfo-fetch (request/response).
    pub fn userinfo_fetch(&self, req: RpUserInfoRequest) -> Result<UserInfo, ClientError> {
        let csil_req = match encode_rp_user_info_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_reply = self
            .transport
            .call_reply("Rp", "userinfo-fetch", &csil_req)?;
        let csil_resp = resolve_rpc_reply(
            "Rp",
            "userinfo-fetch",
            csil_reply.variant.as_deref(),
            csil_reply.payload,
        )?;
        decode_user_info(&csil_resp).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// issue-attestation (request/response).
    pub fn issue_attestation(
        &self,
        req: RpIssueAttestationRequest,
    ) -> Result<RpIssueAttestationResponse, ClientError> {
        let csil_req = match encode_rp_issue_attestation_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("Rp", "issue-attestation", &csil_req)?;
        decode_rp_issue_attestation_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// resolve-domain-keys (request/response).
    pub fn resolve_domain_keys(
        &self,
        req: RpResolveDomainKeysRequest,
    ) -> Result<RpResolveDomainKeysResponse, ClientError> {
        let csil_req = match encode_rp_resolve_domain_keys_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Rp", "resolve-domain-keys", &csil_req)?;
        decode_rp_resolve_domain_keys_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// resolve-application-keys (request/response).
    pub fn resolve_application_keys(
        &self,
        req: RpResolveApplicationKeysRequest,
    ) -> Result<RpResolveApplicationKeysResponse, ClientError> {
        let csil_req = match encode_rp_resolve_application_keys_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Rp", "resolve-application-keys", &csil_req)?;
        decode_rp_resolve_application_keys_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// act-as-refresh-grant (request/response).
    pub fn act_as_refresh_grant(
        &self,
        req: RpActAsRefreshRequest,
    ) -> Result<RefreshActAsGrantResponse, ClientError> {
        let csil_req = match encode_rp_act_as_refresh_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Rp", "act-as-refresh-grant", &csil_req)?;
        decode_refresh_act_as_grant_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// resolve-act-as-revocations (request/response).
    pub fn resolve_act_as_revocations(
        &self,
        req: RpResolveActAsRevocationsRequest,
    ) -> Result<GetActAsGrantRevocationsResponse, ClientError> {
        let csil_req = match encode_rp_resolve_act_as_revocations_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("Rp", "resolve-act-as-revocations", &csil_req)?;
        decode_get_act_as_grant_revocations_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the ActAs service.
pub struct ActAsClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> ActAsClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// refresh-grant (request/response).
    pub fn refresh_grant(
        &self,
        req: RefreshActAsGrantRequest,
    ) -> Result<RefreshActAsGrantResponse, ClientError> {
        let csil_req = match encode_refresh_act_as_grant_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self.transport.call("ActAs", "refresh-grant", &csil_req)?;
        decode_refresh_act_as_grant_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// get-grant-revocations (request/response).
    pub fn get_grant_revocations(
        &self,
        req: GetActAsGrantRevocationsRequest,
    ) -> Result<GetActAsGrantRevocationsResponse, ClientError> {
        let csil_req = match encode_get_act_as_grant_revocations_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("ActAs", "get-grant-revocations", &csil_req)?;
        decode_get_act_as_grant_revocations_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }
}

/// Typed client for the LocalRp service.
pub struct LocalRpClient<T: Transport> {
    #[allow(dead_code)]
    transport: T,
}

impl<T: Transport> LocalRpClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// redeem-claim-ticket (request/response).
    pub fn redeem_claim_ticket(
        &self,
        req: SignedLocalRpTicketRedemptionRequest,
    ) -> Result<LocalRpTicketRedemptionResponse, ClientError> {
        let csil_req = match encode_signed_local_rp_ticket_redemption_request(&req) {
            Ok(csil_bytes) => csil_bytes,
            Err(e) => return Err(ClientError::Encode(e.to_string())),
        };
        let csil_resp = self
            .transport
            .call("LocalRp", "redeem-claim-ticket", &csil_req)?;
        decode_local_rp_ticket_redemption_response(&csil_resp)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }
}
