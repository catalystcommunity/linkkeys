//! Generated service traits from CSIL specification

use super::types::*;

#[derive(Debug, Clone)]
pub struct ServiceError {
    pub code: i32,
    pub message: String,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "service error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for ServiceError {}

/// Ops service trait
pub trait Ops {
    type Context;
    /// healthcheck (request/response).
    fn healthcheck(
        &self,
        ctx: &Self::Context,
        input: EmptyRequest,
    ) -> Result<CheckResult, ServiceError>;
    /// readiness (request/response).
    fn readiness(
        &self,
        ctx: &Self::Context,
        input: EmptyRequest,
    ) -> Result<CheckResult, ServiceError>;
}

/// Hello service trait
pub trait Hello {
    type Context;
    /// hello (request/response).
    fn hello(
        &self,
        ctx: &Self::Context,
        input: HelloRequest,
    ) -> Result<HelloResponse, ServiceError>;
}

/// Guestbook service trait
pub trait Guestbook {
    type Context;
    /// create-entry (request/response).
    fn create_entry(
        &self,
        ctx: &Self::Context,
        input: CreateGuestbookRequest,
    ) -> Result<GuestbookEntry, ServiceError>;
    /// list-entries (request/response).
    fn list_entries(
        &self,
        ctx: &Self::Context,
        input: GuestbookListRequest,
    ) -> Result<GuestbookListResponse, ServiceError>;
    /// update-entry (request/response).
    fn update_entry(
        &self,
        ctx: &Self::Context,
        input: UpdateGuestbookRequest,
    ) -> Result<GuestbookEntry, ServiceError>;
    /// delete-entry (request/response).
    fn delete_entry(
        &self,
        ctx: &Self::Context,
        input: DeleteGuestbookRequest,
    ) -> Result<DeleteGuestbookResponse, ServiceError>;
}

/// DomainKeys service trait
pub trait DomainKeys {
    type Context;
    /// get-domain-keys (request/response).
    fn get_domain_keys(
        &self,
        ctx: &Self::Context,
        input: EmptyRequest,
    ) -> Result<GetDomainKeysResponse, ServiceError>;
}

/// UserKeys service trait
pub trait UserKeys {
    type Context;
    /// get-user-keys (request/response).
    fn get_user_keys(
        &self,
        ctx: &Self::Context,
        input: GetUserKeysRequest,
    ) -> Result<GetUserKeysResponse, ServiceError>;
}

/// Identity service trait
pub trait Identity {
    type Context;
    /// get-user-info (request/response).
    fn get_user_info(
        &self,
        ctx: &Self::Context,
        input: SignedUserInfoRequest,
    ) -> Result<UserInfo, ServiceError>;
}

/// Handshake service trait
pub trait Handshake {
    type Context;
    /// handshake (request/response).
    fn handshake(
        &self,
        ctx: &Self::Context,
        input: HandshakeRequest,
    ) -> Result<HandshakeResponse, ServiceError>;
}

/// Admin service trait
pub trait Admin {
    type Context;
    /// list-users (request/response).
    fn list_users(
        &self,
        ctx: &Self::Context,
        input: ListUsersRequest,
    ) -> Result<ListUsersResponse, ServiceError>;
    /// get-user (request/response).
    fn get_user(
        &self,
        ctx: &Self::Context,
        input: GetUserRequest,
    ) -> Result<GetUserResponse, ServiceError>;
    /// create-user (request/response).
    fn create_user(
        &self,
        ctx: &Self::Context,
        input: CreateUserRequest,
    ) -> Result<CreateUserResponse, ServiceError>;
    /// update-user (request/response).
    fn update_user(
        &self,
        ctx: &Self::Context,
        input: UpdateUserRequest,
    ) -> Result<UpdateUserResponse, ServiceError>;
    /// deactivate-user (request/response).
    fn deactivate_user(
        &self,
        ctx: &Self::Context,
        input: DeactivateUserRequest,
    ) -> Result<DeactivateUserResponse, ServiceError>;
    /// reset-password (request/response).
    fn reset_password(
        &self,
        ctx: &Self::Context,
        input: ResetPasswordRequest,
    ) -> Result<ResetPasswordResponse, ServiceError>;
    /// remove-credential (request/response).
    fn remove_credential(
        &self,
        ctx: &Self::Context,
        input: RemoveCredentialRequest,
    ) -> Result<RemoveCredentialResponse, ServiceError>;
    /// set-claim (request/response).
    fn set_claim(
        &self,
        ctx: &Self::Context,
        input: SetClaimRequest,
    ) -> Result<SetClaimResponse, ServiceError>;
    /// remove-claim (request/response).
    fn remove_claim(
        &self,
        ctx: &Self::Context,
        input: RemoveClaimRequest,
    ) -> Result<RemoveClaimResponse, ServiceError>;
    /// grant-relation (request/response).
    fn grant_relation(
        &self,
        ctx: &Self::Context,
        input: GrantRelationRequest,
    ) -> Result<GrantRelationResponse, ServiceError>;
    /// remove-relation (request/response).
    fn remove_relation(
        &self,
        ctx: &Self::Context,
        input: RemoveRelationRequest,
    ) -> Result<RemoveRelationResponse, ServiceError>;
    /// list-relations (request/response).
    fn list_relations(
        &self,
        ctx: &Self::Context,
        input: ListRelationsRequest,
    ) -> Result<ListRelationsResponse, ServiceError>;
    /// check-permission (request/response).
    fn check_permission(
        &self,
        ctx: &Self::Context,
        input: CheckPermissionRequest,
    ) -> Result<CheckPermissionResponse, ServiceError>;
}

/// Account service trait
pub trait Account {
    type Context;
    /// change-password (request/response).
    fn change_password(
        &self,
        ctx: &Self::Context,
        input: ChangePasswordRequest,
    ) -> Result<ChangePasswordResponse, ServiceError>;
    /// get-my-info (request/response).
    fn get_my_info(
        &self,
        ctx: &Self::Context,
        input: EmptyRequest,
    ) -> Result<GetMyInfoResponse, ServiceError>;
}
