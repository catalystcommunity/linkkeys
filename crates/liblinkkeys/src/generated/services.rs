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
    /// healthcheck operation
    fn healthcheck(&self, ctx: &Self::Context, input: EmptyRequest) -> Result<CheckResult, ServiceError>;
    /// readiness operation
    fn readiness(&self, ctx: &Self::Context, input: EmptyRequest) -> Result<CheckResult, ServiceError>;
}

/// Hello service trait
pub trait Hello {
    type Context;
    /// hello operation
    fn hello(&self, ctx: &Self::Context, input: HelloRequest) -> Result<HelloResponse, ServiceError>;
}

/// Guestbook service trait
pub trait Guestbook {
    type Context;
    /// create-entry operation
    fn create_entry(&self, ctx: &Self::Context, input: CreateGuestbookRequest) -> Result<GuestbookEntry, ServiceError>;
    /// list-entries operation
    fn list_entries(&self, ctx: &Self::Context, input: GuestbookListRequest) -> Result<GuestbookListResponse, ServiceError>;
    /// update-entry operation
    fn update_entry(&self, ctx: &Self::Context, input: UpdateGuestbookRequest) -> Result<GuestbookEntry, ServiceError>;
    /// delete-entry operation
    fn delete_entry(&self, ctx: &Self::Context, input: DeleteGuestbookRequest) -> Result<DeleteGuestbookResponse, ServiceError>;
}

/// DomainKeys service trait
pub trait DomainKeys {
    type Context;
    /// get-domain-keys operation
    fn get_domain_keys(&self, ctx: &Self::Context, input: EmptyRequest) -> Result<GetDomainKeysResponse, ServiceError>;
}

/// UserKeys service trait
pub trait UserKeys {
    type Context;
    /// get-user-keys operation
    fn get_user_keys(&self, ctx: &Self::Context, input: GetUserKeysRequest) -> Result<GetUserKeysResponse, ServiceError>;
}

/// Identity service trait
pub trait Identity {
    type Context;
    /// get-user-info operation
    fn get_user_info(&self, ctx: &Self::Context, input: GetUserInfoRequest) -> Result<UserInfo, ServiceError>;
}

/// Handshake service trait
pub trait Handshake {
    type Context;
    /// handshake operation
    fn handshake(&self, ctx: &Self::Context, input: HandshakeRequest) -> Result<HandshakeResponse, ServiceError>;
}

/// Admin service trait
pub trait Admin {
    type Context;
    /// list-users operation
    fn list_users(&self, ctx: &Self::Context, input: ListUsersRequest) -> Result<ListUsersResponse, ServiceError>;
    /// get-user operation
    fn get_user(&self, ctx: &Self::Context, input: GetUserRequest) -> Result<GetUserResponse, ServiceError>;
    /// create-user operation
    fn create_user(&self, ctx: &Self::Context, input: CreateUserRequest) -> Result<CreateUserResponse, ServiceError>;
    /// update-user operation
    fn update_user(&self, ctx: &Self::Context, input: UpdateUserRequest) -> Result<UpdateUserResponse, ServiceError>;
    /// deactivate-user operation
    fn deactivate_user(&self, ctx: &Self::Context, input: DeactivateUserRequest) -> Result<DeactivateUserResponse, ServiceError>;
    /// reset-password operation
    fn reset_password(&self, ctx: &Self::Context, input: ResetPasswordRequest) -> Result<ResetPasswordResponse, ServiceError>;
    /// remove-credential operation
    fn remove_credential(&self, ctx: &Self::Context, input: RemoveCredentialRequest) -> Result<RemoveCredentialResponse, ServiceError>;
    /// set-claim operation
    fn set_claim(&self, ctx: &Self::Context, input: SetClaimRequest) -> Result<SetClaimResponse, ServiceError>;
    /// remove-claim operation
    fn remove_claim(&self, ctx: &Self::Context, input: RemoveClaimRequest) -> Result<RemoveClaimResponse, ServiceError>;
    /// grant-relation operation
    fn grant_relation(&self, ctx: &Self::Context, input: GrantRelationRequest) -> Result<GrantRelationResponse, ServiceError>;
    /// remove-relation operation
    fn remove_relation(&self, ctx: &Self::Context, input: RemoveRelationRequest) -> Result<RemoveRelationResponse, ServiceError>;
    /// list-relations operation
    fn list_relations(&self, ctx: &Self::Context, input: ListRelationsRequest) -> Result<ListRelationsResponse, ServiceError>;
    /// check-permission operation
    fn check_permission(&self, ctx: &Self::Context, input: CheckPermissionRequest) -> Result<CheckPermissionResponse, ServiceError>;
}

/// Account service trait
pub trait Account {
    type Context;
    /// change-password operation
    fn change_password(&self, ctx: &Self::Context, input: ChangePasswordRequest) -> Result<ChangePasswordResponse, ServiceError>;
    /// get-my-info operation
    fn get_my_info(&self, ctx: &Self::Context, input: EmptyRequest) -> Result<GetMyInfoResponse, ServiceError>;
}

