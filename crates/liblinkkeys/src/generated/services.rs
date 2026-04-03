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

