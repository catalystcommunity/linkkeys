//! Generated service traits from CSIL specification

use super::types::*;

/// Ops service trait
pub trait Ops {
    /// healthcheck operation
    fn healthcheck(&self, input: EmptyRequest) -> CheckResult;
    /// readiness operation
    fn readiness(&self, input: EmptyRequest) -> CheckResult;
}

/// Hello service trait
pub trait Hello {
    /// hello operation
    fn hello(&self, input: HelloRequest) -> HelloResponse;
}

/// Guestbook service trait
pub trait Guestbook {
    /// create-entry operation
    fn create-entry(&self, input: CreateGuestbookRequest) -> GuestbookEntry;
    /// list-entries operation
    fn list-entries(&self, input: GuestbookListRequest) -> GuestbookListResponse;
    /// update-entry operation
    fn update-entry(&self, input: UpdateGuestbookRequest) -> GuestbookEntry;
    /// delete-entry operation
    fn delete-entry(&self, input: DeleteGuestbookRequest) -> DeleteGuestbookResponse;
}

