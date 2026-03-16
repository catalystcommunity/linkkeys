//! Generated types from CSIL specification

use serde::{Deserialize, Serialize};

pub type CheckValue = serde_json::Value;

pub type CheckEntries = std::collections::HashMap<String, CheckValue>;

pub type CheckResult = serde_json::Value;

pub type HelloRequest = serde_json::Value;

pub type HelloResponse = serde_json::Value;

pub type GuestbookEntry = serde_json::Value;

pub type CreateGuestbookRequest = serde_json::Value;

pub type UpdateGuestbookRequest = serde_json::Value;

pub type DeleteGuestbookRequest = serde_json::Value;

pub type DeleteGuestbookResponse = serde_json::Value;

pub type GuestbookListRequest = serde_json::Value;

pub type GuestbookListResponse = serde_json::Value;

pub type EmptyRequest = serde_json::Value;

