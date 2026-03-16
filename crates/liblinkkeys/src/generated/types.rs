//! Generated types from CSIL specification

use serde::{Deserialize, Serialize};

/// CheckValue enum variants
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CheckValue {
    Variant0(String),
    Variant1(i64),
    Variant2(f64),
}

pub type CheckEntries = std::collections::HashMap<String, CheckValue>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CheckResult {
    pub result: bool,
    pub entries: CheckEntries,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HelloRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HelloResponse {
    pub greeting: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuestbookEntry {
    #[serde(skip_serializing)]
    pub id: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub created_at: String,
    #[serde(skip_serializing)]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CreateGuestbookRequest {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpdateGuestbookRequest {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeleteGuestbookRequest {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeleteGuestbookResponse {
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuestbookListRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuestbookListResponse {
    pub entries: Vec<GuestbookEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EmptyRequest {
}

