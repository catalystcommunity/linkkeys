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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DomainPublicKey {
    pub key_id: String,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub algorithm: String,
    pub created_at: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GetDomainKeysResponse {
    pub domain: String,
    pub keys: Vec<DomainPublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserPublicKey {
    pub key_id: String,
    pub user_id: String,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub algorithm: String,
    pub created_at: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GetUserKeysRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GetUserKeysResponse {
    pub user_id: String,
    pub domain: String,
    pub keys: Vec<UserPublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Claim {
    pub claim_id: String,
    pub user_id: String,
    pub claim_type: String,
    #[serde(with = "serde_bytes")]
    pub claim_value: Vec<u8>,
    pub signed_by_key_id: String,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GetUserClaimsRequest {
    pub user_id: String,
    #[serde(with = "serde_bytes")]
    pub token: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GetUserClaimsResponse {
    pub user_id: String,
    pub domain: String,
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityAssertion {
    pub user_id: String,
    pub domain: String,
    pub audience: String,
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedIdentityAssertion {
    #[serde(with = "serde_bytes")]
    pub assertion: Vec<u8>,
    pub signing_key_id: String,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GetUserInfoRequest {
    #[serde(with = "serde_bytes")]
    pub token: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserInfo {
    pub user_id: String,
    pub domain: String,
    pub display_name: String,
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlgorithmSupport {
    pub signing: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HandshakeRequest {
    pub version: String,
    pub algorithms: AlgorithmSupport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HandshakeResponse {
    pub version: String,
    pub algorithms: AlgorithmSupport,
}

