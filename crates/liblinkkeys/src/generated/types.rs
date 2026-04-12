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
pub struct AuthRequest {
    pub relying_party: String,
    pub callback_url: String,
    pub nonce: String,
    pub timestamp: String,
    pub signing_key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedAuthRequest {
    #[serde(with = "serde_bytes")]
    pub request: Vec<u8>,
    pub signing_key_id: String,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptedToken {
    #[serde(with = "serde_bytes")]
    pub ephemeral_public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Relation {
    pub id: String,
    pub subject_type: String,
    pub subject_id: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdminUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ListUsersRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ListUsersResponse {
    pub users: Vec<AdminUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GetUserRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GetUserResponse {
    pub user: AdminUser,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CreateUserRequest {
    pub username: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CreateUserResponse {
    pub user: AdminUser,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpdateUserRequest {
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpdateUserResponse {
    pub user: AdminUser,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeactivateUserRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeactivateUserResponse {
    pub user: AdminUser,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResetPasswordRequest {
    pub user_id: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResetPasswordResponse {
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoveCredentialRequest {
    pub credential_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoveCredentialResponse {
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SetClaimRequest {
    pub user_id: String,
    pub claim_type: String,
    pub claim_value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SetClaimResponse {
    pub claim: Claim,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoveClaimRequest {
    pub claim_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoveClaimResponse {
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GrantRelationRequest {
    pub subject_type: String,
    pub subject_id: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GrantRelationResponse {
    pub relation: Relation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoveRelationRequest {
    pub relation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoveRelationResponse {
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ListRelationsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ListRelationsResponse {
    pub relations: Vec<Relation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CheckPermissionRequest {
    pub user_id: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CheckPermissionResponse {
    pub allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChangePasswordRequest {
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChangePasswordResponse {
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GetMyInfoResponse {
    pub user: AdminUser,
    pub relations: Vec<Relation>,
    pub claims: Vec<Claim>,
}

