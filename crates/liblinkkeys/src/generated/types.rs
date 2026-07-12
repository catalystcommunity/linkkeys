//! Generated types from CSIL specification

/// CheckValue variants
#[derive(Debug, Clone, PartialEq)]
pub enum CheckValue {
    Variant0(String),
    Variant1(i64),
    Variant2(f64),
}

pub type CheckEntries = std::collections::HashMap<String, CheckValue>;

#[derive(Debug, Clone, PartialEq)]
pub struct CheckResult {
    pub result: bool,
    pub entries: CheckEntries,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HelloRequest {
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HelloResponse {
    pub greeting: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GuestbookEntry {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateGuestbookRequest {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateGuestbookRequest {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeleteGuestbookRequest {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeleteGuestbookResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GuestbookListRequest {
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GuestbookListResponse {
    pub entries: Vec<GuestbookEntry>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EmptyRequest {}

#[derive(Debug, Clone, PartialEq)]
pub struct DomainPublicKey {
    pub key_id: String,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub algorithm: String,
    pub key_usage: String,
    pub created_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub signed_by_key_id: Option<String>,
    pub key_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetDomainKeysResponse {
    pub domain: String,
    pub keys: Vec<DomainPublicKey>,
    pub recent_revocations_available: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetRevocationsRequest {
    pub since: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetRevocationsResponse {
    pub revocations: Vec<RevocationCertificate>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecheckPinsRequest {
    pub domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PinRecheckResult {
    pub domain: String,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecheckPinsResponse {
    pub results: Vec<PinRecheckResult>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserPublicKey {
    pub key_id: String,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub algorithm: String,
    pub key_usage: String,
    pub created_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub signed_by_key_id: Option<String>,
    pub key_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserKeysRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserKeysResponse {
    pub user_id: String,
    pub domain: String,
    pub keys: Vec<UserPublicKey>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClaimSignature {
    pub domain: String,
    pub signed_by_key_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevocationCertificate {
    pub target_key_id: String,
    pub target_fingerprint: String,
    pub revoked_at: String,
    pub signatures: Vec<ClaimSignature>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Claim {
    pub claim_id: String,
    pub user_id: String,
    pub claim_type: String,
    pub claim_value: Vec<u8>,
    pub signatures: Vec<ClaimSignature>,
    pub attested_at: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserClaimsRequest {
    pub user_id: String,
    pub token: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserClaimsResponse {
    pub user_id: String,
    pub domain: String,
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequestedClaim {
    pub claim_type: String,
    pub datatype: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClaimRequest {
    pub required: Vec<RequestedClaim>,
    pub optional: Vec<RequestedClaim>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthFlowContext {
    pub flow: String,
    pub prior_session: Option<String>,
    pub request_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConsentGrant {
    pub grant_id: String,
    pub user_id: String,
    pub subject_domain: String,
    pub audience: String,
    pub claim_types: Vec<String>,
    pub issued_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedConsentGrant {
    pub grant: Vec<u8>,
    pub signatures: Vec<ClaimSignature>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DomainClaim {
    pub claim_type: String,
    pub claim_value: Vec<u8>,
    pub signatures: Vec<ClaimSignature>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SigningRequest {
    pub request_id: String,
    pub subject_user_id: String,
    pub subject_domain: String,
    pub issuer_domain: String,
    pub requested_claim_types: Vec<String>,
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
    pub callback: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedSigningRequest {
    pub request: Vec<u8>,
    pub signatures: Vec<ClaimSignature>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DepositClaimRequest {
    pub claim: Claim,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DepositClaimResponse {
    pub stored: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IdentityAssertion {
    pub user_id: String,
    pub domain: String,
    pub audience: String,
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
    pub authorized_claims: Vec<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedIdentityAssertion {
    pub assertion: Vec<u8>,
    pub signing_key_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserInfoRequest {
    pub token: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserInfoRequest {
    pub token: Vec<u8>,
    pub relying_party: String,
    pub timestamp: String,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedUserInfoRequest {
    pub request: Vec<u8>,
    pub signing_key_id: String,
    pub signature: Vec<u8>,
    pub public_keys: Option<Vec<DomainPublicKey>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserInfo {
    pub user_id: String,
    pub domain: String,
    pub display_name: String,
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthRequest {
    pub relying_party: String,
    pub callback_url: String,
    pub nonce: String,
    pub timestamp: String,
    pub signing_key_id: String,
    pub requested_claims: Option<ClaimRequest>,
    pub flow_context: Option<AuthFlowContext>,
    pub relying_party_claims: Option<Vec<DomainClaim>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedAuthRequest {
    pub request: Vec<u8>,
    pub signing_key_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedToken {
    pub ephemeral_public_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AlgorithmSupport {
    pub signing: Vec<String>,
    pub encryption: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeRequest {
    pub version: String,
    pub algorithms: AlgorithmSupport,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeResponse {
    pub version: String,
    pub algorithms: AlgorithmSupport,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Relation {
    pub id: String,
    pub subject_type: String,
    pub subject_id: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
    pub created_at: String,
    pub removed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdminUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListUsersRequest {
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListUsersResponse {
    pub users: Vec<AdminUser>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserResponse {
    pub user: AdminUser,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateUserRequest {
    pub username: String,
    pub display_name: String,
    pub password: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateUserResponse {
    pub user: AdminUser,
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateUserRequest {
    pub user_id: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateUserResponse {
    pub user: AdminUser,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeactivateUserRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeactivateUserResponse {
    pub user: AdminUser,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResetPasswordRequest {
    pub user_id: String,
    pub new_password: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResetPasswordResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticateRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticateResponse {
    pub user: AdminUser,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveCredentialRequest {
    pub credential_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveCredentialResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetClaimRequest {
    pub user_id: String,
    pub claim_type: String,
    pub claim_value: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetClaimResponse {
    pub claim: Claim,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveClaimRequest {
    pub claim_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveClaimResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListUserClaimsRequest {
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListUserClaimsResponse {
    pub claim_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetUserClaimRequest {
    pub user_id: String,
    pub claim_type: String,
    pub claim_value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetUserClaimResponse {
    pub outcome: String,
    pub claim: Option<Claim>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SettableClaimPolicy {
    pub claim_type: String,
    pub datatype: String,
    pub set_rule: String,
    pub requires_approval: bool,
    pub signing_rule: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListSettablePoliciesResponse {
    pub policies: Vec<SettableClaimPolicy>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GrantRelationRequest {
    pub subject_type: String,
    pub subject_id: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GrantRelationResponse {
    pub relation: Relation,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveRelationRequest {
    pub relation_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveRelationResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListRelationsRequest {
    pub subject_type: Option<String>,
    pub subject_id: Option<String>,
    pub object_type: Option<String>,
    pub object_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListRelationsResponse {
    pub relations: Vec<Relation>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CheckPermissionRequest {
    pub user_id: String,
    pub relation: String,
    pub object_type: String,
    pub object_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CheckPermissionResponse {
    pub allowed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChangePasswordRequest {
    pub new_password: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChangePasswordResponse {
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetMyInfoResponse {
    pub user: AdminUser,
    pub relations: Vec<Relation>,
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpSignRequest {
    pub callback_url: String,
    pub nonce: String,
    pub requested_claims: Option<ClaimRequest>,
    pub flow_context: Option<AuthFlowContext>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpSignResponse {
    pub signed_request: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpDecryptRequest {
    pub encrypted_token: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpDecryptResponse {
    pub signed_assertion: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpVerifyRequest {
    pub signed_assertion: String,
    pub expected_domain: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpVerifyResponse {
    pub assertion: IdentityAssertion,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpUserInfoRequest {
    pub token: String,
    pub api_base: String,
    pub domain: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpIssueAttestationRequest {
    pub signed_request: SignedSigningRequest,
    pub claim_type: String,
    pub claim_value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RpIssueAttestationResponse {
    pub claim: Claim,
    pub deposited: bool,
}

pub type LocaleMessages = std::collections::HashMap<String, String>;

#[derive(Debug, Clone, PartialEq)]
pub struct TranslationsRequest {
    pub locale: Option<String>,
    pub accept_language: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TranslationsResponse {
    pub locale: String,
    pub available_locales: Vec<String>,
    pub messages: LocaleMessages,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListLocalesResponse {
    pub available_locales: Vec<String>,
}
