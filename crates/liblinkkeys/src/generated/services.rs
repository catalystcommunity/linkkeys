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
    /// get-revocations (request/response).
    fn get_revocations(
        &self,
        ctx: &Self::Context,
        input: GetRevocationsRequest,
    ) -> Result<GetRevocationsResponse, ServiceError>;
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

/// I18n service trait
pub trait I18n {
    type Context;
    /// get-translations (request/response).
    fn get_translations(
        &self,
        ctx: &Self::Context,
        input: TranslationsRequest,
    ) -> Result<TranslationsResponse, ServiceError>;
    /// list-locales (request/response).
    fn list_locales(
        &self,
        ctx: &Self::Context,
        input: EmptyRequest,
    ) -> Result<ListLocalesResponse, ServiceError>;
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
    /// activate-user (request/response).
    fn activate_user(
        &self,
        ctx: &Self::Context,
        input: ActivateUserRequest,
    ) -> Result<ActivateUserResponse, ServiceError>;
    /// purge-user (request/response).
    fn purge_user(
        &self,
        ctx: &Self::Context,
        input: PurgeUserRequest,
    ) -> Result<PurgeUserResponse, ServiceError>;
    /// revoke-domain-key (request/response).
    fn revoke_domain_key(
        &self,
        ctx: &Self::Context,
        input: RevokeDomainKeyRequest,
    ) -> Result<RevokeDomainKeyResponse, ServiceError>;
    /// reset-password (request/response).
    fn reset_password(
        &self,
        ctx: &Self::Context,
        input: ResetPasswordRequest,
    ) -> Result<ResetPasswordResponse, ServiceError>;
    /// authenticate (request/response).
    fn authenticate(
        &self,
        ctx: &Self::Context,
        input: AuthenticateRequest,
    ) -> Result<AuthenticateResponse, ServiceError>;
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
    /// list-user-claims (request/response).
    fn list_user_claims(
        &self,
        ctx: &Self::Context,
        input: ListUserClaimsRequest,
    ) -> Result<ListUserClaimsResponse, ServiceError>;
    /// set-user-claim (request/response).
    fn set_user_claim(
        &self,
        ctx: &Self::Context,
        input: SetUserClaimRequest,
    ) -> Result<SetUserClaimResponse, ServiceError>;
    /// list-settable-policies (request/response).
    fn list_settable_policies(
        &self,
        ctx: &Self::Context,
        input: EmptyRequest,
    ) -> Result<ListSettablePoliciesResponse, ServiceError>;
    /// list-claim-types (request/response).
    fn list_claim_types(
        &self,
        ctx: &Self::Context,
        input: EmptyRequest,
    ) -> Result<ListClaimTypesResponse, ServiceError>;
    /// set-claim-type (request/response).
    fn set_claim_type(
        &self,
        ctx: &Self::Context,
        input: SetClaimTypeRequest,
    ) -> Result<SetClaimTypeResponse, ServiceError>;
    /// remove-claim-type (request/response).
    fn remove_claim_type(
        &self,
        ctx: &Self::Context,
        input: RemoveClaimTypeRequest,
    ) -> Result<RemoveClaimTypeResponse, ServiceError>;
    /// set-claim-type-label (request/response).
    fn set_claim_type_label(
        &self,
        ctx: &Self::Context,
        input: SetClaimTypeLabelRequest,
    ) -> Result<SetClaimTypeLabelResponse, ServiceError>;
    /// remove-claim-type-label (request/response).
    fn remove_claim_type_label(
        &self,
        ctx: &Self::Context,
        input: RemoveClaimTypeLabelRequest,
    ) -> Result<RemoveClaimTypeLabelResponse, ServiceError>;
    /// list-trusted-issuers (request/response).
    fn list_trusted_issuers(
        &self,
        ctx: &Self::Context,
        input: EmptyRequest,
    ) -> Result<ListTrustedIssuersResponse, ServiceError>;
    /// add-trusted-issuer (request/response).
    fn add_trusted_issuer(
        &self,
        ctx: &Self::Context,
        input: AddTrustedIssuerRequest,
    ) -> Result<AddTrustedIssuerResponse, ServiceError>;
    /// remove-trusted-issuer (request/response).
    fn remove_trusted_issuer(
        &self,
        ctx: &Self::Context,
        input: RemoveTrustedIssuerRequest,
    ) -> Result<RemoveTrustedIssuerResponse, ServiceError>;
    /// list-release-rules (request/response).
    fn list_release_rules(
        &self,
        ctx: &Self::Context,
        input: EmptyRequest,
    ) -> Result<ListReleaseRulesResponse, ServiceError>;
    /// set-release-rule (request/response).
    fn set_release_rule(
        &self,
        ctx: &Self::Context,
        input: SetReleaseRuleRequest,
    ) -> Result<SetReleaseRuleResponse, ServiceError>;
    /// remove-release-rule (request/response).
    fn remove_release_rule(
        &self,
        ctx: &Self::Context,
        input: RemoveReleaseRuleRequest,
    ) -> Result<RemoveReleaseRuleResponse, ServiceError>;
    /// list-pending-claim-approvals (request/response).
    fn list_pending_claim_approvals(
        &self,
        ctx: &Self::Context,
        input: EmptyRequest,
    ) -> Result<ListPendingClaimApprovalsResponse, ServiceError>;
    /// approve-claim (request/response).
    fn approve_claim(
        &self,
        ctx: &Self::Context,
        input: ApproveClaimRequest,
    ) -> Result<ApproveClaimResponse, ServiceError>;
    /// reject-claim (request/response).
    fn reject_claim(
        &self,
        ctx: &Self::Context,
        input: RejectClaimRequest,
    ) -> Result<RejectClaimResponse, ServiceError>;
    /// admin-issue-attestation (request/response).
    fn admin_issue_attestation(
        &self,
        ctx: &Self::Context,
        input: AdminIssueAttestationRequest,
    ) -> Result<AdminIssueAttestationResponse, ServiceError>;
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
    /// recheck-pins (request/response).
    fn recheck_pins(
        &self,
        ctx: &Self::Context,
        input: RecheckPinsRequest,
    ) -> Result<RecheckPinsResponse, ServiceError>;
    /// list-local-rps (request/response).
    fn list_local_rps(
        &self,
        ctx: &Self::Context,
        input: ListLocalRpsRequest,
    ) -> Result<ListLocalRpsResponse, ServiceError>;
    /// get-local-rp (request/response).
    fn get_local_rp(
        &self,
        ctx: &Self::Context,
        input: GetLocalRpRequest,
    ) -> Result<GetLocalRpResponse, ServiceError>;
    /// approve-local-rp (request/response).
    fn approve_local_rp(
        &self,
        ctx: &Self::Context,
        input: ApproveLocalRpRequest,
    ) -> Result<ApproveLocalRpResponse, ServiceError>;
    /// deny-local-rp (request/response).
    fn deny_local_rp(
        &self,
        ctx: &Self::Context,
        input: DenyLocalRpRequest,
    ) -> Result<DenyLocalRpResponse, ServiceError>;
    /// revoke-local-rp (request/response).
    fn revoke_local_rp(
        &self,
        ctx: &Self::Context,
        input: RevokeLocalRpRequest,
    ) -> Result<RevokeLocalRpResponse, ServiceError>;
    /// get-local-rp-policy (request/response).
    fn get_local_rp_policy(
        &self,
        ctx: &Self::Context,
        input: GetLocalRpPolicyRequest,
    ) -> Result<GetLocalRpPolicyResponse, ServiceError>;
    /// set-local-rp-policy (request/response).
    fn set_local_rp_policy(
        &self,
        ctx: &Self::Context,
        input: SetLocalRpPolicyRequest,
    ) -> Result<SetLocalRpPolicyResponse, ServiceError>;
    /// purge-local-rp-tickets (request/response).
    fn purge_local_rp_tickets(
        &self,
        ctx: &Self::Context,
        input: PurgeLocalRpTicketsRequest,
    ) -> Result<PurgeLocalRpTicketsResponse, ServiceError>;
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
    /// set-my-claim (request/response).
    fn set_my_claim(
        &self,
        ctx: &Self::Context,
        input: SetMyClaimRequest,
    ) -> Result<SetMyClaimResponse, ServiceError>;
    /// remove-my-claim (request/response).
    fn remove_my_claim(
        &self,
        ctx: &Self::Context,
        input: RemoveMyClaimRequest,
    ) -> Result<RemoveMyClaimResponse, ServiceError>;
    /// set-my-claim-sharing (request/response).
    fn set_my_claim_sharing(
        &self,
        ctx: &Self::Context,
        input: SetMyClaimSharingRequest,
    ) -> Result<SetMyClaimSharingResponse, ServiceError>;
    /// create-profile (request/response).
    fn create_profile(
        &self,
        ctx: &Self::Context,
        input: CreateProfileRequest,
    ) -> Result<CreateProfileResponse, ServiceError>;
    /// request-verification (request/response).
    fn request_verification(
        &self,
        ctx: &Self::Context,
        input: RequestVerificationRequest,
    ) -> Result<RequestVerificationResponse, ServiceError>;
}

/// Attestation service trait
pub trait Attestation {
    type Context;
    /// deposit-claim (request/response).
    fn deposit_claim(
        &self,
        ctx: &Self::Context,
        input: DepositClaimRequest,
    ) -> Result<DepositClaimResponse, ServiceError>;
}

/// Rp service trait
pub trait Rp {
    type Context;
    /// sign-request (request/response).
    fn sign_request(
        &self,
        ctx: &Self::Context,
        input: RpSignRequest,
    ) -> Result<RpSignResponse, ServiceError>;
    /// decrypt-token (request/response).
    fn decrypt_token(
        &self,
        ctx: &Self::Context,
        input: RpDecryptRequest,
    ) -> Result<RpDecryptResponse, ServiceError>;
    /// verify-assertion (request/response).
    fn verify_assertion(
        &self,
        ctx: &Self::Context,
        input: RpVerifyRequest,
    ) -> Result<RpVerifyResponse, ServiceError>;
    /// userinfo-fetch (request/response).
    fn userinfo_fetch(
        &self,
        ctx: &Self::Context,
        input: RpUserInfoRequest,
    ) -> Result<UserInfo, ServiceError>;
    /// issue-attestation (request/response).
    fn issue_attestation(
        &self,
        ctx: &Self::Context,
        input: RpIssueAttestationRequest,
    ) -> Result<RpIssueAttestationResponse, ServiceError>;
}

/// LocalRp service trait
pub trait LocalRp {
    type Context;
    /// redeem-claim-ticket (request/response).
    fn redeem_claim_ticket(
        &self,
        ctx: &Self::Context,
        input: SignedLocalRpTicketRedemptionRequest,
    ) -> Result<LocalRpTicketRedemptionResponse, ServiceError>;
}
