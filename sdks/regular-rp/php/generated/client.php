<?php

namespace Csilgen\Generated;

class ClientError extends \RuntimeException {}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class OpsClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function healthcheck($request)
    {
        $payload = Codec::encodeEmptyRequest($request);
        $reply = $this->transport->call('Ops', 'healthcheck', $payload);
        return Codec::decodeCheckResult($reply);
    }

    public function readiness($request)
    {
        $payload = Codec::encodeEmptyRequest($request);
        $reply = $this->transport->call('Ops', 'readiness', $payload);
        return Codec::decodeCheckResult($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class HelloClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function hello($request)
    {
        $payload = Codec::encodeHelloRequest($request);
        $reply = $this->transport->call('Hello', 'hello', $payload);
        return Codec::decodeHelloResponse($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class GuestbookClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function createEntry($request)
    {
        $payload = Codec::encodeCreateGuestbookRequest($request);
        $reply = $this->transport->call('Guestbook', 'create-entry', $payload);
        return Codec::decodeGuestbookEntry($reply);
    }

    public function listEntries($request)
    {
        $payload = Codec::encodeGuestbookListRequest($request);
        $reply = $this->transport->call('Guestbook', 'list-entries', $payload);
        return Codec::decodeGuestbookListResponse($reply);
    }

    public function updateEntry($request)
    {
        $payload = Codec::encodeUpdateGuestbookRequest($request);
        $reply = $this->transport->call('Guestbook', 'update-entry', $payload);
        return Codec::decodeGuestbookEntry($reply);
    }

    public function deleteEntry($request)
    {
        $payload = Codec::encodeDeleteGuestbookRequest($request);
        $reply = $this->transport->call('Guestbook', 'delete-entry', $payload);
        return Codec::decodeDeleteGuestbookResponse($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class DomainKeysClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function getDomainKeys($request)
    {
        $payload = Codec::encodeEmptyRequest($request);
        $reply = $this->transport->call('DomainKeys', 'get-domain-keys', $payload);
        return Codec::decodeGetDomainKeysResponse($reply);
    }

    public function getRevocations($request)
    {
        $payload = Codec::encodeGetRevocationsRequest($request);
        $reply = $this->transport->call('DomainKeys', 'get-revocations', $payload);
        return Codec::decodeGetRevocationsResponse($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class UserKeysClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function getUserKeys($request)
    {
        $payload = Codec::encodeGetUserKeysRequest($request);
        $reply = $this->transport->call('UserKeys', 'get-user-keys', $payload);
        return Codec::decodeGetUserKeysResponse($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class ApplicationKeysClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function getApplicationKeys($request)
    {
        $payload = Codec::encodeGetApplicationKeysRequest($request);
        $reply = $this->transport->call('ApplicationKeys', 'get-application-keys', $payload);
        return Codec::decodeGetApplicationKeysResponse($reply);
    }

    public function startKeyChallenge($request)
    {
        $payload = Codec::encodeStartApplicationKeyChallengeRequest($request);
        $reply = $this->transport->call('ApplicationKeys', 'start-key-challenge', $payload);
        return Codec::decodeStartApplicationKeyChallengeResponse($reply);
    }

    public function addKey($request)
    {
        $payload = Codec::encodeAddApplicationKeyRequest($request);
        $reply = $this->transport->call('ApplicationKeys', 'add-key', $payload);
        return Codec::decodeAddApplicationKeyResponse($reply);
    }

    public function renewAttestation($request)
    {
        $payload = Codec::encodeRenewApplicationKeyAttestationRequest($request);
        $reply = $this->transport->call('ApplicationKeys', 'renew-attestation', $payload);
        return Codec::decodeRenewApplicationKeyAttestationResponse($reply);
    }

    public function revokeKey($request)
    {
        $payload = Codec::encodeRevokeApplicationKeyRequest($request);
        $reply = $this->transport->call('ApplicationKeys', 'revoke-key', $payload);
        return Codec::decodeRevokeApplicationKeyResponse($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class IdentityClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function getUserInfo($request)
    {
        $payload = Codec::encodeSignedUserInfoRequest($request);
        $reply = $this->transport->call('Identity', 'get-user-info', $payload);
        return Codec::decodeUserInfo($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class HandshakeClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function handshake($request)
    {
        $payload = Codec::encodeHandshakeRequest($request);
        $reply = $this->transport->call('Handshake', 'handshake', $payload);
        return Codec::decodeHandshakeResponse($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class I18NClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function getTranslations($request)
    {
        $payload = Codec::encodeTranslationsRequest($request);
        $reply = $this->transport->call('I18n', 'get-translations', $payload);
        return Codec::decodeTranslationsResponse($reply);
    }

    public function listLocales($request)
    {
        $payload = Codec::encodeEmptyRequest($request);
        $reply = $this->transport->call('I18n', 'list-locales', $payload);
        return Codec::decodeListLocalesResponse($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class UiClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function getConfiguration($request)
    {
        $payload = Codec::encodeEmptyRequest($request);
        $reply = $this->transport->call('Ui', 'get-configuration', $payload);
        return Codec::decodeGetUiConfigurationResponse($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class NotificationClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function getCapabilities($request)
    {
        $payload = Codec::encodeEmptyRequest($request);
        $reply = $this->transport->call('Notification', 'get-capabilities', $payload);
        return Codec::decodeGetNotificationCapabilitiesResponse($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class SessionClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function loginPassword($request)
    {
        $payload = Codec::encodeSessionPasswordLoginRequest($request);
        $reply = $this->transport->call('Session', 'login-password', $payload);
        return Codec::decodeSessionPasswordLoginResponse($reply);
    }

    public function getCurrent($request)
    {
        $payload = Codec::encodeEmptyRequest($request);
        $reply = $this->transport->call('Session', 'get-current', $payload);
        return Codec::decodeSessionCurrentResponse($reply);
    }

    public function logout($request)
    {
        $payload = Codec::encodeEmptyRequest($request);
        $reply = $this->transport->call('Session', 'logout', $payload);
        return Codec::decodeSessionLogoutResponse($reply);
    }

    public function introspect($request)
    {
        $payload = Codec::encodeIntrospectBrowserSessionRequest($request);
        $reply = $this->transport->call('Session', 'introspect', $payload);
        return Codec::decodeIntrospectBrowserSessionResponse($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class RecoveryClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function requestPasswordRecovery($request)
    {
        $payload = Codec::encodeRequestPasswordRecoveryRequest($request);
        $reply = $this->transport->call('Recovery', 'request-password-recovery', $payload);
        return Codec::decodeRequestPasswordRecoveryResponse($reply);
    }

    public function validatePasswordRecovery($request)
    {
        $payload = Codec::encodeValidatePasswordRecoveryRequest($request);
        $reply = $this->transport->call('Recovery', 'validate-password-recovery', $payload);
        return Codec::decodeValidatePasswordRecoveryResponse($reply);
    }

    public function completePasswordRecovery($request)
    {
        $payload = Codec::encodeCompletePasswordRecoveryRequest($request);
        $reply = $this->transport->call('Recovery', 'complete-password-recovery', $payload);
        return Codec::decodeCompletePasswordRecoveryResponse($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class BrowserAuthorizationClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function inspect($request)
    {
        $payload = Codec::encodeBrowserAuthorizationInspectRequest($request);
        $reply = $this->transport->call('BrowserAuthorization', 'inspect', $payload);
        return Codec::decodeBrowserAuthorizationInspectResponse($reply);
    }

    public function complete($request)
    {
        $payload = Codec::encodeBrowserAuthorizationCompleteRequest($request);
        $reply = $this->transport->call('BrowserAuthorization', 'complete', $payload);
        return Codec::decodeBrowserAuthorizationCompleteResponse($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class AdminClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function listUsers($request)
    {
        $payload = Codec::encodeListUsersRequest($request);
        $reply = $this->transport->call('Admin', 'list-users', $payload);
        return Codec::decodeListUsersResponse($reply);
    }

    public function getUser($request)
    {
        $payload = Codec::encodeGetUserRequest($request);
        $reply = $this->transport->call('Admin', 'get-user', $payload);
        return Codec::decodeGetUserResponse($reply);
    }

    public function createUser($request)
    {
        $payload = Codec::encodeCreateUserRequest($request);
        $reply = $this->transport->call('Admin', 'create-user', $payload);
        return Codec::decodeCreateUserResponse($reply);
    }

    public function updateUser($request)
    {
        $payload = Codec::encodeUpdateUserRequest($request);
        $reply = $this->transport->call('Admin', 'update-user', $payload);
        return Codec::decodeUpdateUserResponse($reply);
    }

    public function deactivateUser($request)
    {
        $payload = Codec::encodeDeactivateUserRequest($request);
        $reply = $this->transport->call('Admin', 'deactivate-user', $payload);
        return Codec::decodeDeactivateUserResponse($reply);
    }

    public function activateUser($request)
    {
        $payload = Codec::encodeActivateUserRequest($request);
        $reply = $this->transport->call('Admin', 'activate-user', $payload);
        return Codec::decodeActivateUserResponse($reply);
    }

    public function purgeUser($request)
    {
        $payload = Codec::encodePurgeUserRequest($request);
        $reply = $this->transport->call('Admin', 'purge-user', $payload);
        return Codec::decodePurgeUserResponse($reply);
    }

    public function revokeDomainKey($request)
    {
        $payload = Codec::encodeRevokeDomainKeyRequest($request);
        $reply = $this->transport->call('Admin', 'revoke-domain-key', $payload);
        return Codec::decodeRevokeDomainKeyResponse($reply);
    }

    public function resetPassword($request)
    {
        $payload = Codec::encodeResetPasswordRequest($request);
        $reply = $this->transport->call('Admin', 'reset-password', $payload);
        return Codec::decodeResetPasswordResponse($reply);
    }

    public function authenticate($request)
    {
        $payload = Codec::encodeAuthenticateRequest($request);
        $reply = $this->transport->call('Admin', 'authenticate', $payload);
        return Codec::decodeAuthenticateResponse($reply);
    }

    public function removeCredential($request)
    {
        $payload = Codec::encodeRemoveCredentialRequest($request);
        $reply = $this->transport->call('Admin', 'remove-credential', $payload);
        return Codec::decodeRemoveCredentialResponse($reply);
    }

    public function setClaim($request)
    {
        $payload = Codec::encodeSetClaimRequest($request);
        $reply = $this->transport->call('Admin', 'set-claim', $payload);
        return Codec::decodeSetClaimResponse($reply);
    }

    public function removeClaim($request)
    {
        $payload = Codec::encodeRemoveClaimRequest($request);
        $reply = $this->transport->call('Admin', 'remove-claim', $payload);
        return Codec::decodeRemoveClaimResponse($reply);
    }

    public function listUserClaims($request)
    {
        $payload = Codec::encodeListUserClaimsRequest($request);
        $reply = $this->transport->call('Admin', 'list-user-claims', $payload);
        return Codec::decodeListUserClaimsResponse($reply);
    }

    public function getUserClaims($request)
    {
        $payload = Codec::encodeAdminUserClaimsRequest($request);
        $reply = $this->transport->call('Admin', 'get-user-claims', $payload);
        return Codec::decodeAdminUserClaimsResponse($reply);
    }

    public function setUserClaim($request)
    {
        $payload = Codec::encodeSetUserClaimRequest($request);
        $reply = $this->transport->call('Admin', 'set-user-claim', $payload);
        return Codec::decodeSetUserClaimResponse($reply);
    }

    public function listSettablePolicies($request)
    {
        $payload = Codec::encodeEmptyRequest($request);
        $reply = $this->transport->call('Admin', 'list-settable-policies', $payload);
        return Codec::decodeListSettablePoliciesResponse($reply);
    }

    public function listClaimTypes($request)
    {
        $payload = Codec::encodeEmptyRequest($request);
        $reply = $this->transport->call('Admin', 'list-claim-types', $payload);
        return Codec::decodeListClaimTypesResponse($reply);
    }

    public function setClaimType($request)
    {
        $payload = Codec::encodeSetClaimTypeRequest($request);
        $reply = $this->transport->call('Admin', 'set-claim-type', $payload);
        return Codec::decodeSetClaimTypeResponse($reply);
    }

    public function removeClaimType($request)
    {
        $payload = Codec::encodeRemoveClaimTypeRequest($request);
        $reply = $this->transport->call('Admin', 'remove-claim-type', $payload);
        return Codec::decodeRemoveClaimTypeResponse($reply);
    }

    public function setClaimTypeLabel($request)
    {
        $payload = Codec::encodeSetClaimTypeLabelRequest($request);
        $reply = $this->transport->call('Admin', 'set-claim-type-label', $payload);
        return Codec::decodeSetClaimTypeLabelResponse($reply);
    }

    public function removeClaimTypeLabel($request)
    {
        $payload = Codec::encodeRemoveClaimTypeLabelRequest($request);
        $reply = $this->transport->call('Admin', 'remove-claim-type-label', $payload);
        return Codec::decodeRemoveClaimTypeLabelResponse($reply);
    }

    public function listTrustedIssuers($request)
    {
        $payload = Codec::encodeEmptyRequest($request);
        $reply = $this->transport->call('Admin', 'list-trusted-issuers', $payload);
        return Codec::decodeListTrustedIssuersResponse($reply);
    }

    public function addTrustedIssuer($request)
    {
        $payload = Codec::encodeAddTrustedIssuerRequest($request);
        $reply = $this->transport->call('Admin', 'add-trusted-issuer', $payload);
        return Codec::decodeAddTrustedIssuerResponse($reply);
    }

    public function removeTrustedIssuer($request)
    {
        $payload = Codec::encodeRemoveTrustedIssuerRequest($request);
        $reply = $this->transport->call('Admin', 'remove-trusted-issuer', $payload);
        return Codec::decodeRemoveTrustedIssuerResponse($reply);
    }

    public function listReleaseRules($request)
    {
        $payload = Codec::encodeEmptyRequest($request);
        $reply = $this->transport->call('Admin', 'list-release-rules', $payload);
        return Codec::decodeListReleaseRulesResponse($reply);
    }

    public function setReleaseRule($request)
    {
        $payload = Codec::encodeSetReleaseRuleRequest($request);
        $reply = $this->transport->call('Admin', 'set-release-rule', $payload);
        return Codec::decodeSetReleaseRuleResponse($reply);
    }

    public function removeReleaseRule($request)
    {
        $payload = Codec::encodeRemoveReleaseRuleRequest($request);
        $reply = $this->transport->call('Admin', 'remove-release-rule', $payload);
        return Codec::decodeRemoveReleaseRuleResponse($reply);
    }

    public function listPendingClaimApprovals($request)
    {
        $payload = Codec::encodeEmptyRequest($request);
        $reply = $this->transport->call('Admin', 'list-pending-claim-approvals', $payload);
        return Codec::decodeListPendingClaimApprovalsResponse($reply);
    }

    public function approveClaim($request)
    {
        $payload = Codec::encodeApproveClaimRequest($request);
        $reply = $this->transport->call('Admin', 'approve-claim', $payload);
        return Codec::decodeApproveClaimResponse($reply);
    }

    public function rejectClaim($request)
    {
        $payload = Codec::encodeRejectClaimRequest($request);
        $reply = $this->transport->call('Admin', 'reject-claim', $payload);
        return Codec::decodeRejectClaimResponse($reply);
    }

    public function adminIssueAttestation($request)
    {
        $payload = Codec::encodeAdminIssueAttestationRequest($request);
        $reply = $this->transport->call('Admin', 'admin-issue-attestation', $payload);
        return Codec::decodeAdminIssueAttestationResponse($reply);
    }

    public function grantRelation($request)
    {
        $payload = Codec::encodeGrantRelationRequest($request);
        $reply = $this->transport->call('Admin', 'grant-relation', $payload);
        return Codec::decodeGrantRelationResponse($reply);
    }

    public function removeRelation($request)
    {
        $payload = Codec::encodeRemoveRelationRequest($request);
        $reply = $this->transport->call('Admin', 'remove-relation', $payload);
        return Codec::decodeRemoveRelationResponse($reply);
    }

    public function listRelations($request)
    {
        $payload = Codec::encodeListRelationsRequest($request);
        $reply = $this->transport->call('Admin', 'list-relations', $payload);
        return Codec::decodeListRelationsResponse($reply);
    }

    public function checkPermission($request)
    {
        $payload = Codec::encodeCheckPermissionRequest($request);
        $reply = $this->transport->call('Admin', 'check-permission', $payload);
        return Codec::decodeCheckPermissionResponse($reply);
    }

    public function recheckPins($request)
    {
        $payload = Codec::encodeRecheckPinsRequest($request);
        $reply = $this->transport->call('Admin', 'recheck-pins', $payload);
        return Codec::decodeRecheckPinsResponse($reply);
    }

    public function listLocalRps($request)
    {
        $payload = Codec::encodeListLocalRpsRequest($request);
        $reply = $this->transport->call('Admin', 'list-local-rps', $payload);
        return Codec::decodeListLocalRpsResponse($reply);
    }

    public function getLocalRp($request)
    {
        $payload = Codec::encodeGetLocalRpRequest($request);
        $reply = $this->transport->call('Admin', 'get-local-rp', $payload);
        return Codec::decodeGetLocalRpResponse($reply);
    }

    public function approveLocalRp($request)
    {
        $payload = Codec::encodeApproveLocalRpRequest($request);
        $reply = $this->transport->call('Admin', 'approve-local-rp', $payload);
        return Codec::decodeApproveLocalRpResponse($reply);
    }

    public function denyLocalRp($request)
    {
        $payload = Codec::encodeDenyLocalRpRequest($request);
        $reply = $this->transport->call('Admin', 'deny-local-rp', $payload);
        return Codec::decodeDenyLocalRpResponse($reply);
    }

    public function revokeLocalRp($request)
    {
        $payload = Codec::encodeRevokeLocalRpRequest($request);
        $reply = $this->transport->call('Admin', 'revoke-local-rp', $payload);
        return Codec::decodeRevokeLocalRpResponse($reply);
    }

    public function getLocalRpPolicy($request)
    {
        $payload = Codec::encodeGetLocalRpPolicyRequest($request);
        $reply = $this->transport->call('Admin', 'get-local-rp-policy', $payload);
        return Codec::decodeGetLocalRpPolicyResponse($reply);
    }

    public function setLocalRpPolicy($request)
    {
        $payload = Codec::encodeSetLocalRpPolicyRequest($request);
        $reply = $this->transport->call('Admin', 'set-local-rp-policy', $payload);
        return Codec::decodeSetLocalRpPolicyResponse($reply);
    }

    public function purgeLocalRpTickets($request)
    {
        $payload = Codec::encodePurgeLocalRpTicketsRequest($request);
        $reply = $this->transport->call('Admin', 'purge-local-rp-tickets', $payload);
        return Codec::decodePurgeLocalRpTicketsResponse($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class AccountClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function changePassword($request)
    {
        $payload = Codec::encodeChangePasswordRequest($request);
        $reply = $this->transport->call('Account', 'change-password', $payload);
        return Codec::decodeChangePasswordResponse($reply);
    }

    public function getMyInfo($request)
    {
        $payload = Codec::encodeEmptyRequest($request);
        $reply = $this->transport->call('Account', 'get-my-info', $payload);
        return Codec::decodeGetMyInfoResponse($reply);
    }

    public function listSettablePolicies($request)
    {
        $payload = Codec::encodeEmptyRequest($request);
        $reply = $this->transport->call('Account', 'list-settable-policies', $payload);
        return Codec::decodeListSettablePoliciesResponse($reply);
    }

    public function setMyClaim($request)
    {
        $payload = Codec::encodeSetMyClaimRequest($request);
        $reply = $this->transport->call('Account', 'set-my-claim', $payload);
        return Codec::decodeSetMyClaimResponse($reply);
    }

    public function removeMyClaim($request)
    {
        $payload = Codec::encodeRemoveMyClaimRequest($request);
        $reply = $this->transport->call('Account', 'remove-my-claim', $payload);
        return Codec::decodeRemoveMyClaimResponse($reply);
    }

    public function setMyClaimSharing($request)
    {
        $payload = Codec::encodeSetMyClaimSharingRequest($request);
        $reply = $this->transport->call('Account', 'set-my-claim-sharing', $payload);
        return Codec::decodeSetMyClaimSharingResponse($reply);
    }

    public function createProfile($request)
    {
        $payload = Codec::encodeCreateProfileRequest($request);
        $reply = $this->transport->call('Account', 'create-profile', $payload);
        return Codec::decodeCreateProfileResponse($reply);
    }

    public function requestVerification($request)
    {
        $payload = Codec::encodeRequestVerificationRequest($request);
        $reply = $this->transport->call('Account', 'request-verification', $payload);
        return Codec::decodeRequestVerificationResponse($reply);
    }

    public function listVerifiedContactMethods($request)
    {
        $payload = Codec::encodeEmptyRequest($request);
        $reply = $this->transport->call('Account', 'list-verified-contact-methods', $payload);
        return Codec::decodeListVerifiedContactMethodsResponse($reply);
    }

    public function revokeVerifiedContactMethod($request)
    {
        $payload = Codec::encodeRevokeVerifiedContactMethodRequest($request);
        $reply = $this->transport->call('Account', 'revoke-verified-contact-method', $payload);
        return Codec::decodeRevokeVerifiedContactMethodResponse($reply);
    }

    public function requestContactVerification($request)
    {
        $payload = Codec::encodeRequestContactVerificationRequest($request);
        $reply = $this->transport->call('Account', 'request-contact-verification', $payload);
        return Codec::decodeRequestContactVerificationResponse($reply);
    }

    public function confirmContactVerification($request)
    {
        $payload = Codec::encodeConfirmContactVerificationRequest($request);
        $reply = $this->transport->call('Account', 'confirm-contact-verification', $payload);
        return Codec::decodeConfirmContactVerificationResponse($reply);
    }

    public function enrollApplicationInstance($request)
    {
        $payload = Codec::encodeEnrollApplicationInstanceRequest($request);
        $reply = $this->transport->call('Account', 'enroll-application-instance', $payload);
        return Codec::decodeEnrollApplicationInstanceResponse($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class AttestationClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function depositClaim($request)
    {
        $payload = Codec::encodeDepositClaimRequest($request);
        $reply = $this->transport->call('Attestation', 'deposit-claim', $payload);
        return Codec::decodeDepositClaimResponse($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class RpClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function signRequest($request)
    {
        $payload = Codec::encodeRpSignRequest($request);
        $reply = $this->transport->call('Rp', 'sign-request', $payload);
        return Codec::decodeRpSignResponse($reply);
    }

    public function decryptToken($request)
    {
        $payload = Codec::encodeRpDecryptRequest($request);
        $reply = $this->transport->call('Rp', 'decrypt-token', $payload);
        return Codec::decodeRpDecryptResponse($reply);
    }

    public function verifyAssertion($request)
    {
        $payload = Codec::encodeRpVerifyRequest($request);
        $reply = $this->transport->call('Rp', 'verify-assertion', $payload);
        return Codec::decodeRpVerifyResponse($reply);
    }

    public function userinfoFetch($request)
    {
        $payload = Codec::encodeRpUserInfoRequest($request);
        $reply = $this->transport->call('Rp', 'userinfo-fetch', $payload);
        return Codec::decodeUserInfo($reply);
    }

    public function issueAttestation($request)
    {
        $payload = Codec::encodeRpIssueAttestationRequest($request);
        $reply = $this->transport->call('Rp', 'issue-attestation', $payload);
        return Codec::decodeRpIssueAttestationResponse($reply);
    }

    public function resolveDomainKeys($request)
    {
        $payload = Codec::encodeRpResolveDomainKeysRequest($request);
        $reply = $this->transport->call('Rp', 'resolve-domain-keys', $payload);
        return Codec::decodeRpResolveDomainKeysResponse($reply);
    }

    public function resolveApplicationKeys($request)
    {
        $payload = Codec::encodeRpResolveApplicationKeysRequest($request);
        $reply = $this->transport->call('Rp', 'resolve-application-keys', $payload);
        return Codec::decodeRpResolveApplicationKeysResponse($reply);
    }

}

/**
 * The injected transport must expose call($service, $op, $payload) and return
 * the reply payload bytes. $service and $op are the CSIL names exactly as
 * written in the source and map verbatim onto the CSIL-RPC v1 envelope's
 * service/op fields.
 */
class LocalRpClient
{
    private $transport;

    public function __construct($transport)
    {
        $this->transport = $transport;
    }

    public function redeemClaimTicket($request)
    {
        $payload = Codec::encodeSignedLocalRpTicketRedemptionRequest($request);
        $reply = $this->transport->call('LocalRp', 'redeem-claim-ticket', $payload);
        return Codec::decodeLocalRpTicketRedemptionResponse($reply);
    }

}

