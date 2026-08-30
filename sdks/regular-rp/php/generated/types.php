<?php

namespace Csilgen\Generated;

/** Generated CSIL value classes. */
class CheckResult
{
    /** @var mixed */
    public $result;

    /** @var mixed */
    public $entries;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->result = array_key_exists('result', $values) ? $values['result'] : null;
        $this->entries = array_key_exists('entries', $values) ? $values['entries'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'result' => $this->result,
            'entries' => $this->entries,
        );
    }
}

class HelloRequest
{
    /** @var mixed */
    public $name;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->name = array_key_exists('name', $values) ? $values['name'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'name' => $this->name,
        );
    }
}

class HelloResponse
{
    /** @var mixed */
    public $greeting;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->greeting = array_key_exists('greeting', $values) ? $values['greeting'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'greeting' => $this->greeting,
        );
    }
}

class GuestbookEntry
{
    /** @var mixed */
    public $id;

    /** @var mixed */
    public $name;

    /** @var mixed */
    public $createdAt;

    /** @var mixed */
    public $updatedAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->id = array_key_exists('id', $values) ? $values['id'] : null;
        $this->name = array_key_exists('name', $values) ? $values['name'] : null;
        $this->createdAt = array_key_exists('created_at', $values) ? $values['created_at'] : null;
        $this->updatedAt = array_key_exists('updated_at', $values) ? $values['updated_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'id' => $this->id,
            'name' => $this->name,
            'created_at' => $this->createdAt,
            'updated_at' => $this->updatedAt,
        );
    }
}

class CreateGuestbookRequest
{
    /** @var mixed */
    public $name;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->name = array_key_exists('name', $values) ? $values['name'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'name' => $this->name,
        );
    }
}

class UpdateGuestbookRequest
{
    /** @var mixed */
    public $id;

    /** @var mixed */
    public $name;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->id = array_key_exists('id', $values) ? $values['id'] : null;
        $this->name = array_key_exists('name', $values) ? $values['name'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'id' => $this->id,
            'name' => $this->name,
        );
    }
}

class DeleteGuestbookRequest
{
    /** @var mixed */
    public $id;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->id = array_key_exists('id', $values) ? $values['id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'id' => $this->id,
        );
    }
}

class DeleteGuestbookResponse
{
    /** @var mixed */
    public $success;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->success = array_key_exists('success', $values) ? $values['success'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'success' => $this->success,
        );
    }
}

class GuestbookListRequest
{
    /** @var mixed */
    public $offset;

    /** @var mixed */
    public $limit;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->offset = array_key_exists('offset', $values) ? $values['offset'] : null;
        $this->limit = array_key_exists('limit', $values) ? $values['limit'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'offset' => $this->offset,
            'limit' => $this->limit,
        );
    }
}

class GuestbookListResponse
{
    /** @var mixed */
    public $entries;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->entries = array_key_exists('entries', $values) ? $values['entries'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'entries' => $this->entries,
        );
    }
}

class EmptyRequest
{
    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
        );
    }
}

class DomainPublicKey
{
    /** @var mixed */
    public $keyId;

    /** @var mixed */
    public $publicKey;

    /** @var mixed */
    public $fingerprint;

    /** @var mixed */
    public $algorithm;

    /** @var mixed */
    public $keyUsage;

    /** @var mixed */
    public $createdAt;

    /** @var mixed */
    public $expiresAt;

    /** @var mixed */
    public $revokedAt;

    /** @var mixed */
    public $signedByKeyId;

    /** @var mixed */
    public $keySignature;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->keyId = array_key_exists('key_id', $values) ? $values['key_id'] : null;
        $this->publicKey = array_key_exists('public_key', $values) ? $values['public_key'] : null;
        $this->fingerprint = array_key_exists('fingerprint', $values) ? $values['fingerprint'] : null;
        $this->algorithm = array_key_exists('algorithm', $values) ? $values['algorithm'] : null;
        $this->keyUsage = array_key_exists('key_usage', $values) ? $values['key_usage'] : null;
        $this->createdAt = array_key_exists('created_at', $values) ? $values['created_at'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
        $this->revokedAt = array_key_exists('revoked_at', $values) ? $values['revoked_at'] : null;
        $this->signedByKeyId = array_key_exists('signed_by_key_id', $values) ? $values['signed_by_key_id'] : null;
        $this->keySignature = array_key_exists('key_signature', $values) ? $values['key_signature'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'key_id' => $this->keyId,
            'public_key' => $this->publicKey,
            'fingerprint' => $this->fingerprint,
            'algorithm' => $this->algorithm,
            'key_usage' => $this->keyUsage,
            'created_at' => $this->createdAt,
            'expires_at' => $this->expiresAt,
            'revoked_at' => $this->revokedAt,
            'signed_by_key_id' => $this->signedByKeyId,
            'key_signature' => $this->keySignature,
        );
    }
}

class GetDomainKeysResponse
{
    /** @var mixed */
    public $domain;

    /** @var mixed */
    public $keys;

    /** @var mixed */
    public $recentRevocationsAvailable;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->domain = array_key_exists('domain', $values) ? $values['domain'] : null;
        $this->keys = array_key_exists('keys', $values) ? $values['keys'] : null;
        $this->recentRevocationsAvailable = array_key_exists('recent_revocations_available', $values) ? $values['recent_revocations_available'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'domain' => $this->domain,
            'keys' => $this->keys,
            'recent_revocations_available' => $this->recentRevocationsAvailable,
        );
    }
}

class GetRevocationsRequest
{
    /** @var mixed */
    public $since;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->since = array_key_exists('since', $values) ? $values['since'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'since' => $this->since,
        );
    }
}

class GetRevocationsResponse
{
    /** @var mixed */
    public $revocations;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->revocations = array_key_exists('revocations', $values) ? $values['revocations'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'revocations' => $this->revocations,
        );
    }
}

class RecheckPinsRequest
{
    /** @var mixed */
    public $domain;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->domain = array_key_exists('domain', $values) ? $values['domain'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'domain' => $this->domain,
        );
    }
}

class PinRecheckResult
{
    /** @var mixed */
    public $domain;

    /** @var mixed */
    public $outcome;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->domain = array_key_exists('domain', $values) ? $values['domain'] : null;
        $this->outcome = array_key_exists('outcome', $values) ? $values['outcome'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'domain' => $this->domain,
            'outcome' => $this->outcome,
        );
    }
}

class RecheckPinsResponse
{
    /** @var mixed */
    public $results;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->results = array_key_exists('results', $values) ? $values['results'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'results' => $this->results,
        );
    }
}

class UserPublicKey
{
    /** @var mixed */
    public $keyId;

    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $publicKey;

    /** @var mixed */
    public $fingerprint;

    /** @var mixed */
    public $algorithm;

    /** @var mixed */
    public $keyUsage;

    /** @var mixed */
    public $createdAt;

    /** @var mixed */
    public $expiresAt;

    /** @var mixed */
    public $revokedAt;

    /** @var mixed */
    public $signedByKeyId;

    /** @var mixed */
    public $keySignature;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->keyId = array_key_exists('key_id', $values) ? $values['key_id'] : null;
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->publicKey = array_key_exists('public_key', $values) ? $values['public_key'] : null;
        $this->fingerprint = array_key_exists('fingerprint', $values) ? $values['fingerprint'] : null;
        $this->algorithm = array_key_exists('algorithm', $values) ? $values['algorithm'] : null;
        $this->keyUsage = array_key_exists('key_usage', $values) ? $values['key_usage'] : null;
        $this->createdAt = array_key_exists('created_at', $values) ? $values['created_at'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
        $this->revokedAt = array_key_exists('revoked_at', $values) ? $values['revoked_at'] : null;
        $this->signedByKeyId = array_key_exists('signed_by_key_id', $values) ? $values['signed_by_key_id'] : null;
        $this->keySignature = array_key_exists('key_signature', $values) ? $values['key_signature'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'key_id' => $this->keyId,
            'user_id' => $this->userId,
            'public_key' => $this->publicKey,
            'fingerprint' => $this->fingerprint,
            'algorithm' => $this->algorithm,
            'key_usage' => $this->keyUsage,
            'created_at' => $this->createdAt,
            'expires_at' => $this->expiresAt,
            'revoked_at' => $this->revokedAt,
            'signed_by_key_id' => $this->signedByKeyId,
            'key_signature' => $this->keySignature,
        );
    }
}

class GetUserKeysRequest
{
    /** @var mixed */
    public $userId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
        );
    }
}

class GetUserKeysResponse
{
    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $domain;

    /** @var mixed */
    public $keys;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->domain = array_key_exists('domain', $values) ? $values['domain'] : null;
        $this->keys = array_key_exists('keys', $values) ? $values['keys'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
            'domain' => $this->domain,
            'keys' => $this->keys,
        );
    }
}

class ClaimSignature
{
    /** @var mixed */
    public $domain;

    /** @var mixed */
    public $signedByKeyId;

    /** @var mixed */
    public $signature;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->domain = array_key_exists('domain', $values) ? $values['domain'] : null;
        $this->signedByKeyId = array_key_exists('signed_by_key_id', $values) ? $values['signed_by_key_id'] : null;
        $this->signature = array_key_exists('signature', $values) ? $values['signature'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'domain' => $this->domain,
            'signed_by_key_id' => $this->signedByKeyId,
            'signature' => $this->signature,
        );
    }
}

class RevocationCertificate
{
    /** @var mixed */
    public $targetKeyId;

    /** @var mixed */
    public $targetFingerprint;

    /** @var mixed */
    public $revokedAt;

    /** @var mixed */
    public $signatures;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->targetKeyId = array_key_exists('target_key_id', $values) ? $values['target_key_id'] : null;
        $this->targetFingerprint = array_key_exists('target_fingerprint', $values) ? $values['target_fingerprint'] : null;
        $this->revokedAt = array_key_exists('revoked_at', $values) ? $values['revoked_at'] : null;
        $this->signatures = array_key_exists('signatures', $values) ? $values['signatures'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'target_key_id' => $this->targetKeyId,
            'target_fingerprint' => $this->targetFingerprint,
            'revoked_at' => $this->revokedAt,
            'signatures' => $this->signatures,
        );
    }
}

class Claim
{
    /** @var mixed */
    public $claimId;

    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $claimValue;

    /** @var mixed */
    public $signatures;

    /** @var mixed */
    public $attestedAt;

    /** @var mixed */
    public $createdAt;

    /** @var mixed */
    public $expiresAt;

    /** @var mixed */
    public $revokedAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimId = array_key_exists('claim_id', $values) ? $values['claim_id'] : null;
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->claimValue = array_key_exists('claim_value', $values) ? $values['claim_value'] : null;
        $this->signatures = array_key_exists('signatures', $values) ? $values['signatures'] : null;
        $this->attestedAt = array_key_exists('attested_at', $values) ? $values['attested_at'] : null;
        $this->createdAt = array_key_exists('created_at', $values) ? $values['created_at'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
        $this->revokedAt = array_key_exists('revoked_at', $values) ? $values['revoked_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_id' => $this->claimId,
            'user_id' => $this->userId,
            'claim_type' => $this->claimType,
            'claim_value' => $this->claimValue,
            'signatures' => $this->signatures,
            'attested_at' => $this->attestedAt,
            'created_at' => $this->createdAt,
            'expires_at' => $this->expiresAt,
            'revoked_at' => $this->revokedAt,
        );
    }
}

class GetUserClaimsRequest
{
    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $token;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->token = array_key_exists('token', $values) ? $values['token'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
            'token' => $this->token,
        );
    }
}

class GetUserClaimsResponse
{
    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $domain;

    /** @var mixed */
    public $claims;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->domain = array_key_exists('domain', $values) ? $values['domain'] : null;
        $this->claims = array_key_exists('claims', $values) ? $values['claims'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
            'domain' => $this->domain,
            'claims' => $this->claims,
        );
    }
}

class RequestedClaim
{
    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $datatype;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->datatype = array_key_exists('datatype', $values) ? $values['datatype'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
            'datatype' => $this->datatype,
        );
    }
}

class ClaimRequest
{
    /** @var mixed */
    public $required;

    /** @var mixed */
    public $optional;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->required = array_key_exists('required', $values) ? $values['required'] : null;
        $this->optional = array_key_exists('optional', $values) ? $values['optional'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'required' => $this->required,
            'optional' => $this->optional,
        );
    }
}

class AuthenticationRequirements
{
    /** @var mixed */
    public $minimumFactorCount;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->minimumFactorCount = array_key_exists('minimum_factor_count', $values) ? $values['minimum_factor_count'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'minimum_factor_count' => $this->minimumFactorCount,
        );
    }
}

class AuthFlowContext
{
    /** @var mixed */
    public $flow;

    /** @var mixed */
    public $priorSession;

    /** @var mixed */
    public $requestReason;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->flow = array_key_exists('flow', $values) ? $values['flow'] : null;
        $this->priorSession = array_key_exists('prior_session', $values) ? $values['prior_session'] : null;
        $this->requestReason = array_key_exists('request_reason', $values) ? $values['request_reason'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'flow' => $this->flow,
            'prior_session' => $this->priorSession,
            'request_reason' => $this->requestReason,
        );
    }
}

class ConsentGrant
{
    /** @var mixed */
    public $grantId;

    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $subjectDomain;

    /** @var mixed */
    public $audience;

    /** @var mixed */
    public $claimTypes;

    /** @var mixed */
    public $issuedAt;

    /** @var mixed */
    public $expiresAt;

    /** @var mixed */
    public $revokedAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->grantId = array_key_exists('grant_id', $values) ? $values['grant_id'] : null;
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->subjectDomain = array_key_exists('subject_domain', $values) ? $values['subject_domain'] : null;
        $this->audience = array_key_exists('audience', $values) ? $values['audience'] : null;
        $this->claimTypes = array_key_exists('claim_types', $values) ? $values['claim_types'] : null;
        $this->issuedAt = array_key_exists('issued_at', $values) ? $values['issued_at'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
        $this->revokedAt = array_key_exists('revoked_at', $values) ? $values['revoked_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'grant_id' => $this->grantId,
            'user_id' => $this->userId,
            'subject_domain' => $this->subjectDomain,
            'audience' => $this->audience,
            'claim_types' => $this->claimTypes,
            'issued_at' => $this->issuedAt,
            'expires_at' => $this->expiresAt,
            'revoked_at' => $this->revokedAt,
        );
    }
}

class SignedConsentGrant
{
    /** @var mixed */
    public $grant;

    /** @var mixed */
    public $signatures;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->grant = array_key_exists('grant', $values) ? $values['grant'] : null;
        $this->signatures = array_key_exists('signatures', $values) ? $values['signatures'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'grant' => $this->grant,
            'signatures' => $this->signatures,
        );
    }
}

class DomainClaim
{
    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $claimValue;

    /** @var mixed */
    public $signatures;

    /** @var mixed */
    public $attestedAt;

    /** @var mixed */
    public $expiresAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->claimValue = array_key_exists('claim_value', $values) ? $values['claim_value'] : null;
        $this->signatures = array_key_exists('signatures', $values) ? $values['signatures'] : null;
        $this->attestedAt = array_key_exists('attested_at', $values) ? $values['attested_at'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
            'claim_value' => $this->claimValue,
            'signatures' => $this->signatures,
            'attested_at' => $this->attestedAt,
            'expires_at' => $this->expiresAt,
        );
    }
}

class SigningRequest
{
    /** @var mixed */
    public $requestId;

    /** @var mixed */
    public $subjectUserId;

    /** @var mixed */
    public $subjectDomain;

    /** @var mixed */
    public $issuerDomain;

    /** @var mixed */
    public $requestedClaimTypes;

    /** @var mixed */
    public $nonce;

    /** @var mixed */
    public $issuedAt;

    /** @var mixed */
    public $expiresAt;

    /** @var mixed */
    public $callback;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->requestId = array_key_exists('request_id', $values) ? $values['request_id'] : null;
        $this->subjectUserId = array_key_exists('subject_user_id', $values) ? $values['subject_user_id'] : null;
        $this->subjectDomain = array_key_exists('subject_domain', $values) ? $values['subject_domain'] : null;
        $this->issuerDomain = array_key_exists('issuer_domain', $values) ? $values['issuer_domain'] : null;
        $this->requestedClaimTypes = array_key_exists('requested_claim_types', $values) ? $values['requested_claim_types'] : null;
        $this->nonce = array_key_exists('nonce', $values) ? $values['nonce'] : null;
        $this->issuedAt = array_key_exists('issued_at', $values) ? $values['issued_at'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
        $this->callback = array_key_exists('callback', $values) ? $values['callback'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'request_id' => $this->requestId,
            'subject_user_id' => $this->subjectUserId,
            'subject_domain' => $this->subjectDomain,
            'issuer_domain' => $this->issuerDomain,
            'requested_claim_types' => $this->requestedClaimTypes,
            'nonce' => $this->nonce,
            'issued_at' => $this->issuedAt,
            'expires_at' => $this->expiresAt,
            'callback' => $this->callback,
        );
    }
}

class SignedSigningRequest
{
    /** @var mixed */
    public $request;

    /** @var mixed */
    public $signatures;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->request = array_key_exists('request', $values) ? $values['request'] : null;
        $this->signatures = array_key_exists('signatures', $values) ? $values['signatures'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'request' => $this->request,
            'signatures' => $this->signatures,
        );
    }
}

class DepositClaimRequest
{
    /** @var mixed */
    public $claim;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claim = array_key_exists('claim', $values) ? $values['claim'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim' => $this->claim,
        );
    }
}

class DepositClaimResponse
{
    /** @var mixed */
    public $stored;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->stored = array_key_exists('stored', $values) ? $values['stored'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'stored' => $this->stored,
        );
    }
}

class IdentityAssertion
{
    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $domain;

    /** @var mixed */
    public $audience;

    /** @var mixed */
    public $nonce;

    /** @var mixed */
    public $issuedAt;

    /** @var mixed */
    public $expiresAt;

    /** @var mixed */
    public $authorizedClaims;

    /** @var mixed */
    public $displayName;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->domain = array_key_exists('domain', $values) ? $values['domain'] : null;
        $this->audience = array_key_exists('audience', $values) ? $values['audience'] : null;
        $this->nonce = array_key_exists('nonce', $values) ? $values['nonce'] : null;
        $this->issuedAt = array_key_exists('issued_at', $values) ? $values['issued_at'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
        $this->authorizedClaims = array_key_exists('authorized_claims', $values) ? $values['authorized_claims'] : null;
        $this->displayName = array_key_exists('display_name', $values) ? $values['display_name'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
            'domain' => $this->domain,
            'audience' => $this->audience,
            'nonce' => $this->nonce,
            'issued_at' => $this->issuedAt,
            'expires_at' => $this->expiresAt,
            'authorized_claims' => $this->authorizedClaims,
            'display_name' => $this->displayName,
        );
    }
}

class SignedIdentityAssertion
{
    /** @var mixed */
    public $assertion;

    /** @var mixed */
    public $signingKeyId;

    /** @var mixed */
    public $signature;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->assertion = array_key_exists('assertion', $values) ? $values['assertion'] : null;
        $this->signingKeyId = array_key_exists('signing_key_id', $values) ? $values['signing_key_id'] : null;
        $this->signature = array_key_exists('signature', $values) ? $values['signature'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'assertion' => $this->assertion,
            'signing_key_id' => $this->signingKeyId,
            'signature' => $this->signature,
        );
    }
}

class GetUserInfoRequest
{
    /** @var mixed */
    public $token;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->token = array_key_exists('token', $values) ? $values['token'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'token' => $this->token,
        );
    }
}

class UserInfoRequest
{
    /** @var mixed */
    public $token;

    /** @var mixed */
    public $relyingParty;

    /** @var mixed */
    public $timestamp;

    /** @var mixed */
    public $nonce;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->token = array_key_exists('token', $values) ? $values['token'] : null;
        $this->relyingParty = array_key_exists('relying_party', $values) ? $values['relying_party'] : null;
        $this->timestamp = array_key_exists('timestamp', $values) ? $values['timestamp'] : null;
        $this->nonce = array_key_exists('nonce', $values) ? $values['nonce'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'token' => $this->token,
            'relying_party' => $this->relyingParty,
            'timestamp' => $this->timestamp,
            'nonce' => $this->nonce,
        );
    }
}

class SignedUserInfoRequest
{
    /** @var mixed */
    public $request;

    /** @var mixed */
    public $signingKeyId;

    /** @var mixed */
    public $signature;

    /** @var mixed */
    public $publicKeys;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->request = array_key_exists('request', $values) ? $values['request'] : null;
        $this->signingKeyId = array_key_exists('signing_key_id', $values) ? $values['signing_key_id'] : null;
        $this->signature = array_key_exists('signature', $values) ? $values['signature'] : null;
        $this->publicKeys = array_key_exists('public_keys', $values) ? $values['public_keys'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'request' => $this->request,
            'signing_key_id' => $this->signingKeyId,
            'signature' => $this->signature,
            'public_keys' => $this->publicKeys,
        );
    }
}

class UserInfo
{
    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $domain;

    /** @var mixed */
    public $displayName;

    /** @var mixed */
    public $claims;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->domain = array_key_exists('domain', $values) ? $values['domain'] : null;
        $this->displayName = array_key_exists('display_name', $values) ? $values['display_name'] : null;
        $this->claims = array_key_exists('claims', $values) ? $values['claims'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
            'domain' => $this->domain,
            'display_name' => $this->displayName,
            'claims' => $this->claims,
        );
    }
}

class AuthRequest
{
    /** @var mixed */
    public $relyingParty;

    /** @var mixed */
    public $callbackUrl;

    /** @var mixed */
    public $nonce;

    /** @var mixed */
    public $timestamp;

    /** @var mixed */
    public $signingKeyId;

    /** @var mixed */
    public $requestedClaims;

    /** @var mixed */
    public $authenticationRequirements;

    /** @var mixed */
    public $flowContext;

    /** @var mixed */
    public $relyingPartyClaims;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->relyingParty = array_key_exists('relying_party', $values) ? $values['relying_party'] : null;
        $this->callbackUrl = array_key_exists('callback_url', $values) ? $values['callback_url'] : null;
        $this->nonce = array_key_exists('nonce', $values) ? $values['nonce'] : null;
        $this->timestamp = array_key_exists('timestamp', $values) ? $values['timestamp'] : null;
        $this->signingKeyId = array_key_exists('signing_key_id', $values) ? $values['signing_key_id'] : null;
        $this->requestedClaims = array_key_exists('requested_claims', $values) ? $values['requested_claims'] : null;
        $this->authenticationRequirements = array_key_exists('authentication_requirements', $values) ? $values['authentication_requirements'] : null;
        $this->flowContext = array_key_exists('flow_context', $values) ? $values['flow_context'] : null;
        $this->relyingPartyClaims = array_key_exists('relying_party_claims', $values) ? $values['relying_party_claims'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'relying_party' => $this->relyingParty,
            'callback_url' => $this->callbackUrl,
            'nonce' => $this->nonce,
            'timestamp' => $this->timestamp,
            'signing_key_id' => $this->signingKeyId,
            'requested_claims' => $this->requestedClaims,
            'authentication_requirements' => $this->authenticationRequirements,
            'flow_context' => $this->flowContext,
            'relying_party_claims' => $this->relyingPartyClaims,
        );
    }
}

class SignedAuthRequest
{
    /** @var mixed */
    public $request;

    /** @var mixed */
    public $signingKeyId;

    /** @var mixed */
    public $signature;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->request = array_key_exists('request', $values) ? $values['request'] : null;
        $this->signingKeyId = array_key_exists('signing_key_id', $values) ? $values['signing_key_id'] : null;
        $this->signature = array_key_exists('signature', $values) ? $values['signature'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'request' => $this->request,
            'signing_key_id' => $this->signingKeyId,
            'signature' => $this->signature,
        );
    }
}

class EncryptedToken
{
    /** @var mixed */
    public $ephemeralPublicKey;

    /** @var mixed */
    public $ciphertext;

    /** @var mixed */
    public $nonce;

    /** @var mixed */
    public $suite;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->ephemeralPublicKey = array_key_exists('ephemeral_public_key', $values) ? $values['ephemeral_public_key'] : null;
        $this->ciphertext = array_key_exists('ciphertext', $values) ? $values['ciphertext'] : null;
        $this->nonce = array_key_exists('nonce', $values) ? $values['nonce'] : null;
        $this->suite = array_key_exists('suite', $values) ? $values['suite'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'ephemeral_public_key' => $this->ephemeralPublicKey,
            'ciphertext' => $this->ciphertext,
            'nonce' => $this->nonce,
            'suite' => $this->suite,
        );
    }
}

class AlgorithmSupport
{
    /** @var mixed */
    public $signing;

    /** @var mixed */
    public $encryption;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->signing = array_key_exists('signing', $values) ? $values['signing'] : null;
        $this->encryption = array_key_exists('encryption', $values) ? $values['encryption'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'signing' => $this->signing,
            'encryption' => $this->encryption,
        );
    }
}

class HandshakeRequest
{
    /** @var mixed */
    public $version;

    /** @var mixed */
    public $algorithms;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->version = array_key_exists('version', $values) ? $values['version'] : null;
        $this->algorithms = array_key_exists('algorithms', $values) ? $values['algorithms'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'version' => $this->version,
            'algorithms' => $this->algorithms,
        );
    }
}

class HandshakeResponse
{
    /** @var mixed */
    public $version;

    /** @var mixed */
    public $algorithms;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->version = array_key_exists('version', $values) ? $values['version'] : null;
        $this->algorithms = array_key_exists('algorithms', $values) ? $values['algorithms'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'version' => $this->version,
            'algorithms' => $this->algorithms,
        );
    }
}

class Relation
{
    /** @var mixed */
    public $id;

    /** @var mixed */
    public $subjectType;

    /** @var mixed */
    public $subjectId;

    /** @var mixed */
    public $relation;

    /** @var mixed */
    public $objectType;

    /** @var mixed */
    public $objectId;

    /** @var mixed */
    public $createdAt;

    /** @var mixed */
    public $removedAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->id = array_key_exists('id', $values) ? $values['id'] : null;
        $this->subjectType = array_key_exists('subject_type', $values) ? $values['subject_type'] : null;
        $this->subjectId = array_key_exists('subject_id', $values) ? $values['subject_id'] : null;
        $this->relation = array_key_exists('relation', $values) ? $values['relation'] : null;
        $this->objectType = array_key_exists('object_type', $values) ? $values['object_type'] : null;
        $this->objectId = array_key_exists('object_id', $values) ? $values['object_id'] : null;
        $this->createdAt = array_key_exists('created_at', $values) ? $values['created_at'] : null;
        $this->removedAt = array_key_exists('removed_at', $values) ? $values['removed_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'id' => $this->id,
            'subject_type' => $this->subjectType,
            'subject_id' => $this->subjectId,
            'relation' => $this->relation,
            'object_type' => $this->objectType,
            'object_id' => $this->objectId,
            'created_at' => $this->createdAt,
            'removed_at' => $this->removedAt,
        );
    }
}

class AdminUser
{
    /** @var mixed */
    public $id;

    /** @var mixed */
    public $username;

    /** @var mixed */
    public $displayName;

    /** @var mixed */
    public $isActive;

    /** @var mixed */
    public $createdAt;

    /** @var mixed */
    public $updatedAt;

    /** @var mixed */
    public $purgedAt;

    /** @var mixed */
    public $purgeReason;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->id = array_key_exists('id', $values) ? $values['id'] : null;
        $this->username = array_key_exists('username', $values) ? $values['username'] : null;
        $this->displayName = array_key_exists('display_name', $values) ? $values['display_name'] : null;
        $this->isActive = array_key_exists('is_active', $values) ? $values['is_active'] : null;
        $this->createdAt = array_key_exists('created_at', $values) ? $values['created_at'] : null;
        $this->updatedAt = array_key_exists('updated_at', $values) ? $values['updated_at'] : null;
        $this->purgedAt = array_key_exists('purged_at', $values) ? $values['purged_at'] : null;
        $this->purgeReason = array_key_exists('purge_reason', $values) ? $values['purge_reason'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'id' => $this->id,
            'username' => $this->username,
            'display_name' => $this->displayName,
            'is_active' => $this->isActive,
            'created_at' => $this->createdAt,
            'updated_at' => $this->updatedAt,
            'purged_at' => $this->purgedAt,
            'purge_reason' => $this->purgeReason,
        );
    }
}

class ListUsersRequest
{
    /** @var mixed */
    public $offset;

    /** @var mixed */
    public $limit;

    /** @var mixed */
    public $includePurged;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->offset = array_key_exists('offset', $values) ? $values['offset'] : null;
        $this->limit = array_key_exists('limit', $values) ? $values['limit'] : null;
        $this->includePurged = array_key_exists('include_purged', $values) ? $values['include_purged'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'offset' => $this->offset,
            'limit' => $this->limit,
            'include_purged' => $this->includePurged,
        );
    }
}

class ListUsersResponse
{
    /** @var mixed */
    public $users;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->users = array_key_exists('users', $values) ? $values['users'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'users' => $this->users,
        );
    }
}

class GetUserRequest
{
    /** @var mixed */
    public $userId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
        );
    }
}

class GetUserResponse
{
    /** @var mixed */
    public $user;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->user = array_key_exists('user', $values) ? $values['user'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user' => $this->user,
        );
    }
}

class CreateUserRequest
{
    /** @var mixed */
    public $username;

    /** @var mixed */
    public $displayName;

    /** @var mixed */
    public $password;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->username = array_key_exists('username', $values) ? $values['username'] : null;
        $this->displayName = array_key_exists('display_name', $values) ? $values['display_name'] : null;
        $this->password = array_key_exists('password', $values) ? $values['password'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'username' => $this->username,
            'display_name' => $this->displayName,
            'password' => $this->password,
        );
    }
}

class CreateUserResponse
{
    /** @var mixed */
    public $user;

    /** @var mixed */
    public $apiKey;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->user = array_key_exists('user', $values) ? $values['user'] : null;
        $this->apiKey = array_key_exists('api_key', $values) ? $values['api_key'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user' => $this->user,
            'api_key' => $this->apiKey,
        );
    }
}

class UpdateUserRequest
{
    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $displayName;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->displayName = array_key_exists('display_name', $values) ? $values['display_name'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
            'display_name' => $this->displayName,
        );
    }
}

class UpdateUserResponse
{
    /** @var mixed */
    public $user;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->user = array_key_exists('user', $values) ? $values['user'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user' => $this->user,
        );
    }
}

class DeactivateUserRequest
{
    /** @var mixed */
    public $userId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
        );
    }
}

class DeactivateUserResponse
{
    /** @var mixed */
    public $user;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->user = array_key_exists('user', $values) ? $values['user'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user' => $this->user,
        );
    }
}

class ActivateUserRequest
{
    /** @var mixed */
    public $userId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
        );
    }
}

class ActivateUserResponse
{
    /** @var mixed */
    public $user;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->user = array_key_exists('user', $values) ? $values['user'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user' => $this->user,
        );
    }
}

class PurgeUserRequest
{
    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $reason;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->reason = array_key_exists('reason', $values) ? $values['reason'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
            'reason' => $this->reason,
        );
    }
}

class PurgeUserResponse
{
    /** @var mixed */
    public $user;

    /** @var mixed */
    public $credentialsRevoked;

    /** @var mixed */
    public $keysRevoked;

    /** @var mixed */
    public $claimsRevoked;

    /** @var mixed */
    public $relationsRemoved;

    /** @var mixed */
    public $profilesDeleted;

    /** @var mixed */
    public $consentGrantsDeleted;

    /** @var mixed */
    public $releasePrefsDeleted;

    /** @var mixed */
    public $emailVerificationsDeleted;

    /** @var mixed */
    public $reviewsResolved;

    /** @var mixed */
    public $localRpClaimTicketsDeleted;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->user = array_key_exists('user', $values) ? $values['user'] : null;
        $this->credentialsRevoked = array_key_exists('credentials_revoked', $values) ? $values['credentials_revoked'] : null;
        $this->keysRevoked = array_key_exists('keys_revoked', $values) ? $values['keys_revoked'] : null;
        $this->claimsRevoked = array_key_exists('claims_revoked', $values) ? $values['claims_revoked'] : null;
        $this->relationsRemoved = array_key_exists('relations_removed', $values) ? $values['relations_removed'] : null;
        $this->profilesDeleted = array_key_exists('profiles_deleted', $values) ? $values['profiles_deleted'] : null;
        $this->consentGrantsDeleted = array_key_exists('consent_grants_deleted', $values) ? $values['consent_grants_deleted'] : null;
        $this->releasePrefsDeleted = array_key_exists('release_prefs_deleted', $values) ? $values['release_prefs_deleted'] : null;
        $this->emailVerificationsDeleted = array_key_exists('email_verifications_deleted', $values) ? $values['email_verifications_deleted'] : null;
        $this->reviewsResolved = array_key_exists('reviews_resolved', $values) ? $values['reviews_resolved'] : null;
        $this->localRpClaimTicketsDeleted = array_key_exists('local_rp_claim_tickets_deleted', $values) ? $values['local_rp_claim_tickets_deleted'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user' => $this->user,
            'credentials_revoked' => $this->credentialsRevoked,
            'keys_revoked' => $this->keysRevoked,
            'claims_revoked' => $this->claimsRevoked,
            'relations_removed' => $this->relationsRemoved,
            'profiles_deleted' => $this->profilesDeleted,
            'consent_grants_deleted' => $this->consentGrantsDeleted,
            'release_prefs_deleted' => $this->releasePrefsDeleted,
            'email_verifications_deleted' => $this->emailVerificationsDeleted,
            'reviews_resolved' => $this->reviewsResolved,
            'local_rp_claim_tickets_deleted' => $this->localRpClaimTicketsDeleted,
        );
    }
}

class RevokeDomainKeyRequest
{
    /** @var mixed */
    public $keyId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->keyId = array_key_exists('key_id', $values) ? $values['key_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'key_id' => $this->keyId,
        );
    }
}

class RevokeDomainKeyResponse
{
    /** @var mixed */
    public $revokedKey;

    /** @var mixed */
    public $certificateIssued;

    /** @var mixed */
    public $dnsRemovalReminder;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->revokedKey = array_key_exists('revoked_key', $values) ? $values['revoked_key'] : null;
        $this->certificateIssued = array_key_exists('certificate_issued', $values) ? $values['certificate_issued'] : null;
        $this->dnsRemovalReminder = array_key_exists('dns_removal_reminder', $values) ? $values['dns_removal_reminder'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'revoked_key' => $this->revokedKey,
            'certificate_issued' => $this->certificateIssued,
            'dns_removal_reminder' => $this->dnsRemovalReminder,
        );
    }
}

class ResetPasswordRequest
{
    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $newPassword;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->newPassword = array_key_exists('new_password', $values) ? $values['new_password'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
            'new_password' => $this->newPassword,
        );
    }
}

class ResetPasswordResponse
{
    /** @var mixed */
    public $success;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->success = array_key_exists('success', $values) ? $values['success'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'success' => $this->success,
        );
    }
}

class AuthenticateRequest
{
    /** @var mixed */
    public $username;

    /** @var mixed */
    public $password;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->username = array_key_exists('username', $values) ? $values['username'] : null;
        $this->password = array_key_exists('password', $values) ? $values['password'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'username' => $this->username,
            'password' => $this->password,
        );
    }
}

class AuthenticateResponse
{
    /** @var mixed */
    public $user;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->user = array_key_exists('user', $values) ? $values['user'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user' => $this->user,
        );
    }
}

class RemoveCredentialRequest
{
    /** @var mixed */
    public $credentialId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->credentialId = array_key_exists('credential_id', $values) ? $values['credential_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'credential_id' => $this->credentialId,
        );
    }
}

class RemoveCredentialResponse
{
    /** @var mixed */
    public $success;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->success = array_key_exists('success', $values) ? $values['success'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'success' => $this->success,
        );
    }
}

class SetClaimRequest
{
    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $claimValue;

    /** @var mixed */
    public $expiresAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->claimValue = array_key_exists('claim_value', $values) ? $values['claim_value'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
            'claim_type' => $this->claimType,
            'claim_value' => $this->claimValue,
            'expires_at' => $this->expiresAt,
        );
    }
}

class SetClaimResponse
{
    /** @var mixed */
    public $claim;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claim = array_key_exists('claim', $values) ? $values['claim'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim' => $this->claim,
        );
    }
}

class RemoveClaimRequest
{
    /** @var mixed */
    public $claimId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimId = array_key_exists('claim_id', $values) ? $values['claim_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_id' => $this->claimId,
        );
    }
}

class RemoveClaimResponse
{
    /** @var mixed */
    public $success;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->success = array_key_exists('success', $values) ? $values['success'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'success' => $this->success,
        );
    }
}

class ListUserClaimsRequest
{
    /** @var mixed */
    public $userId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
        );
    }
}

class ListUserClaimsResponse
{
    /** @var mixed */
    public $claimTypes;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimTypes = array_key_exists('claim_types', $values) ? $values['claim_types'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_types' => $this->claimTypes,
        );
    }
}

class AdminUserClaimsRequest
{
    /** @var mixed */
    public $userId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
        );
    }
}

class AdminUserClaimsResponse
{
    /** @var mixed */
    public $claims;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claims = array_key_exists('claims', $values) ? $values['claims'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claims' => $this->claims,
        );
    }
}

class SetUserClaimRequest
{
    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $claimValue;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->claimValue = array_key_exists('claim_value', $values) ? $values['claim_value'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
            'claim_type' => $this->claimType,
            'claim_value' => $this->claimValue,
        );
    }
}

class SetUserClaimResponse
{
    /** @var mixed */
    public $outcome;

    /** @var mixed */
    public $claim;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->outcome = array_key_exists('outcome', $values) ? $values['outcome'] : null;
        $this->claim = array_key_exists('claim', $values) ? $values['claim'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'outcome' => $this->outcome,
            'claim' => $this->claim,
        );
    }
}

class SettableClaimPolicy
{
    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $label;

    /** @var mixed */
    public $description;

    /** @var mixed */
    public $datatype;

    /** @var mixed */
    public $maxBytes;

    /** @var mixed */
    public $setRule;

    /** @var mixed */
    public $requiresApproval;

    /** @var mixed */
    public $signingRule;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->label = array_key_exists('label', $values) ? $values['label'] : null;
        $this->description = array_key_exists('description', $values) ? $values['description'] : null;
        $this->datatype = array_key_exists('datatype', $values) ? $values['datatype'] : null;
        $this->maxBytes = array_key_exists('max_bytes', $values) ? $values['max_bytes'] : null;
        $this->setRule = array_key_exists('set_rule', $values) ? $values['set_rule'] : null;
        $this->requiresApproval = array_key_exists('requires_approval', $values) ? $values['requires_approval'] : null;
        $this->signingRule = array_key_exists('signing_rule', $values) ? $values['signing_rule'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
            'label' => $this->label,
            'description' => $this->description,
            'datatype' => $this->datatype,
            'max_bytes' => $this->maxBytes,
            'set_rule' => $this->setRule,
            'requires_approval' => $this->requiresApproval,
            'signing_rule' => $this->signingRule,
        );
    }
}

class ListSettablePoliciesResponse
{
    /** @var mixed */
    public $policies;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->policies = array_key_exists('policies', $values) ? $values['policies'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'policies' => $this->policies,
        );
    }
}

class ClaimTypePolicy
{
    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $label;

    /** @var mixed */
    public $description;

    /** @var mixed */
    public $valueType;

    /** @var mixed */
    public $maxBytes;

    /** @var mixed */
    public $setRule;

    /** @var mixed */
    public $signingRule;

    /** @var mixed */
    public $requiresApproval;

    /** @var mixed */
    public $userSettable;

    /** @var mixed */
    public $defaultAutoSign;

    /** @var mixed */
    public $suggested;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->label = array_key_exists('label', $values) ? $values['label'] : null;
        $this->description = array_key_exists('description', $values) ? $values['description'] : null;
        $this->valueType = array_key_exists('value_type', $values) ? $values['value_type'] : null;
        $this->maxBytes = array_key_exists('max_bytes', $values) ? $values['max_bytes'] : null;
        $this->setRule = array_key_exists('set_rule', $values) ? $values['set_rule'] : null;
        $this->signingRule = array_key_exists('signing_rule', $values) ? $values['signing_rule'] : null;
        $this->requiresApproval = array_key_exists('requires_approval', $values) ? $values['requires_approval'] : null;
        $this->userSettable = array_key_exists('user_settable', $values) ? $values['user_settable'] : null;
        $this->defaultAutoSign = array_key_exists('default_auto_sign', $values) ? $values['default_auto_sign'] : null;
        $this->suggested = array_key_exists('suggested', $values) ? $values['suggested'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
            'label' => $this->label,
            'description' => $this->description,
            'value_type' => $this->valueType,
            'max_bytes' => $this->maxBytes,
            'set_rule' => $this->setRule,
            'signing_rule' => $this->signingRule,
            'requires_approval' => $this->requiresApproval,
            'user_settable' => $this->userSettable,
            'default_auto_sign' => $this->defaultAutoSign,
            'suggested' => $this->suggested,
        );
    }
}

class ListClaimTypesResponse
{
    /** @var mixed */
    public $claimTypes;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimTypes = array_key_exists('claim_types', $values) ? $values['claim_types'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_types' => $this->claimTypes,
        );
    }
}

class SetClaimTypeRequest
{
    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $label;

    /** @var mixed */
    public $description;

    /** @var mixed */
    public $valueType;

    /** @var mixed */
    public $maxBytes;

    /** @var mixed */
    public $setRule;

    /** @var mixed */
    public $signingRule;

    /** @var mixed */
    public $userSettable;

    /** @var mixed */
    public $defaultAutoSign;

    /** @var mixed */
    public $requiresApproval;

    /** @var mixed */
    public $suggested;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->label = array_key_exists('label', $values) ? $values['label'] : null;
        $this->description = array_key_exists('description', $values) ? $values['description'] : null;
        $this->valueType = array_key_exists('value_type', $values) ? $values['value_type'] : null;
        $this->maxBytes = array_key_exists('max_bytes', $values) ? $values['max_bytes'] : null;
        $this->setRule = array_key_exists('set_rule', $values) ? $values['set_rule'] : null;
        $this->signingRule = array_key_exists('signing_rule', $values) ? $values['signing_rule'] : null;
        $this->userSettable = array_key_exists('user_settable', $values) ? $values['user_settable'] : null;
        $this->defaultAutoSign = array_key_exists('default_auto_sign', $values) ? $values['default_auto_sign'] : null;
        $this->requiresApproval = array_key_exists('requires_approval', $values) ? $values['requires_approval'] : null;
        $this->suggested = array_key_exists('suggested', $values) ? $values['suggested'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
            'label' => $this->label,
            'description' => $this->description,
            'value_type' => $this->valueType,
            'max_bytes' => $this->maxBytes,
            'set_rule' => $this->setRule,
            'signing_rule' => $this->signingRule,
            'user_settable' => $this->userSettable,
            'default_auto_sign' => $this->defaultAutoSign,
            'requires_approval' => $this->requiresApproval,
            'suggested' => $this->suggested,
        );
    }
}

class SetClaimTypeResponse
{
    /** @var mixed */
    public $claimType;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
        );
    }
}

class RemoveClaimTypeRequest
{
    /** @var mixed */
    public $claimType;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
        );
    }
}

class RemoveClaimTypeResponse
{
    /** @var mixed */
    public $success;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->success = array_key_exists('success', $values) ? $values['success'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'success' => $this->success,
        );
    }
}

class ClaimTypeLabel
{
    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $locale;

    /** @var mixed */
    public $label;

    /** @var mixed */
    public $description;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->locale = array_key_exists('locale', $values) ? $values['locale'] : null;
        $this->label = array_key_exists('label', $values) ? $values['label'] : null;
        $this->description = array_key_exists('description', $values) ? $values['description'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
            'locale' => $this->locale,
            'label' => $this->label,
            'description' => $this->description,
        );
    }
}

class SetClaimTypeLabelRequest
{
    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $locale;

    /** @var mixed */
    public $label;

    /** @var mixed */
    public $description;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->locale = array_key_exists('locale', $values) ? $values['locale'] : null;
        $this->label = array_key_exists('label', $values) ? $values['label'] : null;
        $this->description = array_key_exists('description', $values) ? $values['description'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
            'locale' => $this->locale,
            'label' => $this->label,
            'description' => $this->description,
        );
    }
}

class SetClaimTypeLabelResponse
{
    /** @var mixed */
    public $label;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->label = array_key_exists('label', $values) ? $values['label'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'label' => $this->label,
        );
    }
}

class RemoveClaimTypeLabelRequest
{
    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $locale;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->locale = array_key_exists('locale', $values) ? $values['locale'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
            'locale' => $this->locale,
        );
    }
}

class RemoveClaimTypeLabelResponse
{
    /** @var mixed */
    public $success;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->success = array_key_exists('success', $values) ? $values['success'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'success' => $this->success,
        );
    }
}

class TrustedIssuer
{
    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $issuerDomain;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->issuerDomain = array_key_exists('issuer_domain', $values) ? $values['issuer_domain'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
            'issuer_domain' => $this->issuerDomain,
        );
    }
}

class ListTrustedIssuersResponse
{
    /** @var mixed */
    public $trustedIssuers;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->trustedIssuers = array_key_exists('trusted_issuers', $values) ? $values['trusted_issuers'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'trusted_issuers' => $this->trustedIssuers,
        );
    }
}

class AddTrustedIssuerRequest
{
    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $issuerDomain;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->issuerDomain = array_key_exists('issuer_domain', $values) ? $values['issuer_domain'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
            'issuer_domain' => $this->issuerDomain,
        );
    }
}

class AddTrustedIssuerResponse
{
    /** @var mixed */
    public $trustedIssuer;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->trustedIssuer = array_key_exists('trusted_issuer', $values) ? $values['trusted_issuer'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'trusted_issuer' => $this->trustedIssuer,
        );
    }
}

class RemoveTrustedIssuerRequest
{
    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $issuerDomain;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->issuerDomain = array_key_exists('issuer_domain', $values) ? $values['issuer_domain'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
            'issuer_domain' => $this->issuerDomain,
        );
    }
}

class RemoveTrustedIssuerResponse
{
    /** @var mixed */
    public $success;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->success = array_key_exists('success', $values) ? $values['success'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'success' => $this->success,
        );
    }
}

class ReleaseRule
{
    /** @var mixed */
    public $audience;

    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $disposition;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->audience = array_key_exists('audience', $values) ? $values['audience'] : null;
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->disposition = array_key_exists('disposition', $values) ? $values['disposition'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'audience' => $this->audience,
            'claim_type' => $this->claimType,
            'disposition' => $this->disposition,
        );
    }
}

class ListReleaseRulesResponse
{
    /** @var mixed */
    public $releaseRules;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->releaseRules = array_key_exists('release_rules', $values) ? $values['release_rules'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'release_rules' => $this->releaseRules,
        );
    }
}

class SetReleaseRuleRequest
{
    /** @var mixed */
    public $audience;

    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $disposition;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->audience = array_key_exists('audience', $values) ? $values['audience'] : null;
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->disposition = array_key_exists('disposition', $values) ? $values['disposition'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'audience' => $this->audience,
            'claim_type' => $this->claimType,
            'disposition' => $this->disposition,
        );
    }
}

class SetReleaseRuleResponse
{
    /** @var mixed */
    public $releaseRule;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->releaseRule = array_key_exists('release_rule', $values) ? $values['release_rule'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'release_rule' => $this->releaseRule,
        );
    }
}

class RemoveReleaseRuleRequest
{
    /** @var mixed */
    public $audience;

    /** @var mixed */
    public $claimType;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->audience = array_key_exists('audience', $values) ? $values['audience'] : null;
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'audience' => $this->audience,
            'claim_type' => $this->claimType,
        );
    }
}

class RemoveReleaseRuleResponse
{
    /** @var mixed */
    public $success;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->success = array_key_exists('success', $values) ? $values['success'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'success' => $this->success,
        );
    }
}

class ClaimApproval
{
    /** @var mixed */
    public $id;

    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $claimValue;

    /** @var mixed */
    public $status;

    /** @var mixed */
    public $resolvedBy;

    /** @var mixed */
    public $resolvedAt;

    /** @var mixed */
    public $createdAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->id = array_key_exists('id', $values) ? $values['id'] : null;
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->claimValue = array_key_exists('claim_value', $values) ? $values['claim_value'] : null;
        $this->status = array_key_exists('status', $values) ? $values['status'] : null;
        $this->resolvedBy = array_key_exists('resolved_by', $values) ? $values['resolved_by'] : null;
        $this->resolvedAt = array_key_exists('resolved_at', $values) ? $values['resolved_at'] : null;
        $this->createdAt = array_key_exists('created_at', $values) ? $values['created_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'id' => $this->id,
            'user_id' => $this->userId,
            'claim_type' => $this->claimType,
            'claim_value' => $this->claimValue,
            'status' => $this->status,
            'resolved_by' => $this->resolvedBy,
            'resolved_at' => $this->resolvedAt,
            'created_at' => $this->createdAt,
        );
    }
}

class ListPendingClaimApprovalsResponse
{
    /** @var mixed */
    public $approvals;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->approvals = array_key_exists('approvals', $values) ? $values['approvals'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'approvals' => $this->approvals,
        );
    }
}

class ApproveClaimRequest
{
    /** @var mixed */
    public $approvalId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->approvalId = array_key_exists('approval_id', $values) ? $values['approval_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'approval_id' => $this->approvalId,
        );
    }
}

class ApproveClaimResponse
{
    /** @var mixed */
    public $success;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->success = array_key_exists('success', $values) ? $values['success'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'success' => $this->success,
        );
    }
}

class RejectClaimRequest
{
    /** @var mixed */
    public $approvalId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->approvalId = array_key_exists('approval_id', $values) ? $values['approval_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'approval_id' => $this->approvalId,
        );
    }
}

class RejectClaimResponse
{
    /** @var mixed */
    public $success;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->success = array_key_exists('success', $values) ? $values['success'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'success' => $this->success,
        );
    }
}

class AdminIssueAttestationRequest
{
    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $claimValue;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->claimValue = array_key_exists('claim_value', $values) ? $values['claim_value'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
            'claim_type' => $this->claimType,
            'claim_value' => $this->claimValue,
        );
    }
}

class AdminIssueAttestationResponse
{
    /** @var mixed */
    public $claim;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claim = array_key_exists('claim', $values) ? $values['claim'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim' => $this->claim,
        );
    }
}

class GrantRelationRequest
{
    /** @var mixed */
    public $subjectType;

    /** @var mixed */
    public $subjectId;

    /** @var mixed */
    public $relation;

    /** @var mixed */
    public $objectType;

    /** @var mixed */
    public $objectId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->subjectType = array_key_exists('subject_type', $values) ? $values['subject_type'] : null;
        $this->subjectId = array_key_exists('subject_id', $values) ? $values['subject_id'] : null;
        $this->relation = array_key_exists('relation', $values) ? $values['relation'] : null;
        $this->objectType = array_key_exists('object_type', $values) ? $values['object_type'] : null;
        $this->objectId = array_key_exists('object_id', $values) ? $values['object_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'subject_type' => $this->subjectType,
            'subject_id' => $this->subjectId,
            'relation' => $this->relation,
            'object_type' => $this->objectType,
            'object_id' => $this->objectId,
        );
    }
}

class GrantRelationResponse
{
    /** @var mixed */
    public $relation;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->relation = array_key_exists('relation', $values) ? $values['relation'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'relation' => $this->relation,
        );
    }
}

class RemoveRelationRequest
{
    /** @var mixed */
    public $relationId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->relationId = array_key_exists('relation_id', $values) ? $values['relation_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'relation_id' => $this->relationId,
        );
    }
}

class RemoveRelationResponse
{
    /** @var mixed */
    public $success;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->success = array_key_exists('success', $values) ? $values['success'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'success' => $this->success,
        );
    }
}

class ListRelationsRequest
{
    /** @var mixed */
    public $subjectType;

    /** @var mixed */
    public $subjectId;

    /** @var mixed */
    public $objectType;

    /** @var mixed */
    public $objectId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->subjectType = array_key_exists('subject_type', $values) ? $values['subject_type'] : null;
        $this->subjectId = array_key_exists('subject_id', $values) ? $values['subject_id'] : null;
        $this->objectType = array_key_exists('object_type', $values) ? $values['object_type'] : null;
        $this->objectId = array_key_exists('object_id', $values) ? $values['object_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'subject_type' => $this->subjectType,
            'subject_id' => $this->subjectId,
            'object_type' => $this->objectType,
            'object_id' => $this->objectId,
        );
    }
}

class ListRelationsResponse
{
    /** @var mixed */
    public $relations;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->relations = array_key_exists('relations', $values) ? $values['relations'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'relations' => $this->relations,
        );
    }
}

class CheckPermissionRequest
{
    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $relation;

    /** @var mixed */
    public $objectType;

    /** @var mixed */
    public $objectId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->relation = array_key_exists('relation', $values) ? $values['relation'] : null;
        $this->objectType = array_key_exists('object_type', $values) ? $values['object_type'] : null;
        $this->objectId = array_key_exists('object_id', $values) ? $values['object_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
            'relation' => $this->relation,
            'object_type' => $this->objectType,
            'object_id' => $this->objectId,
        );
    }
}

class CheckPermissionResponse
{
    /** @var mixed */
    public $allowed;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->allowed = array_key_exists('allowed', $values) ? $values['allowed'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'allowed' => $this->allowed,
        );
    }
}

class ChangePasswordRequest
{
    /** @var mixed */
    public $currentPassword;

    /** @var mixed */
    public $newPassword;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->currentPassword = array_key_exists('current_password', $values) ? $values['current_password'] : null;
        $this->newPassword = array_key_exists('new_password', $values) ? $values['new_password'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'current_password' => $this->currentPassword,
            'new_password' => $this->newPassword,
        );
    }
}

class ChangePasswordResponse
{
    /** @var mixed */
    public $success;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->success = array_key_exists('success', $values) ? $values['success'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'success' => $this->success,
        );
    }
}

class GetMyInfoResponse
{
    /** @var mixed */
    public $user;

    /** @var mixed */
    public $relations;

    /** @var mixed */
    public $claims;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->user = array_key_exists('user', $values) ? $values['user'] : null;
        $this->relations = array_key_exists('relations', $values) ? $values['relations'] : null;
        $this->claims = array_key_exists('claims', $values) ? $values['claims'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user' => $this->user,
            'relations' => $this->relations,
            'claims' => $this->claims,
        );
    }
}

class SetMyClaimRequest
{
    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $claimValue;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->claimValue = array_key_exists('claim_value', $values) ? $values['claim_value'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
            'claim_value' => $this->claimValue,
        );
    }
}

class SetMyClaimResponse
{
    /** @var mixed */
    public $outcome;

    /** @var mixed */
    public $claim;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->outcome = array_key_exists('outcome', $values) ? $values['outcome'] : null;
        $this->claim = array_key_exists('claim', $values) ? $values['claim'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'outcome' => $this->outcome,
            'claim' => $this->claim,
        );
    }
}

class RemoveMyClaimRequest
{
    /** @var mixed */
    public $claimId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimId = array_key_exists('claim_id', $values) ? $values['claim_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_id' => $this->claimId,
        );
    }
}

class RemoveMyClaimResponse
{
    /** @var mixed */
    public $success;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->success = array_key_exists('success', $values) ? $values['success'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'success' => $this->success,
        );
    }
}

class SetMyClaimSharingRequest
{
    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $share;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->share = array_key_exists('share', $values) ? $values['share'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
            'share' => $this->share,
        );
    }
}

class SetMyClaimSharingResponse
{
    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
        );
    }
}

class Profile
{
    /** @var mixed */
    public $id;

    /** @var mixed */
    public $accountId;

    /** @var mixed */
    public $domain;

    /** @var mixed */
    public $isRoot;

    /** @var mixed */
    public $label;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->id = array_key_exists('id', $values) ? $values['id'] : null;
        $this->accountId = array_key_exists('account_id', $values) ? $values['account_id'] : null;
        $this->domain = array_key_exists('domain', $values) ? $values['domain'] : null;
        $this->isRoot = array_key_exists('is_root', $values) ? $values['is_root'] : null;
        $this->label = array_key_exists('label', $values) ? $values['label'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'id' => $this->id,
            'account_id' => $this->accountId,
            'domain' => $this->domain,
            'is_root' => $this->isRoot,
            'label' => $this->label,
        );
    }
}

class CreateProfileRequest
{
    /** @var mixed */
    public $label;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->label = array_key_exists('label', $values) ? $values['label'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'label' => $this->label,
        );
    }
}

class CreateProfileResponse
{
    /** @var mixed */
    public $profile;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->profile = array_key_exists('profile', $values) ? $values['profile'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'profile' => $this->profile,
        );
    }
}

class RequestVerificationRequest
{
    /** @var mixed */
    public $issuerDomain;

    /** @var mixed */
    public $requestedClaimTypes;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->issuerDomain = array_key_exists('issuer_domain', $values) ? $values['issuer_domain'] : null;
        $this->requestedClaimTypes = array_key_exists('requested_claim_types', $values) ? $values['requested_claim_types'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'issuer_domain' => $this->issuerDomain,
            'requested_claim_types' => $this->requestedClaimTypes,
        );
    }
}

class RequestVerificationResponse
{
    /** @var mixed */
    public $signedRequest;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->signedRequest = array_key_exists('signed_request', $values) ? $values['signed_request'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'signed_request' => $this->signedRequest,
        );
    }
}

class PasswordPolicy
{
    /** @var mixed */
    public $minLength;

    /** @var mixed */
    public $maxLength;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->minLength = array_key_exists('min_length', $values) ? $values['min_length'] : null;
        $this->maxLength = array_key_exists('max_length', $values) ? $values['max_length'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'min_length' => $this->minLength,
            'max_length' => $this->maxLength,
        );
    }
}

class BrowserSessionInfo
{
    /** @var mixed */
    public $user;

    /** @var mixed */
    public $issuedAt;

    /** @var mixed */
    public $authenticatedAt;

    /** @var mixed */
    public $expiresAt;

    /** @var mixed */
    public $authenticationMethods;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->user = array_key_exists('user', $values) ? $values['user'] : null;
        $this->issuedAt = array_key_exists('issued_at', $values) ? $values['issued_at'] : null;
        $this->authenticatedAt = array_key_exists('authenticated_at', $values) ? $values['authenticated_at'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
        $this->authenticationMethods = array_key_exists('authentication_methods', $values) ? $values['authentication_methods'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user' => $this->user,
            'issued_at' => $this->issuedAt,
            'authenticated_at' => $this->authenticatedAt,
            'expires_at' => $this->expiresAt,
            'authentication_methods' => $this->authenticationMethods,
        );
    }
}

class SessionPasswordLoginRequest
{
    /** @var mixed */
    public $username;

    /** @var mixed */
    public $password;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->username = array_key_exists('username', $values) ? $values['username'] : null;
        $this->password = array_key_exists('password', $values) ? $values['password'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'username' => $this->username,
            'password' => $this->password,
        );
    }
}

class SessionPasswordLoginResponse
{
    /** @var mixed */
    public $session;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->session = array_key_exists('session', $values) ? $values['session'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'session' => $this->session,
        );
    }
}

class SessionCurrentResponse
{
    /** @var mixed */
    public $session;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->session = array_key_exists('session', $values) ? $values['session'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'session' => $this->session,
        );
    }
}

class SessionLogoutResponse
{
    /** @var mixed */
    public $success;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->success = array_key_exists('success', $values) ? $values['success'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'success' => $this->success,
        );
    }
}

class IntrospectBrowserSessionRequest
{
    /** @var mixed */
    public $sessionCookie;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->sessionCookie = array_key_exists('session_cookie', $values) ? $values['session_cookie'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'session_cookie' => $this->sessionCookie,
        );
    }
}

class IntrospectBrowserSessionResponse
{
    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $userDomain;

    /** @var mixed */
    public $authenticatedAt;

    /** @var mixed */
    public $expiresAt;

    /** @var mixed */
    public $authenticationMethods;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->userDomain = array_key_exists('user_domain', $values) ? $values['user_domain'] : null;
        $this->authenticatedAt = array_key_exists('authenticated_at', $values) ? $values['authenticated_at'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
        $this->authenticationMethods = array_key_exists('authentication_methods', $values) ? $values['authentication_methods'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
            'user_domain' => $this->userDomain,
            'authenticated_at' => $this->authenticatedAt,
            'expires_at' => $this->expiresAt,
            'authentication_methods' => $this->authenticationMethods,
        );
    }
}

class NotificationCapability
{
    /** @var mixed */
    public $purpose;

    /** @var mixed */
    public $channel;

    /** @var mixed */
    public $destinationKind;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->purpose = array_key_exists('purpose', $values) ? $values['purpose'] : null;
        $this->channel = array_key_exists('channel', $values) ? $values['channel'] : null;
        $this->destinationKind = array_key_exists('destination_kind', $values) ? $values['destination_kind'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'purpose' => $this->purpose,
            'channel' => $this->channel,
            'destination_kind' => $this->destinationKind,
        );
    }
}

class GetNotificationCapabilitiesResponse
{
    /** @var mixed */
    public $capabilities;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->capabilities = array_key_exists('capabilities', $values) ? $values['capabilities'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'capabilities' => $this->capabilities,
        );
    }
}

class VerifiedContactMethod
{
    /** @var mixed */
    public $id;

    /** @var mixed */
    public $channel;

    /** @var mixed */
    public $destination;

    /** @var mixed */
    public $verifiedAt;

    /** @var mixed */
    public $purposes;

    /** @var mixed */
    public $revokedAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->id = array_key_exists('id', $values) ? $values['id'] : null;
        $this->channel = array_key_exists('channel', $values) ? $values['channel'] : null;
        $this->destination = array_key_exists('destination', $values) ? $values['destination'] : null;
        $this->verifiedAt = array_key_exists('verified_at', $values) ? $values['verified_at'] : null;
        $this->purposes = array_key_exists('purposes', $values) ? $values['purposes'] : null;
        $this->revokedAt = array_key_exists('revoked_at', $values) ? $values['revoked_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'id' => $this->id,
            'channel' => $this->channel,
            'destination' => $this->destination,
            'verified_at' => $this->verifiedAt,
            'purposes' => $this->purposes,
            'revoked_at' => $this->revokedAt,
        );
    }
}

class ListVerifiedContactMethodsResponse
{
    /** @var mixed */
    public $contactMethods;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->contactMethods = array_key_exists('contact_methods', $values) ? $values['contact_methods'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'contact_methods' => $this->contactMethods,
        );
    }
}

class RevokeVerifiedContactMethodRequest
{
    /** @var mixed */
    public $contactMethodId;

    /** @var mixed */
    public $currentPassword;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->contactMethodId = array_key_exists('contact_method_id', $values) ? $values['contact_method_id'] : null;
        $this->currentPassword = array_key_exists('current_password', $values) ? $values['current_password'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'contact_method_id' => $this->contactMethodId,
            'current_password' => $this->currentPassword,
        );
    }
}

class RevokeVerifiedContactMethodResponse
{
    /** @var mixed */
    public $success;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->success = array_key_exists('success', $values) ? $values['success'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'success' => $this->success,
        );
    }
}

class RequestContactVerificationRequest
{
    /** @var mixed */
    public $channel;

    /** @var mixed */
    public $destination;

    /** @var mixed */
    public $currentPassword;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->channel = array_key_exists('channel', $values) ? $values['channel'] : null;
        $this->destination = array_key_exists('destination', $values) ? $values['destination'] : null;
        $this->currentPassword = array_key_exists('current_password', $values) ? $values['current_password'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'channel' => $this->channel,
            'destination' => $this->destination,
            'current_password' => $this->currentPassword,
        );
    }
}

class RequestContactVerificationResponse
{
    /** @var mixed */
    public $expiresAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'expires_at' => $this->expiresAt,
        );
    }
}

class ConfirmContactVerificationRequest
{
    /** @var mixed */
    public $token;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->token = array_key_exists('token', $values) ? $values['token'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'token' => $this->token,
        );
    }
}

class ConfirmContactVerificationResponse
{
    /** @var mixed */
    public $contactMethod;

    /** @var mixed */
    public $claims;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->contactMethod = array_key_exists('contact_method', $values) ? $values['contact_method'] : null;
        $this->claims = array_key_exists('claims', $values) ? $values['claims'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'contact_method' => $this->contactMethod,
            'claims' => $this->claims,
        );
    }
}

class RequestPasswordRecoveryRequest
{
    /** @var mixed */
    public $identifier;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->identifier = array_key_exists('identifier', $values) ? $values['identifier'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'identifier' => $this->identifier,
        );
    }
}

class RequestPasswordRecoveryResponse
{
    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
        );
    }
}

class ValidatePasswordRecoveryRequest
{
    /** @var mixed */
    public $token;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->token = array_key_exists('token', $values) ? $values['token'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'token' => $this->token,
        );
    }
}

class ValidatePasswordRecoveryResponse
{
    /** @var mixed */
    public $expiresAt;

    /** @var mixed */
    public $passwordPolicy;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
        $this->passwordPolicy = array_key_exists('password_policy', $values) ? $values['password_policy'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'expires_at' => $this->expiresAt,
            'password_policy' => $this->passwordPolicy,
        );
    }
}

class CompletePasswordRecoveryRequest
{
    /** @var mixed */
    public $token;

    /** @var mixed */
    public $newPassword;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->token = array_key_exists('token', $values) ? $values['token'] : null;
        $this->newPassword = array_key_exists('new_password', $values) ? $values['new_password'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'token' => $this->token,
            'new_password' => $this->newPassword,
        );
    }
}

class CompletePasswordRecoveryResponse
{
    /** @var mixed */
    public $success;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->success = array_key_exists('success', $values) ? $values['success'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'success' => $this->success,
        );
    }
}

class BrowserAuthorizationInspectRequest
{
    /** @var mixed */
    public $signedRequest;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->signedRequest = array_key_exists('signed_request', $values) ? $values['signed_request'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'signed_request' => $this->signedRequest,
        );
    }
}

class BrowserConsentClaim
{
    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $label;

    /** @var mixed */
    public $datatype;

    /** @var mixed */
    public $required;

    /** @var mixed */
    public $available;

    /** @var mixed */
    public $defaultGranted;

    /** @var mixed */
    public $policy;

    /** @var mixed */
    public $userSettable;

    /** @var mixed */
    public $maxBytes;

    /** @var mixed */
    public $requiresApproval;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->label = array_key_exists('label', $values) ? $values['label'] : null;
        $this->datatype = array_key_exists('datatype', $values) ? $values['datatype'] : null;
        $this->required = array_key_exists('required', $values) ? $values['required'] : null;
        $this->available = array_key_exists('available', $values) ? $values['available'] : null;
        $this->defaultGranted = array_key_exists('default_granted', $values) ? $values['default_granted'] : null;
        $this->policy = array_key_exists('policy', $values) ? $values['policy'] : null;
        $this->userSettable = array_key_exists('user_settable', $values) ? $values['user_settable'] : null;
        $this->maxBytes = array_key_exists('max_bytes', $values) ? $values['max_bytes'] : null;
        $this->requiresApproval = array_key_exists('requires_approval', $values) ? $values['requires_approval'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
            'label' => $this->label,
            'datatype' => $this->datatype,
            'required' => $this->required,
            'available' => $this->available,
            'default_granted' => $this->defaultGranted,
            'policy' => $this->policy,
            'user_settable' => $this->userSettable,
            'max_bytes' => $this->maxBytes,
            'requires_approval' => $this->requiresApproval,
        );
    }
}

class BrowserAuthorizationInspectResponse
{
    /** @var mixed */
    public $relyingParty;

    /** @var mixed */
    public $claims;

    /** @var mixed */
    public $requestReason;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->relyingParty = array_key_exists('relying_party', $values) ? $values['relying_party'] : null;
        $this->claims = array_key_exists('claims', $values) ? $values['claims'] : null;
        $this->requestReason = array_key_exists('request_reason', $values) ? $values['request_reason'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'relying_party' => $this->relyingParty,
            'claims' => $this->claims,
            'request_reason' => $this->requestReason,
        );
    }
}

class BrowserAuthorizationCompleteRequest
{
    /** @var mixed */
    public $signedRequest;

    /** @var mixed */
    public $authorizedClaims;

    /** @var mixed */
    public $claimTypesToSet;

    /** @var mixed */
    public $claimValuesToSet;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->signedRequest = array_key_exists('signed_request', $values) ? $values['signed_request'] : null;
        $this->authorizedClaims = array_key_exists('authorized_claims', $values) ? $values['authorized_claims'] : null;
        $this->claimTypesToSet = array_key_exists('claim_types_to_set', $values) ? $values['claim_types_to_set'] : null;
        $this->claimValuesToSet = array_key_exists('claim_values_to_set', $values) ? $values['claim_values_to_set'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'signed_request' => $this->signedRequest,
            'authorized_claims' => $this->authorizedClaims,
            'claim_types_to_set' => $this->claimTypesToSet,
            'claim_values_to_set' => $this->claimValuesToSet,
        );
    }
}

class BrowserAuthorizationCompleteResponse
{
    /** @var mixed */
    public $redirectUrl;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->redirectUrl = array_key_exists('redirect_url', $values) ? $values['redirect_url'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'redirect_url' => $this->redirectUrl,
        );
    }
}

class UiTheme
{
    /** @var mixed */
    public $stylesheetUrl;

    /** @var mixed */
    public $logoUrl;

    /** @var mixed */
    public $faviconUrl;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->stylesheetUrl = array_key_exists('stylesheet_url', $values) ? $values['stylesheet_url'] : null;
        $this->logoUrl = array_key_exists('logo_url', $values) ? $values['logo_url'] : null;
        $this->faviconUrl = array_key_exists('favicon_url', $values) ? $values['favicon_url'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'stylesheet_url' => $this->stylesheetUrl,
            'logo_url' => $this->logoUrl,
            'favicon_url' => $this->faviconUrl,
        );
    }
}

class UiExtension
{
    /** @var mixed */
    public $id;

    /** @var mixed */
    public $moduleUrl;

    /** @var mixed */
    public $apiVersion;

    /** @var mixed */
    public $stylesheetUrl;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->id = array_key_exists('id', $values) ? $values['id'] : null;
        $this->moduleUrl = array_key_exists('module_url', $values) ? $values['module_url'] : null;
        $this->apiVersion = array_key_exists('api_version', $values) ? $values['api_version'] : null;
        $this->stylesheetUrl = array_key_exists('stylesheet_url', $values) ? $values['stylesheet_url'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'id' => $this->id,
            'module_url' => $this->moduleUrl,
            'api_version' => $this->apiVersion,
            'stylesheet_url' => $this->stylesheetUrl,
        );
    }
}

class UiDisplaySettings
{
    /** @var mixed */
    public $siteName;

    /** @var mixed */
    public $supportUrl;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->siteName = array_key_exists('site_name', $values) ? $values['site_name'] : null;
        $this->supportUrl = array_key_exists('support_url', $values) ? $values['support_url'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'site_name' => $this->siteName,
            'support_url' => $this->supportUrl,
        );
    }
}

class GetUiConfigurationResponse
{
    /** @var mixed */
    public $hostApiVersion;

    /** @var mixed */
    public $domain;

    /** @var mixed */
    public $publicOrigin;

    /** @var mixed */
    public $capabilities;

    /** @var mixed */
    public $display;

    /** @var mixed */
    public $theme;

    /** @var mixed */
    public $extensions;

    /** @var mixed */
    public $passwordPolicy;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->hostApiVersion = array_key_exists('host_api_version', $values) ? $values['host_api_version'] : null;
        $this->domain = array_key_exists('domain', $values) ? $values['domain'] : null;
        $this->publicOrigin = array_key_exists('public_origin', $values) ? $values['public_origin'] : null;
        $this->capabilities = array_key_exists('capabilities', $values) ? $values['capabilities'] : null;
        $this->display = array_key_exists('display', $values) ? $values['display'] : null;
        $this->theme = array_key_exists('theme', $values) ? $values['theme'] : null;
        $this->extensions = array_key_exists('extensions', $values) ? $values['extensions'] : null;
        $this->passwordPolicy = array_key_exists('password_policy', $values) ? $values['password_policy'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'host_api_version' => $this->hostApiVersion,
            'domain' => $this->domain,
            'public_origin' => $this->publicOrigin,
            'capabilities' => $this->capabilities,
            'display' => $this->display,
            'theme' => $this->theme,
            'extensions' => $this->extensions,
            'password_policy' => $this->passwordPolicy,
        );
    }
}

class RpSignRequest
{
    /** @var mixed */
    public $callbackUrl;

    /** @var mixed */
    public $nonce;

    /** @var mixed */
    public $requestedClaims;

    /** @var mixed */
    public $authenticationRequirements;

    /** @var mixed */
    public $flowContext;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->callbackUrl = array_key_exists('callback_url', $values) ? $values['callback_url'] : null;
        $this->nonce = array_key_exists('nonce', $values) ? $values['nonce'] : null;
        $this->requestedClaims = array_key_exists('requested_claims', $values) ? $values['requested_claims'] : null;
        $this->authenticationRequirements = array_key_exists('authentication_requirements', $values) ? $values['authentication_requirements'] : null;
        $this->flowContext = array_key_exists('flow_context', $values) ? $values['flow_context'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'callback_url' => $this->callbackUrl,
            'nonce' => $this->nonce,
            'requested_claims' => $this->requestedClaims,
            'authentication_requirements' => $this->authenticationRequirements,
            'flow_context' => $this->flowContext,
        );
    }
}

class RpSignResponse
{
    /** @var mixed */
    public $signedRequest;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->signedRequest = array_key_exists('signed_request', $values) ? $values['signed_request'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'signed_request' => $this->signedRequest,
        );
    }
}

class RpDecryptRequest
{
    /** @var mixed */
    public $encryptedToken;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->encryptedToken = array_key_exists('encrypted_token', $values) ? $values['encrypted_token'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'encrypted_token' => $this->encryptedToken,
        );
    }
}

class RpDecryptResponse
{
    /** @var mixed */
    public $signedAssertion;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->signedAssertion = array_key_exists('signed_assertion', $values) ? $values['signed_assertion'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'signed_assertion' => $this->signedAssertion,
        );
    }
}

class RpVerifyRequest
{
    /** @var mixed */
    public $signedAssertion;

    /** @var mixed */
    public $expectedDomain;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->signedAssertion = array_key_exists('signed_assertion', $values) ? $values['signed_assertion'] : null;
        $this->expectedDomain = array_key_exists('expected_domain', $values) ? $values['expected_domain'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'signed_assertion' => $this->signedAssertion,
            'expected_domain' => $this->expectedDomain,
        );
    }
}

class RpVerifyResponse
{
    /** @var mixed */
    public $assertion;

    /** @var mixed */
    public $verified;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->assertion = array_key_exists('assertion', $values) ? $values['assertion'] : null;
        $this->verified = array_key_exists('verified', $values) ? $values['verified'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'assertion' => $this->assertion,
            'verified' => $this->verified,
        );
    }
}

class RpUserInfoRequest
{
    /** @var mixed */
    public $token;

    /** @var mixed */
    public $apiBase;

    /** @var mixed */
    public $domain;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->token = array_key_exists('token', $values) ? $values['token'] : null;
        $this->apiBase = array_key_exists('api_base', $values) ? $values['api_base'] : null;
        $this->domain = array_key_exists('domain', $values) ? $values['domain'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'token' => $this->token,
            'api_base' => $this->apiBase,
            'domain' => $this->domain,
        );
    }
}

class RpIssueAttestationRequest
{
    /** @var mixed */
    public $signedRequest;

    /** @var mixed */
    public $claimType;

    /** @var mixed */
    public $claimValue;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->signedRequest = array_key_exists('signed_request', $values) ? $values['signed_request'] : null;
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->claimValue = array_key_exists('claim_value', $values) ? $values['claim_value'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'signed_request' => $this->signedRequest,
            'claim_type' => $this->claimType,
            'claim_value' => $this->claimValue,
        );
    }
}

class RpIssueAttestationResponse
{
    /** @var mixed */
    public $claim;

    /** @var mixed */
    public $deposited;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claim = array_key_exists('claim', $values) ? $values['claim'] : null;
        $this->deposited = array_key_exists('deposited', $values) ? $values['deposited'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim' => $this->claim,
            'deposited' => $this->deposited,
        );
    }
}

class AuthorizeValidateRequest
{
    /** @var mixed */
    public $signedRequest;

    /** @var mixed */
    public $userId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->signedRequest = array_key_exists('signed_request', $values) ? $values['signed_request'] : null;
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'signed_request' => $this->signedRequest,
            'user_id' => $this->userId,
        );
    }
}

class AuthorizeValidateResponse
{
    /** @var mixed */
    public $relyingParty;

    /** @var mixed */
    public $callbackUrl;

    /** @var mixed */
    public $requestedClaims;

    /** @var mixed */
    public $alreadyConsented;

    /** @var mixed */
    public $authorizedClaims;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->relyingParty = array_key_exists('relying_party', $values) ? $values['relying_party'] : null;
        $this->callbackUrl = array_key_exists('callback_url', $values) ? $values['callback_url'] : null;
        $this->requestedClaims = array_key_exists('requested_claims', $values) ? $values['requested_claims'] : null;
        $this->alreadyConsented = array_key_exists('already_consented', $values) ? $values['already_consented'] : null;
        $this->authorizedClaims = array_key_exists('authorized_claims', $values) ? $values['authorized_claims'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'relying_party' => $this->relyingParty,
            'callback_url' => $this->callbackUrl,
            'requested_claims' => $this->requestedClaims,
            'already_consented' => $this->alreadyConsented,
            'authorized_claims' => $this->authorizedClaims,
        );
    }
}

class AuthorizeFinalizeRequest
{
    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $signedRequest;

    /** @var mixed */
    public $authorizedClaims;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->signedRequest = array_key_exists('signed_request', $values) ? $values['signed_request'] : null;
        $this->authorizedClaims = array_key_exists('authorized_claims', $values) ? $values['authorized_claims'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
            'signed_request' => $this->signedRequest,
            'authorized_claims' => $this->authorizedClaims,
        );
    }
}

class AuthorizeFinalizeResponse
{
    /** @var mixed */
    public $redirectUrl;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->redirectUrl = array_key_exists('redirect_url', $values) ? $values['redirect_url'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'redirect_url' => $this->redirectUrl,
        );
    }
}

class ApiError
{
    /** @var mixed */
    public $code;

    /** @var mixed */
    public $message;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->code = array_key_exists('code', $values) ? $values['code'] : null;
        $this->message = array_key_exists('message', $values) ? $values['message'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'code' => $this->code,
            'message' => $this->message,
        );
    }
}

class LocalRpDescriptor
{
    /** @var mixed */
    public $appName;

    /** @var mixed */
    public $localDomainHint;

    /** @var mixed */
    public $signingPublicKey;

    /** @var mixed */
    public $encryptionPublicKey;

    /** @var mixed */
    public $fingerprint;

    /** @var mixed */
    public $supportedSuites;

    /** @var mixed */
    public $createdAt;

    /** @var mixed */
    public $expiresAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->appName = array_key_exists('app_name', $values) ? $values['app_name'] : null;
        $this->localDomainHint = array_key_exists('local_domain_hint', $values) ? $values['local_domain_hint'] : null;
        $this->signingPublicKey = array_key_exists('signing_public_key', $values) ? $values['signing_public_key'] : null;
        $this->encryptionPublicKey = array_key_exists('encryption_public_key', $values) ? $values['encryption_public_key'] : null;
        $this->fingerprint = array_key_exists('fingerprint', $values) ? $values['fingerprint'] : null;
        $this->supportedSuites = array_key_exists('supported_suites', $values) ? $values['supported_suites'] : null;
        $this->createdAt = array_key_exists('created_at', $values) ? $values['created_at'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'app_name' => $this->appName,
            'local_domain_hint' => $this->localDomainHint,
            'signing_public_key' => $this->signingPublicKey,
            'encryption_public_key' => $this->encryptionPublicKey,
            'fingerprint' => $this->fingerprint,
            'supported_suites' => $this->supportedSuites,
            'created_at' => $this->createdAt,
            'expires_at' => $this->expiresAt,
        );
    }
}

class SignedLocalRpDescriptor
{
    /** @var mixed */
    public $descriptor;

    /** @var mixed */
    public $signature;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->descriptor = array_key_exists('descriptor', $values) ? $values['descriptor'] : null;
        $this->signature = array_key_exists('signature', $values) ? $values['signature'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'descriptor' => $this->descriptor,
            'signature' => $this->signature,
        );
    }
}

class LocalRpLoginRequest
{
    /** @var mixed */
    public $descriptor;

    /** @var mixed */
    public $callbackUrl;

    /** @var mixed */
    public $nonce;

    /** @var mixed */
    public $state;

    /** @var mixed */
    public $requestedClaims;

    /** @var mixed */
    public $requiredClaims;

    /** @var mixed */
    public $authenticationRequirements;

    /** @var mixed */
    public $flowContext;

    /** @var mixed */
    public $issuedAt;

    /** @var mixed */
    public $expiresAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->descriptor = array_key_exists('descriptor', $values) ? $values['descriptor'] : null;
        $this->callbackUrl = array_key_exists('callback_url', $values) ? $values['callback_url'] : null;
        $this->nonce = array_key_exists('nonce', $values) ? $values['nonce'] : null;
        $this->state = array_key_exists('state', $values) ? $values['state'] : null;
        $this->requestedClaims = array_key_exists('requested_claims', $values) ? $values['requested_claims'] : null;
        $this->requiredClaims = array_key_exists('required_claims', $values) ? $values['required_claims'] : null;
        $this->authenticationRequirements = array_key_exists('authentication_requirements', $values) ? $values['authentication_requirements'] : null;
        $this->flowContext = array_key_exists('flow_context', $values) ? $values['flow_context'] : null;
        $this->issuedAt = array_key_exists('issued_at', $values) ? $values['issued_at'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'descriptor' => $this->descriptor,
            'callback_url' => $this->callbackUrl,
            'nonce' => $this->nonce,
            'state' => $this->state,
            'requested_claims' => $this->requestedClaims,
            'required_claims' => $this->requiredClaims,
            'authentication_requirements' => $this->authenticationRequirements,
            'flow_context' => $this->flowContext,
            'issued_at' => $this->issuedAt,
            'expires_at' => $this->expiresAt,
        );
    }
}

class SignedLocalRpLoginRequest
{
    /** @var mixed */
    public $request;

    /** @var mixed */
    public $signature;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->request = array_key_exists('request', $values) ? $values['request'] : null;
        $this->signature = array_key_exists('signature', $values) ? $values['signature'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'request' => $this->request,
            'signature' => $this->signature,
        );
    }
}

class LocalRpCallbackHeader
{
    /** @var mixed */
    public $fingerprint;

    /** @var mixed */
    public $nonce;

    /** @var mixed */
    public $state;

    /** @var mixed */
    public $suite;

    /** @var mixed */
    public $ephemeralPublicKey;

    /** @var mixed */
    public $aeadNonce;

    /** @var mixed */
    public $issuedAt;

    /** @var mixed */
    public $expiresAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->fingerprint = array_key_exists('fingerprint', $values) ? $values['fingerprint'] : null;
        $this->nonce = array_key_exists('nonce', $values) ? $values['nonce'] : null;
        $this->state = array_key_exists('state', $values) ? $values['state'] : null;
        $this->suite = array_key_exists('suite', $values) ? $values['suite'] : null;
        $this->ephemeralPublicKey = array_key_exists('ephemeral_public_key', $values) ? $values['ephemeral_public_key'] : null;
        $this->aeadNonce = array_key_exists('aead_nonce', $values) ? $values['aead_nonce'] : null;
        $this->issuedAt = array_key_exists('issued_at', $values) ? $values['issued_at'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'fingerprint' => $this->fingerprint,
            'nonce' => $this->nonce,
            'state' => $this->state,
            'suite' => $this->suite,
            'ephemeral_public_key' => $this->ephemeralPublicKey,
            'aead_nonce' => $this->aeadNonce,
            'issued_at' => $this->issuedAt,
            'expires_at' => $this->expiresAt,
        );
    }
}

class LocalRpEncryptedCallback
{
    /** @var mixed */
    public $header;

    /** @var mixed */
    public $ciphertext;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->header = array_key_exists('header', $values) ? $values['header'] : null;
        $this->ciphertext = array_key_exists('ciphertext', $values) ? $values['ciphertext'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'header' => $this->header,
            'ciphertext' => $this->ciphertext,
        );
    }
}

class LocalRpCallbackPayload
{
    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $userDomain;

    /** @var mixed */
    public $claimTicket;

    /** @var mixed */
    public $audienceFingerprint;

    /** @var mixed */
    public $callbackUrl;

    /** @var mixed */
    public $nonce;

    /** @var mixed */
    public $state;

    /** @var mixed */
    public $issuedAt;

    /** @var mixed */
    public $expiresAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->userDomain = array_key_exists('user_domain', $values) ? $values['user_domain'] : null;
        $this->claimTicket = array_key_exists('claim_ticket', $values) ? $values['claim_ticket'] : null;
        $this->audienceFingerprint = array_key_exists('audience_fingerprint', $values) ? $values['audience_fingerprint'] : null;
        $this->callbackUrl = array_key_exists('callback_url', $values) ? $values['callback_url'] : null;
        $this->nonce = array_key_exists('nonce', $values) ? $values['nonce'] : null;
        $this->state = array_key_exists('state', $values) ? $values['state'] : null;
        $this->issuedAt = array_key_exists('issued_at', $values) ? $values['issued_at'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
            'user_domain' => $this->userDomain,
            'claim_ticket' => $this->claimTicket,
            'audience_fingerprint' => $this->audienceFingerprint,
            'callback_url' => $this->callbackUrl,
            'nonce' => $this->nonce,
            'state' => $this->state,
            'issued_at' => $this->issuedAt,
            'expires_at' => $this->expiresAt,
        );
    }
}

class SignedLocalRpCallbackPayload
{
    /** @var mixed */
    public $payload;

    /** @var mixed */
    public $signingKeyId;

    /** @var mixed */
    public $signature;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->payload = array_key_exists('payload', $values) ? $values['payload'] : null;
        $this->signingKeyId = array_key_exists('signing_key_id', $values) ? $values['signing_key_id'] : null;
        $this->signature = array_key_exists('signature', $values) ? $values['signature'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'payload' => $this->payload,
            'signing_key_id' => $this->signingKeyId,
            'signature' => $this->signature,
        );
    }
}

class LocalRpTicketRedemptionRequest
{
    /** @var mixed */
    public $claimTicket;

    /** @var mixed */
    public $fingerprint;

    /** @var mixed */
    public $issuedAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimTicket = array_key_exists('claim_ticket', $values) ? $values['claim_ticket'] : null;
        $this->fingerprint = array_key_exists('fingerprint', $values) ? $values['fingerprint'] : null;
        $this->issuedAt = array_key_exists('issued_at', $values) ? $values['issued_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_ticket' => $this->claimTicket,
            'fingerprint' => $this->fingerprint,
            'issued_at' => $this->issuedAt,
        );
    }
}

class SignedLocalRpTicketRedemptionRequest
{
    /** @var mixed */
    public $request;

    /** @var mixed */
    public $signature;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->request = array_key_exists('request', $values) ? $values['request'] : null;
        $this->signature = array_key_exists('signature', $values) ? $values['signature'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'request' => $this->request,
            'signature' => $this->signature,
        );
    }
}

class LocalRpTicketRedemptionResponse
{
    /** @var mixed */
    public $userId;

    /** @var mixed */
    public $userDomain;

    /** @var mixed */
    public $claims;

    /** @var mixed */
    public $ticketExpiresAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->userId = array_key_exists('user_id', $values) ? $values['user_id'] : null;
        $this->userDomain = array_key_exists('user_domain', $values) ? $values['user_domain'] : null;
        $this->claims = array_key_exists('claims', $values) ? $values['claims'] : null;
        $this->ticketExpiresAt = array_key_exists('ticket_expires_at', $values) ? $values['ticket_expires_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'user_id' => $this->userId,
            'user_domain' => $this->userDomain,
            'claims' => $this->claims,
            'ticket_expires_at' => $this->ticketExpiresAt,
        );
    }
}

class AdminLocalRp
{
    /** @var mixed */
    public $fingerprint;

    /** @var mixed */
    public $signingPublicKey;

    /** @var mixed */
    public $encryptionPublicKey;

    /** @var mixed */
    public $appName;

    /** @var mixed */
    public $localDomainHint;

    /** @var mixed */
    public $status;

    /** @var mixed */
    public $createdAt;

    /** @var mixed */
    public $updatedAt;

    /** @var mixed */
    public $expiresAt;

    /** @var mixed */
    public $lastSeenAt;

    /** @var mixed */
    public $adminNotes;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->fingerprint = array_key_exists('fingerprint', $values) ? $values['fingerprint'] : null;
        $this->signingPublicKey = array_key_exists('signing_public_key', $values) ? $values['signing_public_key'] : null;
        $this->encryptionPublicKey = array_key_exists('encryption_public_key', $values) ? $values['encryption_public_key'] : null;
        $this->appName = array_key_exists('app_name', $values) ? $values['app_name'] : null;
        $this->localDomainHint = array_key_exists('local_domain_hint', $values) ? $values['local_domain_hint'] : null;
        $this->status = array_key_exists('status', $values) ? $values['status'] : null;
        $this->createdAt = array_key_exists('created_at', $values) ? $values['created_at'] : null;
        $this->updatedAt = array_key_exists('updated_at', $values) ? $values['updated_at'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
        $this->lastSeenAt = array_key_exists('last_seen_at', $values) ? $values['last_seen_at'] : null;
        $this->adminNotes = array_key_exists('admin_notes', $values) ? $values['admin_notes'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'fingerprint' => $this->fingerprint,
            'signing_public_key' => $this->signingPublicKey,
            'encryption_public_key' => $this->encryptionPublicKey,
            'app_name' => $this->appName,
            'local_domain_hint' => $this->localDomainHint,
            'status' => $this->status,
            'created_at' => $this->createdAt,
            'updated_at' => $this->updatedAt,
            'expires_at' => $this->expiresAt,
            'last_seen_at' => $this->lastSeenAt,
            'admin_notes' => $this->adminNotes,
        );
    }
}

class ListLocalRpsRequest
{
    /** @var mixed */
    public $offset;

    /** @var mixed */
    public $limit;

    /** @var mixed */
    public $status;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->offset = array_key_exists('offset', $values) ? $values['offset'] : null;
        $this->limit = array_key_exists('limit', $values) ? $values['limit'] : null;
        $this->status = array_key_exists('status', $values) ? $values['status'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'offset' => $this->offset,
            'limit' => $this->limit,
            'status' => $this->status,
        );
    }
}

class ListLocalRpsResponse
{
    /** @var mixed */
    public $localRps;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->localRps = array_key_exists('local_rps', $values) ? $values['local_rps'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'local_rps' => $this->localRps,
        );
    }
}

class GetLocalRpRequest
{
    /** @var mixed */
    public $fingerprint;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->fingerprint = array_key_exists('fingerprint', $values) ? $values['fingerprint'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'fingerprint' => $this->fingerprint,
        );
    }
}

class GetLocalRpResponse
{
    /** @var mixed */
    public $localRp;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->localRp = array_key_exists('local_rp', $values) ? $values['local_rp'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'local_rp' => $this->localRp,
        );
    }
}

class ApproveLocalRpRequest
{
    /** @var mixed */
    public $fingerprint;

    /** @var mixed */
    public $adminNotes;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->fingerprint = array_key_exists('fingerprint', $values) ? $values['fingerprint'] : null;
        $this->adminNotes = array_key_exists('admin_notes', $values) ? $values['admin_notes'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'fingerprint' => $this->fingerprint,
            'admin_notes' => $this->adminNotes,
        );
    }
}

class ApproveLocalRpResponse
{
    /** @var mixed */
    public $localRp;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->localRp = array_key_exists('local_rp', $values) ? $values['local_rp'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'local_rp' => $this->localRp,
        );
    }
}

class DenyLocalRpRequest
{
    /** @var mixed */
    public $fingerprint;

    /** @var mixed */
    public $adminNotes;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->fingerprint = array_key_exists('fingerprint', $values) ? $values['fingerprint'] : null;
        $this->adminNotes = array_key_exists('admin_notes', $values) ? $values['admin_notes'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'fingerprint' => $this->fingerprint,
            'admin_notes' => $this->adminNotes,
        );
    }
}

class DenyLocalRpResponse
{
    /** @var mixed */
    public $localRp;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->localRp = array_key_exists('local_rp', $values) ? $values['local_rp'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'local_rp' => $this->localRp,
        );
    }
}

class RevokeLocalRpRequest
{
    /** @var mixed */
    public $fingerprint;

    /** @var mixed */
    public $adminNotes;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->fingerprint = array_key_exists('fingerprint', $values) ? $values['fingerprint'] : null;
        $this->adminNotes = array_key_exists('admin_notes', $values) ? $values['admin_notes'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'fingerprint' => $this->fingerprint,
            'admin_notes' => $this->adminNotes,
        );
    }
}

class RevokeLocalRpResponse
{
    /** @var mixed */
    public $localRp;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->localRp = array_key_exists('local_rp', $values) ? $values['local_rp'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'local_rp' => $this->localRp,
        );
    }
}

class GetLocalRpPolicyRequest
{
    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
        );
    }
}

class GetLocalRpPolicyResponse
{
    /** @var mixed */
    public $policy;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->policy = array_key_exists('policy', $values) ? $values['policy'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'policy' => $this->policy,
        );
    }
}

class SetLocalRpPolicyRequest
{
    /** @var mixed */
    public $policy;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->policy = array_key_exists('policy', $values) ? $values['policy'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'policy' => $this->policy,
        );
    }
}

class SetLocalRpPolicyResponse
{
    /** @var mixed */
    public $policy;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->policy = array_key_exists('policy', $values) ? $values['policy'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'policy' => $this->policy,
        );
    }
}

class PurgeLocalRpTicketsRequest
{
    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
        );
    }
}

class PurgeLocalRpTicketsResponse
{
    /** @var mixed */
    public $purgedCount;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->purgedCount = array_key_exists('purged_count', $values) ? $values['purged_count'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'purged_count' => $this->purgedCount,
        );
    }
}

class TranslationsRequest
{
    /** @var mixed */
    public $locale;

    /** @var mixed */
    public $acceptLanguage;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->locale = array_key_exists('locale', $values) ? $values['locale'] : null;
        $this->acceptLanguage = array_key_exists('accept_language', $values) ? $values['accept_language'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'locale' => $this->locale,
            'accept_language' => $this->acceptLanguage,
        );
    }
}

class TranslationsResponse
{
    /** @var mixed */
    public $locale;

    /** @var mixed */
    public $availableLocales;

    /** @var mixed */
    public $messages;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->locale = array_key_exists('locale', $values) ? $values['locale'] : null;
        $this->availableLocales = array_key_exists('available_locales', $values) ? $values['available_locales'] : null;
        $this->messages = array_key_exists('messages', $values) ? $values['messages'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'locale' => $this->locale,
            'available_locales' => $this->availableLocales,
            'messages' => $this->messages,
        );
    }
}

class ListLocalesResponse
{
    /** @var mixed */
    public $availableLocales;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->availableLocales = array_key_exists('available_locales', $values) ? $values['available_locales'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'available_locales' => $this->availableLocales,
        );
    }
}

class ApplicationKeySignature
{
    /** @var mixed */
    public $signedByKeyId;

    /** @var mixed */
    public $signature;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->signedByKeyId = array_key_exists('signed_by_key_id', $values) ? $values['signed_by_key_id'] : null;
        $this->signature = array_key_exists('signature', $values) ? $values['signature'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'signed_by_key_id' => $this->signedByKeyId,
            'signature' => $this->signature,
        );
    }
}

class ApplicationKeyAttestation
{
    /** @var mixed */
    public $subjectUserId;

    /** @var mixed */
    public $subjectDomain;

    /** @var mixed */
    public $applicationId;

    /** @var mixed */
    public $instanceId;

    /** @var mixed */
    public $keyId;

    /** @var mixed */
    public $keyUsage;

    /** @var mixed */
    public $algorithm;

    /** @var mixed */
    public $publicKey;

    /** @var mixed */
    public $fingerprint;

    /** @var mixed */
    public $keyCreatedAt;

    /** @var mixed */
    public $keyExpiresAt;

    /** @var mixed */
    public $attestedAt;

    /** @var mixed */
    public $attestationExpiresAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->subjectUserId = array_key_exists('subject_user_id', $values) ? $values['subject_user_id'] : null;
        $this->subjectDomain = array_key_exists('subject_domain', $values) ? $values['subject_domain'] : null;
        $this->applicationId = array_key_exists('application_id', $values) ? $values['application_id'] : null;
        $this->instanceId = array_key_exists('instance_id', $values) ? $values['instance_id'] : null;
        $this->keyId = array_key_exists('key_id', $values) ? $values['key_id'] : null;
        $this->keyUsage = array_key_exists('key_usage', $values) ? $values['key_usage'] : null;
        $this->algorithm = array_key_exists('algorithm', $values) ? $values['algorithm'] : null;
        $this->publicKey = array_key_exists('public_key', $values) ? $values['public_key'] : null;
        $this->fingerprint = array_key_exists('fingerprint', $values) ? $values['fingerprint'] : null;
        $this->keyCreatedAt = array_key_exists('key_created_at', $values) ? $values['key_created_at'] : null;
        $this->keyExpiresAt = array_key_exists('key_expires_at', $values) ? $values['key_expires_at'] : null;
        $this->attestedAt = array_key_exists('attested_at', $values) ? $values['attested_at'] : null;
        $this->attestationExpiresAt = array_key_exists('attestation_expires_at', $values) ? $values['attestation_expires_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'subject_user_id' => $this->subjectUserId,
            'subject_domain' => $this->subjectDomain,
            'application_id' => $this->applicationId,
            'instance_id' => $this->instanceId,
            'key_id' => $this->keyId,
            'key_usage' => $this->keyUsage,
            'algorithm' => $this->algorithm,
            'public_key' => $this->publicKey,
            'fingerprint' => $this->fingerprint,
            'key_created_at' => $this->keyCreatedAt,
            'key_expires_at' => $this->keyExpiresAt,
            'attested_at' => $this->attestedAt,
            'attestation_expires_at' => $this->attestationExpiresAt,
        );
    }
}

class SignedApplicationKeyAttestation
{
    /** @var mixed */
    public $attestation;

    /** @var mixed */
    public $signatures;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->attestation = array_key_exists('attestation', $values) ? $values['attestation'] : null;
        $this->signatures = array_key_exists('signatures', $values) ? $values['signatures'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'attestation' => $this->attestation,
            'signatures' => $this->signatures,
        );
    }
}

class ApplicationKeyAddition
{
    /** @var mixed */
    public $subjectUserId;

    /** @var mixed */
    public $subjectDomain;

    /** @var mixed */
    public $applicationId;

    /** @var mixed */
    public $instanceId;

    /** @var mixed */
    public $keyId;

    /** @var mixed */
    public $keyUsage;

    /** @var mixed */
    public $algorithm;

    /** @var mixed */
    public $publicKey;

    /** @var mixed */
    public $fingerprint;

    /** @var mixed */
    public $requestedKeyLifetimeSeconds;

    /** @var mixed */
    public $challengeId;

    /** @var mixed */
    public $challenge;

    /** @var mixed */
    public $requestedAt;

    /** @var mixed */
    public $expiresAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->subjectUserId = array_key_exists('subject_user_id', $values) ? $values['subject_user_id'] : null;
        $this->subjectDomain = array_key_exists('subject_domain', $values) ? $values['subject_domain'] : null;
        $this->applicationId = array_key_exists('application_id', $values) ? $values['application_id'] : null;
        $this->instanceId = array_key_exists('instance_id', $values) ? $values['instance_id'] : null;
        $this->keyId = array_key_exists('key_id', $values) ? $values['key_id'] : null;
        $this->keyUsage = array_key_exists('key_usage', $values) ? $values['key_usage'] : null;
        $this->algorithm = array_key_exists('algorithm', $values) ? $values['algorithm'] : null;
        $this->publicKey = array_key_exists('public_key', $values) ? $values['public_key'] : null;
        $this->fingerprint = array_key_exists('fingerprint', $values) ? $values['fingerprint'] : null;
        $this->requestedKeyLifetimeSeconds = array_key_exists('requested_key_lifetime_seconds', $values) ? $values['requested_key_lifetime_seconds'] : null;
        $this->challengeId = array_key_exists('challenge_id', $values) ? $values['challenge_id'] : null;
        $this->challenge = array_key_exists('challenge', $values) ? $values['challenge'] : null;
        $this->requestedAt = array_key_exists('requested_at', $values) ? $values['requested_at'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'subject_user_id' => $this->subjectUserId,
            'subject_domain' => $this->subjectDomain,
            'application_id' => $this->applicationId,
            'instance_id' => $this->instanceId,
            'key_id' => $this->keyId,
            'key_usage' => $this->keyUsage,
            'algorithm' => $this->algorithm,
            'public_key' => $this->publicKey,
            'fingerprint' => $this->fingerprint,
            'requested_key_lifetime_seconds' => $this->requestedKeyLifetimeSeconds,
            'challenge_id' => $this->challengeId,
            'challenge' => $this->challenge,
            'requested_at' => $this->requestedAt,
            'expires_at' => $this->expiresAt,
        );
    }
}

class SignedApplicationKeyAddition
{
    /** @var mixed */
    public $addition;

    /** @var mixed */
    public $signatures;

    /** @var mixed */
    public $possessionProof;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->addition = array_key_exists('addition', $values) ? $values['addition'] : null;
        $this->signatures = array_key_exists('signatures', $values) ? $values['signatures'] : null;
        $this->possessionProof = array_key_exists('possession_proof', $values) ? $values['possession_proof'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'addition' => $this->addition,
            'signatures' => $this->signatures,
            'possession_proof' => $this->possessionProof,
        );
    }
}

class ApplicationKeyRenewal
{
    /** @var mixed */
    public $subjectUserId;

    /** @var mixed */
    public $subjectDomain;

    /** @var mixed */
    public $applicationId;

    /** @var mixed */
    public $instanceId;

    /** @var mixed */
    public $keyId;

    /** @var mixed */
    public $challengeId;

    /** @var mixed */
    public $challenge;

    /** @var mixed */
    public $requestedAt;

    /** @var mixed */
    public $expiresAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->subjectUserId = array_key_exists('subject_user_id', $values) ? $values['subject_user_id'] : null;
        $this->subjectDomain = array_key_exists('subject_domain', $values) ? $values['subject_domain'] : null;
        $this->applicationId = array_key_exists('application_id', $values) ? $values['application_id'] : null;
        $this->instanceId = array_key_exists('instance_id', $values) ? $values['instance_id'] : null;
        $this->keyId = array_key_exists('key_id', $values) ? $values['key_id'] : null;
        $this->challengeId = array_key_exists('challenge_id', $values) ? $values['challenge_id'] : null;
        $this->challenge = array_key_exists('challenge', $values) ? $values['challenge'] : null;
        $this->requestedAt = array_key_exists('requested_at', $values) ? $values['requested_at'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'subject_user_id' => $this->subjectUserId,
            'subject_domain' => $this->subjectDomain,
            'application_id' => $this->applicationId,
            'instance_id' => $this->instanceId,
            'key_id' => $this->keyId,
            'challenge_id' => $this->challengeId,
            'challenge' => $this->challenge,
            'requested_at' => $this->requestedAt,
            'expires_at' => $this->expiresAt,
        );
    }
}

class SignedApplicationKeyRenewal
{
    /** @var mixed */
    public $renewal;

    /** @var mixed */
    public $signatures;

    /** @var mixed */
    public $possessionProof;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->renewal = array_key_exists('renewal', $values) ? $values['renewal'] : null;
        $this->signatures = array_key_exists('signatures', $values) ? $values['signatures'] : null;
        $this->possessionProof = array_key_exists('possession_proof', $values) ? $values['possession_proof'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'renewal' => $this->renewal,
            'signatures' => $this->signatures,
            'possession_proof' => $this->possessionProof,
        );
    }
}

class ApplicationKeyRevocation
{
    /** @var mixed */
    public $subjectUserId;

    /** @var mixed */
    public $subjectDomain;

    /** @var mixed */
    public $applicationId;

    /** @var mixed */
    public $instanceId;

    /** @var mixed */
    public $targetKeyId;

    /** @var mixed */
    public $targetFingerprint;

    /** @var mixed */
    public $revokedAt;

    /** @var mixed */
    public $signatures;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->subjectUserId = array_key_exists('subject_user_id', $values) ? $values['subject_user_id'] : null;
        $this->subjectDomain = array_key_exists('subject_domain', $values) ? $values['subject_domain'] : null;
        $this->applicationId = array_key_exists('application_id', $values) ? $values['application_id'] : null;
        $this->instanceId = array_key_exists('instance_id', $values) ? $values['instance_id'] : null;
        $this->targetKeyId = array_key_exists('target_key_id', $values) ? $values['target_key_id'] : null;
        $this->targetFingerprint = array_key_exists('target_fingerprint', $values) ? $values['target_fingerprint'] : null;
        $this->revokedAt = array_key_exists('revoked_at', $values) ? $values['revoked_at'] : null;
        $this->signatures = array_key_exists('signatures', $values) ? $values['signatures'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'subject_user_id' => $this->subjectUserId,
            'subject_domain' => $this->subjectDomain,
            'application_id' => $this->applicationId,
            'instance_id' => $this->instanceId,
            'target_key_id' => $this->targetKeyId,
            'target_fingerprint' => $this->targetFingerprint,
            'revoked_at' => $this->revokedAt,
            'signatures' => $this->signatures,
        );
    }
}

class StartApplicationKeyChallengeRequest
{
    /** @var mixed */
    public $subjectUserId;

    /** @var mixed */
    public $applicationId;

    /** @var mixed */
    public $instanceId;

    /** @var mixed */
    public $purpose;

    /** @var mixed */
    public $keyUsage;

    /** @var mixed */
    public $algorithm;

    /** @var mixed */
    public $publicKey;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->subjectUserId = array_key_exists('subject_user_id', $values) ? $values['subject_user_id'] : null;
        $this->applicationId = array_key_exists('application_id', $values) ? $values['application_id'] : null;
        $this->instanceId = array_key_exists('instance_id', $values) ? $values['instance_id'] : null;
        $this->purpose = array_key_exists('purpose', $values) ? $values['purpose'] : null;
        $this->keyUsage = array_key_exists('key_usage', $values) ? $values['key_usage'] : null;
        $this->algorithm = array_key_exists('algorithm', $values) ? $values['algorithm'] : null;
        $this->publicKey = array_key_exists('public_key', $values) ? $values['public_key'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'subject_user_id' => $this->subjectUserId,
            'application_id' => $this->applicationId,
            'instance_id' => $this->instanceId,
            'purpose' => $this->purpose,
            'key_usage' => $this->keyUsage,
            'algorithm' => $this->algorithm,
            'public_key' => $this->publicKey,
        );
    }
}

class StartApplicationKeyChallengeResponse
{
    /** @var mixed */
    public $challengeId;

    /** @var mixed */
    public $challenge;

    /** @var mixed */
    public $sealedChallenge;

    /** @var mixed */
    public $expiresAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->challengeId = array_key_exists('challenge_id', $values) ? $values['challenge_id'] : null;
        $this->challenge = array_key_exists('challenge', $values) ? $values['challenge'] : null;
        $this->sealedChallenge = array_key_exists('sealed_challenge', $values) ? $values['sealed_challenge'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'challenge_id' => $this->challengeId,
            'challenge' => $this->challenge,
            'sealed_challenge' => $this->sealedChallenge,
            'expires_at' => $this->expiresAt,
        );
    }
}

class AddApplicationKeyRequest
{
    /** @var mixed */
    public $request;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->request = array_key_exists('request', $values) ? $values['request'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'request' => $this->request,
        );
    }
}

class AddApplicationKeyResponse
{
    /** @var mixed */
    public $attestation;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->attestation = array_key_exists('attestation', $values) ? $values['attestation'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'attestation' => $this->attestation,
        );
    }
}

class RenewApplicationKeyAttestationRequest
{
    /** @var mixed */
    public $request;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->request = array_key_exists('request', $values) ? $values['request'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'request' => $this->request,
        );
    }
}

class RenewApplicationKeyAttestationResponse
{
    /** @var mixed */
    public $attestation;

    /** @var mixed */
    public $signed;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->attestation = array_key_exists('attestation', $values) ? $values['attestation'] : null;
        $this->signed = array_key_exists('signed', $values) ? $values['signed'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'attestation' => $this->attestation,
            'signed' => $this->signed,
        );
    }
}

class RevokeApplicationKeyRequest
{
    /** @var mixed */
    public $revocation;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->revocation = array_key_exists('revocation', $values) ? $values['revocation'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'revocation' => $this->revocation,
        );
    }
}

class RevokeApplicationKeyResponse
{
    /** @var mixed */
    public $revokedAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->revokedAt = array_key_exists('revoked_at', $values) ? $values['revoked_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'revoked_at' => $this->revokedAt,
        );
    }
}

class EnrollApplicationInstanceRequest
{
    /** @var mixed */
    public $applicationId;

    /** @var mixed */
    public $instanceId;

    /** @var mixed */
    public $keys;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->applicationId = array_key_exists('application_id', $values) ? $values['application_id'] : null;
        $this->instanceId = array_key_exists('instance_id', $values) ? $values['instance_id'] : null;
        $this->keys = array_key_exists('keys', $values) ? $values['keys'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'application_id' => $this->applicationId,
            'instance_id' => $this->instanceId,
            'keys' => $this->keys,
        );
    }
}

class EnrollApplicationInstanceResponse
{
    /** @var mixed */
    public $subjectUserId;

    /** @var mixed */
    public $subjectDomain;

    /** @var mixed */
    public $applicationId;

    /** @var mixed */
    public $instanceId;

    /** @var mixed */
    public $attestations;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->subjectUserId = array_key_exists('subject_user_id', $values) ? $values['subject_user_id'] : null;
        $this->subjectDomain = array_key_exists('subject_domain', $values) ? $values['subject_domain'] : null;
        $this->applicationId = array_key_exists('application_id', $values) ? $values['application_id'] : null;
        $this->instanceId = array_key_exists('instance_id', $values) ? $values['instance_id'] : null;
        $this->attestations = array_key_exists('attestations', $values) ? $values['attestations'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'subject_user_id' => $this->subjectUserId,
            'subject_domain' => $this->subjectDomain,
            'application_id' => $this->applicationId,
            'instance_id' => $this->instanceId,
            'attestations' => $this->attestations,
        );
    }
}

class GetApplicationKeysRequest
{
    /** @var mixed */
    public $subjectUserId;

    /** @var mixed */
    public $applicationId;

    /** @var mixed */
    public $instanceId;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->subjectUserId = array_key_exists('subject_user_id', $values) ? $values['subject_user_id'] : null;
        $this->applicationId = array_key_exists('application_id', $values) ? $values['application_id'] : null;
        $this->instanceId = array_key_exists('instance_id', $values) ? $values['instance_id'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'subject_user_id' => $this->subjectUserId,
            'application_id' => $this->applicationId,
            'instance_id' => $this->instanceId,
        );
    }
}

class GetApplicationKeysResponse
{
    /** @var mixed */
    public $subjectUserId;

    /** @var mixed */
    public $subjectDomain;

    /** @var mixed */
    public $applicationId;

    /** @var mixed */
    public $instanceId;

    /** @var mixed */
    public $keys;

    /** @var mixed */
    public $revocations;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->subjectUserId = array_key_exists('subject_user_id', $values) ? $values['subject_user_id'] : null;
        $this->subjectDomain = array_key_exists('subject_domain', $values) ? $values['subject_domain'] : null;
        $this->applicationId = array_key_exists('application_id', $values) ? $values['application_id'] : null;
        $this->instanceId = array_key_exists('instance_id', $values) ? $values['instance_id'] : null;
        $this->keys = array_key_exists('keys', $values) ? $values['keys'] : null;
        $this->revocations = array_key_exists('revocations', $values) ? $values['revocations'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'subject_user_id' => $this->subjectUserId,
            'subject_domain' => $this->subjectDomain,
            'application_id' => $this->applicationId,
            'instance_id' => $this->instanceId,
            'keys' => $this->keys,
            'revocations' => $this->revocations,
        );
    }
}

class RpResolveDomainKeysRequest
{
    /** @var mixed */
    public $domain;

    /** @var mixed */
    public $maxCacheAgeSeconds;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->domain = array_key_exists('domain', $values) ? $values['domain'] : null;
        $this->maxCacheAgeSeconds = array_key_exists('max_cache_age_seconds', $values) ? $values['max_cache_age_seconds'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'domain' => $this->domain,
            'max_cache_age_seconds' => $this->maxCacheAgeSeconds,
        );
    }
}

class RpResolveDomainKeysResponse
{
    /** @var mixed */
    public $domain;

    /** @var mixed */
    public $keys;

    /** @var mixed */
    public $revocations;

    /** @var mixed */
    public $fetchedAt;

    /** @var mixed */
    public $revocationsCheckedAt;

    /** @var mixed */
    public $cacheStatus;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->domain = array_key_exists('domain', $values) ? $values['domain'] : null;
        $this->keys = array_key_exists('keys', $values) ? $values['keys'] : null;
        $this->revocations = array_key_exists('revocations', $values) ? $values['revocations'] : null;
        $this->fetchedAt = array_key_exists('fetched_at', $values) ? $values['fetched_at'] : null;
        $this->revocationsCheckedAt = array_key_exists('revocations_checked_at', $values) ? $values['revocations_checked_at'] : null;
        $this->cacheStatus = array_key_exists('cache_status', $values) ? $values['cache_status'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'domain' => $this->domain,
            'keys' => $this->keys,
            'revocations' => $this->revocations,
            'fetched_at' => $this->fetchedAt,
            'revocations_checked_at' => $this->revocationsCheckedAt,
            'cache_status' => $this->cacheStatus,
        );
    }
}

class RpResolveApplicationKeysRequest
{
    /** @var mixed */
    public $subjectUserId;

    /** @var mixed */
    public $subjectDomain;

    /** @var mixed */
    public $applicationId;

    /** @var mixed */
    public $instanceId;

    /** @var mixed */
    public $maxCacheAgeSeconds;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->subjectUserId = array_key_exists('subject_user_id', $values) ? $values['subject_user_id'] : null;
        $this->subjectDomain = array_key_exists('subject_domain', $values) ? $values['subject_domain'] : null;
        $this->applicationId = array_key_exists('application_id', $values) ? $values['application_id'] : null;
        $this->instanceId = array_key_exists('instance_id', $values) ? $values['instance_id'] : null;
        $this->maxCacheAgeSeconds = array_key_exists('max_cache_age_seconds', $values) ? $values['max_cache_age_seconds'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'subject_user_id' => $this->subjectUserId,
            'subject_domain' => $this->subjectDomain,
            'application_id' => $this->applicationId,
            'instance_id' => $this->instanceId,
            'max_cache_age_seconds' => $this->maxCacheAgeSeconds,
        );
    }
}

class RpResolveApplicationKeysResponse
{
    /** @var mixed */
    public $subjectUserId;

    /** @var mixed */
    public $subjectDomain;

    /** @var mixed */
    public $applicationId;

    /** @var mixed */
    public $instanceId;

    /** @var mixed */
    public $applicationKeys;

    /** @var mixed */
    public $applicationKeyRevocations;

    /** @var mixed */
    public $homeDomainKeys;

    /** @var mixed */
    public $homeDomainKeyRevocations;

    /** @var mixed */
    public $fetchedAt;

    /** @var mixed */
    public $revocationsCheckedAt;

    /** @var mixed */
    public $cacheStatus;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->subjectUserId = array_key_exists('subject_user_id', $values) ? $values['subject_user_id'] : null;
        $this->subjectDomain = array_key_exists('subject_domain', $values) ? $values['subject_domain'] : null;
        $this->applicationId = array_key_exists('application_id', $values) ? $values['application_id'] : null;
        $this->instanceId = array_key_exists('instance_id', $values) ? $values['instance_id'] : null;
        $this->applicationKeys = array_key_exists('application_keys', $values) ? $values['application_keys'] : null;
        $this->applicationKeyRevocations = array_key_exists('application_key_revocations', $values) ? $values['application_key_revocations'] : null;
        $this->homeDomainKeys = array_key_exists('home_domain_keys', $values) ? $values['home_domain_keys'] : null;
        $this->homeDomainKeyRevocations = array_key_exists('home_domain_key_revocations', $values) ? $values['home_domain_key_revocations'] : null;
        $this->fetchedAt = array_key_exists('fetched_at', $values) ? $values['fetched_at'] : null;
        $this->revocationsCheckedAt = array_key_exists('revocations_checked_at', $values) ? $values['revocations_checked_at'] : null;
        $this->cacheStatus = array_key_exists('cache_status', $values) ? $values['cache_status'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'subject_user_id' => $this->subjectUserId,
            'subject_domain' => $this->subjectDomain,
            'application_id' => $this->applicationId,
            'instance_id' => $this->instanceId,
            'application_keys' => $this->applicationKeys,
            'application_key_revocations' => $this->applicationKeyRevocations,
            'home_domain_keys' => $this->homeDomainKeys,
            'home_domain_key_revocations' => $this->homeDomainKeyRevocations,
            'fetched_at' => $this->fetchedAt,
            'revocations_checked_at' => $this->revocationsCheckedAt,
            'cache_status' => $this->cacheStatus,
        );
    }
}

