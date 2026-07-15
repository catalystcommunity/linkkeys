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
    public $expiresAt;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->claimType = array_key_exists('claim_type', $values) ? $values['claim_type'] : null;
        $this->claimValue = array_key_exists('claim_value', $values) ? $values['claim_value'] : null;
        $this->signatures = array_key_exists('signatures', $values) ? $values['signatures'] : null;
        $this->expiresAt = array_key_exists('expires_at', $values) ? $values['expires_at'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
            'claim_value' => $this->claimValue,
            'signatures' => $this->signatures,
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

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->id = array_key_exists('id', $values) ? $values['id'] : null;
        $this->username = array_key_exists('username', $values) ? $values['username'] : null;
        $this->displayName = array_key_exists('display_name', $values) ? $values['display_name'] : null;
        $this->isActive = array_key_exists('is_active', $values) ? $values['is_active'] : null;
        $this->createdAt = array_key_exists('created_at', $values) ? $values['created_at'] : null;
        $this->updatedAt = array_key_exists('updated_at', $values) ? $values['updated_at'] : null;
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
        );
    }
}

class ListUsersRequest
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
    public $datatype;

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
        $this->datatype = array_key_exists('datatype', $values) ? $values['datatype'] : null;
        $this->setRule = array_key_exists('set_rule', $values) ? $values['set_rule'] : null;
        $this->requiresApproval = array_key_exists('requires_approval', $values) ? $values['requires_approval'] : null;
        $this->signingRule = array_key_exists('signing_rule', $values) ? $values['signing_rule'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'claim_type' => $this->claimType,
            'datatype' => $this->datatype,
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
    public $newPassword;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->newPassword = array_key_exists('new_password', $values) ? $values['new_password'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
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

class RpSignRequest
{
    /** @var mixed */
    public $callbackUrl;

    /** @var mixed */
    public $nonce;

    /** @var mixed */
    public $requestedClaims;

    /** @var mixed */
    public $flowContext;

    /** @param array<string,mixed> $values */
    public function __construct(array $values = array())
    {
        $this->callbackUrl = array_key_exists('callback_url', $values) ? $values['callback_url'] : null;
        $this->nonce = array_key_exists('nonce', $values) ? $values['nonce'] : null;
        $this->requestedClaims = array_key_exists('requested_claims', $values) ? $values['requested_claims'] : null;
        $this->flowContext = array_key_exists('flow_context', $values) ? $values['flow_context'] : null;
    }

    /** @return array<string,mixed> */
    public function toArray()
    {
        return array(
            'callback_url' => $this->callbackUrl,
            'nonce' => $this->nonce,
            'requested_claims' => $this->requestedClaims,
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

