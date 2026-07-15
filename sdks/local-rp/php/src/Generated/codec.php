<?php

namespace Csilgen\Generated;

use Csilgen\Transport\CBOR;

/** Raised when decoded CBOR does not match the declared CSIL shape (unknown enum
 * member, tagged-sum literal-arm mismatch, or malformed union envelope). */
class CodecException extends \RuntimeException {}

class Codec
{
    public static function encodeValue($value)
    {
        return CBOR::encode($value);
    }

    public static function decodeValue($bytes)
    {
        return CBOR::decode($bytes);
    }

    public static function toCborValue($value)
    {
        return $value;
    }

    public static function fromCborValue($value)
    {
        return $value;
    }

    /** A literal-typed union/enum arm carries no shape of its own on the wire — the
     * variant index (or the bare value itself for an enum) already selects it — so
     * decode only needs to confirm the payload equals the declared literal. */
    public static function expectLiteral($value, $expected)
    {
        if ($value !== $expected) {
            throw new CodecException('csil cbor: literal mismatch, expected ' . var_export($expected, true) . ', got ' . var_export($value, true));
        }
        return $value;
    }

    public static function encodeCheckValue($value)
    {
        return CBOR::encode(self::toCborCheckValue($value));
    }

    public static function decodeCheckValue($bytes)
    {
        return self::fromCborCheckValue(CBOR::decode($bytes));
    }

    public static function toCborCheckValue($value)
    {
        if (is_string($value)) {
            return array(0, $value);
        }
        if (is_int($value)) {
            return array(1, $value);
        }
        if (is_float($value)) {
            return array(2, $value);
        }
        throw new CodecException('csil cbor: value does not match any CheckValue variant');
    }

    public static function fromCborCheckValue($value)
    {
        if (!is_array($value) || count($value) !== 2) {
            throw new CodecException('csil cbor: CheckValue union expects a 2-element array');
        }
        $csilIdx = $value[0];
        $csilVal = $value[1];
        if ($csilIdx === 0) {
            return $csilVal;
        }
        if ($csilIdx === 1) {
            return $csilVal;
        }
        if ($csilIdx === 2) {
            return $csilVal;
        }
        throw new CodecException('csil cbor: unknown CheckValue variant ' . var_export($csilIdx, true));
    }

    public static function encodeCheckEntries($value)
    {
        return CBOR::encode(self::toCborCheckEntries($value));
    }

    public static function decodeCheckEntries($bytes)
    {
        return self::fromCborCheckEntries(CBOR::decode($bytes));
    }

    public static function toCborCheckEntries($value)
    {
        return (function ($m) { $out = array(); foreach (($m === null ? array() : $m) as $k => $v) { $out[$k] = self::toCborCheckValue($v); } return $out; })($value);
    }

    public static function fromCborCheckEntries($value)
    {
        return (function ($m) { $out = array(); foreach (($m === null ? array() : $m) as $k => $v) { $out[$k] = self::fromCborCheckValue($v); } return $out; })($value);
    }

    public static function encodeCheckResult($value)
    {
        return CBOR::encode(self::toCborCheckResult($value));
    }

    public static function decodeCheckResult($bytes)
    {
        return self::fromCborCheckResult(CBOR::decode($bytes));
    }

    public static function toCborCheckResult($value)
    {
        $out = array();
        $field = $value instanceof CheckResult ? $value->result : (is_array($value) && array_key_exists('result', $value) ? $value['result'] : null);
        $out['result'] = $field;
        $field = $value instanceof CheckResult ? $value->entries : (is_array($value) && array_key_exists('entries', $value) ? $value['entries'] : null);
        $out['entries'] = $field;
        return $out;
    }

    public static function fromCborCheckResult($value)
    {
        return new CheckResult(array(
            'result' => array_key_exists('result', $value) ? $value['result'] : null,
            'entries' => array_key_exists('entries', $value) ? $value['entries'] : null,
        ));
    }

    public static function encodeHelloRequest($value)
    {
        return CBOR::encode(self::toCborHelloRequest($value));
    }

    public static function decodeHelloRequest($bytes)
    {
        return self::fromCborHelloRequest(CBOR::decode($bytes));
    }

    public static function toCborHelloRequest($value)
    {
        $out = array();
        $field = $value instanceof HelloRequest ? $value->name : (is_array($value) && array_key_exists('name', $value) ? $value['name'] : null);
        if ($field !== null) {
            $out['name'] = $field;
        }
        return $out;
    }

    public static function fromCborHelloRequest($value)
    {
        return new HelloRequest(array(
            'name' => array_key_exists('name', $value) ? $value['name'] : null,
        ));
    }

    public static function encodeHelloResponse($value)
    {
        return CBOR::encode(self::toCborHelloResponse($value));
    }

    public static function decodeHelloResponse($bytes)
    {
        return self::fromCborHelloResponse(CBOR::decode($bytes));
    }

    public static function toCborHelloResponse($value)
    {
        $out = array();
        $field = $value instanceof HelloResponse ? $value->greeting : (is_array($value) && array_key_exists('greeting', $value) ? $value['greeting'] : null);
        $out['greeting'] = $field;
        return $out;
    }

    public static function fromCborHelloResponse($value)
    {
        return new HelloResponse(array(
            'greeting' => array_key_exists('greeting', $value) ? $value['greeting'] : null,
        ));
    }

    public static function encodeGuestbookEntry($value)
    {
        return CBOR::encode(self::toCborGuestbookEntry($value));
    }

    public static function decodeGuestbookEntry($bytes)
    {
        return self::fromCborGuestbookEntry(CBOR::decode($bytes));
    }

    public static function toCborGuestbookEntry($value)
    {
        $out = array();
        $field = $value instanceof GuestbookEntry ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof GuestbookEntry ? $value->name : (is_array($value) && array_key_exists('name', $value) ? $value['name'] : null);
        $out['name'] = $field;
        $field = $value instanceof GuestbookEntry ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = $field;
        $field = $value instanceof GuestbookEntry ? $value->updatedAt : (is_array($value) && array_key_exists('updated_at', $value) ? $value['updated_at'] : null);
        $out['updated_at'] = $field;
        return $out;
    }

    public static function fromCborGuestbookEntry($value)
    {
        return new GuestbookEntry(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'name' => array_key_exists('name', $value) ? $value['name'] : null,
            'created_at' => array_key_exists('created_at', $value) ? $value['created_at'] : null,
            'updated_at' => array_key_exists('updated_at', $value) ? $value['updated_at'] : null,
        ));
    }

    public static function encodeCreateGuestbookRequest($value)
    {
        return CBOR::encode(self::toCborCreateGuestbookRequest($value));
    }

    public static function decodeCreateGuestbookRequest($bytes)
    {
        return self::fromCborCreateGuestbookRequest(CBOR::decode($bytes));
    }

    public static function toCborCreateGuestbookRequest($value)
    {
        $out = array();
        $field = $value instanceof CreateGuestbookRequest ? $value->name : (is_array($value) && array_key_exists('name', $value) ? $value['name'] : null);
        $out['name'] = $field;
        return $out;
    }

    public static function fromCborCreateGuestbookRequest($value)
    {
        return new CreateGuestbookRequest(array(
            'name' => array_key_exists('name', $value) ? $value['name'] : null,
        ));
    }

    public static function encodeUpdateGuestbookRequest($value)
    {
        return CBOR::encode(self::toCborUpdateGuestbookRequest($value));
    }

    public static function decodeUpdateGuestbookRequest($bytes)
    {
        return self::fromCborUpdateGuestbookRequest(CBOR::decode($bytes));
    }

    public static function toCborUpdateGuestbookRequest($value)
    {
        $out = array();
        $field = $value instanceof UpdateGuestbookRequest ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof UpdateGuestbookRequest ? $value->name : (is_array($value) && array_key_exists('name', $value) ? $value['name'] : null);
        $out['name'] = $field;
        return $out;
    }

    public static function fromCborUpdateGuestbookRequest($value)
    {
        return new UpdateGuestbookRequest(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'name' => array_key_exists('name', $value) ? $value['name'] : null,
        ));
    }

    public static function encodeDeleteGuestbookRequest($value)
    {
        return CBOR::encode(self::toCborDeleteGuestbookRequest($value));
    }

    public static function decodeDeleteGuestbookRequest($bytes)
    {
        return self::fromCborDeleteGuestbookRequest(CBOR::decode($bytes));
    }

    public static function toCborDeleteGuestbookRequest($value)
    {
        $out = array();
        $field = $value instanceof DeleteGuestbookRequest ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        return $out;
    }

    public static function fromCborDeleteGuestbookRequest($value)
    {
        return new DeleteGuestbookRequest(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
        ));
    }

    public static function encodeDeleteGuestbookResponse($value)
    {
        return CBOR::encode(self::toCborDeleteGuestbookResponse($value));
    }

    public static function decodeDeleteGuestbookResponse($bytes)
    {
        return self::fromCborDeleteGuestbookResponse(CBOR::decode($bytes));
    }

    public static function toCborDeleteGuestbookResponse($value)
    {
        $out = array();
        $field = $value instanceof DeleteGuestbookResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out;
    }

    public static function fromCborDeleteGuestbookResponse($value)
    {
        return new DeleteGuestbookResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeGuestbookListRequest($value)
    {
        return CBOR::encode(self::toCborGuestbookListRequest($value));
    }

    public static function decodeGuestbookListRequest($bytes)
    {
        return self::fromCborGuestbookListRequest(CBOR::decode($bytes));
    }

    public static function toCborGuestbookListRequest($value)
    {
        $out = array();
        $field = $value instanceof GuestbookListRequest ? $value->offset : (is_array($value) && array_key_exists('offset', $value) ? $value['offset'] : null);
        if ($field !== null) {
            $out['offset'] = $field;
        }
        $field = $value instanceof GuestbookListRequest ? $value->limit : (is_array($value) && array_key_exists('limit', $value) ? $value['limit'] : null);
        if ($field !== null) {
            $out['limit'] = $field;
        }
        return $out;
    }

    public static function fromCborGuestbookListRequest($value)
    {
        return new GuestbookListRequest(array(
            'offset' => array_key_exists('offset', $value) ? $value['offset'] : null,
            'limit' => array_key_exists('limit', $value) ? $value['limit'] : null,
        ));
    }

    public static function encodeGuestbookListResponse($value)
    {
        return CBOR::encode(self::toCborGuestbookListResponse($value));
    }

    public static function decodeGuestbookListResponse($bytes)
    {
        return self::fromCborGuestbookListResponse(CBOR::decode($bytes));
    }

    public static function toCborGuestbookListResponse($value)
    {
        $out = array();
        $field = $value instanceof GuestbookListResponse ? $value->entries : (is_array($value) && array_key_exists('entries', $value) ? $value['entries'] : null);
        $out['entries'] = array_map(function ($item) { return self::toCborGuestbookEntry($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborGuestbookListResponse($value)
    {
        return new GuestbookListResponse(array(
            'entries' => array_key_exists('entries', $value) ? array_map(function ($item) { return self::fromCborGuestbookEntry($item); }, $value['entries'] === null ? array() : $value['entries']) : null,
        ));
    }

    public static function encodeEmptyRequest($value)
    {
        return CBOR::encode(self::toCborEmptyRequest($value));
    }

    public static function decodeEmptyRequest($bytes)
    {
        return self::fromCborEmptyRequest(CBOR::decode($bytes));
    }

    public static function toCborEmptyRequest($value)
    {
        $out = array();
        return $out;
    }

    public static function fromCborEmptyRequest($value)
    {
        return new EmptyRequest(array(
        ));
    }

    public static function encodeDomainPublicKey($value)
    {
        return CBOR::encode(self::toCborDomainPublicKey($value));
    }

    public static function decodeDomainPublicKey($bytes)
    {
        return self::fromCborDomainPublicKey(CBOR::decode($bytes));
    }

    public static function toCborDomainPublicKey($value)
    {
        $out = array();
        $field = $value instanceof DomainPublicKey ? $value->keyId : (is_array($value) && array_key_exists('key_id', $value) ? $value['key_id'] : null);
        $out['key_id'] = $field;
        $field = $value instanceof DomainPublicKey ? $value->publicKey : (is_array($value) && array_key_exists('public_key', $value) ? $value['public_key'] : null);
        $out['public_key'] = CBOR::bytes($field);
        $field = $value instanceof DomainPublicKey ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof DomainPublicKey ? $value->algorithm : (is_array($value) && array_key_exists('algorithm', $value) ? $value['algorithm'] : null);
        $out['algorithm'] = $field;
        $field = $value instanceof DomainPublicKey ? $value->keyUsage : (is_array($value) && array_key_exists('key_usage', $value) ? $value['key_usage'] : null);
        $out['key_usage'] = $field;
        $field = $value instanceof DomainPublicKey ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = $field;
        $field = $value instanceof DomainPublicKey ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = $field;
        $field = $value instanceof DomainPublicKey ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        if ($field !== null) {
            $out['revoked_at'] = $field;
        }
        $field = $value instanceof DomainPublicKey ? $value->signedByKeyId : (is_array($value) && array_key_exists('signed_by_key_id', $value) ? $value['signed_by_key_id'] : null);
        if ($field !== null) {
            $out['signed_by_key_id'] = $field;
        }
        $field = $value instanceof DomainPublicKey ? $value->keySignature : (is_array($value) && array_key_exists('key_signature', $value) ? $value['key_signature'] : null);
        if ($field !== null) {
            $out['key_signature'] = CBOR::bytes($field);
        }
        return $out;
    }

    public static function fromCborDomainPublicKey($value)
    {
        return new DomainPublicKey(array(
            'key_id' => array_key_exists('key_id', $value) ? $value['key_id'] : null,
            'public_key' => array_key_exists('public_key', $value) ? $value['public_key'] : null,
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'algorithm' => array_key_exists('algorithm', $value) ? $value['algorithm'] : null,
            'key_usage' => array_key_exists('key_usage', $value) ? $value['key_usage'] : null,
            'created_at' => array_key_exists('created_at', $value) ? $value['created_at'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
            'revoked_at' => array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null,
            'signed_by_key_id' => array_key_exists('signed_by_key_id', $value) ? $value['signed_by_key_id'] : null,
            'key_signature' => array_key_exists('key_signature', $value) ? $value['key_signature'] : null,
        ));
    }

    public static function encodeGetDomainKeysResponse($value)
    {
        return CBOR::encode(self::toCborGetDomainKeysResponse($value));
    }

    public static function decodeGetDomainKeysResponse($bytes)
    {
        return self::fromCborGetDomainKeysResponse(CBOR::decode($bytes));
    }

    public static function toCborGetDomainKeysResponse($value)
    {
        $out = array();
        $field = $value instanceof GetDomainKeysResponse ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof GetDomainKeysResponse ? $value->keys : (is_array($value) && array_key_exists('keys', $value) ? $value['keys'] : null);
        $out['keys'] = array_map(function ($item) { return self::toCborDomainPublicKey($item); }, $field === null ? array() : $field);
        $field = $value instanceof GetDomainKeysResponse ? $value->recentRevocationsAvailable : (is_array($value) && array_key_exists('recent_revocations_available', $value) ? $value['recent_revocations_available'] : null);
        if ($field !== null) {
            $out['recent_revocations_available'] = $field;
        }
        return $out;
    }

    public static function fromCborGetDomainKeysResponse($value)
    {
        return new GetDomainKeysResponse(array(
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'keys' => array_key_exists('keys', $value) ? array_map(function ($item) { return self::fromCborDomainPublicKey($item); }, $value['keys'] === null ? array() : $value['keys']) : null,
            'recent_revocations_available' => array_key_exists('recent_revocations_available', $value) ? $value['recent_revocations_available'] : null,
        ));
    }

    public static function encodeGetRevocationsRequest($value)
    {
        return CBOR::encode(self::toCborGetRevocationsRequest($value));
    }

    public static function decodeGetRevocationsRequest($bytes)
    {
        return self::fromCborGetRevocationsRequest(CBOR::decode($bytes));
    }

    public static function toCborGetRevocationsRequest($value)
    {
        $out = array();
        $field = $value instanceof GetRevocationsRequest ? $value->since : (is_array($value) && array_key_exists('since', $value) ? $value['since'] : null);
        if ($field !== null) {
            $out['since'] = $field;
        }
        return $out;
    }

    public static function fromCborGetRevocationsRequest($value)
    {
        return new GetRevocationsRequest(array(
            'since' => array_key_exists('since', $value) ? $value['since'] : null,
        ));
    }

    public static function encodeGetRevocationsResponse($value)
    {
        return CBOR::encode(self::toCborGetRevocationsResponse($value));
    }

    public static function decodeGetRevocationsResponse($bytes)
    {
        return self::fromCborGetRevocationsResponse(CBOR::decode($bytes));
    }

    public static function toCborGetRevocationsResponse($value)
    {
        $out = array();
        $field = $value instanceof GetRevocationsResponse ? $value->revocations : (is_array($value) && array_key_exists('revocations', $value) ? $value['revocations'] : null);
        $out['revocations'] = array_map(function ($item) { return self::toCborRevocationCertificate($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborGetRevocationsResponse($value)
    {
        return new GetRevocationsResponse(array(
            'revocations' => array_key_exists('revocations', $value) ? array_map(function ($item) { return self::fromCborRevocationCertificate($item); }, $value['revocations'] === null ? array() : $value['revocations']) : null,
        ));
    }

    public static function encodeRecheckPinsRequest($value)
    {
        return CBOR::encode(self::toCborRecheckPinsRequest($value));
    }

    public static function decodeRecheckPinsRequest($bytes)
    {
        return self::fromCborRecheckPinsRequest(CBOR::decode($bytes));
    }

    public static function toCborRecheckPinsRequest($value)
    {
        $out = array();
        $field = $value instanceof RecheckPinsRequest ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        if ($field !== null) {
            $out['domain'] = $field;
        }
        return $out;
    }

    public static function fromCborRecheckPinsRequest($value)
    {
        return new RecheckPinsRequest(array(
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
        ));
    }

    public static function encodePinRecheckResult($value)
    {
        return CBOR::encode(self::toCborPinRecheckResult($value));
    }

    public static function decodePinRecheckResult($bytes)
    {
        return self::fromCborPinRecheckResult(CBOR::decode($bytes));
    }

    public static function toCborPinRecheckResult($value)
    {
        $out = array();
        $field = $value instanceof PinRecheckResult ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof PinRecheckResult ? $value->outcome : (is_array($value) && array_key_exists('outcome', $value) ? $value['outcome'] : null);
        $out['outcome'] = $field;
        return $out;
    }

    public static function fromCborPinRecheckResult($value)
    {
        return new PinRecheckResult(array(
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'outcome' => array_key_exists('outcome', $value) ? $value['outcome'] : null,
        ));
    }

    public static function encodeRecheckPinsResponse($value)
    {
        return CBOR::encode(self::toCborRecheckPinsResponse($value));
    }

    public static function decodeRecheckPinsResponse($bytes)
    {
        return self::fromCborRecheckPinsResponse(CBOR::decode($bytes));
    }

    public static function toCborRecheckPinsResponse($value)
    {
        $out = array();
        $field = $value instanceof RecheckPinsResponse ? $value->results : (is_array($value) && array_key_exists('results', $value) ? $value['results'] : null);
        $out['results'] = array_map(function ($item) { return self::toCborPinRecheckResult($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborRecheckPinsResponse($value)
    {
        return new RecheckPinsResponse(array(
            'results' => array_key_exists('results', $value) ? array_map(function ($item) { return self::fromCborPinRecheckResult($item); }, $value['results'] === null ? array() : $value['results']) : null,
        ));
    }

    public static function encodeUserPublicKey($value)
    {
        return CBOR::encode(self::toCborUserPublicKey($value));
    }

    public static function decodeUserPublicKey($bytes)
    {
        return self::fromCborUserPublicKey(CBOR::decode($bytes));
    }

    public static function toCborUserPublicKey($value)
    {
        $out = array();
        $field = $value instanceof UserPublicKey ? $value->keyId : (is_array($value) && array_key_exists('key_id', $value) ? $value['key_id'] : null);
        $out['key_id'] = $field;
        $field = $value instanceof UserPublicKey ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof UserPublicKey ? $value->publicKey : (is_array($value) && array_key_exists('public_key', $value) ? $value['public_key'] : null);
        $out['public_key'] = CBOR::bytes($field);
        $field = $value instanceof UserPublicKey ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof UserPublicKey ? $value->algorithm : (is_array($value) && array_key_exists('algorithm', $value) ? $value['algorithm'] : null);
        $out['algorithm'] = $field;
        $field = $value instanceof UserPublicKey ? $value->keyUsage : (is_array($value) && array_key_exists('key_usage', $value) ? $value['key_usage'] : null);
        $out['key_usage'] = $field;
        $field = $value instanceof UserPublicKey ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = $field;
        $field = $value instanceof UserPublicKey ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = $field;
        $field = $value instanceof UserPublicKey ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        if ($field !== null) {
            $out['revoked_at'] = $field;
        }
        $field = $value instanceof UserPublicKey ? $value->signedByKeyId : (is_array($value) && array_key_exists('signed_by_key_id', $value) ? $value['signed_by_key_id'] : null);
        if ($field !== null) {
            $out['signed_by_key_id'] = $field;
        }
        $field = $value instanceof UserPublicKey ? $value->keySignature : (is_array($value) && array_key_exists('key_signature', $value) ? $value['key_signature'] : null);
        if ($field !== null) {
            $out['key_signature'] = CBOR::bytes($field);
        }
        return $out;
    }

    public static function fromCborUserPublicKey($value)
    {
        return new UserPublicKey(array(
            'key_id' => array_key_exists('key_id', $value) ? $value['key_id'] : null,
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'public_key' => array_key_exists('public_key', $value) ? $value['public_key'] : null,
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'algorithm' => array_key_exists('algorithm', $value) ? $value['algorithm'] : null,
            'key_usage' => array_key_exists('key_usage', $value) ? $value['key_usage'] : null,
            'created_at' => array_key_exists('created_at', $value) ? $value['created_at'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
            'revoked_at' => array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null,
            'signed_by_key_id' => array_key_exists('signed_by_key_id', $value) ? $value['signed_by_key_id'] : null,
            'key_signature' => array_key_exists('key_signature', $value) ? $value['key_signature'] : null,
        ));
    }

    public static function encodeGetUserKeysRequest($value)
    {
        return CBOR::encode(self::toCborGetUserKeysRequest($value));
    }

    public static function decodeGetUserKeysRequest($bytes)
    {
        return self::fromCborGetUserKeysRequest(CBOR::decode($bytes));
    }

    public static function toCborGetUserKeysRequest($value)
    {
        $out = array();
        $field = $value instanceof GetUserKeysRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        return $out;
    }

    public static function fromCborGetUserKeysRequest($value)
    {
        return new GetUserKeysRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeGetUserKeysResponse($value)
    {
        return CBOR::encode(self::toCborGetUserKeysResponse($value));
    }

    public static function decodeGetUserKeysResponse($bytes)
    {
        return self::fromCborGetUserKeysResponse(CBOR::decode($bytes));
    }

    public static function toCborGetUserKeysResponse($value)
    {
        $out = array();
        $field = $value instanceof GetUserKeysResponse ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof GetUserKeysResponse ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof GetUserKeysResponse ? $value->keys : (is_array($value) && array_key_exists('keys', $value) ? $value['keys'] : null);
        $out['keys'] = array_map(function ($item) { return self::toCborUserPublicKey($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborGetUserKeysResponse($value)
    {
        return new GetUserKeysResponse(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'keys' => array_key_exists('keys', $value) ? array_map(function ($item) { return self::fromCborUserPublicKey($item); }, $value['keys'] === null ? array() : $value['keys']) : null,
        ));
    }

    public static function encodeClaimSignature($value)
    {
        return CBOR::encode(self::toCborClaimSignature($value));
    }

    public static function decodeClaimSignature($bytes)
    {
        return self::fromCborClaimSignature(CBOR::decode($bytes));
    }

    public static function toCborClaimSignature($value)
    {
        $out = array();
        $field = $value instanceof ClaimSignature ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof ClaimSignature ? $value->signedByKeyId : (is_array($value) && array_key_exists('signed_by_key_id', $value) ? $value['signed_by_key_id'] : null);
        $out['signed_by_key_id'] = $field;
        $field = $value instanceof ClaimSignature ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        return $out;
    }

    public static function fromCborClaimSignature($value)
    {
        return new ClaimSignature(array(
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'signed_by_key_id' => array_key_exists('signed_by_key_id', $value) ? $value['signed_by_key_id'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
        ));
    }

    public static function encodeRevocationCertificate($value)
    {
        return CBOR::encode(self::toCborRevocationCertificate($value));
    }

    public static function decodeRevocationCertificate($bytes)
    {
        return self::fromCborRevocationCertificate(CBOR::decode($bytes));
    }

    public static function toCborRevocationCertificate($value)
    {
        $out = array();
        $field = $value instanceof RevocationCertificate ? $value->targetKeyId : (is_array($value) && array_key_exists('target_key_id', $value) ? $value['target_key_id'] : null);
        $out['target_key_id'] = $field;
        $field = $value instanceof RevocationCertificate ? $value->targetFingerprint : (is_array($value) && array_key_exists('target_fingerprint', $value) ? $value['target_fingerprint'] : null);
        $out['target_fingerprint'] = $field;
        $field = $value instanceof RevocationCertificate ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        $out['revoked_at'] = $field;
        $field = $value instanceof RevocationCertificate ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborClaimSignature($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborRevocationCertificate($value)
    {
        return new RevocationCertificate(array(
            'target_key_id' => array_key_exists('target_key_id', $value) ? $value['target_key_id'] : null,
            'target_fingerprint' => array_key_exists('target_fingerprint', $value) ? $value['target_fingerprint'] : null,
            'revoked_at' => array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborClaimSignature($item); }, $value['signatures'] === null ? array() : $value['signatures']) : null,
        ));
    }

    public static function encodeClaim($value)
    {
        return CBOR::encode(self::toCborClaim($value));
    }

    public static function decodeClaim($bytes)
    {
        return self::fromCborClaim(CBOR::decode($bytes));
    }

    public static function toCborClaim($value)
    {
        $out = array();
        $field = $value instanceof Claim ? $value->claimId : (is_array($value) && array_key_exists('claim_id', $value) ? $value['claim_id'] : null);
        $out['claim_id'] = $field;
        $field = $value instanceof Claim ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof Claim ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof Claim ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        $out['claim_value'] = CBOR::bytes($field);
        $field = $value instanceof Claim ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborClaimSignature($item); }, $field === null ? array() : $field);
        $field = $value instanceof Claim ? $value->attestedAt : (is_array($value) && array_key_exists('attested_at', $value) ? $value['attested_at'] : null);
        $out['attested_at'] = $field;
        $field = $value instanceof Claim ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = $field;
        $field = $value instanceof Claim ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        if ($field !== null) {
            $out['expires_at'] = $field;
        }
        $field = $value instanceof Claim ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        if ($field !== null) {
            $out['revoked_at'] = $field;
        }
        return $out;
    }

    public static function fromCborClaim($value)
    {
        return new Claim(array(
            'claim_id' => array_key_exists('claim_id', $value) ? $value['claim_id'] : null,
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborClaimSignature($item); }, $value['signatures'] === null ? array() : $value['signatures']) : null,
            'attested_at' => array_key_exists('attested_at', $value) ? $value['attested_at'] : null,
            'created_at' => array_key_exists('created_at', $value) ? $value['created_at'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
            'revoked_at' => array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null,
        ));
    }

    public static function encodeGetUserClaimsRequest($value)
    {
        return CBOR::encode(self::toCborGetUserClaimsRequest($value));
    }

    public static function decodeGetUserClaimsRequest($bytes)
    {
        return self::fromCborGetUserClaimsRequest(CBOR::decode($bytes));
    }

    public static function toCborGetUserClaimsRequest($value)
    {
        $out = array();
        $field = $value instanceof GetUserClaimsRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof GetUserClaimsRequest ? $value->token : (is_array($value) && array_key_exists('token', $value) ? $value['token'] : null);
        $out['token'] = CBOR::bytes($field);
        return $out;
    }

    public static function fromCborGetUserClaimsRequest($value)
    {
        return new GetUserClaimsRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'token' => array_key_exists('token', $value) ? $value['token'] : null,
        ));
    }

    public static function encodeGetUserClaimsResponse($value)
    {
        return CBOR::encode(self::toCborGetUserClaimsResponse($value));
    }

    public static function decodeGetUserClaimsResponse($bytes)
    {
        return self::fromCborGetUserClaimsResponse(CBOR::decode($bytes));
    }

    public static function toCborGetUserClaimsResponse($value)
    {
        $out = array();
        $field = $value instanceof GetUserClaimsResponse ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof GetUserClaimsResponse ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof GetUserClaimsResponse ? $value->claims : (is_array($value) && array_key_exists('claims', $value) ? $value['claims'] : null);
        $out['claims'] = array_map(function ($item) { return self::toCborClaim($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborGetUserClaimsResponse($value)
    {
        return new GetUserClaimsResponse(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'claims' => array_key_exists('claims', $value) ? array_map(function ($item) { return self::fromCborClaim($item); }, $value['claims'] === null ? array() : $value['claims']) : null,
        ));
    }

    public static function encodeRequestedClaim($value)
    {
        return CBOR::encode(self::toCborRequestedClaim($value));
    }

    public static function decodeRequestedClaim($bytes)
    {
        return self::fromCborRequestedClaim(CBOR::decode($bytes));
    }

    public static function toCborRequestedClaim($value)
    {
        $out = array();
        $field = $value instanceof RequestedClaim ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof RequestedClaim ? $value->datatype : (is_array($value) && array_key_exists('datatype', $value) ? $value['datatype'] : null);
        $out['datatype'] = $field;
        return $out;
    }

    public static function fromCborRequestedClaim($value)
    {
        return new RequestedClaim(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'datatype' => array_key_exists('datatype', $value) ? $value['datatype'] : null,
        ));
    }

    public static function encodeClaimRequest($value)
    {
        return CBOR::encode(self::toCborClaimRequest($value));
    }

    public static function decodeClaimRequest($bytes)
    {
        return self::fromCborClaimRequest(CBOR::decode($bytes));
    }

    public static function toCborClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof ClaimRequest ? $value->required : (is_array($value) && array_key_exists('required', $value) ? $value['required'] : null);
        $out['required'] = array_map(function ($item) { return self::toCborRequestedClaim($item); }, $field === null ? array() : $field);
        $field = $value instanceof ClaimRequest ? $value->optional : (is_array($value) && array_key_exists('optional', $value) ? $value['optional'] : null);
        $out['optional'] = array_map(function ($item) { return self::toCborRequestedClaim($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborClaimRequest($value)
    {
        return new ClaimRequest(array(
            'required' => array_key_exists('required', $value) ? array_map(function ($item) { return self::fromCborRequestedClaim($item); }, $value['required'] === null ? array() : $value['required']) : null,
            'optional' => array_key_exists('optional', $value) ? array_map(function ($item) { return self::fromCborRequestedClaim($item); }, $value['optional'] === null ? array() : $value['optional']) : null,
        ));
    }

    public static function encodeAuthFlowContext($value)
    {
        return CBOR::encode(self::toCborAuthFlowContext($value));
    }

    public static function decodeAuthFlowContext($bytes)
    {
        return self::fromCborAuthFlowContext(CBOR::decode($bytes));
    }

    public static function toCborAuthFlowContext($value)
    {
        $out = array();
        $field = $value instanceof AuthFlowContext ? $value->flow : (is_array($value) && array_key_exists('flow', $value) ? $value['flow'] : null);
        $out['flow'] = $field;
        $field = $value instanceof AuthFlowContext ? $value->priorSession : (is_array($value) && array_key_exists('prior_session', $value) ? $value['prior_session'] : null);
        if ($field !== null) {
            $out['prior_session'] = $field;
        }
        $field = $value instanceof AuthFlowContext ? $value->requestReason : (is_array($value) && array_key_exists('request_reason', $value) ? $value['request_reason'] : null);
        if ($field !== null) {
            $out['request_reason'] = $field;
        }
        return $out;
    }

    public static function fromCborAuthFlowContext($value)
    {
        return new AuthFlowContext(array(
            'flow' => array_key_exists('flow', $value) ? $value['flow'] : null,
            'prior_session' => array_key_exists('prior_session', $value) ? $value['prior_session'] : null,
            'request_reason' => array_key_exists('request_reason', $value) ? $value['request_reason'] : null,
        ));
    }

    public static function encodeConsentGrant($value)
    {
        return CBOR::encode(self::toCborConsentGrant($value));
    }

    public static function decodeConsentGrant($bytes)
    {
        return self::fromCborConsentGrant(CBOR::decode($bytes));
    }

    public static function toCborConsentGrant($value)
    {
        $out = array();
        $field = $value instanceof ConsentGrant ? $value->grantId : (is_array($value) && array_key_exists('grant_id', $value) ? $value['grant_id'] : null);
        $out['grant_id'] = $field;
        $field = $value instanceof ConsentGrant ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof ConsentGrant ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof ConsentGrant ? $value->audience : (is_array($value) && array_key_exists('audience', $value) ? $value['audience'] : null);
        $out['audience'] = $field;
        $field = $value instanceof ConsentGrant ? $value->claimTypes : (is_array($value) && array_key_exists('claim_types', $value) ? $value['claim_types'] : null);
        $out['claim_types'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof ConsentGrant ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = $field;
        $field = $value instanceof ConsentGrant ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = $field;
        $field = $value instanceof ConsentGrant ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        if ($field !== null) {
            $out['revoked_at'] = $field;
        }
        return $out;
    }

    public static function fromCborConsentGrant($value)
    {
        return new ConsentGrant(array(
            'grant_id' => array_key_exists('grant_id', $value) ? $value['grant_id'] : null,
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'audience' => array_key_exists('audience', $value) ? $value['audience'] : null,
            'claim_types' => array_key_exists('claim_types', $value) ? array_map(function ($item) { return $item; }, $value['claim_types'] === null ? array() : $value['claim_types']) : null,
            'issued_at' => array_key_exists('issued_at', $value) ? $value['issued_at'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
            'revoked_at' => array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null,
        ));
    }

    public static function encodeSignedConsentGrant($value)
    {
        return CBOR::encode(self::toCborSignedConsentGrant($value));
    }

    public static function decodeSignedConsentGrant($bytes)
    {
        return self::fromCborSignedConsentGrant(CBOR::decode($bytes));
    }

    public static function toCborSignedConsentGrant($value)
    {
        $out = array();
        $field = $value instanceof SignedConsentGrant ? $value->grant : (is_array($value) && array_key_exists('grant', $value) ? $value['grant'] : null);
        $out['grant'] = CBOR::bytes($field);
        $field = $value instanceof SignedConsentGrant ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborClaimSignature($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborSignedConsentGrant($value)
    {
        return new SignedConsentGrant(array(
            'grant' => array_key_exists('grant', $value) ? $value['grant'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborClaimSignature($item); }, $value['signatures'] === null ? array() : $value['signatures']) : null,
        ));
    }

    public static function encodeDomainClaim($value)
    {
        return CBOR::encode(self::toCborDomainClaim($value));
    }

    public static function decodeDomainClaim($bytes)
    {
        return self::fromCborDomainClaim(CBOR::decode($bytes));
    }

    public static function toCborDomainClaim($value)
    {
        $out = array();
        $field = $value instanceof DomainClaim ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof DomainClaim ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        $out['claim_value'] = CBOR::bytes($field);
        $field = $value instanceof DomainClaim ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborClaimSignature($item); }, $field === null ? array() : $field);
        $field = $value instanceof DomainClaim ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        if ($field !== null) {
            $out['expires_at'] = $field;
        }
        return $out;
    }

    public static function fromCborDomainClaim($value)
    {
        return new DomainClaim(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborClaimSignature($item); }, $value['signatures'] === null ? array() : $value['signatures']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
        ));
    }

    public static function encodeSigningRequest($value)
    {
        return CBOR::encode(self::toCborSigningRequest($value));
    }

    public static function decodeSigningRequest($bytes)
    {
        return self::fromCborSigningRequest(CBOR::decode($bytes));
    }

    public static function toCborSigningRequest($value)
    {
        $out = array();
        $field = $value instanceof SigningRequest ? $value->requestId : (is_array($value) && array_key_exists('request_id', $value) ? $value['request_id'] : null);
        $out['request_id'] = $field;
        $field = $value instanceof SigningRequest ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof SigningRequest ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof SigningRequest ? $value->issuerDomain : (is_array($value) && array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null);
        $out['issuer_domain'] = $field;
        $field = $value instanceof SigningRequest ? $value->requestedClaimTypes : (is_array($value) && array_key_exists('requested_claim_types', $value) ? $value['requested_claim_types'] : null);
        $out['requested_claim_types'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof SigningRequest ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = $field;
        $field = $value instanceof SigningRequest ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = $field;
        $field = $value instanceof SigningRequest ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = $field;
        $field = $value instanceof SigningRequest ? $value->callback : (is_array($value) && array_key_exists('callback', $value) ? $value['callback'] : null);
        if ($field !== null) {
            $out['callback'] = $field;
        }
        return $out;
    }

    public static function fromCborSigningRequest($value)
    {
        return new SigningRequest(array(
            'request_id' => array_key_exists('request_id', $value) ? $value['request_id'] : null,
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'issuer_domain' => array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null,
            'requested_claim_types' => array_key_exists('requested_claim_types', $value) ? array_map(function ($item) { return $item; }, $value['requested_claim_types'] === null ? array() : $value['requested_claim_types']) : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'issued_at' => array_key_exists('issued_at', $value) ? $value['issued_at'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
            'callback' => array_key_exists('callback', $value) ? $value['callback'] : null,
        ));
    }

    public static function encodeSignedSigningRequest($value)
    {
        return CBOR::encode(self::toCborSignedSigningRequest($value));
    }

    public static function decodeSignedSigningRequest($bytes)
    {
        return self::fromCborSignedSigningRequest(CBOR::decode($bytes));
    }

    public static function toCborSignedSigningRequest($value)
    {
        $out = array();
        $field = $value instanceof SignedSigningRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = CBOR::bytes($field);
        $field = $value instanceof SignedSigningRequest ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborClaimSignature($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborSignedSigningRequest($value)
    {
        return new SignedSigningRequest(array(
            'request' => array_key_exists('request', $value) ? $value['request'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborClaimSignature($item); }, $value['signatures'] === null ? array() : $value['signatures']) : null,
        ));
    }

    public static function encodeDepositClaimRequest($value)
    {
        return CBOR::encode(self::toCborDepositClaimRequest($value));
    }

    public static function decodeDepositClaimRequest($bytes)
    {
        return self::fromCborDepositClaimRequest(CBOR::decode($bytes));
    }

    public static function toCborDepositClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof DepositClaimRequest ? $value->claim : (is_array($value) && array_key_exists('claim', $value) ? $value['claim'] : null);
        $out['claim'] = self::toCborClaim($field);
        return $out;
    }

    public static function fromCborDepositClaimRequest($value)
    {
        return new DepositClaimRequest(array(
            'claim' => array_key_exists('claim', $value) ? self::fromCborClaim($value['claim']) : null,
        ));
    }

    public static function encodeDepositClaimResponse($value)
    {
        return CBOR::encode(self::toCborDepositClaimResponse($value));
    }

    public static function decodeDepositClaimResponse($bytes)
    {
        return self::fromCborDepositClaimResponse(CBOR::decode($bytes));
    }

    public static function toCborDepositClaimResponse($value)
    {
        $out = array();
        $field = $value instanceof DepositClaimResponse ? $value->stored : (is_array($value) && array_key_exists('stored', $value) ? $value['stored'] : null);
        $out['stored'] = $field;
        return $out;
    }

    public static function fromCborDepositClaimResponse($value)
    {
        return new DepositClaimResponse(array(
            'stored' => array_key_exists('stored', $value) ? $value['stored'] : null,
        ));
    }

    public static function encodeIdentityAssertion($value)
    {
        return CBOR::encode(self::toCborIdentityAssertion($value));
    }

    public static function decodeIdentityAssertion($bytes)
    {
        return self::fromCborIdentityAssertion(CBOR::decode($bytes));
    }

    public static function toCborIdentityAssertion($value)
    {
        $out = array();
        $field = $value instanceof IdentityAssertion ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof IdentityAssertion ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof IdentityAssertion ? $value->audience : (is_array($value) && array_key_exists('audience', $value) ? $value['audience'] : null);
        $out['audience'] = $field;
        $field = $value instanceof IdentityAssertion ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = $field;
        $field = $value instanceof IdentityAssertion ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = $field;
        $field = $value instanceof IdentityAssertion ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = $field;
        $field = $value instanceof IdentityAssertion ? $value->authorizedClaims : (is_array($value) && array_key_exists('authorized_claims', $value) ? $value['authorized_claims'] : null);
        $out['authorized_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof IdentityAssertion ? $value->displayName : (is_array($value) && array_key_exists('display_name', $value) ? $value['display_name'] : null);
        if ($field !== null) {
            $out['display_name'] = $field;
        }
        return $out;
    }

    public static function fromCborIdentityAssertion($value)
    {
        return new IdentityAssertion(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'audience' => array_key_exists('audience', $value) ? $value['audience'] : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'issued_at' => array_key_exists('issued_at', $value) ? $value['issued_at'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
            'authorized_claims' => array_key_exists('authorized_claims', $value) ? array_map(function ($item) { return $item; }, $value['authorized_claims'] === null ? array() : $value['authorized_claims']) : null,
            'display_name' => array_key_exists('display_name', $value) ? $value['display_name'] : null,
        ));
    }

    public static function encodeSignedIdentityAssertion($value)
    {
        return CBOR::encode(self::toCborSignedIdentityAssertion($value));
    }

    public static function decodeSignedIdentityAssertion($bytes)
    {
        return self::fromCborSignedIdentityAssertion(CBOR::decode($bytes));
    }

    public static function toCborSignedIdentityAssertion($value)
    {
        $out = array();
        $field = $value instanceof SignedIdentityAssertion ? $value->assertion : (is_array($value) && array_key_exists('assertion', $value) ? $value['assertion'] : null);
        $out['assertion'] = CBOR::bytes($field);
        $field = $value instanceof SignedIdentityAssertion ? $value->signingKeyId : (is_array($value) && array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null);
        $out['signing_key_id'] = $field;
        $field = $value instanceof SignedIdentityAssertion ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        return $out;
    }

    public static function fromCborSignedIdentityAssertion($value)
    {
        return new SignedIdentityAssertion(array(
            'assertion' => array_key_exists('assertion', $value) ? $value['assertion'] : null,
            'signing_key_id' => array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
        ));
    }

    public static function encodeGetUserInfoRequest($value)
    {
        return CBOR::encode(self::toCborGetUserInfoRequest($value));
    }

    public static function decodeGetUserInfoRequest($bytes)
    {
        return self::fromCborGetUserInfoRequest(CBOR::decode($bytes));
    }

    public static function toCborGetUserInfoRequest($value)
    {
        $out = array();
        $field = $value instanceof GetUserInfoRequest ? $value->token : (is_array($value) && array_key_exists('token', $value) ? $value['token'] : null);
        $out['token'] = CBOR::bytes($field);
        return $out;
    }

    public static function fromCborGetUserInfoRequest($value)
    {
        return new GetUserInfoRequest(array(
            'token' => array_key_exists('token', $value) ? $value['token'] : null,
        ));
    }

    public static function encodeUserInfoRequest($value)
    {
        return CBOR::encode(self::toCborUserInfoRequest($value));
    }

    public static function decodeUserInfoRequest($bytes)
    {
        return self::fromCborUserInfoRequest(CBOR::decode($bytes));
    }

    public static function toCborUserInfoRequest($value)
    {
        $out = array();
        $field = $value instanceof UserInfoRequest ? $value->token : (is_array($value) && array_key_exists('token', $value) ? $value['token'] : null);
        $out['token'] = CBOR::bytes($field);
        $field = $value instanceof UserInfoRequest ? $value->relyingParty : (is_array($value) && array_key_exists('relying_party', $value) ? $value['relying_party'] : null);
        $out['relying_party'] = $field;
        $field = $value instanceof UserInfoRequest ? $value->timestamp : (is_array($value) && array_key_exists('timestamp', $value) ? $value['timestamp'] : null);
        $out['timestamp'] = $field;
        $field = $value instanceof UserInfoRequest ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = $field;
        return $out;
    }

    public static function fromCborUserInfoRequest($value)
    {
        return new UserInfoRequest(array(
            'token' => array_key_exists('token', $value) ? $value['token'] : null,
            'relying_party' => array_key_exists('relying_party', $value) ? $value['relying_party'] : null,
            'timestamp' => array_key_exists('timestamp', $value) ? $value['timestamp'] : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
        ));
    }

    public static function encodeSignedUserInfoRequest($value)
    {
        return CBOR::encode(self::toCborSignedUserInfoRequest($value));
    }

    public static function decodeSignedUserInfoRequest($bytes)
    {
        return self::fromCborSignedUserInfoRequest(CBOR::decode($bytes));
    }

    public static function toCborSignedUserInfoRequest($value)
    {
        $out = array();
        $field = $value instanceof SignedUserInfoRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = CBOR::bytes($field);
        $field = $value instanceof SignedUserInfoRequest ? $value->signingKeyId : (is_array($value) && array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null);
        $out['signing_key_id'] = $field;
        $field = $value instanceof SignedUserInfoRequest ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        $field = $value instanceof SignedUserInfoRequest ? $value->publicKeys : (is_array($value) && array_key_exists('public_keys', $value) ? $value['public_keys'] : null);
        if ($field !== null) {
            $out['public_keys'] = array_map(function ($item) { return self::toCborDomainPublicKey($item); }, $field === null ? array() : $field);
        }
        return $out;
    }

    public static function fromCborSignedUserInfoRequest($value)
    {
        return new SignedUserInfoRequest(array(
            'request' => array_key_exists('request', $value) ? $value['request'] : null,
            'signing_key_id' => array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
            'public_keys' => array_key_exists('public_keys', $value) ? array_map(function ($item) { return self::fromCborDomainPublicKey($item); }, $value['public_keys'] === null ? array() : $value['public_keys']) : null,
        ));
    }

    public static function encodeUserInfo($value)
    {
        return CBOR::encode(self::toCborUserInfo($value));
    }

    public static function decodeUserInfo($bytes)
    {
        return self::fromCborUserInfo(CBOR::decode($bytes));
    }

    public static function toCborUserInfo($value)
    {
        $out = array();
        $field = $value instanceof UserInfo ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof UserInfo ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof UserInfo ? $value->displayName : (is_array($value) && array_key_exists('display_name', $value) ? $value['display_name'] : null);
        $out['display_name'] = $field;
        $field = $value instanceof UserInfo ? $value->claims : (is_array($value) && array_key_exists('claims', $value) ? $value['claims'] : null);
        $out['claims'] = array_map(function ($item) { return self::toCborClaim($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborUserInfo($value)
    {
        return new UserInfo(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'display_name' => array_key_exists('display_name', $value) ? $value['display_name'] : null,
            'claims' => array_key_exists('claims', $value) ? array_map(function ($item) { return self::fromCborClaim($item); }, $value['claims'] === null ? array() : $value['claims']) : null,
        ));
    }

    public static function encodeAuthRequest($value)
    {
        return CBOR::encode(self::toCborAuthRequest($value));
    }

    public static function decodeAuthRequest($bytes)
    {
        return self::fromCborAuthRequest(CBOR::decode($bytes));
    }

    public static function toCborAuthRequest($value)
    {
        $out = array();
        $field = $value instanceof AuthRequest ? $value->relyingParty : (is_array($value) && array_key_exists('relying_party', $value) ? $value['relying_party'] : null);
        $out['relying_party'] = $field;
        $field = $value instanceof AuthRequest ? $value->callbackUrl : (is_array($value) && array_key_exists('callback_url', $value) ? $value['callback_url'] : null);
        $out['callback_url'] = $field;
        $field = $value instanceof AuthRequest ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = $field;
        $field = $value instanceof AuthRequest ? $value->timestamp : (is_array($value) && array_key_exists('timestamp', $value) ? $value['timestamp'] : null);
        $out['timestamp'] = $field;
        $field = $value instanceof AuthRequest ? $value->signingKeyId : (is_array($value) && array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null);
        $out['signing_key_id'] = $field;
        $field = $value instanceof AuthRequest ? $value->requestedClaims : (is_array($value) && array_key_exists('requested_claims', $value) ? $value['requested_claims'] : null);
        if ($field !== null) {
            $out['requested_claims'] = self::toCborClaimRequest($field);
        }
        $field = $value instanceof AuthRequest ? $value->flowContext : (is_array($value) && array_key_exists('flow_context', $value) ? $value['flow_context'] : null);
        if ($field !== null) {
            $out['flow_context'] = self::toCborAuthFlowContext($field);
        }
        $field = $value instanceof AuthRequest ? $value->relyingPartyClaims : (is_array($value) && array_key_exists('relying_party_claims', $value) ? $value['relying_party_claims'] : null);
        if ($field !== null) {
            $out['relying_party_claims'] = array_map(function ($item) { return self::toCborDomainClaim($item); }, $field === null ? array() : $field);
        }
        return $out;
    }

    public static function fromCborAuthRequest($value)
    {
        return new AuthRequest(array(
            'relying_party' => array_key_exists('relying_party', $value) ? $value['relying_party'] : null,
            'callback_url' => array_key_exists('callback_url', $value) ? $value['callback_url'] : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'timestamp' => array_key_exists('timestamp', $value) ? $value['timestamp'] : null,
            'signing_key_id' => array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null,
            'requested_claims' => array_key_exists('requested_claims', $value) ? self::fromCborClaimRequest($value['requested_claims']) : null,
            'flow_context' => array_key_exists('flow_context', $value) ? self::fromCborAuthFlowContext($value['flow_context']) : null,
            'relying_party_claims' => array_key_exists('relying_party_claims', $value) ? array_map(function ($item) { return self::fromCborDomainClaim($item); }, $value['relying_party_claims'] === null ? array() : $value['relying_party_claims']) : null,
        ));
    }

    public static function encodeSignedAuthRequest($value)
    {
        return CBOR::encode(self::toCborSignedAuthRequest($value));
    }

    public static function decodeSignedAuthRequest($bytes)
    {
        return self::fromCborSignedAuthRequest(CBOR::decode($bytes));
    }

    public static function toCborSignedAuthRequest($value)
    {
        $out = array();
        $field = $value instanceof SignedAuthRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = CBOR::bytes($field);
        $field = $value instanceof SignedAuthRequest ? $value->signingKeyId : (is_array($value) && array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null);
        $out['signing_key_id'] = $field;
        $field = $value instanceof SignedAuthRequest ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        return $out;
    }

    public static function fromCborSignedAuthRequest($value)
    {
        return new SignedAuthRequest(array(
            'request' => array_key_exists('request', $value) ? $value['request'] : null,
            'signing_key_id' => array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
        ));
    }

    public static function encodeEncryptedToken($value)
    {
        return CBOR::encode(self::toCborEncryptedToken($value));
    }

    public static function decodeEncryptedToken($bytes)
    {
        return self::fromCborEncryptedToken(CBOR::decode($bytes));
    }

    public static function toCborEncryptedToken($value)
    {
        $out = array();
        $field = $value instanceof EncryptedToken ? $value->ephemeralPublicKey : (is_array($value) && array_key_exists('ephemeral_public_key', $value) ? $value['ephemeral_public_key'] : null);
        $out['ephemeral_public_key'] = CBOR::bytes($field);
        $field = $value instanceof EncryptedToken ? $value->ciphertext : (is_array($value) && array_key_exists('ciphertext', $value) ? $value['ciphertext'] : null);
        $out['ciphertext'] = CBOR::bytes($field);
        $field = $value instanceof EncryptedToken ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = CBOR::bytes($field);
        $field = $value instanceof EncryptedToken ? $value->suite : (is_array($value) && array_key_exists('suite', $value) ? $value['suite'] : null);
        if ($field !== null) {
            $out['suite'] = $field;
        }
        return $out;
    }

    public static function fromCborEncryptedToken($value)
    {
        return new EncryptedToken(array(
            'ephemeral_public_key' => array_key_exists('ephemeral_public_key', $value) ? $value['ephemeral_public_key'] : null,
            'ciphertext' => array_key_exists('ciphertext', $value) ? $value['ciphertext'] : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'suite' => array_key_exists('suite', $value) ? $value['suite'] : null,
        ));
    }

    public static function encodeAlgorithmSupport($value)
    {
        return CBOR::encode(self::toCborAlgorithmSupport($value));
    }

    public static function decodeAlgorithmSupport($bytes)
    {
        return self::fromCborAlgorithmSupport(CBOR::decode($bytes));
    }

    public static function toCborAlgorithmSupport($value)
    {
        $out = array();
        $field = $value instanceof AlgorithmSupport ? $value->signing : (is_array($value) && array_key_exists('signing', $value) ? $value['signing'] : null);
        $out['signing'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof AlgorithmSupport ? $value->encryption : (is_array($value) && array_key_exists('encryption', $value) ? $value['encryption'] : null);
        if ($field !== null) {
            $out['encryption'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        }
        return $out;
    }

    public static function fromCborAlgorithmSupport($value)
    {
        return new AlgorithmSupport(array(
            'signing' => array_key_exists('signing', $value) ? array_map(function ($item) { return $item; }, $value['signing'] === null ? array() : $value['signing']) : null,
            'encryption' => array_key_exists('encryption', $value) ? array_map(function ($item) { return $item; }, $value['encryption'] === null ? array() : $value['encryption']) : null,
        ));
    }

    public static function encodeHandshakeRequest($value)
    {
        return CBOR::encode(self::toCborHandshakeRequest($value));
    }

    public static function decodeHandshakeRequest($bytes)
    {
        return self::fromCborHandshakeRequest(CBOR::decode($bytes));
    }

    public static function toCborHandshakeRequest($value)
    {
        $out = array();
        $field = $value instanceof HandshakeRequest ? $value->version : (is_array($value) && array_key_exists('version', $value) ? $value['version'] : null);
        $out['version'] = $field;
        $field = $value instanceof HandshakeRequest ? $value->algorithms : (is_array($value) && array_key_exists('algorithms', $value) ? $value['algorithms'] : null);
        $out['algorithms'] = self::toCborAlgorithmSupport($field);
        return $out;
    }

    public static function fromCborHandshakeRequest($value)
    {
        return new HandshakeRequest(array(
            'version' => array_key_exists('version', $value) ? $value['version'] : null,
            'algorithms' => array_key_exists('algorithms', $value) ? self::fromCborAlgorithmSupport($value['algorithms']) : null,
        ));
    }

    public static function encodeHandshakeResponse($value)
    {
        return CBOR::encode(self::toCborHandshakeResponse($value));
    }

    public static function decodeHandshakeResponse($bytes)
    {
        return self::fromCborHandshakeResponse(CBOR::decode($bytes));
    }

    public static function toCborHandshakeResponse($value)
    {
        $out = array();
        $field = $value instanceof HandshakeResponse ? $value->version : (is_array($value) && array_key_exists('version', $value) ? $value['version'] : null);
        $out['version'] = $field;
        $field = $value instanceof HandshakeResponse ? $value->algorithms : (is_array($value) && array_key_exists('algorithms', $value) ? $value['algorithms'] : null);
        $out['algorithms'] = self::toCborAlgorithmSupport($field);
        return $out;
    }

    public static function fromCborHandshakeResponse($value)
    {
        return new HandshakeResponse(array(
            'version' => array_key_exists('version', $value) ? $value['version'] : null,
            'algorithms' => array_key_exists('algorithms', $value) ? self::fromCborAlgorithmSupport($value['algorithms']) : null,
        ));
    }

    public static function encodeRelation($value)
    {
        return CBOR::encode(self::toCborRelation($value));
    }

    public static function decodeRelation($bytes)
    {
        return self::fromCborRelation(CBOR::decode($bytes));
    }

    public static function toCborRelation($value)
    {
        $out = array();
        $field = $value instanceof Relation ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof Relation ? $value->subjectType : (is_array($value) && array_key_exists('subject_type', $value) ? $value['subject_type'] : null);
        $out['subject_type'] = $field;
        $field = $value instanceof Relation ? $value->subjectId : (is_array($value) && array_key_exists('subject_id', $value) ? $value['subject_id'] : null);
        $out['subject_id'] = $field;
        $field = $value instanceof Relation ? $value->relation : (is_array($value) && array_key_exists('relation', $value) ? $value['relation'] : null);
        $out['relation'] = $field;
        $field = $value instanceof Relation ? $value->objectType : (is_array($value) && array_key_exists('object_type', $value) ? $value['object_type'] : null);
        $out['object_type'] = $field;
        $field = $value instanceof Relation ? $value->objectId : (is_array($value) && array_key_exists('object_id', $value) ? $value['object_id'] : null);
        $out['object_id'] = $field;
        $field = $value instanceof Relation ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = $field;
        $field = $value instanceof Relation ? $value->removedAt : (is_array($value) && array_key_exists('removed_at', $value) ? $value['removed_at'] : null);
        if ($field !== null) {
            $out['removed_at'] = $field;
        }
        return $out;
    }

    public static function fromCborRelation($value)
    {
        return new Relation(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'subject_type' => array_key_exists('subject_type', $value) ? $value['subject_type'] : null,
            'subject_id' => array_key_exists('subject_id', $value) ? $value['subject_id'] : null,
            'relation' => array_key_exists('relation', $value) ? $value['relation'] : null,
            'object_type' => array_key_exists('object_type', $value) ? $value['object_type'] : null,
            'object_id' => array_key_exists('object_id', $value) ? $value['object_id'] : null,
            'created_at' => array_key_exists('created_at', $value) ? $value['created_at'] : null,
            'removed_at' => array_key_exists('removed_at', $value) ? $value['removed_at'] : null,
        ));
    }

    public static function encodeAdminUser($value)
    {
        return CBOR::encode(self::toCborAdminUser($value));
    }

    public static function decodeAdminUser($bytes)
    {
        return self::fromCborAdminUser(CBOR::decode($bytes));
    }

    public static function toCborAdminUser($value)
    {
        $out = array();
        $field = $value instanceof AdminUser ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof AdminUser ? $value->username : (is_array($value) && array_key_exists('username', $value) ? $value['username'] : null);
        $out['username'] = $field;
        $field = $value instanceof AdminUser ? $value->displayName : (is_array($value) && array_key_exists('display_name', $value) ? $value['display_name'] : null);
        $out['display_name'] = $field;
        $field = $value instanceof AdminUser ? $value->isActive : (is_array($value) && array_key_exists('is_active', $value) ? $value['is_active'] : null);
        $out['is_active'] = $field;
        $field = $value instanceof AdminUser ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = $field;
        $field = $value instanceof AdminUser ? $value->updatedAt : (is_array($value) && array_key_exists('updated_at', $value) ? $value['updated_at'] : null);
        $out['updated_at'] = $field;
        return $out;
    }

    public static function fromCborAdminUser($value)
    {
        return new AdminUser(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'username' => array_key_exists('username', $value) ? $value['username'] : null,
            'display_name' => array_key_exists('display_name', $value) ? $value['display_name'] : null,
            'is_active' => array_key_exists('is_active', $value) ? $value['is_active'] : null,
            'created_at' => array_key_exists('created_at', $value) ? $value['created_at'] : null,
            'updated_at' => array_key_exists('updated_at', $value) ? $value['updated_at'] : null,
        ));
    }

    public static function encodeListUsersRequest($value)
    {
        return CBOR::encode(self::toCborListUsersRequest($value));
    }

    public static function decodeListUsersRequest($bytes)
    {
        return self::fromCborListUsersRequest(CBOR::decode($bytes));
    }

    public static function toCborListUsersRequest($value)
    {
        $out = array();
        $field = $value instanceof ListUsersRequest ? $value->offset : (is_array($value) && array_key_exists('offset', $value) ? $value['offset'] : null);
        if ($field !== null) {
            $out['offset'] = $field;
        }
        $field = $value instanceof ListUsersRequest ? $value->limit : (is_array($value) && array_key_exists('limit', $value) ? $value['limit'] : null);
        if ($field !== null) {
            $out['limit'] = $field;
        }
        return $out;
    }

    public static function fromCborListUsersRequest($value)
    {
        return new ListUsersRequest(array(
            'offset' => array_key_exists('offset', $value) ? $value['offset'] : null,
            'limit' => array_key_exists('limit', $value) ? $value['limit'] : null,
        ));
    }

    public static function encodeListUsersResponse($value)
    {
        return CBOR::encode(self::toCborListUsersResponse($value));
    }

    public static function decodeListUsersResponse($bytes)
    {
        return self::fromCborListUsersResponse(CBOR::decode($bytes));
    }

    public static function toCborListUsersResponse($value)
    {
        $out = array();
        $field = $value instanceof ListUsersResponse ? $value->users : (is_array($value) && array_key_exists('users', $value) ? $value['users'] : null);
        $out['users'] = array_map(function ($item) { return self::toCborAdminUser($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborListUsersResponse($value)
    {
        return new ListUsersResponse(array(
            'users' => array_key_exists('users', $value) ? array_map(function ($item) { return self::fromCborAdminUser($item); }, $value['users'] === null ? array() : $value['users']) : null,
        ));
    }

    public static function encodeGetUserRequest($value)
    {
        return CBOR::encode(self::toCborGetUserRequest($value));
    }

    public static function decodeGetUserRequest($bytes)
    {
        return self::fromCborGetUserRequest(CBOR::decode($bytes));
    }

    public static function toCborGetUserRequest($value)
    {
        $out = array();
        $field = $value instanceof GetUserRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        return $out;
    }

    public static function fromCborGetUserRequest($value)
    {
        return new GetUserRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeGetUserResponse($value)
    {
        return CBOR::encode(self::toCborGetUserResponse($value));
    }

    public static function decodeGetUserResponse($bytes)
    {
        return self::fromCborGetUserResponse(CBOR::decode($bytes));
    }

    public static function toCborGetUserResponse($value)
    {
        $out = array();
        $field = $value instanceof GetUserResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        return $out;
    }

    public static function fromCborGetUserResponse($value)
    {
        return new GetUserResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
        ));
    }

    public static function encodeCreateUserRequest($value)
    {
        return CBOR::encode(self::toCborCreateUserRequest($value));
    }

    public static function decodeCreateUserRequest($bytes)
    {
        return self::fromCborCreateUserRequest(CBOR::decode($bytes));
    }

    public static function toCborCreateUserRequest($value)
    {
        $out = array();
        $field = $value instanceof CreateUserRequest ? $value->username : (is_array($value) && array_key_exists('username', $value) ? $value['username'] : null);
        $out['username'] = $field;
        $field = $value instanceof CreateUserRequest ? $value->displayName : (is_array($value) && array_key_exists('display_name', $value) ? $value['display_name'] : null);
        $out['display_name'] = $field;
        $field = $value instanceof CreateUserRequest ? $value->password : (is_array($value) && array_key_exists('password', $value) ? $value['password'] : null);
        if ($field !== null) {
            $out['password'] = $field;
        }
        return $out;
    }

    public static function fromCborCreateUserRequest($value)
    {
        return new CreateUserRequest(array(
            'username' => array_key_exists('username', $value) ? $value['username'] : null,
            'display_name' => array_key_exists('display_name', $value) ? $value['display_name'] : null,
            'password' => array_key_exists('password', $value) ? $value['password'] : null,
        ));
    }

    public static function encodeCreateUserResponse($value)
    {
        return CBOR::encode(self::toCborCreateUserResponse($value));
    }

    public static function decodeCreateUserResponse($bytes)
    {
        return self::fromCborCreateUserResponse(CBOR::decode($bytes));
    }

    public static function toCborCreateUserResponse($value)
    {
        $out = array();
        $field = $value instanceof CreateUserResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        $field = $value instanceof CreateUserResponse ? $value->apiKey : (is_array($value) && array_key_exists('api_key', $value) ? $value['api_key'] : null);
        if ($field !== null) {
            $out['api_key'] = $field;
        }
        return $out;
    }

    public static function fromCborCreateUserResponse($value)
    {
        return new CreateUserResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
            'api_key' => array_key_exists('api_key', $value) ? $value['api_key'] : null,
        ));
    }

    public static function encodeUpdateUserRequest($value)
    {
        return CBOR::encode(self::toCborUpdateUserRequest($value));
    }

    public static function decodeUpdateUserRequest($bytes)
    {
        return self::fromCborUpdateUserRequest(CBOR::decode($bytes));
    }

    public static function toCborUpdateUserRequest($value)
    {
        $out = array();
        $field = $value instanceof UpdateUserRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof UpdateUserRequest ? $value->displayName : (is_array($value) && array_key_exists('display_name', $value) ? $value['display_name'] : null);
        if ($field !== null) {
            $out['display_name'] = $field;
        }
        return $out;
    }

    public static function fromCborUpdateUserRequest($value)
    {
        return new UpdateUserRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'display_name' => array_key_exists('display_name', $value) ? $value['display_name'] : null,
        ));
    }

    public static function encodeUpdateUserResponse($value)
    {
        return CBOR::encode(self::toCborUpdateUserResponse($value));
    }

    public static function decodeUpdateUserResponse($bytes)
    {
        return self::fromCborUpdateUserResponse(CBOR::decode($bytes));
    }

    public static function toCborUpdateUserResponse($value)
    {
        $out = array();
        $field = $value instanceof UpdateUserResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        return $out;
    }

    public static function fromCborUpdateUserResponse($value)
    {
        return new UpdateUserResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
        ));
    }

    public static function encodeDeactivateUserRequest($value)
    {
        return CBOR::encode(self::toCborDeactivateUserRequest($value));
    }

    public static function decodeDeactivateUserRequest($bytes)
    {
        return self::fromCborDeactivateUserRequest(CBOR::decode($bytes));
    }

    public static function toCborDeactivateUserRequest($value)
    {
        $out = array();
        $field = $value instanceof DeactivateUserRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        return $out;
    }

    public static function fromCborDeactivateUserRequest($value)
    {
        return new DeactivateUserRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeDeactivateUserResponse($value)
    {
        return CBOR::encode(self::toCborDeactivateUserResponse($value));
    }

    public static function decodeDeactivateUserResponse($bytes)
    {
        return self::fromCborDeactivateUserResponse(CBOR::decode($bytes));
    }

    public static function toCborDeactivateUserResponse($value)
    {
        $out = array();
        $field = $value instanceof DeactivateUserResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        return $out;
    }

    public static function fromCborDeactivateUserResponse($value)
    {
        return new DeactivateUserResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
        ));
    }

    public static function encodeResetPasswordRequest($value)
    {
        return CBOR::encode(self::toCborResetPasswordRequest($value));
    }

    public static function decodeResetPasswordRequest($bytes)
    {
        return self::fromCborResetPasswordRequest(CBOR::decode($bytes));
    }

    public static function toCborResetPasswordRequest($value)
    {
        $out = array();
        $field = $value instanceof ResetPasswordRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof ResetPasswordRequest ? $value->newPassword : (is_array($value) && array_key_exists('new_password', $value) ? $value['new_password'] : null);
        $out['new_password'] = $field;
        return $out;
    }

    public static function fromCborResetPasswordRequest($value)
    {
        return new ResetPasswordRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'new_password' => array_key_exists('new_password', $value) ? $value['new_password'] : null,
        ));
    }

    public static function encodeResetPasswordResponse($value)
    {
        return CBOR::encode(self::toCborResetPasswordResponse($value));
    }

    public static function decodeResetPasswordResponse($bytes)
    {
        return self::fromCborResetPasswordResponse(CBOR::decode($bytes));
    }

    public static function toCborResetPasswordResponse($value)
    {
        $out = array();
        $field = $value instanceof ResetPasswordResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out;
    }

    public static function fromCborResetPasswordResponse($value)
    {
        return new ResetPasswordResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeAuthenticateRequest($value)
    {
        return CBOR::encode(self::toCborAuthenticateRequest($value));
    }

    public static function decodeAuthenticateRequest($bytes)
    {
        return self::fromCborAuthenticateRequest(CBOR::decode($bytes));
    }

    public static function toCborAuthenticateRequest($value)
    {
        $out = array();
        $field = $value instanceof AuthenticateRequest ? $value->username : (is_array($value) && array_key_exists('username', $value) ? $value['username'] : null);
        $out['username'] = $field;
        $field = $value instanceof AuthenticateRequest ? $value->password : (is_array($value) && array_key_exists('password', $value) ? $value['password'] : null);
        $out['password'] = $field;
        return $out;
    }

    public static function fromCborAuthenticateRequest($value)
    {
        return new AuthenticateRequest(array(
            'username' => array_key_exists('username', $value) ? $value['username'] : null,
            'password' => array_key_exists('password', $value) ? $value['password'] : null,
        ));
    }

    public static function encodeAuthenticateResponse($value)
    {
        return CBOR::encode(self::toCborAuthenticateResponse($value));
    }

    public static function decodeAuthenticateResponse($bytes)
    {
        return self::fromCborAuthenticateResponse(CBOR::decode($bytes));
    }

    public static function toCborAuthenticateResponse($value)
    {
        $out = array();
        $field = $value instanceof AuthenticateResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        return $out;
    }

    public static function fromCborAuthenticateResponse($value)
    {
        return new AuthenticateResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
        ));
    }

    public static function encodeRemoveCredentialRequest($value)
    {
        return CBOR::encode(self::toCborRemoveCredentialRequest($value));
    }

    public static function decodeRemoveCredentialRequest($bytes)
    {
        return self::fromCborRemoveCredentialRequest(CBOR::decode($bytes));
    }

    public static function toCborRemoveCredentialRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveCredentialRequest ? $value->credentialId : (is_array($value) && array_key_exists('credential_id', $value) ? $value['credential_id'] : null);
        $out['credential_id'] = $field;
        return $out;
    }

    public static function fromCborRemoveCredentialRequest($value)
    {
        return new RemoveCredentialRequest(array(
            'credential_id' => array_key_exists('credential_id', $value) ? $value['credential_id'] : null,
        ));
    }

    public static function encodeRemoveCredentialResponse($value)
    {
        return CBOR::encode(self::toCborRemoveCredentialResponse($value));
    }

    public static function decodeRemoveCredentialResponse($bytes)
    {
        return self::fromCborRemoveCredentialResponse(CBOR::decode($bytes));
    }

    public static function toCborRemoveCredentialResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveCredentialResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out;
    }

    public static function fromCborRemoveCredentialResponse($value)
    {
        return new RemoveCredentialResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeSetClaimRequest($value)
    {
        return CBOR::encode(self::toCborSetClaimRequest($value));
    }

    public static function decodeSetClaimRequest($bytes)
    {
        return self::fromCborSetClaimRequest(CBOR::decode($bytes));
    }

    public static function toCborSetClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof SetClaimRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof SetClaimRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SetClaimRequest ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        $out['claim_value'] = $field;
        $field = $value instanceof SetClaimRequest ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        if ($field !== null) {
            $out['expires_at'] = $field;
        }
        return $out;
    }

    public static function fromCborSetClaimRequest($value)
    {
        return new SetClaimRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
        ));
    }

    public static function encodeSetClaimResponse($value)
    {
        return CBOR::encode(self::toCborSetClaimResponse($value));
    }

    public static function decodeSetClaimResponse($bytes)
    {
        return self::fromCborSetClaimResponse(CBOR::decode($bytes));
    }

    public static function toCborSetClaimResponse($value)
    {
        $out = array();
        $field = $value instanceof SetClaimResponse ? $value->claim : (is_array($value) && array_key_exists('claim', $value) ? $value['claim'] : null);
        $out['claim'] = self::toCborClaim($field);
        return $out;
    }

    public static function fromCborSetClaimResponse($value)
    {
        return new SetClaimResponse(array(
            'claim' => array_key_exists('claim', $value) ? self::fromCborClaim($value['claim']) : null,
        ));
    }

    public static function encodeRemoveClaimRequest($value)
    {
        return CBOR::encode(self::toCborRemoveClaimRequest($value));
    }

    public static function decodeRemoveClaimRequest($bytes)
    {
        return self::fromCborRemoveClaimRequest(CBOR::decode($bytes));
    }

    public static function toCborRemoveClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveClaimRequest ? $value->claimId : (is_array($value) && array_key_exists('claim_id', $value) ? $value['claim_id'] : null);
        $out['claim_id'] = $field;
        return $out;
    }

    public static function fromCborRemoveClaimRequest($value)
    {
        return new RemoveClaimRequest(array(
            'claim_id' => array_key_exists('claim_id', $value) ? $value['claim_id'] : null,
        ));
    }

    public static function encodeRemoveClaimResponse($value)
    {
        return CBOR::encode(self::toCborRemoveClaimResponse($value));
    }

    public static function decodeRemoveClaimResponse($bytes)
    {
        return self::fromCborRemoveClaimResponse(CBOR::decode($bytes));
    }

    public static function toCborRemoveClaimResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveClaimResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out;
    }

    public static function fromCborRemoveClaimResponse($value)
    {
        return new RemoveClaimResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeListUserClaimsRequest($value)
    {
        return CBOR::encode(self::toCborListUserClaimsRequest($value));
    }

    public static function decodeListUserClaimsRequest($bytes)
    {
        return self::fromCborListUserClaimsRequest(CBOR::decode($bytes));
    }

    public static function toCborListUserClaimsRequest($value)
    {
        $out = array();
        $field = $value instanceof ListUserClaimsRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        return $out;
    }

    public static function fromCborListUserClaimsRequest($value)
    {
        return new ListUserClaimsRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeListUserClaimsResponse($value)
    {
        return CBOR::encode(self::toCborListUserClaimsResponse($value));
    }

    public static function decodeListUserClaimsResponse($bytes)
    {
        return self::fromCborListUserClaimsResponse(CBOR::decode($bytes));
    }

    public static function toCborListUserClaimsResponse($value)
    {
        $out = array();
        $field = $value instanceof ListUserClaimsResponse ? $value->claimTypes : (is_array($value) && array_key_exists('claim_types', $value) ? $value['claim_types'] : null);
        $out['claim_types'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborListUserClaimsResponse($value)
    {
        return new ListUserClaimsResponse(array(
            'claim_types' => array_key_exists('claim_types', $value) ? array_map(function ($item) { return $item; }, $value['claim_types'] === null ? array() : $value['claim_types']) : null,
        ));
    }

    public static function encodeSetUserClaimRequest($value)
    {
        return CBOR::encode(self::toCborSetUserClaimRequest($value));
    }

    public static function decodeSetUserClaimRequest($bytes)
    {
        return self::fromCborSetUserClaimRequest(CBOR::decode($bytes));
    }

    public static function toCborSetUserClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof SetUserClaimRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof SetUserClaimRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SetUserClaimRequest ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        $out['claim_value'] = $field;
        return $out;
    }

    public static function fromCborSetUserClaimRequest($value)
    {
        return new SetUserClaimRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
        ));
    }

    public static function encodeSetUserClaimResponse($value)
    {
        return CBOR::encode(self::toCborSetUserClaimResponse($value));
    }

    public static function decodeSetUserClaimResponse($bytes)
    {
        return self::fromCborSetUserClaimResponse(CBOR::decode($bytes));
    }

    public static function toCborSetUserClaimResponse($value)
    {
        $out = array();
        $field = $value instanceof SetUserClaimResponse ? $value->outcome : (is_array($value) && array_key_exists('outcome', $value) ? $value['outcome'] : null);
        $out['outcome'] = $field;
        $field = $value instanceof SetUserClaimResponse ? $value->claim : (is_array($value) && array_key_exists('claim', $value) ? $value['claim'] : null);
        if ($field !== null) {
            $out['claim'] = self::toCborClaim($field);
        }
        return $out;
    }

    public static function fromCborSetUserClaimResponse($value)
    {
        return new SetUserClaimResponse(array(
            'outcome' => array_key_exists('outcome', $value) ? $value['outcome'] : null,
            'claim' => array_key_exists('claim', $value) ? self::fromCborClaim($value['claim']) : null,
        ));
    }

    public static function encodeSettableClaimPolicy($value)
    {
        return CBOR::encode(self::toCborSettableClaimPolicy($value));
    }

    public static function decodeSettableClaimPolicy($bytes)
    {
        return self::fromCborSettableClaimPolicy(CBOR::decode($bytes));
    }

    public static function toCborSettableClaimPolicy($value)
    {
        $out = array();
        $field = $value instanceof SettableClaimPolicy ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SettableClaimPolicy ? $value->datatype : (is_array($value) && array_key_exists('datatype', $value) ? $value['datatype'] : null);
        $out['datatype'] = $field;
        $field = $value instanceof SettableClaimPolicy ? $value->setRule : (is_array($value) && array_key_exists('set_rule', $value) ? $value['set_rule'] : null);
        $out['set_rule'] = $field;
        $field = $value instanceof SettableClaimPolicy ? $value->requiresApproval : (is_array($value) && array_key_exists('requires_approval', $value) ? $value['requires_approval'] : null);
        $out['requires_approval'] = $field;
        $field = $value instanceof SettableClaimPolicy ? $value->signingRule : (is_array($value) && array_key_exists('signing_rule', $value) ? $value['signing_rule'] : null);
        $out['signing_rule'] = $field;
        return $out;
    }

    public static function fromCborSettableClaimPolicy($value)
    {
        return new SettableClaimPolicy(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'datatype' => array_key_exists('datatype', $value) ? $value['datatype'] : null,
            'set_rule' => array_key_exists('set_rule', $value) ? $value['set_rule'] : null,
            'requires_approval' => array_key_exists('requires_approval', $value) ? $value['requires_approval'] : null,
            'signing_rule' => array_key_exists('signing_rule', $value) ? $value['signing_rule'] : null,
        ));
    }

    public static function encodeListSettablePoliciesResponse($value)
    {
        return CBOR::encode(self::toCborListSettablePoliciesResponse($value));
    }

    public static function decodeListSettablePoliciesResponse($bytes)
    {
        return self::fromCborListSettablePoliciesResponse(CBOR::decode($bytes));
    }

    public static function toCborListSettablePoliciesResponse($value)
    {
        $out = array();
        $field = $value instanceof ListSettablePoliciesResponse ? $value->policies : (is_array($value) && array_key_exists('policies', $value) ? $value['policies'] : null);
        $out['policies'] = array_map(function ($item) { return self::toCborSettableClaimPolicy($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborListSettablePoliciesResponse($value)
    {
        return new ListSettablePoliciesResponse(array(
            'policies' => array_key_exists('policies', $value) ? array_map(function ($item) { return self::fromCborSettableClaimPolicy($item); }, $value['policies'] === null ? array() : $value['policies']) : null,
        ));
    }

    public static function encodeGrantRelationRequest($value)
    {
        return CBOR::encode(self::toCborGrantRelationRequest($value));
    }

    public static function decodeGrantRelationRequest($bytes)
    {
        return self::fromCborGrantRelationRequest(CBOR::decode($bytes));
    }

    public static function toCborGrantRelationRequest($value)
    {
        $out = array();
        $field = $value instanceof GrantRelationRequest ? $value->subjectType : (is_array($value) && array_key_exists('subject_type', $value) ? $value['subject_type'] : null);
        $out['subject_type'] = $field;
        $field = $value instanceof GrantRelationRequest ? $value->subjectId : (is_array($value) && array_key_exists('subject_id', $value) ? $value['subject_id'] : null);
        $out['subject_id'] = $field;
        $field = $value instanceof GrantRelationRequest ? $value->relation : (is_array($value) && array_key_exists('relation', $value) ? $value['relation'] : null);
        $out['relation'] = $field;
        $field = $value instanceof GrantRelationRequest ? $value->objectType : (is_array($value) && array_key_exists('object_type', $value) ? $value['object_type'] : null);
        $out['object_type'] = $field;
        $field = $value instanceof GrantRelationRequest ? $value->objectId : (is_array($value) && array_key_exists('object_id', $value) ? $value['object_id'] : null);
        $out['object_id'] = $field;
        return $out;
    }

    public static function fromCborGrantRelationRequest($value)
    {
        return new GrantRelationRequest(array(
            'subject_type' => array_key_exists('subject_type', $value) ? $value['subject_type'] : null,
            'subject_id' => array_key_exists('subject_id', $value) ? $value['subject_id'] : null,
            'relation' => array_key_exists('relation', $value) ? $value['relation'] : null,
            'object_type' => array_key_exists('object_type', $value) ? $value['object_type'] : null,
            'object_id' => array_key_exists('object_id', $value) ? $value['object_id'] : null,
        ));
    }

    public static function encodeGrantRelationResponse($value)
    {
        return CBOR::encode(self::toCborGrantRelationResponse($value));
    }

    public static function decodeGrantRelationResponse($bytes)
    {
        return self::fromCborGrantRelationResponse(CBOR::decode($bytes));
    }

    public static function toCborGrantRelationResponse($value)
    {
        $out = array();
        $field = $value instanceof GrantRelationResponse ? $value->relation : (is_array($value) && array_key_exists('relation', $value) ? $value['relation'] : null);
        $out['relation'] = self::toCborRelation($field);
        return $out;
    }

    public static function fromCborGrantRelationResponse($value)
    {
        return new GrantRelationResponse(array(
            'relation' => array_key_exists('relation', $value) ? self::fromCborRelation($value['relation']) : null,
        ));
    }

    public static function encodeRemoveRelationRequest($value)
    {
        return CBOR::encode(self::toCborRemoveRelationRequest($value));
    }

    public static function decodeRemoveRelationRequest($bytes)
    {
        return self::fromCborRemoveRelationRequest(CBOR::decode($bytes));
    }

    public static function toCborRemoveRelationRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveRelationRequest ? $value->relationId : (is_array($value) && array_key_exists('relation_id', $value) ? $value['relation_id'] : null);
        $out['relation_id'] = $field;
        return $out;
    }

    public static function fromCborRemoveRelationRequest($value)
    {
        return new RemoveRelationRequest(array(
            'relation_id' => array_key_exists('relation_id', $value) ? $value['relation_id'] : null,
        ));
    }

    public static function encodeRemoveRelationResponse($value)
    {
        return CBOR::encode(self::toCborRemoveRelationResponse($value));
    }

    public static function decodeRemoveRelationResponse($bytes)
    {
        return self::fromCborRemoveRelationResponse(CBOR::decode($bytes));
    }

    public static function toCborRemoveRelationResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveRelationResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out;
    }

    public static function fromCborRemoveRelationResponse($value)
    {
        return new RemoveRelationResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeListRelationsRequest($value)
    {
        return CBOR::encode(self::toCborListRelationsRequest($value));
    }

    public static function decodeListRelationsRequest($bytes)
    {
        return self::fromCborListRelationsRequest(CBOR::decode($bytes));
    }

    public static function toCborListRelationsRequest($value)
    {
        $out = array();
        $field = $value instanceof ListRelationsRequest ? $value->subjectType : (is_array($value) && array_key_exists('subject_type', $value) ? $value['subject_type'] : null);
        if ($field !== null) {
            $out['subject_type'] = $field;
        }
        $field = $value instanceof ListRelationsRequest ? $value->subjectId : (is_array($value) && array_key_exists('subject_id', $value) ? $value['subject_id'] : null);
        if ($field !== null) {
            $out['subject_id'] = $field;
        }
        $field = $value instanceof ListRelationsRequest ? $value->objectType : (is_array($value) && array_key_exists('object_type', $value) ? $value['object_type'] : null);
        if ($field !== null) {
            $out['object_type'] = $field;
        }
        $field = $value instanceof ListRelationsRequest ? $value->objectId : (is_array($value) && array_key_exists('object_id', $value) ? $value['object_id'] : null);
        if ($field !== null) {
            $out['object_id'] = $field;
        }
        return $out;
    }

    public static function fromCborListRelationsRequest($value)
    {
        return new ListRelationsRequest(array(
            'subject_type' => array_key_exists('subject_type', $value) ? $value['subject_type'] : null,
            'subject_id' => array_key_exists('subject_id', $value) ? $value['subject_id'] : null,
            'object_type' => array_key_exists('object_type', $value) ? $value['object_type'] : null,
            'object_id' => array_key_exists('object_id', $value) ? $value['object_id'] : null,
        ));
    }

    public static function encodeListRelationsResponse($value)
    {
        return CBOR::encode(self::toCborListRelationsResponse($value));
    }

    public static function decodeListRelationsResponse($bytes)
    {
        return self::fromCborListRelationsResponse(CBOR::decode($bytes));
    }

    public static function toCborListRelationsResponse($value)
    {
        $out = array();
        $field = $value instanceof ListRelationsResponse ? $value->relations : (is_array($value) && array_key_exists('relations', $value) ? $value['relations'] : null);
        $out['relations'] = array_map(function ($item) { return self::toCborRelation($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborListRelationsResponse($value)
    {
        return new ListRelationsResponse(array(
            'relations' => array_key_exists('relations', $value) ? array_map(function ($item) { return self::fromCborRelation($item); }, $value['relations'] === null ? array() : $value['relations']) : null,
        ));
    }

    public static function encodeCheckPermissionRequest($value)
    {
        return CBOR::encode(self::toCborCheckPermissionRequest($value));
    }

    public static function decodeCheckPermissionRequest($bytes)
    {
        return self::fromCborCheckPermissionRequest(CBOR::decode($bytes));
    }

    public static function toCborCheckPermissionRequest($value)
    {
        $out = array();
        $field = $value instanceof CheckPermissionRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof CheckPermissionRequest ? $value->relation : (is_array($value) && array_key_exists('relation', $value) ? $value['relation'] : null);
        $out['relation'] = $field;
        $field = $value instanceof CheckPermissionRequest ? $value->objectType : (is_array($value) && array_key_exists('object_type', $value) ? $value['object_type'] : null);
        $out['object_type'] = $field;
        $field = $value instanceof CheckPermissionRequest ? $value->objectId : (is_array($value) && array_key_exists('object_id', $value) ? $value['object_id'] : null);
        $out['object_id'] = $field;
        return $out;
    }

    public static function fromCborCheckPermissionRequest($value)
    {
        return new CheckPermissionRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'relation' => array_key_exists('relation', $value) ? $value['relation'] : null,
            'object_type' => array_key_exists('object_type', $value) ? $value['object_type'] : null,
            'object_id' => array_key_exists('object_id', $value) ? $value['object_id'] : null,
        ));
    }

    public static function encodeCheckPermissionResponse($value)
    {
        return CBOR::encode(self::toCborCheckPermissionResponse($value));
    }

    public static function decodeCheckPermissionResponse($bytes)
    {
        return self::fromCborCheckPermissionResponse(CBOR::decode($bytes));
    }

    public static function toCborCheckPermissionResponse($value)
    {
        $out = array();
        $field = $value instanceof CheckPermissionResponse ? $value->allowed : (is_array($value) && array_key_exists('allowed', $value) ? $value['allowed'] : null);
        $out['allowed'] = $field;
        return $out;
    }

    public static function fromCborCheckPermissionResponse($value)
    {
        return new CheckPermissionResponse(array(
            'allowed' => array_key_exists('allowed', $value) ? $value['allowed'] : null,
        ));
    }

    public static function encodeChangePasswordRequest($value)
    {
        return CBOR::encode(self::toCborChangePasswordRequest($value));
    }

    public static function decodeChangePasswordRequest($bytes)
    {
        return self::fromCborChangePasswordRequest(CBOR::decode($bytes));
    }

    public static function toCborChangePasswordRequest($value)
    {
        $out = array();
        $field = $value instanceof ChangePasswordRequest ? $value->newPassword : (is_array($value) && array_key_exists('new_password', $value) ? $value['new_password'] : null);
        $out['new_password'] = $field;
        return $out;
    }

    public static function fromCborChangePasswordRequest($value)
    {
        return new ChangePasswordRequest(array(
            'new_password' => array_key_exists('new_password', $value) ? $value['new_password'] : null,
        ));
    }

    public static function encodeChangePasswordResponse($value)
    {
        return CBOR::encode(self::toCborChangePasswordResponse($value));
    }

    public static function decodeChangePasswordResponse($bytes)
    {
        return self::fromCborChangePasswordResponse(CBOR::decode($bytes));
    }

    public static function toCborChangePasswordResponse($value)
    {
        $out = array();
        $field = $value instanceof ChangePasswordResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out;
    }

    public static function fromCborChangePasswordResponse($value)
    {
        return new ChangePasswordResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeGetMyInfoResponse($value)
    {
        return CBOR::encode(self::toCborGetMyInfoResponse($value));
    }

    public static function decodeGetMyInfoResponse($bytes)
    {
        return self::fromCborGetMyInfoResponse(CBOR::decode($bytes));
    }

    public static function toCborGetMyInfoResponse($value)
    {
        $out = array();
        $field = $value instanceof GetMyInfoResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        $field = $value instanceof GetMyInfoResponse ? $value->relations : (is_array($value) && array_key_exists('relations', $value) ? $value['relations'] : null);
        $out['relations'] = array_map(function ($item) { return self::toCborRelation($item); }, $field === null ? array() : $field);
        $field = $value instanceof GetMyInfoResponse ? $value->claims : (is_array($value) && array_key_exists('claims', $value) ? $value['claims'] : null);
        $out['claims'] = array_map(function ($item) { return self::toCborClaim($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborGetMyInfoResponse($value)
    {
        return new GetMyInfoResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
            'relations' => array_key_exists('relations', $value) ? array_map(function ($item) { return self::fromCborRelation($item); }, $value['relations'] === null ? array() : $value['relations']) : null,
            'claims' => array_key_exists('claims', $value) ? array_map(function ($item) { return self::fromCborClaim($item); }, $value['claims'] === null ? array() : $value['claims']) : null,
        ));
    }

    public static function encodeRpSignRequest($value)
    {
        return CBOR::encode(self::toCborRpSignRequest($value));
    }

    public static function decodeRpSignRequest($bytes)
    {
        return self::fromCborRpSignRequest(CBOR::decode($bytes));
    }

    public static function toCborRpSignRequest($value)
    {
        $out = array();
        $field = $value instanceof RpSignRequest ? $value->callbackUrl : (is_array($value) && array_key_exists('callback_url', $value) ? $value['callback_url'] : null);
        $out['callback_url'] = $field;
        $field = $value instanceof RpSignRequest ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = $field;
        $field = $value instanceof RpSignRequest ? $value->requestedClaims : (is_array($value) && array_key_exists('requested_claims', $value) ? $value['requested_claims'] : null);
        if ($field !== null) {
            $out['requested_claims'] = self::toCborClaimRequest($field);
        }
        $field = $value instanceof RpSignRequest ? $value->flowContext : (is_array($value) && array_key_exists('flow_context', $value) ? $value['flow_context'] : null);
        if ($field !== null) {
            $out['flow_context'] = self::toCborAuthFlowContext($field);
        }
        return $out;
    }

    public static function fromCborRpSignRequest($value)
    {
        return new RpSignRequest(array(
            'callback_url' => array_key_exists('callback_url', $value) ? $value['callback_url'] : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'requested_claims' => array_key_exists('requested_claims', $value) ? self::fromCborClaimRequest($value['requested_claims']) : null,
            'flow_context' => array_key_exists('flow_context', $value) ? self::fromCborAuthFlowContext($value['flow_context']) : null,
        ));
    }

    public static function encodeRpSignResponse($value)
    {
        return CBOR::encode(self::toCborRpSignResponse($value));
    }

    public static function decodeRpSignResponse($bytes)
    {
        return self::fromCborRpSignResponse(CBOR::decode($bytes));
    }

    public static function toCborRpSignResponse($value)
    {
        $out = array();
        $field = $value instanceof RpSignResponse ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = $field;
        return $out;
    }

    public static function fromCborRpSignResponse($value)
    {
        return new RpSignResponse(array(
            'signed_request' => array_key_exists('signed_request', $value) ? $value['signed_request'] : null,
        ));
    }

    public static function encodeRpDecryptRequest($value)
    {
        return CBOR::encode(self::toCborRpDecryptRequest($value));
    }

    public static function decodeRpDecryptRequest($bytes)
    {
        return self::fromCborRpDecryptRequest(CBOR::decode($bytes));
    }

    public static function toCborRpDecryptRequest($value)
    {
        $out = array();
        $field = $value instanceof RpDecryptRequest ? $value->encryptedToken : (is_array($value) && array_key_exists('encrypted_token', $value) ? $value['encrypted_token'] : null);
        $out['encrypted_token'] = $field;
        return $out;
    }

    public static function fromCborRpDecryptRequest($value)
    {
        return new RpDecryptRequest(array(
            'encrypted_token' => array_key_exists('encrypted_token', $value) ? $value['encrypted_token'] : null,
        ));
    }

    public static function encodeRpDecryptResponse($value)
    {
        return CBOR::encode(self::toCborRpDecryptResponse($value));
    }

    public static function decodeRpDecryptResponse($bytes)
    {
        return self::fromCborRpDecryptResponse(CBOR::decode($bytes));
    }

    public static function toCborRpDecryptResponse($value)
    {
        $out = array();
        $field = $value instanceof RpDecryptResponse ? $value->signedAssertion : (is_array($value) && array_key_exists('signed_assertion', $value) ? $value['signed_assertion'] : null);
        $out['signed_assertion'] = $field;
        return $out;
    }

    public static function fromCborRpDecryptResponse($value)
    {
        return new RpDecryptResponse(array(
            'signed_assertion' => array_key_exists('signed_assertion', $value) ? $value['signed_assertion'] : null,
        ));
    }

    public static function encodeRpVerifyRequest($value)
    {
        return CBOR::encode(self::toCborRpVerifyRequest($value));
    }

    public static function decodeRpVerifyRequest($bytes)
    {
        return self::fromCborRpVerifyRequest(CBOR::decode($bytes));
    }

    public static function toCborRpVerifyRequest($value)
    {
        $out = array();
        $field = $value instanceof RpVerifyRequest ? $value->signedAssertion : (is_array($value) && array_key_exists('signed_assertion', $value) ? $value['signed_assertion'] : null);
        $out['signed_assertion'] = $field;
        $field = $value instanceof RpVerifyRequest ? $value->expectedDomain : (is_array($value) && array_key_exists('expected_domain', $value) ? $value['expected_domain'] : null);
        $out['expected_domain'] = $field;
        return $out;
    }

    public static function fromCborRpVerifyRequest($value)
    {
        return new RpVerifyRequest(array(
            'signed_assertion' => array_key_exists('signed_assertion', $value) ? $value['signed_assertion'] : null,
            'expected_domain' => array_key_exists('expected_domain', $value) ? $value['expected_domain'] : null,
        ));
    }

    public static function encodeRpVerifyResponse($value)
    {
        return CBOR::encode(self::toCborRpVerifyResponse($value));
    }

    public static function decodeRpVerifyResponse($bytes)
    {
        return self::fromCborRpVerifyResponse(CBOR::decode($bytes));
    }

    public static function toCborRpVerifyResponse($value)
    {
        $out = array();
        $field = $value instanceof RpVerifyResponse ? $value->assertion : (is_array($value) && array_key_exists('assertion', $value) ? $value['assertion'] : null);
        $out['assertion'] = self::toCborIdentityAssertion($field);
        $field = $value instanceof RpVerifyResponse ? $value->verified : (is_array($value) && array_key_exists('verified', $value) ? $value['verified'] : null);
        $out['verified'] = $field;
        return $out;
    }

    public static function fromCborRpVerifyResponse($value)
    {
        return new RpVerifyResponse(array(
            'assertion' => array_key_exists('assertion', $value) ? self::fromCborIdentityAssertion($value['assertion']) : null,
            'verified' => array_key_exists('verified', $value) ? $value['verified'] : null,
        ));
    }

    public static function encodeRpUserInfoRequest($value)
    {
        return CBOR::encode(self::toCborRpUserInfoRequest($value));
    }

    public static function decodeRpUserInfoRequest($bytes)
    {
        return self::fromCborRpUserInfoRequest(CBOR::decode($bytes));
    }

    public static function toCborRpUserInfoRequest($value)
    {
        $out = array();
        $field = $value instanceof RpUserInfoRequest ? $value->token : (is_array($value) && array_key_exists('token', $value) ? $value['token'] : null);
        $out['token'] = $field;
        $field = $value instanceof RpUserInfoRequest ? $value->apiBase : (is_array($value) && array_key_exists('api_base', $value) ? $value['api_base'] : null);
        $out['api_base'] = $field;
        $field = $value instanceof RpUserInfoRequest ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        return $out;
    }

    public static function fromCborRpUserInfoRequest($value)
    {
        return new RpUserInfoRequest(array(
            'token' => array_key_exists('token', $value) ? $value['token'] : null,
            'api_base' => array_key_exists('api_base', $value) ? $value['api_base'] : null,
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
        ));
    }

    public static function encodeRpIssueAttestationRequest($value)
    {
        return CBOR::encode(self::toCborRpIssueAttestationRequest($value));
    }

    public static function decodeRpIssueAttestationRequest($bytes)
    {
        return self::fromCborRpIssueAttestationRequest(CBOR::decode($bytes));
    }

    public static function toCborRpIssueAttestationRequest($value)
    {
        $out = array();
        $field = $value instanceof RpIssueAttestationRequest ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = self::toCborSignedSigningRequest($field);
        $field = $value instanceof RpIssueAttestationRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof RpIssueAttestationRequest ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        $out['claim_value'] = CBOR::bytes($field);
        return $out;
    }

    public static function fromCborRpIssueAttestationRequest($value)
    {
        return new RpIssueAttestationRequest(array(
            'signed_request' => array_key_exists('signed_request', $value) ? self::fromCborSignedSigningRequest($value['signed_request']) : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
        ));
    }

    public static function encodeRpIssueAttestationResponse($value)
    {
        return CBOR::encode(self::toCborRpIssueAttestationResponse($value));
    }

    public static function decodeRpIssueAttestationResponse($bytes)
    {
        return self::fromCborRpIssueAttestationResponse(CBOR::decode($bytes));
    }

    public static function toCborRpIssueAttestationResponse($value)
    {
        $out = array();
        $field = $value instanceof RpIssueAttestationResponse ? $value->claim : (is_array($value) && array_key_exists('claim', $value) ? $value['claim'] : null);
        $out['claim'] = self::toCborClaim($field);
        $field = $value instanceof RpIssueAttestationResponse ? $value->deposited : (is_array($value) && array_key_exists('deposited', $value) ? $value['deposited'] : null);
        $out['deposited'] = $field;
        return $out;
    }

    public static function fromCborRpIssueAttestationResponse($value)
    {
        return new RpIssueAttestationResponse(array(
            'claim' => array_key_exists('claim', $value) ? self::fromCborClaim($value['claim']) : null,
            'deposited' => array_key_exists('deposited', $value) ? $value['deposited'] : null,
        ));
    }

    public static function encodeAeadSuite($value)
    {
        return CBOR::encode(self::toCborAeadSuite($value));
    }

    public static function decodeAeadSuite($bytes)
    {
        return self::fromCborAeadSuite(CBOR::decode($bytes));
    }

    public static function toCborAeadSuite($value)
    {
        return $value;
    }

    public static function fromCborAeadSuite($value)
    {
        return $value;
    }

    public static function encodeLocalRpPolicy($value)
    {
        return CBOR::encode(self::toCborLocalRpPolicy($value));
    }

    public static function decodeLocalRpPolicy($bytes)
    {
        return self::fromCborLocalRpPolicy(CBOR::decode($bytes));
    }

    public static function toCborLocalRpPolicy($value)
    {
        return $value;
    }

    public static function fromCborLocalRpPolicy($value)
    {
        return $value;
    }

    public static function encodeLocalRpDescriptor($value)
    {
        return CBOR::encode(self::toCborLocalRpDescriptor($value));
    }

    public static function decodeLocalRpDescriptor($bytes)
    {
        return self::fromCborLocalRpDescriptor(CBOR::decode($bytes));
    }

    public static function toCborLocalRpDescriptor($value)
    {
        $out = array();
        $field = $value instanceof LocalRpDescriptor ? $value->appName : (is_array($value) && array_key_exists('app_name', $value) ? $value['app_name'] : null);
        $out['app_name'] = $field;
        $field = $value instanceof LocalRpDescriptor ? $value->localDomainHint : (is_array($value) && array_key_exists('local_domain_hint', $value) ? $value['local_domain_hint'] : null);
        if ($field !== null) {
            $out['local_domain_hint'] = $field;
        }
        $field = $value instanceof LocalRpDescriptor ? $value->signingPublicKey : (is_array($value) && array_key_exists('signing_public_key', $value) ? $value['signing_public_key'] : null);
        $out['signing_public_key'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpDescriptor ? $value->encryptionPublicKey : (is_array($value) && array_key_exists('encryption_public_key', $value) ? $value['encryption_public_key'] : null);
        $out['encryption_public_key'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpDescriptor ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof LocalRpDescriptor ? $value->supportedSuites : (is_array($value) && array_key_exists('supported_suites', $value) ? $value['supported_suites'] : null);
        $out['supported_suites'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof LocalRpDescriptor ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = $field;
        $field = $value instanceof LocalRpDescriptor ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = $field;
        return $out;
    }

    public static function fromCborLocalRpDescriptor($value)
    {
        return new LocalRpDescriptor(array(
            'app_name' => array_key_exists('app_name', $value) ? $value['app_name'] : null,
            'local_domain_hint' => array_key_exists('local_domain_hint', $value) ? $value['local_domain_hint'] : null,
            'signing_public_key' => array_key_exists('signing_public_key', $value) ? $value['signing_public_key'] : null,
            'encryption_public_key' => array_key_exists('encryption_public_key', $value) ? $value['encryption_public_key'] : null,
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'supported_suites' => array_key_exists('supported_suites', $value) ? array_map(function ($item) { return $item; }, $value['supported_suites'] === null ? array() : $value['supported_suites']) : null,
            'created_at' => array_key_exists('created_at', $value) ? $value['created_at'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
        ));
    }

    public static function encodeSignedLocalRpDescriptor($value)
    {
        return CBOR::encode(self::toCborSignedLocalRpDescriptor($value));
    }

    public static function decodeSignedLocalRpDescriptor($bytes)
    {
        return self::fromCborSignedLocalRpDescriptor(CBOR::decode($bytes));
    }

    public static function toCborSignedLocalRpDescriptor($value)
    {
        $out = array();
        $field = $value instanceof SignedLocalRpDescriptor ? $value->descriptor : (is_array($value) && array_key_exists('descriptor', $value) ? $value['descriptor'] : null);
        $out['descriptor'] = CBOR::bytes($field);
        $field = $value instanceof SignedLocalRpDescriptor ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        return $out;
    }

    public static function fromCborSignedLocalRpDescriptor($value)
    {
        return new SignedLocalRpDescriptor(array(
            'descriptor' => array_key_exists('descriptor', $value) ? $value['descriptor'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
        ));
    }

    public static function encodeLocalRpLoginRequest($value)
    {
        return CBOR::encode(self::toCborLocalRpLoginRequest($value));
    }

    public static function decodeLocalRpLoginRequest($bytes)
    {
        return self::fromCborLocalRpLoginRequest(CBOR::decode($bytes));
    }

    public static function toCborLocalRpLoginRequest($value)
    {
        $out = array();
        $field = $value instanceof LocalRpLoginRequest ? $value->descriptor : (is_array($value) && array_key_exists('descriptor', $value) ? $value['descriptor'] : null);
        $out['descriptor'] = self::toCborSignedLocalRpDescriptor($field);
        $field = $value instanceof LocalRpLoginRequest ? $value->callbackUrl : (is_array($value) && array_key_exists('callback_url', $value) ? $value['callback_url'] : null);
        $out['callback_url'] = $field;
        $field = $value instanceof LocalRpLoginRequest ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpLoginRequest ? $value->state : (is_array($value) && array_key_exists('state', $value) ? $value['state'] : null);
        $out['state'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpLoginRequest ? $value->requestedClaims : (is_array($value) && array_key_exists('requested_claims', $value) ? $value['requested_claims'] : null);
        $out['requested_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof LocalRpLoginRequest ? $value->requiredClaims : (is_array($value) && array_key_exists('required_claims', $value) ? $value['required_claims'] : null);
        $out['required_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof LocalRpLoginRequest ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = $field;
        $field = $value instanceof LocalRpLoginRequest ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = $field;
        return $out;
    }

    public static function fromCborLocalRpLoginRequest($value)
    {
        return new LocalRpLoginRequest(array(
            'descriptor' => array_key_exists('descriptor', $value) ? self::fromCborSignedLocalRpDescriptor($value['descriptor']) : null,
            'callback_url' => array_key_exists('callback_url', $value) ? $value['callback_url'] : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'state' => array_key_exists('state', $value) ? $value['state'] : null,
            'requested_claims' => array_key_exists('requested_claims', $value) ? array_map(function ($item) { return $item; }, $value['requested_claims'] === null ? array() : $value['requested_claims']) : null,
            'required_claims' => array_key_exists('required_claims', $value) ? array_map(function ($item) { return $item; }, $value['required_claims'] === null ? array() : $value['required_claims']) : null,
            'issued_at' => array_key_exists('issued_at', $value) ? $value['issued_at'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
        ));
    }

    public static function encodeSignedLocalRpLoginRequest($value)
    {
        return CBOR::encode(self::toCborSignedLocalRpLoginRequest($value));
    }

    public static function decodeSignedLocalRpLoginRequest($bytes)
    {
        return self::fromCborSignedLocalRpLoginRequest(CBOR::decode($bytes));
    }

    public static function toCborSignedLocalRpLoginRequest($value)
    {
        $out = array();
        $field = $value instanceof SignedLocalRpLoginRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = CBOR::bytes($field);
        $field = $value instanceof SignedLocalRpLoginRequest ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        return $out;
    }

    public static function fromCborSignedLocalRpLoginRequest($value)
    {
        return new SignedLocalRpLoginRequest(array(
            'request' => array_key_exists('request', $value) ? $value['request'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
        ));
    }

    public static function encodeLocalRpCallbackHeader($value)
    {
        return CBOR::encode(self::toCborLocalRpCallbackHeader($value));
    }

    public static function decodeLocalRpCallbackHeader($bytes)
    {
        return self::fromCborLocalRpCallbackHeader(CBOR::decode($bytes));
    }

    public static function toCborLocalRpCallbackHeader($value)
    {
        $out = array();
        $field = $value instanceof LocalRpCallbackHeader ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof LocalRpCallbackHeader ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpCallbackHeader ? $value->state : (is_array($value) && array_key_exists('state', $value) ? $value['state'] : null);
        $out['state'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpCallbackHeader ? $value->suite : (is_array($value) && array_key_exists('suite', $value) ? $value['suite'] : null);
        $out['suite'] = $field;
        $field = $value instanceof LocalRpCallbackHeader ? $value->ephemeralPublicKey : (is_array($value) && array_key_exists('ephemeral_public_key', $value) ? $value['ephemeral_public_key'] : null);
        $out['ephemeral_public_key'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpCallbackHeader ? $value->aeadNonce : (is_array($value) && array_key_exists('aead_nonce', $value) ? $value['aead_nonce'] : null);
        $out['aead_nonce'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpCallbackHeader ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = $field;
        $field = $value instanceof LocalRpCallbackHeader ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = $field;
        return $out;
    }

    public static function fromCborLocalRpCallbackHeader($value)
    {
        return new LocalRpCallbackHeader(array(
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'state' => array_key_exists('state', $value) ? $value['state'] : null,
            'suite' => array_key_exists('suite', $value) ? $value['suite'] : null,
            'ephemeral_public_key' => array_key_exists('ephemeral_public_key', $value) ? $value['ephemeral_public_key'] : null,
            'aead_nonce' => array_key_exists('aead_nonce', $value) ? $value['aead_nonce'] : null,
            'issued_at' => array_key_exists('issued_at', $value) ? $value['issued_at'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
        ));
    }

    public static function encodeLocalRpEncryptedCallback($value)
    {
        return CBOR::encode(self::toCborLocalRpEncryptedCallback($value));
    }

    public static function decodeLocalRpEncryptedCallback($bytes)
    {
        return self::fromCborLocalRpEncryptedCallback(CBOR::decode($bytes));
    }

    public static function toCborLocalRpEncryptedCallback($value)
    {
        $out = array();
        $field = $value instanceof LocalRpEncryptedCallback ? $value->header : (is_array($value) && array_key_exists('header', $value) ? $value['header'] : null);
        $out['header'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpEncryptedCallback ? $value->ciphertext : (is_array($value) && array_key_exists('ciphertext', $value) ? $value['ciphertext'] : null);
        $out['ciphertext'] = CBOR::bytes($field);
        return $out;
    }

    public static function fromCborLocalRpEncryptedCallback($value)
    {
        return new LocalRpEncryptedCallback(array(
            'header' => array_key_exists('header', $value) ? $value['header'] : null,
            'ciphertext' => array_key_exists('ciphertext', $value) ? $value['ciphertext'] : null,
        ));
    }

    public static function encodeLocalRpCallbackPayload($value)
    {
        return CBOR::encode(self::toCborLocalRpCallbackPayload($value));
    }

    public static function decodeLocalRpCallbackPayload($bytes)
    {
        return self::fromCborLocalRpCallbackPayload(CBOR::decode($bytes));
    }

    public static function toCborLocalRpCallbackPayload($value)
    {
        $out = array();
        $field = $value instanceof LocalRpCallbackPayload ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof LocalRpCallbackPayload ? $value->userDomain : (is_array($value) && array_key_exists('user_domain', $value) ? $value['user_domain'] : null);
        $out['user_domain'] = $field;
        $field = $value instanceof LocalRpCallbackPayload ? $value->claimTicket : (is_array($value) && array_key_exists('claim_ticket', $value) ? $value['claim_ticket'] : null);
        $out['claim_ticket'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpCallbackPayload ? $value->audienceFingerprint : (is_array($value) && array_key_exists('audience_fingerprint', $value) ? $value['audience_fingerprint'] : null);
        $out['audience_fingerprint'] = $field;
        $field = $value instanceof LocalRpCallbackPayload ? $value->callbackUrl : (is_array($value) && array_key_exists('callback_url', $value) ? $value['callback_url'] : null);
        $out['callback_url'] = $field;
        $field = $value instanceof LocalRpCallbackPayload ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpCallbackPayload ? $value->state : (is_array($value) && array_key_exists('state', $value) ? $value['state'] : null);
        $out['state'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpCallbackPayload ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = $field;
        $field = $value instanceof LocalRpCallbackPayload ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = $field;
        return $out;
    }

    public static function fromCborLocalRpCallbackPayload($value)
    {
        return new LocalRpCallbackPayload(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'user_domain' => array_key_exists('user_domain', $value) ? $value['user_domain'] : null,
            'claim_ticket' => array_key_exists('claim_ticket', $value) ? $value['claim_ticket'] : null,
            'audience_fingerprint' => array_key_exists('audience_fingerprint', $value) ? $value['audience_fingerprint'] : null,
            'callback_url' => array_key_exists('callback_url', $value) ? $value['callback_url'] : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'state' => array_key_exists('state', $value) ? $value['state'] : null,
            'issued_at' => array_key_exists('issued_at', $value) ? $value['issued_at'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
        ));
    }

    public static function encodeSignedLocalRpCallbackPayload($value)
    {
        return CBOR::encode(self::toCborSignedLocalRpCallbackPayload($value));
    }

    public static function decodeSignedLocalRpCallbackPayload($bytes)
    {
        return self::fromCborSignedLocalRpCallbackPayload(CBOR::decode($bytes));
    }

    public static function toCborSignedLocalRpCallbackPayload($value)
    {
        $out = array();
        $field = $value instanceof SignedLocalRpCallbackPayload ? $value->payload : (is_array($value) && array_key_exists('payload', $value) ? $value['payload'] : null);
        $out['payload'] = CBOR::bytes($field);
        $field = $value instanceof SignedLocalRpCallbackPayload ? $value->signingKeyId : (is_array($value) && array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null);
        $out['signing_key_id'] = $field;
        $field = $value instanceof SignedLocalRpCallbackPayload ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        return $out;
    }

    public static function fromCborSignedLocalRpCallbackPayload($value)
    {
        return new SignedLocalRpCallbackPayload(array(
            'payload' => array_key_exists('payload', $value) ? $value['payload'] : null,
            'signing_key_id' => array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
        ));
    }

    public static function encodeLocalRpTicketRedemptionRequest($value)
    {
        return CBOR::encode(self::toCborLocalRpTicketRedemptionRequest($value));
    }

    public static function decodeLocalRpTicketRedemptionRequest($bytes)
    {
        return self::fromCborLocalRpTicketRedemptionRequest(CBOR::decode($bytes));
    }

    public static function toCborLocalRpTicketRedemptionRequest($value)
    {
        $out = array();
        $field = $value instanceof LocalRpTicketRedemptionRequest ? $value->claimTicket : (is_array($value) && array_key_exists('claim_ticket', $value) ? $value['claim_ticket'] : null);
        $out['claim_ticket'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpTicketRedemptionRequest ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof LocalRpTicketRedemptionRequest ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = $field;
        return $out;
    }

    public static function fromCborLocalRpTicketRedemptionRequest($value)
    {
        return new LocalRpTicketRedemptionRequest(array(
            'claim_ticket' => array_key_exists('claim_ticket', $value) ? $value['claim_ticket'] : null,
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'issued_at' => array_key_exists('issued_at', $value) ? $value['issued_at'] : null,
        ));
    }

    public static function encodeSignedLocalRpTicketRedemptionRequest($value)
    {
        return CBOR::encode(self::toCborSignedLocalRpTicketRedemptionRequest($value));
    }

    public static function decodeSignedLocalRpTicketRedemptionRequest($bytes)
    {
        return self::fromCborSignedLocalRpTicketRedemptionRequest(CBOR::decode($bytes));
    }

    public static function toCborSignedLocalRpTicketRedemptionRequest($value)
    {
        $out = array();
        $field = $value instanceof SignedLocalRpTicketRedemptionRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = CBOR::bytes($field);
        $field = $value instanceof SignedLocalRpTicketRedemptionRequest ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        return $out;
    }

    public static function fromCborSignedLocalRpTicketRedemptionRequest($value)
    {
        return new SignedLocalRpTicketRedemptionRequest(array(
            'request' => array_key_exists('request', $value) ? $value['request'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
        ));
    }

    public static function encodeLocalRpTicketRedemptionResponse($value)
    {
        return CBOR::encode(self::toCborLocalRpTicketRedemptionResponse($value));
    }

    public static function decodeLocalRpTicketRedemptionResponse($bytes)
    {
        return self::fromCborLocalRpTicketRedemptionResponse(CBOR::decode($bytes));
    }

    public static function toCborLocalRpTicketRedemptionResponse($value)
    {
        $out = array();
        $field = $value instanceof LocalRpTicketRedemptionResponse ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof LocalRpTicketRedemptionResponse ? $value->userDomain : (is_array($value) && array_key_exists('user_domain', $value) ? $value['user_domain'] : null);
        $out['user_domain'] = $field;
        $field = $value instanceof LocalRpTicketRedemptionResponse ? $value->claims : (is_array($value) && array_key_exists('claims', $value) ? $value['claims'] : null);
        $out['claims'] = array_map(function ($item) { return self::toCborClaim($item); }, $field === null ? array() : $field);
        $field = $value instanceof LocalRpTicketRedemptionResponse ? $value->ticketExpiresAt : (is_array($value) && array_key_exists('ticket_expires_at', $value) ? $value['ticket_expires_at'] : null);
        $out['ticket_expires_at'] = $field;
        return $out;
    }

    public static function fromCborLocalRpTicketRedemptionResponse($value)
    {
        return new LocalRpTicketRedemptionResponse(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'user_domain' => array_key_exists('user_domain', $value) ? $value['user_domain'] : null,
            'claims' => array_key_exists('claims', $value) ? array_map(function ($item) { return self::fromCborClaim($item); }, $value['claims'] === null ? array() : $value['claims']) : null,
            'ticket_expires_at' => array_key_exists('ticket_expires_at', $value) ? $value['ticket_expires_at'] : null,
        ));
    }

    public static function encodeAdminLocalRp($value)
    {
        return CBOR::encode(self::toCborAdminLocalRp($value));
    }

    public static function decodeAdminLocalRp($bytes)
    {
        return self::fromCborAdminLocalRp(CBOR::decode($bytes));
    }

    public static function toCborAdminLocalRp($value)
    {
        $out = array();
        $field = $value instanceof AdminLocalRp ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof AdminLocalRp ? $value->signingPublicKey : (is_array($value) && array_key_exists('signing_public_key', $value) ? $value['signing_public_key'] : null);
        $out['signing_public_key'] = CBOR::bytes($field);
        $field = $value instanceof AdminLocalRp ? $value->encryptionPublicKey : (is_array($value) && array_key_exists('encryption_public_key', $value) ? $value['encryption_public_key'] : null);
        $out['encryption_public_key'] = CBOR::bytes($field);
        $field = $value instanceof AdminLocalRp ? $value->appName : (is_array($value) && array_key_exists('app_name', $value) ? $value['app_name'] : null);
        $out['app_name'] = $field;
        $field = $value instanceof AdminLocalRp ? $value->localDomainHint : (is_array($value) && array_key_exists('local_domain_hint', $value) ? $value['local_domain_hint'] : null);
        if ($field !== null) {
            $out['local_domain_hint'] = $field;
        }
        $field = $value instanceof AdminLocalRp ? $value->status : (is_array($value) && array_key_exists('status', $value) ? $value['status'] : null);
        $out['status'] = $field;
        $field = $value instanceof AdminLocalRp ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = $field;
        $field = $value instanceof AdminLocalRp ? $value->updatedAt : (is_array($value) && array_key_exists('updated_at', $value) ? $value['updated_at'] : null);
        $out['updated_at'] = $field;
        $field = $value instanceof AdminLocalRp ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        if ($field !== null) {
            $out['expires_at'] = $field;
        }
        $field = $value instanceof AdminLocalRp ? $value->lastSeenAt : (is_array($value) && array_key_exists('last_seen_at', $value) ? $value['last_seen_at'] : null);
        if ($field !== null) {
            $out['last_seen_at'] = $field;
        }
        $field = $value instanceof AdminLocalRp ? $value->adminNotes : (is_array($value) && array_key_exists('admin_notes', $value) ? $value['admin_notes'] : null);
        if ($field !== null) {
            $out['admin_notes'] = $field;
        }
        return $out;
    }

    public static function fromCborAdminLocalRp($value)
    {
        return new AdminLocalRp(array(
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'signing_public_key' => array_key_exists('signing_public_key', $value) ? $value['signing_public_key'] : null,
            'encryption_public_key' => array_key_exists('encryption_public_key', $value) ? $value['encryption_public_key'] : null,
            'app_name' => array_key_exists('app_name', $value) ? $value['app_name'] : null,
            'local_domain_hint' => array_key_exists('local_domain_hint', $value) ? $value['local_domain_hint'] : null,
            'status' => array_key_exists('status', $value) ? $value['status'] : null,
            'created_at' => array_key_exists('created_at', $value) ? $value['created_at'] : null,
            'updated_at' => array_key_exists('updated_at', $value) ? $value['updated_at'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
            'last_seen_at' => array_key_exists('last_seen_at', $value) ? $value['last_seen_at'] : null,
            'admin_notes' => array_key_exists('admin_notes', $value) ? $value['admin_notes'] : null,
        ));
    }

    public static function encodeListLocalRpsRequest($value)
    {
        return CBOR::encode(self::toCborListLocalRpsRequest($value));
    }

    public static function decodeListLocalRpsRequest($bytes)
    {
        return self::fromCborListLocalRpsRequest(CBOR::decode($bytes));
    }

    public static function toCborListLocalRpsRequest($value)
    {
        $out = array();
        $field = $value instanceof ListLocalRpsRequest ? $value->offset : (is_array($value) && array_key_exists('offset', $value) ? $value['offset'] : null);
        if ($field !== null) {
            $out['offset'] = $field;
        }
        $field = $value instanceof ListLocalRpsRequest ? $value->limit : (is_array($value) && array_key_exists('limit', $value) ? $value['limit'] : null);
        if ($field !== null) {
            $out['limit'] = $field;
        }
        $field = $value instanceof ListLocalRpsRequest ? $value->status : (is_array($value) && array_key_exists('status', $value) ? $value['status'] : null);
        if ($field !== null) {
            $out['status'] = $field;
        }
        return $out;
    }

    public static function fromCborListLocalRpsRequest($value)
    {
        return new ListLocalRpsRequest(array(
            'offset' => array_key_exists('offset', $value) ? $value['offset'] : null,
            'limit' => array_key_exists('limit', $value) ? $value['limit'] : null,
            'status' => array_key_exists('status', $value) ? $value['status'] : null,
        ));
    }

    public static function encodeListLocalRpsResponse($value)
    {
        return CBOR::encode(self::toCborListLocalRpsResponse($value));
    }

    public static function decodeListLocalRpsResponse($bytes)
    {
        return self::fromCborListLocalRpsResponse(CBOR::decode($bytes));
    }

    public static function toCborListLocalRpsResponse($value)
    {
        $out = array();
        $field = $value instanceof ListLocalRpsResponse ? $value->localRps : (is_array($value) && array_key_exists('local_rps', $value) ? $value['local_rps'] : null);
        $out['local_rps'] = array_map(function ($item) { return self::toCborAdminLocalRp($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborListLocalRpsResponse($value)
    {
        return new ListLocalRpsResponse(array(
            'local_rps' => array_key_exists('local_rps', $value) ? array_map(function ($item) { return self::fromCborAdminLocalRp($item); }, $value['local_rps'] === null ? array() : $value['local_rps']) : null,
        ));
    }

    public static function encodeGetLocalRpRequest($value)
    {
        return CBOR::encode(self::toCborGetLocalRpRequest($value));
    }

    public static function decodeGetLocalRpRequest($bytes)
    {
        return self::fromCborGetLocalRpRequest(CBOR::decode($bytes));
    }

    public static function toCborGetLocalRpRequest($value)
    {
        $out = array();
        $field = $value instanceof GetLocalRpRequest ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        return $out;
    }

    public static function fromCborGetLocalRpRequest($value)
    {
        return new GetLocalRpRequest(array(
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
        ));
    }

    public static function encodeGetLocalRpResponse($value)
    {
        return CBOR::encode(self::toCborGetLocalRpResponse($value));
    }

    public static function decodeGetLocalRpResponse($bytes)
    {
        return self::fromCborGetLocalRpResponse(CBOR::decode($bytes));
    }

    public static function toCborGetLocalRpResponse($value)
    {
        $out = array();
        $field = $value instanceof GetLocalRpResponse ? $value->localRp : (is_array($value) && array_key_exists('local_rp', $value) ? $value['local_rp'] : null);
        $out['local_rp'] = self::toCborAdminLocalRp($field);
        return $out;
    }

    public static function fromCborGetLocalRpResponse($value)
    {
        return new GetLocalRpResponse(array(
            'local_rp' => array_key_exists('local_rp', $value) ? self::fromCborAdminLocalRp($value['local_rp']) : null,
        ));
    }

    public static function encodeApproveLocalRpRequest($value)
    {
        return CBOR::encode(self::toCborApproveLocalRpRequest($value));
    }

    public static function decodeApproveLocalRpRequest($bytes)
    {
        return self::fromCborApproveLocalRpRequest(CBOR::decode($bytes));
    }

    public static function toCborApproveLocalRpRequest($value)
    {
        $out = array();
        $field = $value instanceof ApproveLocalRpRequest ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof ApproveLocalRpRequest ? $value->adminNotes : (is_array($value) && array_key_exists('admin_notes', $value) ? $value['admin_notes'] : null);
        if ($field !== null) {
            $out['admin_notes'] = $field;
        }
        return $out;
    }

    public static function fromCborApproveLocalRpRequest($value)
    {
        return new ApproveLocalRpRequest(array(
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'admin_notes' => array_key_exists('admin_notes', $value) ? $value['admin_notes'] : null,
        ));
    }

    public static function encodeApproveLocalRpResponse($value)
    {
        return CBOR::encode(self::toCborApproveLocalRpResponse($value));
    }

    public static function decodeApproveLocalRpResponse($bytes)
    {
        return self::fromCborApproveLocalRpResponse(CBOR::decode($bytes));
    }

    public static function toCborApproveLocalRpResponse($value)
    {
        $out = array();
        $field = $value instanceof ApproveLocalRpResponse ? $value->localRp : (is_array($value) && array_key_exists('local_rp', $value) ? $value['local_rp'] : null);
        $out['local_rp'] = self::toCborAdminLocalRp($field);
        return $out;
    }

    public static function fromCborApproveLocalRpResponse($value)
    {
        return new ApproveLocalRpResponse(array(
            'local_rp' => array_key_exists('local_rp', $value) ? self::fromCborAdminLocalRp($value['local_rp']) : null,
        ));
    }

    public static function encodeDenyLocalRpRequest($value)
    {
        return CBOR::encode(self::toCborDenyLocalRpRequest($value));
    }

    public static function decodeDenyLocalRpRequest($bytes)
    {
        return self::fromCborDenyLocalRpRequest(CBOR::decode($bytes));
    }

    public static function toCborDenyLocalRpRequest($value)
    {
        $out = array();
        $field = $value instanceof DenyLocalRpRequest ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof DenyLocalRpRequest ? $value->adminNotes : (is_array($value) && array_key_exists('admin_notes', $value) ? $value['admin_notes'] : null);
        if ($field !== null) {
            $out['admin_notes'] = $field;
        }
        return $out;
    }

    public static function fromCborDenyLocalRpRequest($value)
    {
        return new DenyLocalRpRequest(array(
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'admin_notes' => array_key_exists('admin_notes', $value) ? $value['admin_notes'] : null,
        ));
    }

    public static function encodeDenyLocalRpResponse($value)
    {
        return CBOR::encode(self::toCborDenyLocalRpResponse($value));
    }

    public static function decodeDenyLocalRpResponse($bytes)
    {
        return self::fromCborDenyLocalRpResponse(CBOR::decode($bytes));
    }

    public static function toCborDenyLocalRpResponse($value)
    {
        $out = array();
        $field = $value instanceof DenyLocalRpResponse ? $value->localRp : (is_array($value) && array_key_exists('local_rp', $value) ? $value['local_rp'] : null);
        $out['local_rp'] = self::toCborAdminLocalRp($field);
        return $out;
    }

    public static function fromCborDenyLocalRpResponse($value)
    {
        return new DenyLocalRpResponse(array(
            'local_rp' => array_key_exists('local_rp', $value) ? self::fromCborAdminLocalRp($value['local_rp']) : null,
        ));
    }

    public static function encodeRevokeLocalRpRequest($value)
    {
        return CBOR::encode(self::toCborRevokeLocalRpRequest($value));
    }

    public static function decodeRevokeLocalRpRequest($bytes)
    {
        return self::fromCborRevokeLocalRpRequest(CBOR::decode($bytes));
    }

    public static function toCborRevokeLocalRpRequest($value)
    {
        $out = array();
        $field = $value instanceof RevokeLocalRpRequest ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof RevokeLocalRpRequest ? $value->adminNotes : (is_array($value) && array_key_exists('admin_notes', $value) ? $value['admin_notes'] : null);
        if ($field !== null) {
            $out['admin_notes'] = $field;
        }
        return $out;
    }

    public static function fromCborRevokeLocalRpRequest($value)
    {
        return new RevokeLocalRpRequest(array(
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'admin_notes' => array_key_exists('admin_notes', $value) ? $value['admin_notes'] : null,
        ));
    }

    public static function encodeRevokeLocalRpResponse($value)
    {
        return CBOR::encode(self::toCborRevokeLocalRpResponse($value));
    }

    public static function decodeRevokeLocalRpResponse($bytes)
    {
        return self::fromCborRevokeLocalRpResponse(CBOR::decode($bytes));
    }

    public static function toCborRevokeLocalRpResponse($value)
    {
        $out = array();
        $field = $value instanceof RevokeLocalRpResponse ? $value->localRp : (is_array($value) && array_key_exists('local_rp', $value) ? $value['local_rp'] : null);
        $out['local_rp'] = self::toCborAdminLocalRp($field);
        return $out;
    }

    public static function fromCborRevokeLocalRpResponse($value)
    {
        return new RevokeLocalRpResponse(array(
            'local_rp' => array_key_exists('local_rp', $value) ? self::fromCborAdminLocalRp($value['local_rp']) : null,
        ));
    }

    public static function encodeGetLocalRpPolicyRequest($value)
    {
        return CBOR::encode(self::toCborGetLocalRpPolicyRequest($value));
    }

    public static function decodeGetLocalRpPolicyRequest($bytes)
    {
        return self::fromCborGetLocalRpPolicyRequest(CBOR::decode($bytes));
    }

    public static function toCborGetLocalRpPolicyRequest($value)
    {
        $out = array();
        return $out;
    }

    public static function fromCborGetLocalRpPolicyRequest($value)
    {
        return new GetLocalRpPolicyRequest(array(
        ));
    }

    public static function encodeGetLocalRpPolicyResponse($value)
    {
        return CBOR::encode(self::toCborGetLocalRpPolicyResponse($value));
    }

    public static function decodeGetLocalRpPolicyResponse($bytes)
    {
        return self::fromCborGetLocalRpPolicyResponse(CBOR::decode($bytes));
    }

    public static function toCborGetLocalRpPolicyResponse($value)
    {
        $out = array();
        $field = $value instanceof GetLocalRpPolicyResponse ? $value->policy : (is_array($value) && array_key_exists('policy', $value) ? $value['policy'] : null);
        $out['policy'] = $field;
        return $out;
    }

    public static function fromCborGetLocalRpPolicyResponse($value)
    {
        return new GetLocalRpPolicyResponse(array(
            'policy' => array_key_exists('policy', $value) ? $value['policy'] : null,
        ));
    }

    public static function encodeSetLocalRpPolicyRequest($value)
    {
        return CBOR::encode(self::toCborSetLocalRpPolicyRequest($value));
    }

    public static function decodeSetLocalRpPolicyRequest($bytes)
    {
        return self::fromCborSetLocalRpPolicyRequest(CBOR::decode($bytes));
    }

    public static function toCborSetLocalRpPolicyRequest($value)
    {
        $out = array();
        $field = $value instanceof SetLocalRpPolicyRequest ? $value->policy : (is_array($value) && array_key_exists('policy', $value) ? $value['policy'] : null);
        $out['policy'] = $field;
        return $out;
    }

    public static function fromCborSetLocalRpPolicyRequest($value)
    {
        return new SetLocalRpPolicyRequest(array(
            'policy' => array_key_exists('policy', $value) ? $value['policy'] : null,
        ));
    }

    public static function encodeSetLocalRpPolicyResponse($value)
    {
        return CBOR::encode(self::toCborSetLocalRpPolicyResponse($value));
    }

    public static function decodeSetLocalRpPolicyResponse($bytes)
    {
        return self::fromCborSetLocalRpPolicyResponse(CBOR::decode($bytes));
    }

    public static function toCborSetLocalRpPolicyResponse($value)
    {
        $out = array();
        $field = $value instanceof SetLocalRpPolicyResponse ? $value->policy : (is_array($value) && array_key_exists('policy', $value) ? $value['policy'] : null);
        $out['policy'] = $field;
        return $out;
    }

    public static function fromCborSetLocalRpPolicyResponse($value)
    {
        return new SetLocalRpPolicyResponse(array(
            'policy' => array_key_exists('policy', $value) ? $value['policy'] : null,
        ));
    }

    public static function encodeLocaleMessages($value)
    {
        return CBOR::encode(self::toCborLocaleMessages($value));
    }

    public static function decodeLocaleMessages($bytes)
    {
        return self::fromCborLocaleMessages(CBOR::decode($bytes));
    }

    public static function toCborLocaleMessages($value)
    {
        return (function ($m) { $out = array(); foreach (($m === null ? array() : $m) as $k => $v) { $out[$k] = $v; } return $out; })($value);
    }

    public static function fromCborLocaleMessages($value)
    {
        return (function ($m) { $out = array(); foreach (($m === null ? array() : $m) as $k => $v) { $out[$k] = $v; } return $out; })($value);
    }

    public static function encodeTranslationsRequest($value)
    {
        return CBOR::encode(self::toCborTranslationsRequest($value));
    }

    public static function decodeTranslationsRequest($bytes)
    {
        return self::fromCborTranslationsRequest(CBOR::decode($bytes));
    }

    public static function toCborTranslationsRequest($value)
    {
        $out = array();
        $field = $value instanceof TranslationsRequest ? $value->locale : (is_array($value) && array_key_exists('locale', $value) ? $value['locale'] : null);
        if ($field !== null) {
            $out['locale'] = $field;
        }
        $field = $value instanceof TranslationsRequest ? $value->acceptLanguage : (is_array($value) && array_key_exists('accept_language', $value) ? $value['accept_language'] : null);
        if ($field !== null) {
            $out['accept_language'] = $field;
        }
        return $out;
    }

    public static function fromCborTranslationsRequest($value)
    {
        return new TranslationsRequest(array(
            'locale' => array_key_exists('locale', $value) ? $value['locale'] : null,
            'accept_language' => array_key_exists('accept_language', $value) ? $value['accept_language'] : null,
        ));
    }

    public static function encodeTranslationsResponse($value)
    {
        return CBOR::encode(self::toCborTranslationsResponse($value));
    }

    public static function decodeTranslationsResponse($bytes)
    {
        return self::fromCborTranslationsResponse(CBOR::decode($bytes));
    }

    public static function toCborTranslationsResponse($value)
    {
        $out = array();
        $field = $value instanceof TranslationsResponse ? $value->locale : (is_array($value) && array_key_exists('locale', $value) ? $value['locale'] : null);
        $out['locale'] = $field;
        $field = $value instanceof TranslationsResponse ? $value->availableLocales : (is_array($value) && array_key_exists('available_locales', $value) ? $value['available_locales'] : null);
        $out['available_locales'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof TranslationsResponse ? $value->messages : (is_array($value) && array_key_exists('messages', $value) ? $value['messages'] : null);
        $out['messages'] = $field;
        return $out;
    }

    public static function fromCborTranslationsResponse($value)
    {
        return new TranslationsResponse(array(
            'locale' => array_key_exists('locale', $value) ? $value['locale'] : null,
            'available_locales' => array_key_exists('available_locales', $value) ? array_map(function ($item) { return $item; }, $value['available_locales'] === null ? array() : $value['available_locales']) : null,
            'messages' => array_key_exists('messages', $value) ? $value['messages'] : null,
        ));
    }

    public static function encodeListLocalesResponse($value)
    {
        return CBOR::encode(self::toCborListLocalesResponse($value));
    }

    public static function decodeListLocalesResponse($bytes)
    {
        return self::fromCborListLocalesResponse(CBOR::decode($bytes));
    }

    public static function toCborListLocalesResponse($value)
    {
        $out = array();
        $field = $value instanceof ListLocalesResponse ? $value->availableLocales : (is_array($value) && array_key_exists('available_locales', $value) ? $value['available_locales'] : null);
        $out['available_locales'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborListLocalesResponse($value)
    {
        return new ListLocalesResponse(array(
            'available_locales' => array_key_exists('available_locales', $value) ? array_map(function ($item) { return $item; }, $value['available_locales'] === null ? array() : $value['available_locales']) : null,
        ));
    }

}
