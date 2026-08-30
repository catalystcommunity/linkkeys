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

    public static function encodeAuthenticationRequirements($value)
    {
        return CBOR::encode(self::toCborAuthenticationRequirements($value));
    }

    public static function decodeAuthenticationRequirements($bytes)
    {
        return self::fromCborAuthenticationRequirements(CBOR::decode($bytes));
    }

    public static function toCborAuthenticationRequirements($value)
    {
        $out = array();
        $field = $value instanceof AuthenticationRequirements ? $value->minimumFactorCount : (is_array($value) && array_key_exists('minimum_factor_count', $value) ? $value['minimum_factor_count'] : null);
        $out['minimum_factor_count'] = $field;
        return $out;
    }

    public static function fromCborAuthenticationRequirements($value)
    {
        return new AuthenticationRequirements(array(
            'minimum_factor_count' => array_key_exists('minimum_factor_count', $value) ? $value['minimum_factor_count'] : null,
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
        $field = $value instanceof DomainClaim ? $value->attestedAt : (is_array($value) && array_key_exists('attested_at', $value) ? $value['attested_at'] : null);
        $out['attested_at'] = $field;
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
            'attested_at' => array_key_exists('attested_at', $value) ? $value['attested_at'] : null,
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
        $field = $value instanceof AuthRequest ? $value->authenticationRequirements : (is_array($value) && array_key_exists('authentication_requirements', $value) ? $value['authentication_requirements'] : null);
        if ($field !== null) {
            $out['authentication_requirements'] = self::toCborAuthenticationRequirements($field);
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
            'authentication_requirements' => array_key_exists('authentication_requirements', $value) ? self::fromCborAuthenticationRequirements($value['authentication_requirements']) : null,
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
        $field = $value instanceof AdminUser ? $value->purgedAt : (is_array($value) && array_key_exists('purged_at', $value) ? $value['purged_at'] : null);
        if ($field !== null) {
            $out['purged_at'] = $field;
        }
        $field = $value instanceof AdminUser ? $value->purgeReason : (is_array($value) && array_key_exists('purge_reason', $value) ? $value['purge_reason'] : null);
        if ($field !== null) {
            $out['purge_reason'] = $field;
        }
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
            'purged_at' => array_key_exists('purged_at', $value) ? $value['purged_at'] : null,
            'purge_reason' => array_key_exists('purge_reason', $value) ? $value['purge_reason'] : null,
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
        $field = $value instanceof ListUsersRequest ? $value->includePurged : (is_array($value) && array_key_exists('include_purged', $value) ? $value['include_purged'] : null);
        if ($field !== null) {
            $out['include_purged'] = $field;
        }
        return $out;
    }

    public static function fromCborListUsersRequest($value)
    {
        return new ListUsersRequest(array(
            'offset' => array_key_exists('offset', $value) ? $value['offset'] : null,
            'limit' => array_key_exists('limit', $value) ? $value['limit'] : null,
            'include_purged' => array_key_exists('include_purged', $value) ? $value['include_purged'] : null,
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

    public static function encodeActivateUserRequest($value)
    {
        return CBOR::encode(self::toCborActivateUserRequest($value));
    }

    public static function decodeActivateUserRequest($bytes)
    {
        return self::fromCborActivateUserRequest(CBOR::decode($bytes));
    }

    public static function toCborActivateUserRequest($value)
    {
        $out = array();
        $field = $value instanceof ActivateUserRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        return $out;
    }

    public static function fromCborActivateUserRequest($value)
    {
        return new ActivateUserRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeActivateUserResponse($value)
    {
        return CBOR::encode(self::toCborActivateUserResponse($value));
    }

    public static function decodeActivateUserResponse($bytes)
    {
        return self::fromCborActivateUserResponse(CBOR::decode($bytes));
    }

    public static function toCborActivateUserResponse($value)
    {
        $out = array();
        $field = $value instanceof ActivateUserResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        return $out;
    }

    public static function fromCborActivateUserResponse($value)
    {
        return new ActivateUserResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
        ));
    }

    public static function encodePurgeUserRequest($value)
    {
        return CBOR::encode(self::toCborPurgeUserRequest($value));
    }

    public static function decodePurgeUserRequest($bytes)
    {
        return self::fromCborPurgeUserRequest(CBOR::decode($bytes));
    }

    public static function toCborPurgeUserRequest($value)
    {
        $out = array();
        $field = $value instanceof PurgeUserRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof PurgeUserRequest ? $value->reason : (is_array($value) && array_key_exists('reason', $value) ? $value['reason'] : null);
        if ($field !== null) {
            $out['reason'] = $field;
        }
        return $out;
    }

    public static function fromCborPurgeUserRequest($value)
    {
        return new PurgeUserRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'reason' => array_key_exists('reason', $value) ? $value['reason'] : null,
        ));
    }

    public static function encodePurgeUserResponse($value)
    {
        return CBOR::encode(self::toCborPurgeUserResponse($value));
    }

    public static function decodePurgeUserResponse($bytes)
    {
        return self::fromCborPurgeUserResponse(CBOR::decode($bytes));
    }

    public static function toCborPurgeUserResponse($value)
    {
        $out = array();
        $field = $value instanceof PurgeUserResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        $field = $value instanceof PurgeUserResponse ? $value->credentialsRevoked : (is_array($value) && array_key_exists('credentials_revoked', $value) ? $value['credentials_revoked'] : null);
        $out['credentials_revoked'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->keysRevoked : (is_array($value) && array_key_exists('keys_revoked', $value) ? $value['keys_revoked'] : null);
        $out['keys_revoked'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->claimsRevoked : (is_array($value) && array_key_exists('claims_revoked', $value) ? $value['claims_revoked'] : null);
        $out['claims_revoked'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->relationsRemoved : (is_array($value) && array_key_exists('relations_removed', $value) ? $value['relations_removed'] : null);
        $out['relations_removed'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->profilesDeleted : (is_array($value) && array_key_exists('profiles_deleted', $value) ? $value['profiles_deleted'] : null);
        $out['profiles_deleted'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->consentGrantsDeleted : (is_array($value) && array_key_exists('consent_grants_deleted', $value) ? $value['consent_grants_deleted'] : null);
        $out['consent_grants_deleted'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->releasePrefsDeleted : (is_array($value) && array_key_exists('release_prefs_deleted', $value) ? $value['release_prefs_deleted'] : null);
        $out['release_prefs_deleted'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->emailVerificationsDeleted : (is_array($value) && array_key_exists('email_verifications_deleted', $value) ? $value['email_verifications_deleted'] : null);
        $out['email_verifications_deleted'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->reviewsResolved : (is_array($value) && array_key_exists('reviews_resolved', $value) ? $value['reviews_resolved'] : null);
        $out['reviews_resolved'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->localRpClaimTicketsDeleted : (is_array($value) && array_key_exists('local_rp_claim_tickets_deleted', $value) ? $value['local_rp_claim_tickets_deleted'] : null);
        $out['local_rp_claim_tickets_deleted'] = $field;
        return $out;
    }

    public static function fromCborPurgeUserResponse($value)
    {
        return new PurgeUserResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
            'credentials_revoked' => array_key_exists('credentials_revoked', $value) ? $value['credentials_revoked'] : null,
            'keys_revoked' => array_key_exists('keys_revoked', $value) ? $value['keys_revoked'] : null,
            'claims_revoked' => array_key_exists('claims_revoked', $value) ? $value['claims_revoked'] : null,
            'relations_removed' => array_key_exists('relations_removed', $value) ? $value['relations_removed'] : null,
            'profiles_deleted' => array_key_exists('profiles_deleted', $value) ? $value['profiles_deleted'] : null,
            'consent_grants_deleted' => array_key_exists('consent_grants_deleted', $value) ? $value['consent_grants_deleted'] : null,
            'release_prefs_deleted' => array_key_exists('release_prefs_deleted', $value) ? $value['release_prefs_deleted'] : null,
            'email_verifications_deleted' => array_key_exists('email_verifications_deleted', $value) ? $value['email_verifications_deleted'] : null,
            'reviews_resolved' => array_key_exists('reviews_resolved', $value) ? $value['reviews_resolved'] : null,
            'local_rp_claim_tickets_deleted' => array_key_exists('local_rp_claim_tickets_deleted', $value) ? $value['local_rp_claim_tickets_deleted'] : null,
        ));
    }

    public static function encodeRevokeDomainKeyRequest($value)
    {
        return CBOR::encode(self::toCborRevokeDomainKeyRequest($value));
    }

    public static function decodeRevokeDomainKeyRequest($bytes)
    {
        return self::fromCborRevokeDomainKeyRequest(CBOR::decode($bytes));
    }

    public static function toCborRevokeDomainKeyRequest($value)
    {
        $out = array();
        $field = $value instanceof RevokeDomainKeyRequest ? $value->keyId : (is_array($value) && array_key_exists('key_id', $value) ? $value['key_id'] : null);
        $out['key_id'] = $field;
        return $out;
    }

    public static function fromCborRevokeDomainKeyRequest($value)
    {
        return new RevokeDomainKeyRequest(array(
            'key_id' => array_key_exists('key_id', $value) ? $value['key_id'] : null,
        ));
    }

    public static function encodeRevokeDomainKeyResponse($value)
    {
        return CBOR::encode(self::toCborRevokeDomainKeyResponse($value));
    }

    public static function decodeRevokeDomainKeyResponse($bytes)
    {
        return self::fromCborRevokeDomainKeyResponse(CBOR::decode($bytes));
    }

    public static function toCborRevokeDomainKeyResponse($value)
    {
        $out = array();
        $field = $value instanceof RevokeDomainKeyResponse ? $value->revokedKey : (is_array($value) && array_key_exists('revoked_key', $value) ? $value['revoked_key'] : null);
        $out['revoked_key'] = self::toCborDomainPublicKey($field);
        $field = $value instanceof RevokeDomainKeyResponse ? $value->certificateIssued : (is_array($value) && array_key_exists('certificate_issued', $value) ? $value['certificate_issued'] : null);
        $out['certificate_issued'] = $field;
        $field = $value instanceof RevokeDomainKeyResponse ? $value->dnsRemovalReminder : (is_array($value) && array_key_exists('dns_removal_reminder', $value) ? $value['dns_removal_reminder'] : null);
        $out['dns_removal_reminder'] = $field;
        return $out;
    }

    public static function fromCborRevokeDomainKeyResponse($value)
    {
        return new RevokeDomainKeyResponse(array(
            'revoked_key' => array_key_exists('revoked_key', $value) ? self::fromCborDomainPublicKey($value['revoked_key']) : null,
            'certificate_issued' => array_key_exists('certificate_issued', $value) ? $value['certificate_issued'] : null,
            'dns_removal_reminder' => array_key_exists('dns_removal_reminder', $value) ? $value['dns_removal_reminder'] : null,
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

    public static function encodeAdminUserClaimsRequest($value)
    {
        return CBOR::encode(self::toCborAdminUserClaimsRequest($value));
    }

    public static function decodeAdminUserClaimsRequest($bytes)
    {
        return self::fromCborAdminUserClaimsRequest(CBOR::decode($bytes));
    }

    public static function toCborAdminUserClaimsRequest($value)
    {
        $out = array();
        $field = $value instanceof AdminUserClaimsRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        return $out;
    }

    public static function fromCborAdminUserClaimsRequest($value)
    {
        return new AdminUserClaimsRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeAdminUserClaimsResponse($value)
    {
        return CBOR::encode(self::toCborAdminUserClaimsResponse($value));
    }

    public static function decodeAdminUserClaimsResponse($bytes)
    {
        return self::fromCborAdminUserClaimsResponse(CBOR::decode($bytes));
    }

    public static function toCborAdminUserClaimsResponse($value)
    {
        $out = array();
        $field = $value instanceof AdminUserClaimsResponse ? $value->claims : (is_array($value) && array_key_exists('claims', $value) ? $value['claims'] : null);
        $out['claims'] = array_map(function ($item) { return self::toCborClaim($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborAdminUserClaimsResponse($value)
    {
        return new AdminUserClaimsResponse(array(
            'claims' => array_key_exists('claims', $value) ? array_map(function ($item) { return self::fromCborClaim($item); }, $value['claims'] === null ? array() : $value['claims']) : null,
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
        $field = $value instanceof SettableClaimPolicy ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        $out['label'] = $field;
        $field = $value instanceof SettableClaimPolicy ? $value->description : (is_array($value) && array_key_exists('description', $value) ? $value['description'] : null);
        $out['description'] = $field;
        $field = $value instanceof SettableClaimPolicy ? $value->datatype : (is_array($value) && array_key_exists('datatype', $value) ? $value['datatype'] : null);
        $out['datatype'] = $field;
        $field = $value instanceof SettableClaimPolicy ? $value->maxBytes : (is_array($value) && array_key_exists('max_bytes', $value) ? $value['max_bytes'] : null);
        $out['max_bytes'] = $field;
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
            'label' => array_key_exists('label', $value) ? $value['label'] : null,
            'description' => array_key_exists('description', $value) ? $value['description'] : null,
            'datatype' => array_key_exists('datatype', $value) ? $value['datatype'] : null,
            'max_bytes' => array_key_exists('max_bytes', $value) ? $value['max_bytes'] : null,
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

    public static function encodeClaimTypePolicy($value)
    {
        return CBOR::encode(self::toCborClaimTypePolicy($value));
    }

    public static function decodeClaimTypePolicy($bytes)
    {
        return self::fromCborClaimTypePolicy(CBOR::decode($bytes));
    }

    public static function toCborClaimTypePolicy($value)
    {
        $out = array();
        $field = $value instanceof ClaimTypePolicy ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        $out['label'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->description : (is_array($value) && array_key_exists('description', $value) ? $value['description'] : null);
        $out['description'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->valueType : (is_array($value) && array_key_exists('value_type', $value) ? $value['value_type'] : null);
        $out['value_type'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->maxBytes : (is_array($value) && array_key_exists('max_bytes', $value) ? $value['max_bytes'] : null);
        $out['max_bytes'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->setRule : (is_array($value) && array_key_exists('set_rule', $value) ? $value['set_rule'] : null);
        $out['set_rule'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->signingRule : (is_array($value) && array_key_exists('signing_rule', $value) ? $value['signing_rule'] : null);
        $out['signing_rule'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->requiresApproval : (is_array($value) && array_key_exists('requires_approval', $value) ? $value['requires_approval'] : null);
        $out['requires_approval'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->userSettable : (is_array($value) && array_key_exists('user_settable', $value) ? $value['user_settable'] : null);
        $out['user_settable'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->defaultAutoSign : (is_array($value) && array_key_exists('default_auto_sign', $value) ? $value['default_auto_sign'] : null);
        $out['default_auto_sign'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->suggested : (is_array($value) && array_key_exists('suggested', $value) ? $value['suggested'] : null);
        $out['suggested'] = $field;
        return $out;
    }

    public static function fromCborClaimTypePolicy($value)
    {
        return new ClaimTypePolicy(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'label' => array_key_exists('label', $value) ? $value['label'] : null,
            'description' => array_key_exists('description', $value) ? $value['description'] : null,
            'value_type' => array_key_exists('value_type', $value) ? $value['value_type'] : null,
            'max_bytes' => array_key_exists('max_bytes', $value) ? $value['max_bytes'] : null,
            'set_rule' => array_key_exists('set_rule', $value) ? $value['set_rule'] : null,
            'signing_rule' => array_key_exists('signing_rule', $value) ? $value['signing_rule'] : null,
            'requires_approval' => array_key_exists('requires_approval', $value) ? $value['requires_approval'] : null,
            'user_settable' => array_key_exists('user_settable', $value) ? $value['user_settable'] : null,
            'default_auto_sign' => array_key_exists('default_auto_sign', $value) ? $value['default_auto_sign'] : null,
            'suggested' => array_key_exists('suggested', $value) ? $value['suggested'] : null,
        ));
    }

    public static function encodeListClaimTypesResponse($value)
    {
        return CBOR::encode(self::toCborListClaimTypesResponse($value));
    }

    public static function decodeListClaimTypesResponse($bytes)
    {
        return self::fromCborListClaimTypesResponse(CBOR::decode($bytes));
    }

    public static function toCborListClaimTypesResponse($value)
    {
        $out = array();
        $field = $value instanceof ListClaimTypesResponse ? $value->claimTypes : (is_array($value) && array_key_exists('claim_types', $value) ? $value['claim_types'] : null);
        $out['claim_types'] = array_map(function ($item) { return self::toCborClaimTypePolicy($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborListClaimTypesResponse($value)
    {
        return new ListClaimTypesResponse(array(
            'claim_types' => array_key_exists('claim_types', $value) ? array_map(function ($item) { return self::fromCborClaimTypePolicy($item); }, $value['claim_types'] === null ? array() : $value['claim_types']) : null,
        ));
    }

    public static function encodeSetClaimTypeRequest($value)
    {
        return CBOR::encode(self::toCborSetClaimTypeRequest($value));
    }

    public static function decodeSetClaimTypeRequest($bytes)
    {
        return self::fromCborSetClaimTypeRequest(CBOR::decode($bytes));
    }

    public static function toCborSetClaimTypeRequest($value)
    {
        $out = array();
        $field = $value instanceof SetClaimTypeRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SetClaimTypeRequest ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        $out['label'] = $field;
        $field = $value instanceof SetClaimTypeRequest ? $value->description : (is_array($value) && array_key_exists('description', $value) ? $value['description'] : null);
        if ($field !== null) {
            $out['description'] = $field;
        }
        $field = $value instanceof SetClaimTypeRequest ? $value->valueType : (is_array($value) && array_key_exists('value_type', $value) ? $value['value_type'] : null);
        $out['value_type'] = $field;
        $field = $value instanceof SetClaimTypeRequest ? $value->maxBytes : (is_array($value) && array_key_exists('max_bytes', $value) ? $value['max_bytes'] : null);
        $out['max_bytes'] = $field;
        $field = $value instanceof SetClaimTypeRequest ? $value->setRule : (is_array($value) && array_key_exists('set_rule', $value) ? $value['set_rule'] : null);
        $out['set_rule'] = $field;
        $field = $value instanceof SetClaimTypeRequest ? $value->signingRule : (is_array($value) && array_key_exists('signing_rule', $value) ? $value['signing_rule'] : null);
        $out['signing_rule'] = $field;
        $field = $value instanceof SetClaimTypeRequest ? $value->userSettable : (is_array($value) && array_key_exists('user_settable', $value) ? $value['user_settable'] : null);
        $out['user_settable'] = $field;
        $field = $value instanceof SetClaimTypeRequest ? $value->defaultAutoSign : (is_array($value) && array_key_exists('default_auto_sign', $value) ? $value['default_auto_sign'] : null);
        $out['default_auto_sign'] = $field;
        $field = $value instanceof SetClaimTypeRequest ? $value->requiresApproval : (is_array($value) && array_key_exists('requires_approval', $value) ? $value['requires_approval'] : null);
        $out['requires_approval'] = $field;
        $field = $value instanceof SetClaimTypeRequest ? $value->suggested : (is_array($value) && array_key_exists('suggested', $value) ? $value['suggested'] : null);
        $out['suggested'] = $field;
        return $out;
    }

    public static function fromCborSetClaimTypeRequest($value)
    {
        return new SetClaimTypeRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'label' => array_key_exists('label', $value) ? $value['label'] : null,
            'description' => array_key_exists('description', $value) ? $value['description'] : null,
            'value_type' => array_key_exists('value_type', $value) ? $value['value_type'] : null,
            'max_bytes' => array_key_exists('max_bytes', $value) ? $value['max_bytes'] : null,
            'set_rule' => array_key_exists('set_rule', $value) ? $value['set_rule'] : null,
            'signing_rule' => array_key_exists('signing_rule', $value) ? $value['signing_rule'] : null,
            'user_settable' => array_key_exists('user_settable', $value) ? $value['user_settable'] : null,
            'default_auto_sign' => array_key_exists('default_auto_sign', $value) ? $value['default_auto_sign'] : null,
            'requires_approval' => array_key_exists('requires_approval', $value) ? $value['requires_approval'] : null,
            'suggested' => array_key_exists('suggested', $value) ? $value['suggested'] : null,
        ));
    }

    public static function encodeSetClaimTypeResponse($value)
    {
        return CBOR::encode(self::toCborSetClaimTypeResponse($value));
    }

    public static function decodeSetClaimTypeResponse($bytes)
    {
        return self::fromCborSetClaimTypeResponse(CBOR::decode($bytes));
    }

    public static function toCborSetClaimTypeResponse($value)
    {
        $out = array();
        $field = $value instanceof SetClaimTypeResponse ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = self::toCborClaimTypePolicy($field);
        return $out;
    }

    public static function fromCborSetClaimTypeResponse($value)
    {
        return new SetClaimTypeResponse(array(
            'claim_type' => array_key_exists('claim_type', $value) ? self::fromCborClaimTypePolicy($value['claim_type']) : null,
        ));
    }

    public static function encodeRemoveClaimTypeRequest($value)
    {
        return CBOR::encode(self::toCborRemoveClaimTypeRequest($value));
    }

    public static function decodeRemoveClaimTypeRequest($bytes)
    {
        return self::fromCborRemoveClaimTypeRequest(CBOR::decode($bytes));
    }

    public static function toCborRemoveClaimTypeRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveClaimTypeRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        return $out;
    }

    public static function fromCborRemoveClaimTypeRequest($value)
    {
        return new RemoveClaimTypeRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
        ));
    }

    public static function encodeRemoveClaimTypeResponse($value)
    {
        return CBOR::encode(self::toCborRemoveClaimTypeResponse($value));
    }

    public static function decodeRemoveClaimTypeResponse($bytes)
    {
        return self::fromCborRemoveClaimTypeResponse(CBOR::decode($bytes));
    }

    public static function toCborRemoveClaimTypeResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveClaimTypeResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out;
    }

    public static function fromCborRemoveClaimTypeResponse($value)
    {
        return new RemoveClaimTypeResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeClaimTypeLabel($value)
    {
        return CBOR::encode(self::toCborClaimTypeLabel($value));
    }

    public static function decodeClaimTypeLabel($bytes)
    {
        return self::fromCborClaimTypeLabel(CBOR::decode($bytes));
    }

    public static function toCborClaimTypeLabel($value)
    {
        $out = array();
        $field = $value instanceof ClaimTypeLabel ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof ClaimTypeLabel ? $value->locale : (is_array($value) && array_key_exists('locale', $value) ? $value['locale'] : null);
        $out['locale'] = $field;
        $field = $value instanceof ClaimTypeLabel ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        $out['label'] = $field;
        $field = $value instanceof ClaimTypeLabel ? $value->description : (is_array($value) && array_key_exists('description', $value) ? $value['description'] : null);
        if ($field !== null) {
            $out['description'] = $field;
        }
        return $out;
    }

    public static function fromCborClaimTypeLabel($value)
    {
        return new ClaimTypeLabel(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'locale' => array_key_exists('locale', $value) ? $value['locale'] : null,
            'label' => array_key_exists('label', $value) ? $value['label'] : null,
            'description' => array_key_exists('description', $value) ? $value['description'] : null,
        ));
    }

    public static function encodeSetClaimTypeLabelRequest($value)
    {
        return CBOR::encode(self::toCborSetClaimTypeLabelRequest($value));
    }

    public static function decodeSetClaimTypeLabelRequest($bytes)
    {
        return self::fromCborSetClaimTypeLabelRequest(CBOR::decode($bytes));
    }

    public static function toCborSetClaimTypeLabelRequest($value)
    {
        $out = array();
        $field = $value instanceof SetClaimTypeLabelRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SetClaimTypeLabelRequest ? $value->locale : (is_array($value) && array_key_exists('locale', $value) ? $value['locale'] : null);
        $out['locale'] = $field;
        $field = $value instanceof SetClaimTypeLabelRequest ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        $out['label'] = $field;
        $field = $value instanceof SetClaimTypeLabelRequest ? $value->description : (is_array($value) && array_key_exists('description', $value) ? $value['description'] : null);
        if ($field !== null) {
            $out['description'] = $field;
        }
        return $out;
    }

    public static function fromCborSetClaimTypeLabelRequest($value)
    {
        return new SetClaimTypeLabelRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'locale' => array_key_exists('locale', $value) ? $value['locale'] : null,
            'label' => array_key_exists('label', $value) ? $value['label'] : null,
            'description' => array_key_exists('description', $value) ? $value['description'] : null,
        ));
    }

    public static function encodeSetClaimTypeLabelResponse($value)
    {
        return CBOR::encode(self::toCborSetClaimTypeLabelResponse($value));
    }

    public static function decodeSetClaimTypeLabelResponse($bytes)
    {
        return self::fromCborSetClaimTypeLabelResponse(CBOR::decode($bytes));
    }

    public static function toCborSetClaimTypeLabelResponse($value)
    {
        $out = array();
        $field = $value instanceof SetClaimTypeLabelResponse ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        $out['label'] = self::toCborClaimTypeLabel($field);
        return $out;
    }

    public static function fromCborSetClaimTypeLabelResponse($value)
    {
        return new SetClaimTypeLabelResponse(array(
            'label' => array_key_exists('label', $value) ? self::fromCborClaimTypeLabel($value['label']) : null,
        ));
    }

    public static function encodeRemoveClaimTypeLabelRequest($value)
    {
        return CBOR::encode(self::toCborRemoveClaimTypeLabelRequest($value));
    }

    public static function decodeRemoveClaimTypeLabelRequest($bytes)
    {
        return self::fromCborRemoveClaimTypeLabelRequest(CBOR::decode($bytes));
    }

    public static function toCborRemoveClaimTypeLabelRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveClaimTypeLabelRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof RemoveClaimTypeLabelRequest ? $value->locale : (is_array($value) && array_key_exists('locale', $value) ? $value['locale'] : null);
        $out['locale'] = $field;
        return $out;
    }

    public static function fromCborRemoveClaimTypeLabelRequest($value)
    {
        return new RemoveClaimTypeLabelRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'locale' => array_key_exists('locale', $value) ? $value['locale'] : null,
        ));
    }

    public static function encodeRemoveClaimTypeLabelResponse($value)
    {
        return CBOR::encode(self::toCborRemoveClaimTypeLabelResponse($value));
    }

    public static function decodeRemoveClaimTypeLabelResponse($bytes)
    {
        return self::fromCborRemoveClaimTypeLabelResponse(CBOR::decode($bytes));
    }

    public static function toCborRemoveClaimTypeLabelResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveClaimTypeLabelResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out;
    }

    public static function fromCborRemoveClaimTypeLabelResponse($value)
    {
        return new RemoveClaimTypeLabelResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeTrustedIssuer($value)
    {
        return CBOR::encode(self::toCborTrustedIssuer($value));
    }

    public static function decodeTrustedIssuer($bytes)
    {
        return self::fromCborTrustedIssuer(CBOR::decode($bytes));
    }

    public static function toCborTrustedIssuer($value)
    {
        $out = array();
        $field = $value instanceof TrustedIssuer ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof TrustedIssuer ? $value->issuerDomain : (is_array($value) && array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null);
        $out['issuer_domain'] = $field;
        return $out;
    }

    public static function fromCborTrustedIssuer($value)
    {
        return new TrustedIssuer(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'issuer_domain' => array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null,
        ));
    }

    public static function encodeListTrustedIssuersResponse($value)
    {
        return CBOR::encode(self::toCborListTrustedIssuersResponse($value));
    }

    public static function decodeListTrustedIssuersResponse($bytes)
    {
        return self::fromCborListTrustedIssuersResponse(CBOR::decode($bytes));
    }

    public static function toCborListTrustedIssuersResponse($value)
    {
        $out = array();
        $field = $value instanceof ListTrustedIssuersResponse ? $value->trustedIssuers : (is_array($value) && array_key_exists('trusted_issuers', $value) ? $value['trusted_issuers'] : null);
        $out['trusted_issuers'] = array_map(function ($item) { return self::toCborTrustedIssuer($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborListTrustedIssuersResponse($value)
    {
        return new ListTrustedIssuersResponse(array(
            'trusted_issuers' => array_key_exists('trusted_issuers', $value) ? array_map(function ($item) { return self::fromCborTrustedIssuer($item); }, $value['trusted_issuers'] === null ? array() : $value['trusted_issuers']) : null,
        ));
    }

    public static function encodeAddTrustedIssuerRequest($value)
    {
        return CBOR::encode(self::toCborAddTrustedIssuerRequest($value));
    }

    public static function decodeAddTrustedIssuerRequest($bytes)
    {
        return self::fromCborAddTrustedIssuerRequest(CBOR::decode($bytes));
    }

    public static function toCborAddTrustedIssuerRequest($value)
    {
        $out = array();
        $field = $value instanceof AddTrustedIssuerRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof AddTrustedIssuerRequest ? $value->issuerDomain : (is_array($value) && array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null);
        $out['issuer_domain'] = $field;
        return $out;
    }

    public static function fromCborAddTrustedIssuerRequest($value)
    {
        return new AddTrustedIssuerRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'issuer_domain' => array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null,
        ));
    }

    public static function encodeAddTrustedIssuerResponse($value)
    {
        return CBOR::encode(self::toCborAddTrustedIssuerResponse($value));
    }

    public static function decodeAddTrustedIssuerResponse($bytes)
    {
        return self::fromCborAddTrustedIssuerResponse(CBOR::decode($bytes));
    }

    public static function toCborAddTrustedIssuerResponse($value)
    {
        $out = array();
        $field = $value instanceof AddTrustedIssuerResponse ? $value->trustedIssuer : (is_array($value) && array_key_exists('trusted_issuer', $value) ? $value['trusted_issuer'] : null);
        $out['trusted_issuer'] = self::toCborTrustedIssuer($field);
        return $out;
    }

    public static function fromCborAddTrustedIssuerResponse($value)
    {
        return new AddTrustedIssuerResponse(array(
            'trusted_issuer' => array_key_exists('trusted_issuer', $value) ? self::fromCborTrustedIssuer($value['trusted_issuer']) : null,
        ));
    }

    public static function encodeRemoveTrustedIssuerRequest($value)
    {
        return CBOR::encode(self::toCborRemoveTrustedIssuerRequest($value));
    }

    public static function decodeRemoveTrustedIssuerRequest($bytes)
    {
        return self::fromCborRemoveTrustedIssuerRequest(CBOR::decode($bytes));
    }

    public static function toCborRemoveTrustedIssuerRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveTrustedIssuerRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof RemoveTrustedIssuerRequest ? $value->issuerDomain : (is_array($value) && array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null);
        $out['issuer_domain'] = $field;
        return $out;
    }

    public static function fromCborRemoveTrustedIssuerRequest($value)
    {
        return new RemoveTrustedIssuerRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'issuer_domain' => array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null,
        ));
    }

    public static function encodeRemoveTrustedIssuerResponse($value)
    {
        return CBOR::encode(self::toCborRemoveTrustedIssuerResponse($value));
    }

    public static function decodeRemoveTrustedIssuerResponse($bytes)
    {
        return self::fromCborRemoveTrustedIssuerResponse(CBOR::decode($bytes));
    }

    public static function toCborRemoveTrustedIssuerResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveTrustedIssuerResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out;
    }

    public static function fromCborRemoveTrustedIssuerResponse($value)
    {
        return new RemoveTrustedIssuerResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeReleaseRule($value)
    {
        return CBOR::encode(self::toCborReleaseRule($value));
    }

    public static function decodeReleaseRule($bytes)
    {
        return self::fromCborReleaseRule(CBOR::decode($bytes));
    }

    public static function toCborReleaseRule($value)
    {
        $out = array();
        $field = $value instanceof ReleaseRule ? $value->audience : (is_array($value) && array_key_exists('audience', $value) ? $value['audience'] : null);
        $out['audience'] = $field;
        $field = $value instanceof ReleaseRule ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof ReleaseRule ? $value->disposition : (is_array($value) && array_key_exists('disposition', $value) ? $value['disposition'] : null);
        $out['disposition'] = $field;
        return $out;
    }

    public static function fromCborReleaseRule($value)
    {
        return new ReleaseRule(array(
            'audience' => array_key_exists('audience', $value) ? $value['audience'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'disposition' => array_key_exists('disposition', $value) ? $value['disposition'] : null,
        ));
    }

    public static function encodeListReleaseRulesResponse($value)
    {
        return CBOR::encode(self::toCborListReleaseRulesResponse($value));
    }

    public static function decodeListReleaseRulesResponse($bytes)
    {
        return self::fromCborListReleaseRulesResponse(CBOR::decode($bytes));
    }

    public static function toCborListReleaseRulesResponse($value)
    {
        $out = array();
        $field = $value instanceof ListReleaseRulesResponse ? $value->releaseRules : (is_array($value) && array_key_exists('release_rules', $value) ? $value['release_rules'] : null);
        $out['release_rules'] = array_map(function ($item) { return self::toCborReleaseRule($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborListReleaseRulesResponse($value)
    {
        return new ListReleaseRulesResponse(array(
            'release_rules' => array_key_exists('release_rules', $value) ? array_map(function ($item) { return self::fromCborReleaseRule($item); }, $value['release_rules'] === null ? array() : $value['release_rules']) : null,
        ));
    }

    public static function encodeSetReleaseRuleRequest($value)
    {
        return CBOR::encode(self::toCborSetReleaseRuleRequest($value));
    }

    public static function decodeSetReleaseRuleRequest($bytes)
    {
        return self::fromCborSetReleaseRuleRequest(CBOR::decode($bytes));
    }

    public static function toCborSetReleaseRuleRequest($value)
    {
        $out = array();
        $field = $value instanceof SetReleaseRuleRequest ? $value->audience : (is_array($value) && array_key_exists('audience', $value) ? $value['audience'] : null);
        $out['audience'] = $field;
        $field = $value instanceof SetReleaseRuleRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SetReleaseRuleRequest ? $value->disposition : (is_array($value) && array_key_exists('disposition', $value) ? $value['disposition'] : null);
        $out['disposition'] = $field;
        return $out;
    }

    public static function fromCborSetReleaseRuleRequest($value)
    {
        return new SetReleaseRuleRequest(array(
            'audience' => array_key_exists('audience', $value) ? $value['audience'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'disposition' => array_key_exists('disposition', $value) ? $value['disposition'] : null,
        ));
    }

    public static function encodeSetReleaseRuleResponse($value)
    {
        return CBOR::encode(self::toCborSetReleaseRuleResponse($value));
    }

    public static function decodeSetReleaseRuleResponse($bytes)
    {
        return self::fromCborSetReleaseRuleResponse(CBOR::decode($bytes));
    }

    public static function toCborSetReleaseRuleResponse($value)
    {
        $out = array();
        $field = $value instanceof SetReleaseRuleResponse ? $value->releaseRule : (is_array($value) && array_key_exists('release_rule', $value) ? $value['release_rule'] : null);
        $out['release_rule'] = self::toCborReleaseRule($field);
        return $out;
    }

    public static function fromCborSetReleaseRuleResponse($value)
    {
        return new SetReleaseRuleResponse(array(
            'release_rule' => array_key_exists('release_rule', $value) ? self::fromCborReleaseRule($value['release_rule']) : null,
        ));
    }

    public static function encodeRemoveReleaseRuleRequest($value)
    {
        return CBOR::encode(self::toCborRemoveReleaseRuleRequest($value));
    }

    public static function decodeRemoveReleaseRuleRequest($bytes)
    {
        return self::fromCborRemoveReleaseRuleRequest(CBOR::decode($bytes));
    }

    public static function toCborRemoveReleaseRuleRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveReleaseRuleRequest ? $value->audience : (is_array($value) && array_key_exists('audience', $value) ? $value['audience'] : null);
        $out['audience'] = $field;
        $field = $value instanceof RemoveReleaseRuleRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        return $out;
    }

    public static function fromCborRemoveReleaseRuleRequest($value)
    {
        return new RemoveReleaseRuleRequest(array(
            'audience' => array_key_exists('audience', $value) ? $value['audience'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
        ));
    }

    public static function encodeRemoveReleaseRuleResponse($value)
    {
        return CBOR::encode(self::toCborRemoveReleaseRuleResponse($value));
    }

    public static function decodeRemoveReleaseRuleResponse($bytes)
    {
        return self::fromCborRemoveReleaseRuleResponse(CBOR::decode($bytes));
    }

    public static function toCborRemoveReleaseRuleResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveReleaseRuleResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out;
    }

    public static function fromCborRemoveReleaseRuleResponse($value)
    {
        return new RemoveReleaseRuleResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeClaimApproval($value)
    {
        return CBOR::encode(self::toCborClaimApproval($value));
    }

    public static function decodeClaimApproval($bytes)
    {
        return self::fromCborClaimApproval(CBOR::decode($bytes));
    }

    public static function toCborClaimApproval($value)
    {
        $out = array();
        $field = $value instanceof ClaimApproval ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof ClaimApproval ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof ClaimApproval ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof ClaimApproval ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        $out['claim_value'] = CBOR::bytes($field);
        $field = $value instanceof ClaimApproval ? $value->status : (is_array($value) && array_key_exists('status', $value) ? $value['status'] : null);
        $out['status'] = $field;
        $field = $value instanceof ClaimApproval ? $value->resolvedBy : (is_array($value) && array_key_exists('resolved_by', $value) ? $value['resolved_by'] : null);
        if ($field !== null) {
            $out['resolved_by'] = $field;
        }
        $field = $value instanceof ClaimApproval ? $value->resolvedAt : (is_array($value) && array_key_exists('resolved_at', $value) ? $value['resolved_at'] : null);
        if ($field !== null) {
            $out['resolved_at'] = $field;
        }
        $field = $value instanceof ClaimApproval ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = $field;
        return $out;
    }

    public static function fromCborClaimApproval($value)
    {
        return new ClaimApproval(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
            'status' => array_key_exists('status', $value) ? $value['status'] : null,
            'resolved_by' => array_key_exists('resolved_by', $value) ? $value['resolved_by'] : null,
            'resolved_at' => array_key_exists('resolved_at', $value) ? $value['resolved_at'] : null,
            'created_at' => array_key_exists('created_at', $value) ? $value['created_at'] : null,
        ));
    }

    public static function encodeListPendingClaimApprovalsResponse($value)
    {
        return CBOR::encode(self::toCborListPendingClaimApprovalsResponse($value));
    }

    public static function decodeListPendingClaimApprovalsResponse($bytes)
    {
        return self::fromCborListPendingClaimApprovalsResponse(CBOR::decode($bytes));
    }

    public static function toCborListPendingClaimApprovalsResponse($value)
    {
        $out = array();
        $field = $value instanceof ListPendingClaimApprovalsResponse ? $value->approvals : (is_array($value) && array_key_exists('approvals', $value) ? $value['approvals'] : null);
        $out['approvals'] = array_map(function ($item) { return self::toCborClaimApproval($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborListPendingClaimApprovalsResponse($value)
    {
        return new ListPendingClaimApprovalsResponse(array(
            'approvals' => array_key_exists('approvals', $value) ? array_map(function ($item) { return self::fromCborClaimApproval($item); }, $value['approvals'] === null ? array() : $value['approvals']) : null,
        ));
    }

    public static function encodeApproveClaimRequest($value)
    {
        return CBOR::encode(self::toCborApproveClaimRequest($value));
    }

    public static function decodeApproveClaimRequest($bytes)
    {
        return self::fromCborApproveClaimRequest(CBOR::decode($bytes));
    }

    public static function toCborApproveClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof ApproveClaimRequest ? $value->approvalId : (is_array($value) && array_key_exists('approval_id', $value) ? $value['approval_id'] : null);
        $out['approval_id'] = $field;
        return $out;
    }

    public static function fromCborApproveClaimRequest($value)
    {
        return new ApproveClaimRequest(array(
            'approval_id' => array_key_exists('approval_id', $value) ? $value['approval_id'] : null,
        ));
    }

    public static function encodeApproveClaimResponse($value)
    {
        return CBOR::encode(self::toCborApproveClaimResponse($value));
    }

    public static function decodeApproveClaimResponse($bytes)
    {
        return self::fromCborApproveClaimResponse(CBOR::decode($bytes));
    }

    public static function toCborApproveClaimResponse($value)
    {
        $out = array();
        $field = $value instanceof ApproveClaimResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out;
    }

    public static function fromCborApproveClaimResponse($value)
    {
        return new ApproveClaimResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeRejectClaimRequest($value)
    {
        return CBOR::encode(self::toCborRejectClaimRequest($value));
    }

    public static function decodeRejectClaimRequest($bytes)
    {
        return self::fromCborRejectClaimRequest(CBOR::decode($bytes));
    }

    public static function toCborRejectClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof RejectClaimRequest ? $value->approvalId : (is_array($value) && array_key_exists('approval_id', $value) ? $value['approval_id'] : null);
        $out['approval_id'] = $field;
        return $out;
    }

    public static function fromCborRejectClaimRequest($value)
    {
        return new RejectClaimRequest(array(
            'approval_id' => array_key_exists('approval_id', $value) ? $value['approval_id'] : null,
        ));
    }

    public static function encodeRejectClaimResponse($value)
    {
        return CBOR::encode(self::toCborRejectClaimResponse($value));
    }

    public static function decodeRejectClaimResponse($bytes)
    {
        return self::fromCborRejectClaimResponse(CBOR::decode($bytes));
    }

    public static function toCborRejectClaimResponse($value)
    {
        $out = array();
        $field = $value instanceof RejectClaimResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out;
    }

    public static function fromCborRejectClaimResponse($value)
    {
        return new RejectClaimResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeAdminIssueAttestationRequest($value)
    {
        return CBOR::encode(self::toCborAdminIssueAttestationRequest($value));
    }

    public static function decodeAdminIssueAttestationRequest($bytes)
    {
        return self::fromCborAdminIssueAttestationRequest(CBOR::decode($bytes));
    }

    public static function toCborAdminIssueAttestationRequest($value)
    {
        $out = array();
        $field = $value instanceof AdminIssueAttestationRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof AdminIssueAttestationRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof AdminIssueAttestationRequest ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        $out['claim_value'] = CBOR::bytes($field);
        return $out;
    }

    public static function fromCborAdminIssueAttestationRequest($value)
    {
        return new AdminIssueAttestationRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
        ));
    }

    public static function encodeAdminIssueAttestationResponse($value)
    {
        return CBOR::encode(self::toCborAdminIssueAttestationResponse($value));
    }

    public static function decodeAdminIssueAttestationResponse($bytes)
    {
        return self::fromCborAdminIssueAttestationResponse(CBOR::decode($bytes));
    }

    public static function toCborAdminIssueAttestationResponse($value)
    {
        $out = array();
        $field = $value instanceof AdminIssueAttestationResponse ? $value->claim : (is_array($value) && array_key_exists('claim', $value) ? $value['claim'] : null);
        $out['claim'] = self::toCborClaim($field);
        return $out;
    }

    public static function fromCborAdminIssueAttestationResponse($value)
    {
        return new AdminIssueAttestationResponse(array(
            'claim' => array_key_exists('claim', $value) ? self::fromCborClaim($value['claim']) : null,
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
        $field = $value instanceof ChangePasswordRequest ? $value->currentPassword : (is_array($value) && array_key_exists('current_password', $value) ? $value['current_password'] : null);
        $out['current_password'] = $field;
        $field = $value instanceof ChangePasswordRequest ? $value->newPassword : (is_array($value) && array_key_exists('new_password', $value) ? $value['new_password'] : null);
        $out['new_password'] = $field;
        return $out;
    }

    public static function fromCborChangePasswordRequest($value)
    {
        return new ChangePasswordRequest(array(
            'current_password' => array_key_exists('current_password', $value) ? $value['current_password'] : null,
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

    public static function encodeSetMyClaimRequest($value)
    {
        return CBOR::encode(self::toCborSetMyClaimRequest($value));
    }

    public static function decodeSetMyClaimRequest($bytes)
    {
        return self::fromCborSetMyClaimRequest(CBOR::decode($bytes));
    }

    public static function toCborSetMyClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof SetMyClaimRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SetMyClaimRequest ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        $out['claim_value'] = $field;
        return $out;
    }

    public static function fromCborSetMyClaimRequest($value)
    {
        return new SetMyClaimRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
        ));
    }

    public static function encodeSetMyClaimResponse($value)
    {
        return CBOR::encode(self::toCborSetMyClaimResponse($value));
    }

    public static function decodeSetMyClaimResponse($bytes)
    {
        return self::fromCborSetMyClaimResponse(CBOR::decode($bytes));
    }

    public static function toCborSetMyClaimResponse($value)
    {
        $out = array();
        $field = $value instanceof SetMyClaimResponse ? $value->outcome : (is_array($value) && array_key_exists('outcome', $value) ? $value['outcome'] : null);
        $out['outcome'] = $field;
        $field = $value instanceof SetMyClaimResponse ? $value->claim : (is_array($value) && array_key_exists('claim', $value) ? $value['claim'] : null);
        if ($field !== null) {
            $out['claim'] = self::toCborClaim($field);
        }
        return $out;
    }

    public static function fromCborSetMyClaimResponse($value)
    {
        return new SetMyClaimResponse(array(
            'outcome' => array_key_exists('outcome', $value) ? $value['outcome'] : null,
            'claim' => array_key_exists('claim', $value) ? self::fromCborClaim($value['claim']) : null,
        ));
    }

    public static function encodeRemoveMyClaimRequest($value)
    {
        return CBOR::encode(self::toCborRemoveMyClaimRequest($value));
    }

    public static function decodeRemoveMyClaimRequest($bytes)
    {
        return self::fromCborRemoveMyClaimRequest(CBOR::decode($bytes));
    }

    public static function toCborRemoveMyClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveMyClaimRequest ? $value->claimId : (is_array($value) && array_key_exists('claim_id', $value) ? $value['claim_id'] : null);
        $out['claim_id'] = $field;
        return $out;
    }

    public static function fromCborRemoveMyClaimRequest($value)
    {
        return new RemoveMyClaimRequest(array(
            'claim_id' => array_key_exists('claim_id', $value) ? $value['claim_id'] : null,
        ));
    }

    public static function encodeRemoveMyClaimResponse($value)
    {
        return CBOR::encode(self::toCborRemoveMyClaimResponse($value));
    }

    public static function decodeRemoveMyClaimResponse($bytes)
    {
        return self::fromCborRemoveMyClaimResponse(CBOR::decode($bytes));
    }

    public static function toCborRemoveMyClaimResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveMyClaimResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out;
    }

    public static function fromCborRemoveMyClaimResponse($value)
    {
        return new RemoveMyClaimResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeSetMyClaimSharingRequest($value)
    {
        return CBOR::encode(self::toCborSetMyClaimSharingRequest($value));
    }

    public static function decodeSetMyClaimSharingRequest($bytes)
    {
        return self::fromCborSetMyClaimSharingRequest(CBOR::decode($bytes));
    }

    public static function toCborSetMyClaimSharingRequest($value)
    {
        $out = array();
        $field = $value instanceof SetMyClaimSharingRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SetMyClaimSharingRequest ? $value->share : (is_array($value) && array_key_exists('share', $value) ? $value['share'] : null);
        $out['share'] = $field;
        return $out;
    }

    public static function fromCborSetMyClaimSharingRequest($value)
    {
        return new SetMyClaimSharingRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'share' => array_key_exists('share', $value) ? $value['share'] : null,
        ));
    }

    public static function encodeSetMyClaimSharingResponse($value)
    {
        return CBOR::encode(self::toCborSetMyClaimSharingResponse($value));
    }

    public static function decodeSetMyClaimSharingResponse($bytes)
    {
        return self::fromCborSetMyClaimSharingResponse(CBOR::decode($bytes));
    }

    public static function toCborSetMyClaimSharingResponse($value)
    {
        $out = array();
        return $out;
    }

    public static function fromCborSetMyClaimSharingResponse($value)
    {
        return new SetMyClaimSharingResponse(array(
        ));
    }

    public static function encodeProfile($value)
    {
        return CBOR::encode(self::toCborProfile($value));
    }

    public static function decodeProfile($bytes)
    {
        return self::fromCborProfile(CBOR::decode($bytes));
    }

    public static function toCborProfile($value)
    {
        $out = array();
        $field = $value instanceof Profile ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof Profile ? $value->accountId : (is_array($value) && array_key_exists('account_id', $value) ? $value['account_id'] : null);
        $out['account_id'] = $field;
        $field = $value instanceof Profile ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof Profile ? $value->isRoot : (is_array($value) && array_key_exists('is_root', $value) ? $value['is_root'] : null);
        $out['is_root'] = $field;
        $field = $value instanceof Profile ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        if ($field !== null) {
            $out['label'] = $field;
        }
        return $out;
    }

    public static function fromCborProfile($value)
    {
        return new Profile(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'account_id' => array_key_exists('account_id', $value) ? $value['account_id'] : null,
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'is_root' => array_key_exists('is_root', $value) ? $value['is_root'] : null,
            'label' => array_key_exists('label', $value) ? $value['label'] : null,
        ));
    }

    public static function encodeCreateProfileRequest($value)
    {
        return CBOR::encode(self::toCborCreateProfileRequest($value));
    }

    public static function decodeCreateProfileRequest($bytes)
    {
        return self::fromCborCreateProfileRequest(CBOR::decode($bytes));
    }

    public static function toCborCreateProfileRequest($value)
    {
        $out = array();
        $field = $value instanceof CreateProfileRequest ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        if ($field !== null) {
            $out['label'] = $field;
        }
        return $out;
    }

    public static function fromCborCreateProfileRequest($value)
    {
        return new CreateProfileRequest(array(
            'label' => array_key_exists('label', $value) ? $value['label'] : null,
        ));
    }

    public static function encodeCreateProfileResponse($value)
    {
        return CBOR::encode(self::toCborCreateProfileResponse($value));
    }

    public static function decodeCreateProfileResponse($bytes)
    {
        return self::fromCborCreateProfileResponse(CBOR::decode($bytes));
    }

    public static function toCborCreateProfileResponse($value)
    {
        $out = array();
        $field = $value instanceof CreateProfileResponse ? $value->profile : (is_array($value) && array_key_exists('profile', $value) ? $value['profile'] : null);
        $out['profile'] = self::toCborProfile($field);
        return $out;
    }

    public static function fromCborCreateProfileResponse($value)
    {
        return new CreateProfileResponse(array(
            'profile' => array_key_exists('profile', $value) ? self::fromCborProfile($value['profile']) : null,
        ));
    }

    public static function encodeRequestVerificationRequest($value)
    {
        return CBOR::encode(self::toCborRequestVerificationRequest($value));
    }

    public static function decodeRequestVerificationRequest($bytes)
    {
        return self::fromCborRequestVerificationRequest(CBOR::decode($bytes));
    }

    public static function toCborRequestVerificationRequest($value)
    {
        $out = array();
        $field = $value instanceof RequestVerificationRequest ? $value->issuerDomain : (is_array($value) && array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null);
        $out['issuer_domain'] = $field;
        $field = $value instanceof RequestVerificationRequest ? $value->requestedClaimTypes : (is_array($value) && array_key_exists('requested_claim_types', $value) ? $value['requested_claim_types'] : null);
        $out['requested_claim_types'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborRequestVerificationRequest($value)
    {
        return new RequestVerificationRequest(array(
            'issuer_domain' => array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null,
            'requested_claim_types' => array_key_exists('requested_claim_types', $value) ? array_map(function ($item) { return $item; }, $value['requested_claim_types'] === null ? array() : $value['requested_claim_types']) : null,
        ));
    }

    public static function encodeRequestVerificationResponse($value)
    {
        return CBOR::encode(self::toCborRequestVerificationResponse($value));
    }

    public static function decodeRequestVerificationResponse($bytes)
    {
        return self::fromCborRequestVerificationResponse(CBOR::decode($bytes));
    }

    public static function toCborRequestVerificationResponse($value)
    {
        $out = array();
        $field = $value instanceof RequestVerificationResponse ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = self::toCborSignedSigningRequest($field);
        return $out;
    }

    public static function fromCborRequestVerificationResponse($value)
    {
        return new RequestVerificationResponse(array(
            'signed_request' => array_key_exists('signed_request', $value) ? self::fromCborSignedSigningRequest($value['signed_request']) : null,
        ));
    }

    public static function encodePasswordPolicy($value)
    {
        return CBOR::encode(self::toCborPasswordPolicy($value));
    }

    public static function decodePasswordPolicy($bytes)
    {
        return self::fromCborPasswordPolicy(CBOR::decode($bytes));
    }

    public static function toCborPasswordPolicy($value)
    {
        $out = array();
        $field = $value instanceof PasswordPolicy ? $value->minLength : (is_array($value) && array_key_exists('min_length', $value) ? $value['min_length'] : null);
        $out['min_length'] = $field;
        $field = $value instanceof PasswordPolicy ? $value->maxLength : (is_array($value) && array_key_exists('max_length', $value) ? $value['max_length'] : null);
        $out['max_length'] = $field;
        return $out;
    }

    public static function fromCborPasswordPolicy($value)
    {
        return new PasswordPolicy(array(
            'min_length' => array_key_exists('min_length', $value) ? $value['min_length'] : null,
            'max_length' => array_key_exists('max_length', $value) ? $value['max_length'] : null,
        ));
    }

    public static function encodeBrowserSessionInfo($value)
    {
        return CBOR::encode(self::toCborBrowserSessionInfo($value));
    }

    public static function decodeBrowserSessionInfo($bytes)
    {
        return self::fromCborBrowserSessionInfo(CBOR::decode($bytes));
    }

    public static function toCborBrowserSessionInfo($value)
    {
        $out = array();
        $field = $value instanceof BrowserSessionInfo ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        $field = $value instanceof BrowserSessionInfo ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = $field;
        $field = $value instanceof BrowserSessionInfo ? $value->authenticatedAt : (is_array($value) && array_key_exists('authenticated_at', $value) ? $value['authenticated_at'] : null);
        $out['authenticated_at'] = $field;
        $field = $value instanceof BrowserSessionInfo ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = $field;
        $field = $value instanceof BrowserSessionInfo ? $value->authenticationMethods : (is_array($value) && array_key_exists('authentication_methods', $value) ? $value['authentication_methods'] : null);
        $out['authentication_methods'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborBrowserSessionInfo($value)
    {
        return new BrowserSessionInfo(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
            'issued_at' => array_key_exists('issued_at', $value) ? $value['issued_at'] : null,
            'authenticated_at' => array_key_exists('authenticated_at', $value) ? $value['authenticated_at'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
            'authentication_methods' => array_key_exists('authentication_methods', $value) ? array_map(function ($item) { return $item; }, $value['authentication_methods'] === null ? array() : $value['authentication_methods']) : null,
        ));
    }

    public static function encodeSessionPasswordLoginRequest($value)
    {
        return CBOR::encode(self::toCborSessionPasswordLoginRequest($value));
    }

    public static function decodeSessionPasswordLoginRequest($bytes)
    {
        return self::fromCborSessionPasswordLoginRequest(CBOR::decode($bytes));
    }

    public static function toCborSessionPasswordLoginRequest($value)
    {
        $out = array();
        $field = $value instanceof SessionPasswordLoginRequest ? $value->username : (is_array($value) && array_key_exists('username', $value) ? $value['username'] : null);
        $out['username'] = $field;
        $field = $value instanceof SessionPasswordLoginRequest ? $value->password : (is_array($value) && array_key_exists('password', $value) ? $value['password'] : null);
        $out['password'] = $field;
        return $out;
    }

    public static function fromCborSessionPasswordLoginRequest($value)
    {
        return new SessionPasswordLoginRequest(array(
            'username' => array_key_exists('username', $value) ? $value['username'] : null,
            'password' => array_key_exists('password', $value) ? $value['password'] : null,
        ));
    }

    public static function encodeSessionPasswordLoginResponse($value)
    {
        return CBOR::encode(self::toCborSessionPasswordLoginResponse($value));
    }

    public static function decodeSessionPasswordLoginResponse($bytes)
    {
        return self::fromCborSessionPasswordLoginResponse(CBOR::decode($bytes));
    }

    public static function toCborSessionPasswordLoginResponse($value)
    {
        $out = array();
        $field = $value instanceof SessionPasswordLoginResponse ? $value->session : (is_array($value) && array_key_exists('session', $value) ? $value['session'] : null);
        $out['session'] = self::toCborBrowserSessionInfo($field);
        return $out;
    }

    public static function fromCborSessionPasswordLoginResponse($value)
    {
        return new SessionPasswordLoginResponse(array(
            'session' => array_key_exists('session', $value) ? self::fromCborBrowserSessionInfo($value['session']) : null,
        ));
    }

    public static function encodeSessionCurrentResponse($value)
    {
        return CBOR::encode(self::toCborSessionCurrentResponse($value));
    }

    public static function decodeSessionCurrentResponse($bytes)
    {
        return self::fromCborSessionCurrentResponse(CBOR::decode($bytes));
    }

    public static function toCborSessionCurrentResponse($value)
    {
        $out = array();
        $field = $value instanceof SessionCurrentResponse ? $value->session : (is_array($value) && array_key_exists('session', $value) ? $value['session'] : null);
        $out['session'] = self::toCborBrowserSessionInfo($field);
        return $out;
    }

    public static function fromCborSessionCurrentResponse($value)
    {
        return new SessionCurrentResponse(array(
            'session' => array_key_exists('session', $value) ? self::fromCborBrowserSessionInfo($value['session']) : null,
        ));
    }

    public static function encodeSessionLogoutResponse($value)
    {
        return CBOR::encode(self::toCborSessionLogoutResponse($value));
    }

    public static function decodeSessionLogoutResponse($bytes)
    {
        return self::fromCborSessionLogoutResponse(CBOR::decode($bytes));
    }

    public static function toCborSessionLogoutResponse($value)
    {
        $out = array();
        $field = $value instanceof SessionLogoutResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out;
    }

    public static function fromCborSessionLogoutResponse($value)
    {
        return new SessionLogoutResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeIntrospectBrowserSessionRequest($value)
    {
        return CBOR::encode(self::toCborIntrospectBrowserSessionRequest($value));
    }

    public static function decodeIntrospectBrowserSessionRequest($bytes)
    {
        return self::fromCborIntrospectBrowserSessionRequest(CBOR::decode($bytes));
    }

    public static function toCborIntrospectBrowserSessionRequest($value)
    {
        $out = array();
        $field = $value instanceof IntrospectBrowserSessionRequest ? $value->sessionCookie : (is_array($value) && array_key_exists('session_cookie', $value) ? $value['session_cookie'] : null);
        $out['session_cookie'] = $field;
        return $out;
    }

    public static function fromCborIntrospectBrowserSessionRequest($value)
    {
        return new IntrospectBrowserSessionRequest(array(
            'session_cookie' => array_key_exists('session_cookie', $value) ? $value['session_cookie'] : null,
        ));
    }

    public static function encodeIntrospectBrowserSessionResponse($value)
    {
        return CBOR::encode(self::toCborIntrospectBrowserSessionResponse($value));
    }

    public static function decodeIntrospectBrowserSessionResponse($bytes)
    {
        return self::fromCborIntrospectBrowserSessionResponse(CBOR::decode($bytes));
    }

    public static function toCborIntrospectBrowserSessionResponse($value)
    {
        $out = array();
        $field = $value instanceof IntrospectBrowserSessionResponse ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof IntrospectBrowserSessionResponse ? $value->userDomain : (is_array($value) && array_key_exists('user_domain', $value) ? $value['user_domain'] : null);
        $out['user_domain'] = $field;
        $field = $value instanceof IntrospectBrowserSessionResponse ? $value->authenticatedAt : (is_array($value) && array_key_exists('authenticated_at', $value) ? $value['authenticated_at'] : null);
        $out['authenticated_at'] = $field;
        $field = $value instanceof IntrospectBrowserSessionResponse ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = $field;
        $field = $value instanceof IntrospectBrowserSessionResponse ? $value->authenticationMethods : (is_array($value) && array_key_exists('authentication_methods', $value) ? $value['authentication_methods'] : null);
        $out['authentication_methods'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborIntrospectBrowserSessionResponse($value)
    {
        return new IntrospectBrowserSessionResponse(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'user_domain' => array_key_exists('user_domain', $value) ? $value['user_domain'] : null,
            'authenticated_at' => array_key_exists('authenticated_at', $value) ? $value['authenticated_at'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
            'authentication_methods' => array_key_exists('authentication_methods', $value) ? array_map(function ($item) { return $item; }, $value['authentication_methods'] === null ? array() : $value['authentication_methods']) : null,
        ));
    }

    public static function encodeNotificationCapability($value)
    {
        return CBOR::encode(self::toCborNotificationCapability($value));
    }

    public static function decodeNotificationCapability($bytes)
    {
        return self::fromCborNotificationCapability(CBOR::decode($bytes));
    }

    public static function toCborNotificationCapability($value)
    {
        $out = array();
        $field = $value instanceof NotificationCapability ? $value->purpose : (is_array($value) && array_key_exists('purpose', $value) ? $value['purpose'] : null);
        $out['purpose'] = $field;
        $field = $value instanceof NotificationCapability ? $value->channel : (is_array($value) && array_key_exists('channel', $value) ? $value['channel'] : null);
        $out['channel'] = $field;
        $field = $value instanceof NotificationCapability ? $value->destinationKind : (is_array($value) && array_key_exists('destination_kind', $value) ? $value['destination_kind'] : null);
        $out['destination_kind'] = $field;
        return $out;
    }

    public static function fromCborNotificationCapability($value)
    {
        return new NotificationCapability(array(
            'purpose' => array_key_exists('purpose', $value) ? $value['purpose'] : null,
            'channel' => array_key_exists('channel', $value) ? $value['channel'] : null,
            'destination_kind' => array_key_exists('destination_kind', $value) ? $value['destination_kind'] : null,
        ));
    }

    public static function encodeGetNotificationCapabilitiesResponse($value)
    {
        return CBOR::encode(self::toCborGetNotificationCapabilitiesResponse($value));
    }

    public static function decodeGetNotificationCapabilitiesResponse($bytes)
    {
        return self::fromCborGetNotificationCapabilitiesResponse(CBOR::decode($bytes));
    }

    public static function toCborGetNotificationCapabilitiesResponse($value)
    {
        $out = array();
        $field = $value instanceof GetNotificationCapabilitiesResponse ? $value->capabilities : (is_array($value) && array_key_exists('capabilities', $value) ? $value['capabilities'] : null);
        $out['capabilities'] = array_map(function ($item) { return self::toCborNotificationCapability($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborGetNotificationCapabilitiesResponse($value)
    {
        return new GetNotificationCapabilitiesResponse(array(
            'capabilities' => array_key_exists('capabilities', $value) ? array_map(function ($item) { return self::fromCborNotificationCapability($item); }, $value['capabilities'] === null ? array() : $value['capabilities']) : null,
        ));
    }

    public static function encodeVerifiedContactMethod($value)
    {
        return CBOR::encode(self::toCborVerifiedContactMethod($value));
    }

    public static function decodeVerifiedContactMethod($bytes)
    {
        return self::fromCborVerifiedContactMethod(CBOR::decode($bytes));
    }

    public static function toCborVerifiedContactMethod($value)
    {
        $out = array();
        $field = $value instanceof VerifiedContactMethod ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof VerifiedContactMethod ? $value->channel : (is_array($value) && array_key_exists('channel', $value) ? $value['channel'] : null);
        $out['channel'] = $field;
        $field = $value instanceof VerifiedContactMethod ? $value->destination : (is_array($value) && array_key_exists('destination', $value) ? $value['destination'] : null);
        $out['destination'] = $field;
        $field = $value instanceof VerifiedContactMethod ? $value->verifiedAt : (is_array($value) && array_key_exists('verified_at', $value) ? $value['verified_at'] : null);
        $out['verified_at'] = $field;
        $field = $value instanceof VerifiedContactMethod ? $value->purposes : (is_array($value) && array_key_exists('purposes', $value) ? $value['purposes'] : null);
        $out['purposes'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof VerifiedContactMethod ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        if ($field !== null) {
            $out['revoked_at'] = $field;
        }
        return $out;
    }

    public static function fromCborVerifiedContactMethod($value)
    {
        return new VerifiedContactMethod(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'channel' => array_key_exists('channel', $value) ? $value['channel'] : null,
            'destination' => array_key_exists('destination', $value) ? $value['destination'] : null,
            'verified_at' => array_key_exists('verified_at', $value) ? $value['verified_at'] : null,
            'purposes' => array_key_exists('purposes', $value) ? array_map(function ($item) { return $item; }, $value['purposes'] === null ? array() : $value['purposes']) : null,
            'revoked_at' => array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null,
        ));
    }

    public static function encodeListVerifiedContactMethodsResponse($value)
    {
        return CBOR::encode(self::toCborListVerifiedContactMethodsResponse($value));
    }

    public static function decodeListVerifiedContactMethodsResponse($bytes)
    {
        return self::fromCborListVerifiedContactMethodsResponse(CBOR::decode($bytes));
    }

    public static function toCborListVerifiedContactMethodsResponse($value)
    {
        $out = array();
        $field = $value instanceof ListVerifiedContactMethodsResponse ? $value->contactMethods : (is_array($value) && array_key_exists('contact_methods', $value) ? $value['contact_methods'] : null);
        $out['contact_methods'] = array_map(function ($item) { return self::toCborVerifiedContactMethod($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborListVerifiedContactMethodsResponse($value)
    {
        return new ListVerifiedContactMethodsResponse(array(
            'contact_methods' => array_key_exists('contact_methods', $value) ? array_map(function ($item) { return self::fromCborVerifiedContactMethod($item); }, $value['contact_methods'] === null ? array() : $value['contact_methods']) : null,
        ));
    }

    public static function encodeRevokeVerifiedContactMethodRequest($value)
    {
        return CBOR::encode(self::toCborRevokeVerifiedContactMethodRequest($value));
    }

    public static function decodeRevokeVerifiedContactMethodRequest($bytes)
    {
        return self::fromCborRevokeVerifiedContactMethodRequest(CBOR::decode($bytes));
    }

    public static function toCborRevokeVerifiedContactMethodRequest($value)
    {
        $out = array();
        $field = $value instanceof RevokeVerifiedContactMethodRequest ? $value->contactMethodId : (is_array($value) && array_key_exists('contact_method_id', $value) ? $value['contact_method_id'] : null);
        $out['contact_method_id'] = $field;
        $field = $value instanceof RevokeVerifiedContactMethodRequest ? $value->currentPassword : (is_array($value) && array_key_exists('current_password', $value) ? $value['current_password'] : null);
        $out['current_password'] = $field;
        return $out;
    }

    public static function fromCborRevokeVerifiedContactMethodRequest($value)
    {
        return new RevokeVerifiedContactMethodRequest(array(
            'contact_method_id' => array_key_exists('contact_method_id', $value) ? $value['contact_method_id'] : null,
            'current_password' => array_key_exists('current_password', $value) ? $value['current_password'] : null,
        ));
    }

    public static function encodeRevokeVerifiedContactMethodResponse($value)
    {
        return CBOR::encode(self::toCborRevokeVerifiedContactMethodResponse($value));
    }

    public static function decodeRevokeVerifiedContactMethodResponse($bytes)
    {
        return self::fromCborRevokeVerifiedContactMethodResponse(CBOR::decode($bytes));
    }

    public static function toCborRevokeVerifiedContactMethodResponse($value)
    {
        $out = array();
        $field = $value instanceof RevokeVerifiedContactMethodResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out;
    }

    public static function fromCborRevokeVerifiedContactMethodResponse($value)
    {
        return new RevokeVerifiedContactMethodResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeRequestContactVerificationRequest($value)
    {
        return CBOR::encode(self::toCborRequestContactVerificationRequest($value));
    }

    public static function decodeRequestContactVerificationRequest($bytes)
    {
        return self::fromCborRequestContactVerificationRequest(CBOR::decode($bytes));
    }

    public static function toCborRequestContactVerificationRequest($value)
    {
        $out = array();
        $field = $value instanceof RequestContactVerificationRequest ? $value->channel : (is_array($value) && array_key_exists('channel', $value) ? $value['channel'] : null);
        $out['channel'] = $field;
        $field = $value instanceof RequestContactVerificationRequest ? $value->destination : (is_array($value) && array_key_exists('destination', $value) ? $value['destination'] : null);
        $out['destination'] = $field;
        $field = $value instanceof RequestContactVerificationRequest ? $value->currentPassword : (is_array($value) && array_key_exists('current_password', $value) ? $value['current_password'] : null);
        $out['current_password'] = $field;
        return $out;
    }

    public static function fromCborRequestContactVerificationRequest($value)
    {
        return new RequestContactVerificationRequest(array(
            'channel' => array_key_exists('channel', $value) ? $value['channel'] : null,
            'destination' => array_key_exists('destination', $value) ? $value['destination'] : null,
            'current_password' => array_key_exists('current_password', $value) ? $value['current_password'] : null,
        ));
    }

    public static function encodeRequestContactVerificationResponse($value)
    {
        return CBOR::encode(self::toCborRequestContactVerificationResponse($value));
    }

    public static function decodeRequestContactVerificationResponse($bytes)
    {
        return self::fromCborRequestContactVerificationResponse(CBOR::decode($bytes));
    }

    public static function toCborRequestContactVerificationResponse($value)
    {
        $out = array();
        $field = $value instanceof RequestContactVerificationResponse ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = $field;
        return $out;
    }

    public static function fromCborRequestContactVerificationResponse($value)
    {
        return new RequestContactVerificationResponse(array(
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
        ));
    }

    public static function encodeConfirmContactVerificationRequest($value)
    {
        return CBOR::encode(self::toCborConfirmContactVerificationRequest($value));
    }

    public static function decodeConfirmContactVerificationRequest($bytes)
    {
        return self::fromCborConfirmContactVerificationRequest(CBOR::decode($bytes));
    }

    public static function toCborConfirmContactVerificationRequest($value)
    {
        $out = array();
        $field = $value instanceof ConfirmContactVerificationRequest ? $value->token : (is_array($value) && array_key_exists('token', $value) ? $value['token'] : null);
        $out['token'] = $field;
        return $out;
    }

    public static function fromCborConfirmContactVerificationRequest($value)
    {
        return new ConfirmContactVerificationRequest(array(
            'token' => array_key_exists('token', $value) ? $value['token'] : null,
        ));
    }

    public static function encodeConfirmContactVerificationResponse($value)
    {
        return CBOR::encode(self::toCborConfirmContactVerificationResponse($value));
    }

    public static function decodeConfirmContactVerificationResponse($bytes)
    {
        return self::fromCborConfirmContactVerificationResponse(CBOR::decode($bytes));
    }

    public static function toCborConfirmContactVerificationResponse($value)
    {
        $out = array();
        $field = $value instanceof ConfirmContactVerificationResponse ? $value->contactMethod : (is_array($value) && array_key_exists('contact_method', $value) ? $value['contact_method'] : null);
        $out['contact_method'] = self::toCborVerifiedContactMethod($field);
        $field = $value instanceof ConfirmContactVerificationResponse ? $value->claims : (is_array($value) && array_key_exists('claims', $value) ? $value['claims'] : null);
        $out['claims'] = array_map(function ($item) { return self::toCborClaim($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborConfirmContactVerificationResponse($value)
    {
        return new ConfirmContactVerificationResponse(array(
            'contact_method' => array_key_exists('contact_method', $value) ? self::fromCborVerifiedContactMethod($value['contact_method']) : null,
            'claims' => array_key_exists('claims', $value) ? array_map(function ($item) { return self::fromCborClaim($item); }, $value['claims'] === null ? array() : $value['claims']) : null,
        ));
    }

    public static function encodeRequestPasswordRecoveryRequest($value)
    {
        return CBOR::encode(self::toCborRequestPasswordRecoveryRequest($value));
    }

    public static function decodeRequestPasswordRecoveryRequest($bytes)
    {
        return self::fromCborRequestPasswordRecoveryRequest(CBOR::decode($bytes));
    }

    public static function toCborRequestPasswordRecoveryRequest($value)
    {
        $out = array();
        $field = $value instanceof RequestPasswordRecoveryRequest ? $value->identifier : (is_array($value) && array_key_exists('identifier', $value) ? $value['identifier'] : null);
        $out['identifier'] = $field;
        return $out;
    }

    public static function fromCborRequestPasswordRecoveryRequest($value)
    {
        return new RequestPasswordRecoveryRequest(array(
            'identifier' => array_key_exists('identifier', $value) ? $value['identifier'] : null,
        ));
    }

    public static function encodeRequestPasswordRecoveryResponse($value)
    {
        return CBOR::encode(self::toCborRequestPasswordRecoveryResponse($value));
    }

    public static function decodeRequestPasswordRecoveryResponse($bytes)
    {
        return self::fromCborRequestPasswordRecoveryResponse(CBOR::decode($bytes));
    }

    public static function toCborRequestPasswordRecoveryResponse($value)
    {
        $out = array();
        return $out;
    }

    public static function fromCborRequestPasswordRecoveryResponse($value)
    {
        return new RequestPasswordRecoveryResponse(array(
        ));
    }

    public static function encodeValidatePasswordRecoveryRequest($value)
    {
        return CBOR::encode(self::toCborValidatePasswordRecoveryRequest($value));
    }

    public static function decodeValidatePasswordRecoveryRequest($bytes)
    {
        return self::fromCborValidatePasswordRecoveryRequest(CBOR::decode($bytes));
    }

    public static function toCborValidatePasswordRecoveryRequest($value)
    {
        $out = array();
        $field = $value instanceof ValidatePasswordRecoveryRequest ? $value->token : (is_array($value) && array_key_exists('token', $value) ? $value['token'] : null);
        $out['token'] = $field;
        return $out;
    }

    public static function fromCborValidatePasswordRecoveryRequest($value)
    {
        return new ValidatePasswordRecoveryRequest(array(
            'token' => array_key_exists('token', $value) ? $value['token'] : null,
        ));
    }

    public static function encodeValidatePasswordRecoveryResponse($value)
    {
        return CBOR::encode(self::toCborValidatePasswordRecoveryResponse($value));
    }

    public static function decodeValidatePasswordRecoveryResponse($bytes)
    {
        return self::fromCborValidatePasswordRecoveryResponse(CBOR::decode($bytes));
    }

    public static function toCborValidatePasswordRecoveryResponse($value)
    {
        $out = array();
        $field = $value instanceof ValidatePasswordRecoveryResponse ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = $field;
        $field = $value instanceof ValidatePasswordRecoveryResponse ? $value->passwordPolicy : (is_array($value) && array_key_exists('password_policy', $value) ? $value['password_policy'] : null);
        $out['password_policy'] = self::toCborPasswordPolicy($field);
        return $out;
    }

    public static function fromCborValidatePasswordRecoveryResponse($value)
    {
        return new ValidatePasswordRecoveryResponse(array(
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
            'password_policy' => array_key_exists('password_policy', $value) ? self::fromCborPasswordPolicy($value['password_policy']) : null,
        ));
    }

    public static function encodeCompletePasswordRecoveryRequest($value)
    {
        return CBOR::encode(self::toCborCompletePasswordRecoveryRequest($value));
    }

    public static function decodeCompletePasswordRecoveryRequest($bytes)
    {
        return self::fromCborCompletePasswordRecoveryRequest(CBOR::decode($bytes));
    }

    public static function toCborCompletePasswordRecoveryRequest($value)
    {
        $out = array();
        $field = $value instanceof CompletePasswordRecoveryRequest ? $value->token : (is_array($value) && array_key_exists('token', $value) ? $value['token'] : null);
        $out['token'] = $field;
        $field = $value instanceof CompletePasswordRecoveryRequest ? $value->newPassword : (is_array($value) && array_key_exists('new_password', $value) ? $value['new_password'] : null);
        $out['new_password'] = $field;
        return $out;
    }

    public static function fromCborCompletePasswordRecoveryRequest($value)
    {
        return new CompletePasswordRecoveryRequest(array(
            'token' => array_key_exists('token', $value) ? $value['token'] : null,
            'new_password' => array_key_exists('new_password', $value) ? $value['new_password'] : null,
        ));
    }

    public static function encodeCompletePasswordRecoveryResponse($value)
    {
        return CBOR::encode(self::toCborCompletePasswordRecoveryResponse($value));
    }

    public static function decodeCompletePasswordRecoveryResponse($bytes)
    {
        return self::fromCborCompletePasswordRecoveryResponse(CBOR::decode($bytes));
    }

    public static function toCborCompletePasswordRecoveryResponse($value)
    {
        $out = array();
        $field = $value instanceof CompletePasswordRecoveryResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out;
    }

    public static function fromCborCompletePasswordRecoveryResponse($value)
    {
        return new CompletePasswordRecoveryResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeBrowserAuthorizationInspectRequest($value)
    {
        return CBOR::encode(self::toCborBrowserAuthorizationInspectRequest($value));
    }

    public static function decodeBrowserAuthorizationInspectRequest($bytes)
    {
        return self::fromCborBrowserAuthorizationInspectRequest(CBOR::decode($bytes));
    }

    public static function toCborBrowserAuthorizationInspectRequest($value)
    {
        $out = array();
        $field = $value instanceof BrowserAuthorizationInspectRequest ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = $field;
        return $out;
    }

    public static function fromCborBrowserAuthorizationInspectRequest($value)
    {
        return new BrowserAuthorizationInspectRequest(array(
            'signed_request' => array_key_exists('signed_request', $value) ? $value['signed_request'] : null,
        ));
    }

    public static function encodeBrowserConsentClaim($value)
    {
        return CBOR::encode(self::toCborBrowserConsentClaim($value));
    }

    public static function decodeBrowserConsentClaim($bytes)
    {
        return self::fromCborBrowserConsentClaim(CBOR::decode($bytes));
    }

    public static function toCborBrowserConsentClaim($value)
    {
        $out = array();
        $field = $value instanceof BrowserConsentClaim ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        $out['label'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->datatype : (is_array($value) && array_key_exists('datatype', $value) ? $value['datatype'] : null);
        $out['datatype'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->required : (is_array($value) && array_key_exists('required', $value) ? $value['required'] : null);
        $out['required'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->available : (is_array($value) && array_key_exists('available', $value) ? $value['available'] : null);
        $out['available'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->defaultGranted : (is_array($value) && array_key_exists('default_granted', $value) ? $value['default_granted'] : null);
        $out['default_granted'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->policy : (is_array($value) && array_key_exists('policy', $value) ? $value['policy'] : null);
        $out['policy'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->userSettable : (is_array($value) && array_key_exists('user_settable', $value) ? $value['user_settable'] : null);
        $out['user_settable'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->maxBytes : (is_array($value) && array_key_exists('max_bytes', $value) ? $value['max_bytes'] : null);
        $out['max_bytes'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->requiresApproval : (is_array($value) && array_key_exists('requires_approval', $value) ? $value['requires_approval'] : null);
        $out['requires_approval'] = $field;
        return $out;
    }

    public static function fromCborBrowserConsentClaim($value)
    {
        return new BrowserConsentClaim(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'label' => array_key_exists('label', $value) ? $value['label'] : null,
            'datatype' => array_key_exists('datatype', $value) ? $value['datatype'] : null,
            'required' => array_key_exists('required', $value) ? $value['required'] : null,
            'available' => array_key_exists('available', $value) ? $value['available'] : null,
            'default_granted' => array_key_exists('default_granted', $value) ? $value['default_granted'] : null,
            'policy' => array_key_exists('policy', $value) ? $value['policy'] : null,
            'user_settable' => array_key_exists('user_settable', $value) ? $value['user_settable'] : null,
            'max_bytes' => array_key_exists('max_bytes', $value) ? $value['max_bytes'] : null,
            'requires_approval' => array_key_exists('requires_approval', $value) ? $value['requires_approval'] : null,
        ));
    }

    public static function encodeBrowserAuthorizationInspectResponse($value)
    {
        return CBOR::encode(self::toCborBrowserAuthorizationInspectResponse($value));
    }

    public static function decodeBrowserAuthorizationInspectResponse($bytes)
    {
        return self::fromCborBrowserAuthorizationInspectResponse(CBOR::decode($bytes));
    }

    public static function toCborBrowserAuthorizationInspectResponse($value)
    {
        $out = array();
        $field = $value instanceof BrowserAuthorizationInspectResponse ? $value->relyingParty : (is_array($value) && array_key_exists('relying_party', $value) ? $value['relying_party'] : null);
        $out['relying_party'] = $field;
        $field = $value instanceof BrowserAuthorizationInspectResponse ? $value->claims : (is_array($value) && array_key_exists('claims', $value) ? $value['claims'] : null);
        $out['claims'] = array_map(function ($item) { return self::toCborBrowserConsentClaim($item); }, $field === null ? array() : $field);
        $field = $value instanceof BrowserAuthorizationInspectResponse ? $value->requestReason : (is_array($value) && array_key_exists('request_reason', $value) ? $value['request_reason'] : null);
        if ($field !== null) {
            $out['request_reason'] = $field;
        }
        return $out;
    }

    public static function fromCborBrowserAuthorizationInspectResponse($value)
    {
        return new BrowserAuthorizationInspectResponse(array(
            'relying_party' => array_key_exists('relying_party', $value) ? $value['relying_party'] : null,
            'claims' => array_key_exists('claims', $value) ? array_map(function ($item) { return self::fromCborBrowserConsentClaim($item); }, $value['claims'] === null ? array() : $value['claims']) : null,
            'request_reason' => array_key_exists('request_reason', $value) ? $value['request_reason'] : null,
        ));
    }

    public static function encodeBrowserAuthorizationCompleteRequest($value)
    {
        return CBOR::encode(self::toCborBrowserAuthorizationCompleteRequest($value));
    }

    public static function decodeBrowserAuthorizationCompleteRequest($bytes)
    {
        return self::fromCborBrowserAuthorizationCompleteRequest(CBOR::decode($bytes));
    }

    public static function toCborBrowserAuthorizationCompleteRequest($value)
    {
        $out = array();
        $field = $value instanceof BrowserAuthorizationCompleteRequest ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = $field;
        $field = $value instanceof BrowserAuthorizationCompleteRequest ? $value->authorizedClaims : (is_array($value) && array_key_exists('authorized_claims', $value) ? $value['authorized_claims'] : null);
        $out['authorized_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof BrowserAuthorizationCompleteRequest ? $value->claimTypesToSet : (is_array($value) && array_key_exists('claim_types_to_set', $value) ? $value['claim_types_to_set'] : null);
        $out['claim_types_to_set'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof BrowserAuthorizationCompleteRequest ? $value->claimValuesToSet : (is_array($value) && array_key_exists('claim_values_to_set', $value) ? $value['claim_values_to_set'] : null);
        $out['claim_values_to_set'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborBrowserAuthorizationCompleteRequest($value)
    {
        return new BrowserAuthorizationCompleteRequest(array(
            'signed_request' => array_key_exists('signed_request', $value) ? $value['signed_request'] : null,
            'authorized_claims' => array_key_exists('authorized_claims', $value) ? array_map(function ($item) { return $item; }, $value['authorized_claims'] === null ? array() : $value['authorized_claims']) : null,
            'claim_types_to_set' => array_key_exists('claim_types_to_set', $value) ? array_map(function ($item) { return $item; }, $value['claim_types_to_set'] === null ? array() : $value['claim_types_to_set']) : null,
            'claim_values_to_set' => array_key_exists('claim_values_to_set', $value) ? array_map(function ($item) { return $item; }, $value['claim_values_to_set'] === null ? array() : $value['claim_values_to_set']) : null,
        ));
    }

    public static function encodeBrowserAuthorizationCompleteResponse($value)
    {
        return CBOR::encode(self::toCborBrowserAuthorizationCompleteResponse($value));
    }

    public static function decodeBrowserAuthorizationCompleteResponse($bytes)
    {
        return self::fromCborBrowserAuthorizationCompleteResponse(CBOR::decode($bytes));
    }

    public static function toCborBrowserAuthorizationCompleteResponse($value)
    {
        $out = array();
        $field = $value instanceof BrowserAuthorizationCompleteResponse ? $value->redirectUrl : (is_array($value) && array_key_exists('redirect_url', $value) ? $value['redirect_url'] : null);
        $out['redirect_url'] = $field;
        return $out;
    }

    public static function fromCborBrowserAuthorizationCompleteResponse($value)
    {
        return new BrowserAuthorizationCompleteResponse(array(
            'redirect_url' => array_key_exists('redirect_url', $value) ? $value['redirect_url'] : null,
        ));
    }

    public static function encodeUiTheme($value)
    {
        return CBOR::encode(self::toCborUiTheme($value));
    }

    public static function decodeUiTheme($bytes)
    {
        return self::fromCborUiTheme(CBOR::decode($bytes));
    }

    public static function toCborUiTheme($value)
    {
        $out = array();
        $field = $value instanceof UiTheme ? $value->stylesheetUrl : (is_array($value) && array_key_exists('stylesheet_url', $value) ? $value['stylesheet_url'] : null);
        if ($field !== null) {
            $out['stylesheet_url'] = $field;
        }
        $field = $value instanceof UiTheme ? $value->logoUrl : (is_array($value) && array_key_exists('logo_url', $value) ? $value['logo_url'] : null);
        if ($field !== null) {
            $out['logo_url'] = $field;
        }
        $field = $value instanceof UiTheme ? $value->faviconUrl : (is_array($value) && array_key_exists('favicon_url', $value) ? $value['favicon_url'] : null);
        if ($field !== null) {
            $out['favicon_url'] = $field;
        }
        return $out;
    }

    public static function fromCborUiTheme($value)
    {
        return new UiTheme(array(
            'stylesheet_url' => array_key_exists('stylesheet_url', $value) ? $value['stylesheet_url'] : null,
            'logo_url' => array_key_exists('logo_url', $value) ? $value['logo_url'] : null,
            'favicon_url' => array_key_exists('favicon_url', $value) ? $value['favicon_url'] : null,
        ));
    }

    public static function encodeUiExtension($value)
    {
        return CBOR::encode(self::toCborUiExtension($value));
    }

    public static function decodeUiExtension($bytes)
    {
        return self::fromCborUiExtension(CBOR::decode($bytes));
    }

    public static function toCborUiExtension($value)
    {
        $out = array();
        $field = $value instanceof UiExtension ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof UiExtension ? $value->moduleUrl : (is_array($value) && array_key_exists('module_url', $value) ? $value['module_url'] : null);
        $out['module_url'] = $field;
        $field = $value instanceof UiExtension ? $value->apiVersion : (is_array($value) && array_key_exists('api_version', $value) ? $value['api_version'] : null);
        $out['api_version'] = $field;
        $field = $value instanceof UiExtension ? $value->stylesheetUrl : (is_array($value) && array_key_exists('stylesheet_url', $value) ? $value['stylesheet_url'] : null);
        if ($field !== null) {
            $out['stylesheet_url'] = $field;
        }
        return $out;
    }

    public static function fromCborUiExtension($value)
    {
        return new UiExtension(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'module_url' => array_key_exists('module_url', $value) ? $value['module_url'] : null,
            'api_version' => array_key_exists('api_version', $value) ? $value['api_version'] : null,
            'stylesheet_url' => array_key_exists('stylesheet_url', $value) ? $value['stylesheet_url'] : null,
        ));
    }

    public static function encodeUiDisplaySettings($value)
    {
        return CBOR::encode(self::toCborUiDisplaySettings($value));
    }

    public static function decodeUiDisplaySettings($bytes)
    {
        return self::fromCborUiDisplaySettings(CBOR::decode($bytes));
    }

    public static function toCborUiDisplaySettings($value)
    {
        $out = array();
        $field = $value instanceof UiDisplaySettings ? $value->siteName : (is_array($value) && array_key_exists('site_name', $value) ? $value['site_name'] : null);
        $out['site_name'] = $field;
        $field = $value instanceof UiDisplaySettings ? $value->supportUrl : (is_array($value) && array_key_exists('support_url', $value) ? $value['support_url'] : null);
        if ($field !== null) {
            $out['support_url'] = $field;
        }
        return $out;
    }

    public static function fromCborUiDisplaySettings($value)
    {
        return new UiDisplaySettings(array(
            'site_name' => array_key_exists('site_name', $value) ? $value['site_name'] : null,
            'support_url' => array_key_exists('support_url', $value) ? $value['support_url'] : null,
        ));
    }

    public static function encodeGetUiConfigurationResponse($value)
    {
        return CBOR::encode(self::toCborGetUiConfigurationResponse($value));
    }

    public static function decodeGetUiConfigurationResponse($bytes)
    {
        return self::fromCborGetUiConfigurationResponse(CBOR::decode($bytes));
    }

    public static function toCborGetUiConfigurationResponse($value)
    {
        $out = array();
        $field = $value instanceof GetUiConfigurationResponse ? $value->hostApiVersion : (is_array($value) && array_key_exists('host_api_version', $value) ? $value['host_api_version'] : null);
        $out['host_api_version'] = $field;
        $field = $value instanceof GetUiConfigurationResponse ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof GetUiConfigurationResponse ? $value->publicOrigin : (is_array($value) && array_key_exists('public_origin', $value) ? $value['public_origin'] : null);
        if ($field !== null) {
            $out['public_origin'] = $field;
        }
        $field = $value instanceof GetUiConfigurationResponse ? $value->capabilities : (is_array($value) && array_key_exists('capabilities', $value) ? $value['capabilities'] : null);
        $out['capabilities'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof GetUiConfigurationResponse ? $value->display : (is_array($value) && array_key_exists('display', $value) ? $value['display'] : null);
        $out['display'] = self::toCborUiDisplaySettings($field);
        $field = $value instanceof GetUiConfigurationResponse ? $value->theme : (is_array($value) && array_key_exists('theme', $value) ? $value['theme'] : null);
        if ($field !== null) {
            $out['theme'] = self::toCborUiTheme($field);
        }
        $field = $value instanceof GetUiConfigurationResponse ? $value->extensions : (is_array($value) && array_key_exists('extensions', $value) ? $value['extensions'] : null);
        $out['extensions'] = array_map(function ($item) { return self::toCborUiExtension($item); }, $field === null ? array() : $field);
        $field = $value instanceof GetUiConfigurationResponse ? $value->passwordPolicy : (is_array($value) && array_key_exists('password_policy', $value) ? $value['password_policy'] : null);
        if ($field !== null) {
            $out['password_policy'] = self::toCborPasswordPolicy($field);
        }
        return $out;
    }

    public static function fromCborGetUiConfigurationResponse($value)
    {
        return new GetUiConfigurationResponse(array(
            'host_api_version' => array_key_exists('host_api_version', $value) ? $value['host_api_version'] : null,
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'public_origin' => array_key_exists('public_origin', $value) ? $value['public_origin'] : null,
            'capabilities' => array_key_exists('capabilities', $value) ? array_map(function ($item) { return $item; }, $value['capabilities'] === null ? array() : $value['capabilities']) : null,
            'display' => array_key_exists('display', $value) ? self::fromCborUiDisplaySettings($value['display']) : null,
            'theme' => array_key_exists('theme', $value) ? self::fromCborUiTheme($value['theme']) : null,
            'extensions' => array_key_exists('extensions', $value) ? array_map(function ($item) { return self::fromCborUiExtension($item); }, $value['extensions'] === null ? array() : $value['extensions']) : null,
            'password_policy' => array_key_exists('password_policy', $value) ? self::fromCborPasswordPolicy($value['password_policy']) : null,
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
        $field = $value instanceof RpSignRequest ? $value->authenticationRequirements : (is_array($value) && array_key_exists('authentication_requirements', $value) ? $value['authentication_requirements'] : null);
        if ($field !== null) {
            $out['authentication_requirements'] = self::toCborAuthenticationRequirements($field);
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
            'authentication_requirements' => array_key_exists('authentication_requirements', $value) ? self::fromCborAuthenticationRequirements($value['authentication_requirements']) : null,
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

    public static function encodeAuthorizeValidateRequest($value)
    {
        return CBOR::encode(self::toCborAuthorizeValidateRequest($value));
    }

    public static function decodeAuthorizeValidateRequest($bytes)
    {
        return self::fromCborAuthorizeValidateRequest(CBOR::decode($bytes));
    }

    public static function toCborAuthorizeValidateRequest($value)
    {
        $out = array();
        $field = $value instanceof AuthorizeValidateRequest ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = $field;
        $field = $value instanceof AuthorizeValidateRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        if ($field !== null) {
            $out['user_id'] = $field;
        }
        return $out;
    }

    public static function fromCborAuthorizeValidateRequest($value)
    {
        return new AuthorizeValidateRequest(array(
            'signed_request' => array_key_exists('signed_request', $value) ? $value['signed_request'] : null,
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeAuthorizeValidateResponse($value)
    {
        return CBOR::encode(self::toCborAuthorizeValidateResponse($value));
    }

    public static function decodeAuthorizeValidateResponse($bytes)
    {
        return self::fromCborAuthorizeValidateResponse(CBOR::decode($bytes));
    }

    public static function toCborAuthorizeValidateResponse($value)
    {
        $out = array();
        $field = $value instanceof AuthorizeValidateResponse ? $value->relyingParty : (is_array($value) && array_key_exists('relying_party', $value) ? $value['relying_party'] : null);
        $out['relying_party'] = $field;
        $field = $value instanceof AuthorizeValidateResponse ? $value->callbackUrl : (is_array($value) && array_key_exists('callback_url', $value) ? $value['callback_url'] : null);
        $out['callback_url'] = $field;
        $field = $value instanceof AuthorizeValidateResponse ? $value->requestedClaims : (is_array($value) && array_key_exists('requested_claims', $value) ? $value['requested_claims'] : null);
        $out['requested_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof AuthorizeValidateResponse ? $value->alreadyConsented : (is_array($value) && array_key_exists('already_consented', $value) ? $value['already_consented'] : null);
        if ($field !== null) {
            $out['already_consented'] = $field;
        }
        $field = $value instanceof AuthorizeValidateResponse ? $value->authorizedClaims : (is_array($value) && array_key_exists('authorized_claims', $value) ? $value['authorized_claims'] : null);
        if ($field !== null) {
            $out['authorized_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        }
        return $out;
    }

    public static function fromCborAuthorizeValidateResponse($value)
    {
        return new AuthorizeValidateResponse(array(
            'relying_party' => array_key_exists('relying_party', $value) ? $value['relying_party'] : null,
            'callback_url' => array_key_exists('callback_url', $value) ? $value['callback_url'] : null,
            'requested_claims' => array_key_exists('requested_claims', $value) ? array_map(function ($item) { return $item; }, $value['requested_claims'] === null ? array() : $value['requested_claims']) : null,
            'already_consented' => array_key_exists('already_consented', $value) ? $value['already_consented'] : null,
            'authorized_claims' => array_key_exists('authorized_claims', $value) ? array_map(function ($item) { return $item; }, $value['authorized_claims'] === null ? array() : $value['authorized_claims']) : null,
        ));
    }

    public static function encodeAuthorizeFinalizeRequest($value)
    {
        return CBOR::encode(self::toCborAuthorizeFinalizeRequest($value));
    }

    public static function decodeAuthorizeFinalizeRequest($bytes)
    {
        return self::fromCborAuthorizeFinalizeRequest(CBOR::decode($bytes));
    }

    public static function toCborAuthorizeFinalizeRequest($value)
    {
        $out = array();
        $field = $value instanceof AuthorizeFinalizeRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof AuthorizeFinalizeRequest ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = $field;
        $field = $value instanceof AuthorizeFinalizeRequest ? $value->authorizedClaims : (is_array($value) && array_key_exists('authorized_claims', $value) ? $value['authorized_claims'] : null);
        $out['authorized_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborAuthorizeFinalizeRequest($value)
    {
        return new AuthorizeFinalizeRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'signed_request' => array_key_exists('signed_request', $value) ? $value['signed_request'] : null,
            'authorized_claims' => array_key_exists('authorized_claims', $value) ? array_map(function ($item) { return $item; }, $value['authorized_claims'] === null ? array() : $value['authorized_claims']) : null,
        ));
    }

    public static function encodeAuthorizeFinalizeResponse($value)
    {
        return CBOR::encode(self::toCborAuthorizeFinalizeResponse($value));
    }

    public static function decodeAuthorizeFinalizeResponse($bytes)
    {
        return self::fromCborAuthorizeFinalizeResponse(CBOR::decode($bytes));
    }

    public static function toCborAuthorizeFinalizeResponse($value)
    {
        $out = array();
        $field = $value instanceof AuthorizeFinalizeResponse ? $value->redirectUrl : (is_array($value) && array_key_exists('redirect_url', $value) ? $value['redirect_url'] : null);
        $out['redirect_url'] = $field;
        return $out;
    }

    public static function fromCborAuthorizeFinalizeResponse($value)
    {
        return new AuthorizeFinalizeResponse(array(
            'redirect_url' => array_key_exists('redirect_url', $value) ? $value['redirect_url'] : null,
        ));
    }

    public static function encodeApiErrorCode($value)
    {
        return CBOR::encode(self::toCborApiErrorCode($value));
    }

    public static function decodeApiErrorCode($bytes)
    {
        return self::fromCborApiErrorCode(CBOR::decode($bytes));
    }

    public static function toCborApiErrorCode($value)
    {
        return $value;
    }

    public static function fromCborApiErrorCode($value)
    {
        static $csilMembers = array('request_already_used', 'rp_key_fetch_failed', 'rp_encrypt_key_untrusted', 'signing_failed', 'storage_failed', 'bad_request', 'unauthorized', 'forbidden', 'not_found', 'internal');
        foreach ($csilMembers as $csilMember) {
            if ($value === $csilMember) {
                return $value;
            }
        }
        throw new CodecException('csil cbor: unknown ApiErrorCode value ' . var_export($value, true));
    }

    public static function encodeApiError($value)
    {
        return CBOR::encode(self::toCborApiError($value));
    }

    public static function decodeApiError($bytes)
    {
        return self::fromCborApiError(CBOR::decode($bytes));
    }

    public static function toCborApiError($value)
    {
        $out = array();
        $field = $value instanceof ApiError ? $value->code : (is_array($value) && array_key_exists('code', $value) ? $value['code'] : null);
        $out['code'] = $field;
        $field = $value instanceof ApiError ? $value->message : (is_array($value) && array_key_exists('message', $value) ? $value['message'] : null);
        $out['message'] = $field;
        return $out;
    }

    public static function fromCborApiError($value)
    {
        return new ApiError(array(
            'code' => array_key_exists('code', $value) ? self::fromCborApiErrorCode($value['code']) : null,
            'message' => array_key_exists('message', $value) ? $value['message'] : null,
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
        $field = $value instanceof LocalRpLoginRequest ? $value->authenticationRequirements : (is_array($value) && array_key_exists('authentication_requirements', $value) ? $value['authentication_requirements'] : null);
        if ($field !== null) {
            $out['authentication_requirements'] = self::toCborAuthenticationRequirements($field);
        }
        $field = $value instanceof LocalRpLoginRequest ? $value->flowContext : (is_array($value) && array_key_exists('flow_context', $value) ? $value['flow_context'] : null);
        if ($field !== null) {
            $out['flow_context'] = self::toCborAuthFlowContext($field);
        }
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
            'authentication_requirements' => array_key_exists('authentication_requirements', $value) ? self::fromCborAuthenticationRequirements($value['authentication_requirements']) : null,
            'flow_context' => array_key_exists('flow_context', $value) ? self::fromCborAuthFlowContext($value['flow_context']) : null,
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

    public static function encodePurgeLocalRpTicketsRequest($value)
    {
        return CBOR::encode(self::toCborPurgeLocalRpTicketsRequest($value));
    }

    public static function decodePurgeLocalRpTicketsRequest($bytes)
    {
        return self::fromCborPurgeLocalRpTicketsRequest(CBOR::decode($bytes));
    }

    public static function toCborPurgeLocalRpTicketsRequest($value)
    {
        $out = array();
        return $out;
    }

    public static function fromCborPurgeLocalRpTicketsRequest($value)
    {
        return new PurgeLocalRpTicketsRequest(array(
        ));
    }

    public static function encodePurgeLocalRpTicketsResponse($value)
    {
        return CBOR::encode(self::toCborPurgeLocalRpTicketsResponse($value));
    }

    public static function decodePurgeLocalRpTicketsResponse($bytes)
    {
        return self::fromCborPurgeLocalRpTicketsResponse(CBOR::decode($bytes));
    }

    public static function toCborPurgeLocalRpTicketsResponse($value)
    {
        $out = array();
        $field = $value instanceof PurgeLocalRpTicketsResponse ? $value->purgedCount : (is_array($value) && array_key_exists('purged_count', $value) ? $value['purged_count'] : null);
        $out['purged_count'] = $field;
        return $out;
    }

    public static function fromCborPurgeLocalRpTicketsResponse($value)
    {
        return new PurgeLocalRpTicketsResponse(array(
            'purged_count' => array_key_exists('purged_count', $value) ? $value['purged_count'] : null,
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

    public static function encodeApplicationKeySignature($value)
    {
        return CBOR::encode(self::toCborApplicationKeySignature($value));
    }

    public static function decodeApplicationKeySignature($bytes)
    {
        return self::fromCborApplicationKeySignature(CBOR::decode($bytes));
    }

    public static function toCborApplicationKeySignature($value)
    {
        $out = array();
        $field = $value instanceof ApplicationKeySignature ? $value->signedByKeyId : (is_array($value) && array_key_exists('signed_by_key_id', $value) ? $value['signed_by_key_id'] : null);
        $out['signed_by_key_id'] = $field;
        $field = $value instanceof ApplicationKeySignature ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        return $out;
    }

    public static function fromCborApplicationKeySignature($value)
    {
        return new ApplicationKeySignature(array(
            'signed_by_key_id' => array_key_exists('signed_by_key_id', $value) ? $value['signed_by_key_id'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
        ));
    }

    public static function encodeApplicationKeyAttestation($value)
    {
        return CBOR::encode(self::toCborApplicationKeyAttestation($value));
    }

    public static function decodeApplicationKeyAttestation($bytes)
    {
        return self::fromCborApplicationKeyAttestation(CBOR::decode($bytes));
    }

    public static function toCborApplicationKeyAttestation($value)
    {
        $out = array();
        $field = $value instanceof ApplicationKeyAttestation ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->keyId : (is_array($value) && array_key_exists('key_id', $value) ? $value['key_id'] : null);
        $out['key_id'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->keyUsage : (is_array($value) && array_key_exists('key_usage', $value) ? $value['key_usage'] : null);
        $out['key_usage'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->algorithm : (is_array($value) && array_key_exists('algorithm', $value) ? $value['algorithm'] : null);
        $out['algorithm'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->publicKey : (is_array($value) && array_key_exists('public_key', $value) ? $value['public_key'] : null);
        $out['public_key'] = CBOR::bytes($field);
        $field = $value instanceof ApplicationKeyAttestation ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->keyCreatedAt : (is_array($value) && array_key_exists('key_created_at', $value) ? $value['key_created_at'] : null);
        $out['key_created_at'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->keyExpiresAt : (is_array($value) && array_key_exists('key_expires_at', $value) ? $value['key_expires_at'] : null);
        $out['key_expires_at'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->attestedAt : (is_array($value) && array_key_exists('attested_at', $value) ? $value['attested_at'] : null);
        $out['attested_at'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->attestationExpiresAt : (is_array($value) && array_key_exists('attestation_expires_at', $value) ? $value['attestation_expires_at'] : null);
        $out['attestation_expires_at'] = $field;
        return $out;
    }

    public static function fromCborApplicationKeyAttestation($value)
    {
        return new ApplicationKeyAttestation(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'key_id' => array_key_exists('key_id', $value) ? $value['key_id'] : null,
            'key_usage' => array_key_exists('key_usage', $value) ? $value['key_usage'] : null,
            'algorithm' => array_key_exists('algorithm', $value) ? $value['algorithm'] : null,
            'public_key' => array_key_exists('public_key', $value) ? $value['public_key'] : null,
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'key_created_at' => array_key_exists('key_created_at', $value) ? $value['key_created_at'] : null,
            'key_expires_at' => array_key_exists('key_expires_at', $value) ? $value['key_expires_at'] : null,
            'attested_at' => array_key_exists('attested_at', $value) ? $value['attested_at'] : null,
            'attestation_expires_at' => array_key_exists('attestation_expires_at', $value) ? $value['attestation_expires_at'] : null,
        ));
    }

    public static function encodeSignedApplicationKeyAttestation($value)
    {
        return CBOR::encode(self::toCborSignedApplicationKeyAttestation($value));
    }

    public static function decodeSignedApplicationKeyAttestation($bytes)
    {
        return self::fromCborSignedApplicationKeyAttestation(CBOR::decode($bytes));
    }

    public static function toCborSignedApplicationKeyAttestation($value)
    {
        $out = array();
        $field = $value instanceof SignedApplicationKeyAttestation ? $value->attestation : (is_array($value) && array_key_exists('attestation', $value) ? $value['attestation'] : null);
        $out['attestation'] = CBOR::bytes($field);
        $field = $value instanceof SignedApplicationKeyAttestation ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborClaimSignature($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborSignedApplicationKeyAttestation($value)
    {
        return new SignedApplicationKeyAttestation(array(
            'attestation' => array_key_exists('attestation', $value) ? $value['attestation'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborClaimSignature($item); }, $value['signatures'] === null ? array() : $value['signatures']) : null,
        ));
    }

    public static function encodeApplicationKeyAddition($value)
    {
        return CBOR::encode(self::toCborApplicationKeyAddition($value));
    }

    public static function decodeApplicationKeyAddition($bytes)
    {
        return self::fromCborApplicationKeyAddition(CBOR::decode($bytes));
    }

    public static function toCborApplicationKeyAddition($value)
    {
        $out = array();
        $field = $value instanceof ApplicationKeyAddition ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->keyId : (is_array($value) && array_key_exists('key_id', $value) ? $value['key_id'] : null);
        $out['key_id'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->keyUsage : (is_array($value) && array_key_exists('key_usage', $value) ? $value['key_usage'] : null);
        $out['key_usage'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->algorithm : (is_array($value) && array_key_exists('algorithm', $value) ? $value['algorithm'] : null);
        $out['algorithm'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->publicKey : (is_array($value) && array_key_exists('public_key', $value) ? $value['public_key'] : null);
        $out['public_key'] = CBOR::bytes($field);
        $field = $value instanceof ApplicationKeyAddition ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->requestedKeyLifetimeSeconds : (is_array($value) && array_key_exists('requested_key_lifetime_seconds', $value) ? $value['requested_key_lifetime_seconds'] : null);
        $out['requested_key_lifetime_seconds'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->challengeId : (is_array($value) && array_key_exists('challenge_id', $value) ? $value['challenge_id'] : null);
        $out['challenge_id'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->challenge : (is_array($value) && array_key_exists('challenge', $value) ? $value['challenge'] : null);
        $out['challenge'] = CBOR::bytes($field);
        $field = $value instanceof ApplicationKeyAddition ? $value->requestedAt : (is_array($value) && array_key_exists('requested_at', $value) ? $value['requested_at'] : null);
        $out['requested_at'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = $field;
        return $out;
    }

    public static function fromCborApplicationKeyAddition($value)
    {
        return new ApplicationKeyAddition(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'key_id' => array_key_exists('key_id', $value) ? $value['key_id'] : null,
            'key_usage' => array_key_exists('key_usage', $value) ? $value['key_usage'] : null,
            'algorithm' => array_key_exists('algorithm', $value) ? $value['algorithm'] : null,
            'public_key' => array_key_exists('public_key', $value) ? $value['public_key'] : null,
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'requested_key_lifetime_seconds' => array_key_exists('requested_key_lifetime_seconds', $value) ? $value['requested_key_lifetime_seconds'] : null,
            'challenge_id' => array_key_exists('challenge_id', $value) ? $value['challenge_id'] : null,
            'challenge' => array_key_exists('challenge', $value) ? $value['challenge'] : null,
            'requested_at' => array_key_exists('requested_at', $value) ? $value['requested_at'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
        ));
    }

    public static function encodeSignedApplicationKeyAddition($value)
    {
        return CBOR::encode(self::toCborSignedApplicationKeyAddition($value));
    }

    public static function decodeSignedApplicationKeyAddition($bytes)
    {
        return self::fromCborSignedApplicationKeyAddition(CBOR::decode($bytes));
    }

    public static function toCborSignedApplicationKeyAddition($value)
    {
        $out = array();
        $field = $value instanceof SignedApplicationKeyAddition ? $value->addition : (is_array($value) && array_key_exists('addition', $value) ? $value['addition'] : null);
        $out['addition'] = CBOR::bytes($field);
        $field = $value instanceof SignedApplicationKeyAddition ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborApplicationKeySignature($item); }, $field === null ? array() : $field);
        $field = $value instanceof SignedApplicationKeyAddition ? $value->possessionProof : (is_array($value) && array_key_exists('possession_proof', $value) ? $value['possession_proof'] : null);
        if ($field !== null) {
            $out['possession_proof'] = CBOR::bytes($field);
        }
        return $out;
    }

    public static function fromCborSignedApplicationKeyAddition($value)
    {
        return new SignedApplicationKeyAddition(array(
            'addition' => array_key_exists('addition', $value) ? $value['addition'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborApplicationKeySignature($item); }, $value['signatures'] === null ? array() : $value['signatures']) : null,
            'possession_proof' => array_key_exists('possession_proof', $value) ? $value['possession_proof'] : null,
        ));
    }

    public static function encodeApplicationKeyRenewal($value)
    {
        return CBOR::encode(self::toCborApplicationKeyRenewal($value));
    }

    public static function decodeApplicationKeyRenewal($bytes)
    {
        return self::fromCborApplicationKeyRenewal(CBOR::decode($bytes));
    }

    public static function toCborApplicationKeyRenewal($value)
    {
        $out = array();
        $field = $value instanceof ApplicationKeyRenewal ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof ApplicationKeyRenewal ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof ApplicationKeyRenewal ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof ApplicationKeyRenewal ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof ApplicationKeyRenewal ? $value->keyId : (is_array($value) && array_key_exists('key_id', $value) ? $value['key_id'] : null);
        $out['key_id'] = $field;
        $field = $value instanceof ApplicationKeyRenewal ? $value->challengeId : (is_array($value) && array_key_exists('challenge_id', $value) ? $value['challenge_id'] : null);
        $out['challenge_id'] = $field;
        $field = $value instanceof ApplicationKeyRenewal ? $value->challenge : (is_array($value) && array_key_exists('challenge', $value) ? $value['challenge'] : null);
        $out['challenge'] = CBOR::bytes($field);
        $field = $value instanceof ApplicationKeyRenewal ? $value->requestedAt : (is_array($value) && array_key_exists('requested_at', $value) ? $value['requested_at'] : null);
        $out['requested_at'] = $field;
        $field = $value instanceof ApplicationKeyRenewal ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = $field;
        return $out;
    }

    public static function fromCborApplicationKeyRenewal($value)
    {
        return new ApplicationKeyRenewal(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'key_id' => array_key_exists('key_id', $value) ? $value['key_id'] : null,
            'challenge_id' => array_key_exists('challenge_id', $value) ? $value['challenge_id'] : null,
            'challenge' => array_key_exists('challenge', $value) ? $value['challenge'] : null,
            'requested_at' => array_key_exists('requested_at', $value) ? $value['requested_at'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
        ));
    }

    public static function encodeSignedApplicationKeyRenewal($value)
    {
        return CBOR::encode(self::toCborSignedApplicationKeyRenewal($value));
    }

    public static function decodeSignedApplicationKeyRenewal($bytes)
    {
        return self::fromCborSignedApplicationKeyRenewal(CBOR::decode($bytes));
    }

    public static function toCborSignedApplicationKeyRenewal($value)
    {
        $out = array();
        $field = $value instanceof SignedApplicationKeyRenewal ? $value->renewal : (is_array($value) && array_key_exists('renewal', $value) ? $value['renewal'] : null);
        $out['renewal'] = CBOR::bytes($field);
        $field = $value instanceof SignedApplicationKeyRenewal ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborApplicationKeySignature($item); }, $field === null ? array() : $field);
        $field = $value instanceof SignedApplicationKeyRenewal ? $value->possessionProof : (is_array($value) && array_key_exists('possession_proof', $value) ? $value['possession_proof'] : null);
        if ($field !== null) {
            $out['possession_proof'] = CBOR::bytes($field);
        }
        return $out;
    }

    public static function fromCborSignedApplicationKeyRenewal($value)
    {
        return new SignedApplicationKeyRenewal(array(
            'renewal' => array_key_exists('renewal', $value) ? $value['renewal'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborApplicationKeySignature($item); }, $value['signatures'] === null ? array() : $value['signatures']) : null,
            'possession_proof' => array_key_exists('possession_proof', $value) ? $value['possession_proof'] : null,
        ));
    }

    public static function encodeApplicationKeyRevocation($value)
    {
        return CBOR::encode(self::toCborApplicationKeyRevocation($value));
    }

    public static function decodeApplicationKeyRevocation($bytes)
    {
        return self::fromCborApplicationKeyRevocation(CBOR::decode($bytes));
    }

    public static function toCborApplicationKeyRevocation($value)
    {
        $out = array();
        $field = $value instanceof ApplicationKeyRevocation ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof ApplicationKeyRevocation ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof ApplicationKeyRevocation ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof ApplicationKeyRevocation ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof ApplicationKeyRevocation ? $value->targetKeyId : (is_array($value) && array_key_exists('target_key_id', $value) ? $value['target_key_id'] : null);
        $out['target_key_id'] = $field;
        $field = $value instanceof ApplicationKeyRevocation ? $value->targetFingerprint : (is_array($value) && array_key_exists('target_fingerprint', $value) ? $value['target_fingerprint'] : null);
        $out['target_fingerprint'] = $field;
        $field = $value instanceof ApplicationKeyRevocation ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        $out['revoked_at'] = $field;
        $field = $value instanceof ApplicationKeyRevocation ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborApplicationKeySignature($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborApplicationKeyRevocation($value)
    {
        return new ApplicationKeyRevocation(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'target_key_id' => array_key_exists('target_key_id', $value) ? $value['target_key_id'] : null,
            'target_fingerprint' => array_key_exists('target_fingerprint', $value) ? $value['target_fingerprint'] : null,
            'revoked_at' => array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborApplicationKeySignature($item); }, $value['signatures'] === null ? array() : $value['signatures']) : null,
        ));
    }

    public static function encodeStartApplicationKeyChallengeRequest($value)
    {
        return CBOR::encode(self::toCborStartApplicationKeyChallengeRequest($value));
    }

    public static function decodeStartApplicationKeyChallengeRequest($bytes)
    {
        return self::fromCborStartApplicationKeyChallengeRequest(CBOR::decode($bytes));
    }

    public static function toCborStartApplicationKeyChallengeRequest($value)
    {
        $out = array();
        $field = $value instanceof StartApplicationKeyChallengeRequest ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof StartApplicationKeyChallengeRequest ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof StartApplicationKeyChallengeRequest ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof StartApplicationKeyChallengeRequest ? $value->purpose : (is_array($value) && array_key_exists('purpose', $value) ? $value['purpose'] : null);
        $out['purpose'] = $field;
        $field = $value instanceof StartApplicationKeyChallengeRequest ? $value->keyUsage : (is_array($value) && array_key_exists('key_usage', $value) ? $value['key_usage'] : null);
        $out['key_usage'] = $field;
        $field = $value instanceof StartApplicationKeyChallengeRequest ? $value->algorithm : (is_array($value) && array_key_exists('algorithm', $value) ? $value['algorithm'] : null);
        $out['algorithm'] = $field;
        $field = $value instanceof StartApplicationKeyChallengeRequest ? $value->publicKey : (is_array($value) && array_key_exists('public_key', $value) ? $value['public_key'] : null);
        $out['public_key'] = CBOR::bytes($field);
        return $out;
    }

    public static function fromCborStartApplicationKeyChallengeRequest($value)
    {
        return new StartApplicationKeyChallengeRequest(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'purpose' => array_key_exists('purpose', $value) ? $value['purpose'] : null,
            'key_usage' => array_key_exists('key_usage', $value) ? $value['key_usage'] : null,
            'algorithm' => array_key_exists('algorithm', $value) ? $value['algorithm'] : null,
            'public_key' => array_key_exists('public_key', $value) ? $value['public_key'] : null,
        ));
    }

    public static function encodeStartApplicationKeyChallengeResponse($value)
    {
        return CBOR::encode(self::toCborStartApplicationKeyChallengeResponse($value));
    }

    public static function decodeStartApplicationKeyChallengeResponse($bytes)
    {
        return self::fromCborStartApplicationKeyChallengeResponse(CBOR::decode($bytes));
    }

    public static function toCborStartApplicationKeyChallengeResponse($value)
    {
        $out = array();
        $field = $value instanceof StartApplicationKeyChallengeResponse ? $value->challengeId : (is_array($value) && array_key_exists('challenge_id', $value) ? $value['challenge_id'] : null);
        $out['challenge_id'] = $field;
        $field = $value instanceof StartApplicationKeyChallengeResponse ? $value->challenge : (is_array($value) && array_key_exists('challenge', $value) ? $value['challenge'] : null);
        if ($field !== null) {
            $out['challenge'] = CBOR::bytes($field);
        }
        $field = $value instanceof StartApplicationKeyChallengeResponse ? $value->sealedChallenge : (is_array($value) && array_key_exists('sealed_challenge', $value) ? $value['sealed_challenge'] : null);
        if ($field !== null) {
            $out['sealed_challenge'] = CBOR::bytes($field);
        }
        $field = $value instanceof StartApplicationKeyChallengeResponse ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = $field;
        return $out;
    }

    public static function fromCborStartApplicationKeyChallengeResponse($value)
    {
        return new StartApplicationKeyChallengeResponse(array(
            'challenge_id' => array_key_exists('challenge_id', $value) ? $value['challenge_id'] : null,
            'challenge' => array_key_exists('challenge', $value) ? $value['challenge'] : null,
            'sealed_challenge' => array_key_exists('sealed_challenge', $value) ? $value['sealed_challenge'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? $value['expires_at'] : null,
        ));
    }

    public static function encodeAddApplicationKeyRequest($value)
    {
        return CBOR::encode(self::toCborAddApplicationKeyRequest($value));
    }

    public static function decodeAddApplicationKeyRequest($bytes)
    {
        return self::fromCborAddApplicationKeyRequest(CBOR::decode($bytes));
    }

    public static function toCborAddApplicationKeyRequest($value)
    {
        $out = array();
        $field = $value instanceof AddApplicationKeyRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = self::toCborSignedApplicationKeyAddition($field);
        return $out;
    }

    public static function fromCborAddApplicationKeyRequest($value)
    {
        return new AddApplicationKeyRequest(array(
            'request' => array_key_exists('request', $value) ? self::fromCborSignedApplicationKeyAddition($value['request']) : null,
        ));
    }

    public static function encodeAddApplicationKeyResponse($value)
    {
        return CBOR::encode(self::toCborAddApplicationKeyResponse($value));
    }

    public static function decodeAddApplicationKeyResponse($bytes)
    {
        return self::fromCborAddApplicationKeyResponse(CBOR::decode($bytes));
    }

    public static function toCborAddApplicationKeyResponse($value)
    {
        $out = array();
        $field = $value instanceof AddApplicationKeyResponse ? $value->attestation : (is_array($value) && array_key_exists('attestation', $value) ? $value['attestation'] : null);
        $out['attestation'] = self::toCborSignedApplicationKeyAttestation($field);
        return $out;
    }

    public static function fromCborAddApplicationKeyResponse($value)
    {
        return new AddApplicationKeyResponse(array(
            'attestation' => array_key_exists('attestation', $value) ? self::fromCborSignedApplicationKeyAttestation($value['attestation']) : null,
        ));
    }

    public static function encodeRenewApplicationKeyAttestationRequest($value)
    {
        return CBOR::encode(self::toCborRenewApplicationKeyAttestationRequest($value));
    }

    public static function decodeRenewApplicationKeyAttestationRequest($bytes)
    {
        return self::fromCborRenewApplicationKeyAttestationRequest(CBOR::decode($bytes));
    }

    public static function toCborRenewApplicationKeyAttestationRequest($value)
    {
        $out = array();
        $field = $value instanceof RenewApplicationKeyAttestationRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = self::toCborSignedApplicationKeyRenewal($field);
        return $out;
    }

    public static function fromCborRenewApplicationKeyAttestationRequest($value)
    {
        return new RenewApplicationKeyAttestationRequest(array(
            'request' => array_key_exists('request', $value) ? self::fromCborSignedApplicationKeyRenewal($value['request']) : null,
        ));
    }

    public static function encodeRenewApplicationKeyAttestationResponse($value)
    {
        return CBOR::encode(self::toCborRenewApplicationKeyAttestationResponse($value));
    }

    public static function decodeRenewApplicationKeyAttestationResponse($bytes)
    {
        return self::fromCborRenewApplicationKeyAttestationResponse(CBOR::decode($bytes));
    }

    public static function toCborRenewApplicationKeyAttestationResponse($value)
    {
        $out = array();
        $field = $value instanceof RenewApplicationKeyAttestationResponse ? $value->attestation : (is_array($value) && array_key_exists('attestation', $value) ? $value['attestation'] : null);
        $out['attestation'] = self::toCborSignedApplicationKeyAttestation($field);
        $field = $value instanceof RenewApplicationKeyAttestationResponse ? $value->signed : (is_array($value) && array_key_exists('signed', $value) ? $value['signed'] : null);
        $out['signed'] = $field;
        return $out;
    }

    public static function fromCborRenewApplicationKeyAttestationResponse($value)
    {
        return new RenewApplicationKeyAttestationResponse(array(
            'attestation' => array_key_exists('attestation', $value) ? self::fromCborSignedApplicationKeyAttestation($value['attestation']) : null,
            'signed' => array_key_exists('signed', $value) ? $value['signed'] : null,
        ));
    }

    public static function encodeRevokeApplicationKeyRequest($value)
    {
        return CBOR::encode(self::toCborRevokeApplicationKeyRequest($value));
    }

    public static function decodeRevokeApplicationKeyRequest($bytes)
    {
        return self::fromCborRevokeApplicationKeyRequest(CBOR::decode($bytes));
    }

    public static function toCborRevokeApplicationKeyRequest($value)
    {
        $out = array();
        $field = $value instanceof RevokeApplicationKeyRequest ? $value->revocation : (is_array($value) && array_key_exists('revocation', $value) ? $value['revocation'] : null);
        $out['revocation'] = self::toCborApplicationKeyRevocation($field);
        return $out;
    }

    public static function fromCborRevokeApplicationKeyRequest($value)
    {
        return new RevokeApplicationKeyRequest(array(
            'revocation' => array_key_exists('revocation', $value) ? self::fromCborApplicationKeyRevocation($value['revocation']) : null,
        ));
    }

    public static function encodeRevokeApplicationKeyResponse($value)
    {
        return CBOR::encode(self::toCborRevokeApplicationKeyResponse($value));
    }

    public static function decodeRevokeApplicationKeyResponse($bytes)
    {
        return self::fromCborRevokeApplicationKeyResponse(CBOR::decode($bytes));
    }

    public static function toCborRevokeApplicationKeyResponse($value)
    {
        $out = array();
        $field = $value instanceof RevokeApplicationKeyResponse ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        $out['revoked_at'] = $field;
        return $out;
    }

    public static function fromCborRevokeApplicationKeyResponse($value)
    {
        return new RevokeApplicationKeyResponse(array(
            'revoked_at' => array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null,
        ));
    }

    public static function encodeEnrollApplicationInstanceRequest($value)
    {
        return CBOR::encode(self::toCborEnrollApplicationInstanceRequest($value));
    }

    public static function decodeEnrollApplicationInstanceRequest($bytes)
    {
        return self::fromCborEnrollApplicationInstanceRequest(CBOR::decode($bytes));
    }

    public static function toCborEnrollApplicationInstanceRequest($value)
    {
        $out = array();
        $field = $value instanceof EnrollApplicationInstanceRequest ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof EnrollApplicationInstanceRequest ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof EnrollApplicationInstanceRequest ? $value->keys : (is_array($value) && array_key_exists('keys', $value) ? $value['keys'] : null);
        $out['keys'] = array_map(function ($item) { return self::toCborSignedApplicationKeyAddition($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborEnrollApplicationInstanceRequest($value)
    {
        return new EnrollApplicationInstanceRequest(array(
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'keys' => array_key_exists('keys', $value) ? array_map(function ($item) { return self::fromCborSignedApplicationKeyAddition($item); }, $value['keys'] === null ? array() : $value['keys']) : null,
        ));
    }

    public static function encodeEnrollApplicationInstanceResponse($value)
    {
        return CBOR::encode(self::toCborEnrollApplicationInstanceResponse($value));
    }

    public static function decodeEnrollApplicationInstanceResponse($bytes)
    {
        return self::fromCborEnrollApplicationInstanceResponse(CBOR::decode($bytes));
    }

    public static function toCborEnrollApplicationInstanceResponse($value)
    {
        $out = array();
        $field = $value instanceof EnrollApplicationInstanceResponse ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof EnrollApplicationInstanceResponse ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof EnrollApplicationInstanceResponse ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof EnrollApplicationInstanceResponse ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof EnrollApplicationInstanceResponse ? $value->attestations : (is_array($value) && array_key_exists('attestations', $value) ? $value['attestations'] : null);
        $out['attestations'] = array_map(function ($item) { return self::toCborSignedApplicationKeyAttestation($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborEnrollApplicationInstanceResponse($value)
    {
        return new EnrollApplicationInstanceResponse(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'attestations' => array_key_exists('attestations', $value) ? array_map(function ($item) { return self::fromCborSignedApplicationKeyAttestation($item); }, $value['attestations'] === null ? array() : $value['attestations']) : null,
        ));
    }

    public static function encodeGetApplicationKeysRequest($value)
    {
        return CBOR::encode(self::toCborGetApplicationKeysRequest($value));
    }

    public static function decodeGetApplicationKeysRequest($bytes)
    {
        return self::fromCborGetApplicationKeysRequest(CBOR::decode($bytes));
    }

    public static function toCborGetApplicationKeysRequest($value)
    {
        $out = array();
        $field = $value instanceof GetApplicationKeysRequest ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof GetApplicationKeysRequest ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof GetApplicationKeysRequest ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        return $out;
    }

    public static function fromCborGetApplicationKeysRequest($value)
    {
        return new GetApplicationKeysRequest(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
        ));
    }

    public static function encodeGetApplicationKeysResponse($value)
    {
        return CBOR::encode(self::toCborGetApplicationKeysResponse($value));
    }

    public static function decodeGetApplicationKeysResponse($bytes)
    {
        return self::fromCborGetApplicationKeysResponse(CBOR::decode($bytes));
    }

    public static function toCborGetApplicationKeysResponse($value)
    {
        $out = array();
        $field = $value instanceof GetApplicationKeysResponse ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof GetApplicationKeysResponse ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof GetApplicationKeysResponse ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof GetApplicationKeysResponse ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof GetApplicationKeysResponse ? $value->keys : (is_array($value) && array_key_exists('keys', $value) ? $value['keys'] : null);
        $out['keys'] = array_map(function ($item) { return self::toCborSignedApplicationKeyAttestation($item); }, $field === null ? array() : $field);
        $field = $value instanceof GetApplicationKeysResponse ? $value->revocations : (is_array($value) && array_key_exists('revocations', $value) ? $value['revocations'] : null);
        $out['revocations'] = array_map(function ($item) { return self::toCborApplicationKeyRevocation($item); }, $field === null ? array() : $field);
        return $out;
    }

    public static function fromCborGetApplicationKeysResponse($value)
    {
        return new GetApplicationKeysResponse(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'keys' => array_key_exists('keys', $value) ? array_map(function ($item) { return self::fromCborSignedApplicationKeyAttestation($item); }, $value['keys'] === null ? array() : $value['keys']) : null,
            'revocations' => array_key_exists('revocations', $value) ? array_map(function ($item) { return self::fromCborApplicationKeyRevocation($item); }, $value['revocations'] === null ? array() : $value['revocations']) : null,
        ));
    }

    public static function encodeRpResolveDomainKeysRequest($value)
    {
        return CBOR::encode(self::toCborRpResolveDomainKeysRequest($value));
    }

    public static function decodeRpResolveDomainKeysRequest($bytes)
    {
        return self::fromCborRpResolveDomainKeysRequest(CBOR::decode($bytes));
    }

    public static function toCborRpResolveDomainKeysRequest($value)
    {
        $out = array();
        $field = $value instanceof RpResolveDomainKeysRequest ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof RpResolveDomainKeysRequest ? $value->maxCacheAgeSeconds : (is_array($value) && array_key_exists('max_cache_age_seconds', $value) ? $value['max_cache_age_seconds'] : null);
        if ($field !== null) {
            $out['max_cache_age_seconds'] = $field;
        }
        return $out;
    }

    public static function fromCborRpResolveDomainKeysRequest($value)
    {
        return new RpResolveDomainKeysRequest(array(
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'max_cache_age_seconds' => array_key_exists('max_cache_age_seconds', $value) ? $value['max_cache_age_seconds'] : null,
        ));
    }

    public static function encodeRpResolveDomainKeysResponse($value)
    {
        return CBOR::encode(self::toCborRpResolveDomainKeysResponse($value));
    }

    public static function decodeRpResolveDomainKeysResponse($bytes)
    {
        return self::fromCborRpResolveDomainKeysResponse(CBOR::decode($bytes));
    }

    public static function toCborRpResolveDomainKeysResponse($value)
    {
        $out = array();
        $field = $value instanceof RpResolveDomainKeysResponse ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof RpResolveDomainKeysResponse ? $value->keys : (is_array($value) && array_key_exists('keys', $value) ? $value['keys'] : null);
        $out['keys'] = array_map(function ($item) { return self::toCborDomainPublicKey($item); }, $field === null ? array() : $field);
        $field = $value instanceof RpResolveDomainKeysResponse ? $value->revocations : (is_array($value) && array_key_exists('revocations', $value) ? $value['revocations'] : null);
        $out['revocations'] = array_map(function ($item) { return self::toCborRevocationCertificate($item); }, $field === null ? array() : $field);
        $field = $value instanceof RpResolveDomainKeysResponse ? $value->fetchedAt : (is_array($value) && array_key_exists('fetched_at', $value) ? $value['fetched_at'] : null);
        $out['fetched_at'] = $field;
        $field = $value instanceof RpResolveDomainKeysResponse ? $value->revocationsCheckedAt : (is_array($value) && array_key_exists('revocations_checked_at', $value) ? $value['revocations_checked_at'] : null);
        $out['revocations_checked_at'] = $field;
        $field = $value instanceof RpResolveDomainKeysResponse ? $value->cacheStatus : (is_array($value) && array_key_exists('cache_status', $value) ? $value['cache_status'] : null);
        $out['cache_status'] = $field;
        return $out;
    }

    public static function fromCborRpResolveDomainKeysResponse($value)
    {
        return new RpResolveDomainKeysResponse(array(
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'keys' => array_key_exists('keys', $value) ? array_map(function ($item) { return self::fromCborDomainPublicKey($item); }, $value['keys'] === null ? array() : $value['keys']) : null,
            'revocations' => array_key_exists('revocations', $value) ? array_map(function ($item) { return self::fromCborRevocationCertificate($item); }, $value['revocations'] === null ? array() : $value['revocations']) : null,
            'fetched_at' => array_key_exists('fetched_at', $value) ? $value['fetched_at'] : null,
            'revocations_checked_at' => array_key_exists('revocations_checked_at', $value) ? $value['revocations_checked_at'] : null,
            'cache_status' => array_key_exists('cache_status', $value) ? $value['cache_status'] : null,
        ));
    }

    public static function encodeRpResolveApplicationKeysRequest($value)
    {
        return CBOR::encode(self::toCborRpResolveApplicationKeysRequest($value));
    }

    public static function decodeRpResolveApplicationKeysRequest($bytes)
    {
        return self::fromCborRpResolveApplicationKeysRequest(CBOR::decode($bytes));
    }

    public static function toCborRpResolveApplicationKeysRequest($value)
    {
        $out = array();
        $field = $value instanceof RpResolveApplicationKeysRequest ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof RpResolveApplicationKeysRequest ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof RpResolveApplicationKeysRequest ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof RpResolveApplicationKeysRequest ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof RpResolveApplicationKeysRequest ? $value->maxCacheAgeSeconds : (is_array($value) && array_key_exists('max_cache_age_seconds', $value) ? $value['max_cache_age_seconds'] : null);
        if ($field !== null) {
            $out['max_cache_age_seconds'] = $field;
        }
        return $out;
    }

    public static function fromCborRpResolveApplicationKeysRequest($value)
    {
        return new RpResolveApplicationKeysRequest(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'max_cache_age_seconds' => array_key_exists('max_cache_age_seconds', $value) ? $value['max_cache_age_seconds'] : null,
        ));
    }

    public static function encodeRpResolveApplicationKeysResponse($value)
    {
        return CBOR::encode(self::toCborRpResolveApplicationKeysResponse($value));
    }

    public static function decodeRpResolveApplicationKeysResponse($bytes)
    {
        return self::fromCborRpResolveApplicationKeysResponse(CBOR::decode($bytes));
    }

    public static function toCborRpResolveApplicationKeysResponse($value)
    {
        $out = array();
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->applicationKeys : (is_array($value) && array_key_exists('application_keys', $value) ? $value['application_keys'] : null);
        $out['application_keys'] = array_map(function ($item) { return self::toCborSignedApplicationKeyAttestation($item); }, $field === null ? array() : $field);
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->applicationKeyRevocations : (is_array($value) && array_key_exists('application_key_revocations', $value) ? $value['application_key_revocations'] : null);
        $out['application_key_revocations'] = array_map(function ($item) { return self::toCborApplicationKeyRevocation($item); }, $field === null ? array() : $field);
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->homeDomainKeys : (is_array($value) && array_key_exists('home_domain_keys', $value) ? $value['home_domain_keys'] : null);
        $out['home_domain_keys'] = array_map(function ($item) { return self::toCborDomainPublicKey($item); }, $field === null ? array() : $field);
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->homeDomainKeyRevocations : (is_array($value) && array_key_exists('home_domain_key_revocations', $value) ? $value['home_domain_key_revocations'] : null);
        $out['home_domain_key_revocations'] = array_map(function ($item) { return self::toCborRevocationCertificate($item); }, $field === null ? array() : $field);
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->fetchedAt : (is_array($value) && array_key_exists('fetched_at', $value) ? $value['fetched_at'] : null);
        $out['fetched_at'] = $field;
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->revocationsCheckedAt : (is_array($value) && array_key_exists('revocations_checked_at', $value) ? $value['revocations_checked_at'] : null);
        $out['revocations_checked_at'] = $field;
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->cacheStatus : (is_array($value) && array_key_exists('cache_status', $value) ? $value['cache_status'] : null);
        $out['cache_status'] = $field;
        return $out;
    }

    public static function fromCborRpResolveApplicationKeysResponse($value)
    {
        return new RpResolveApplicationKeysResponse(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'application_keys' => array_key_exists('application_keys', $value) ? array_map(function ($item) { return self::fromCborSignedApplicationKeyAttestation($item); }, $value['application_keys'] === null ? array() : $value['application_keys']) : null,
            'application_key_revocations' => array_key_exists('application_key_revocations', $value) ? array_map(function ($item) { return self::fromCborApplicationKeyRevocation($item); }, $value['application_key_revocations'] === null ? array() : $value['application_key_revocations']) : null,
            'home_domain_keys' => array_key_exists('home_domain_keys', $value) ? array_map(function ($item) { return self::fromCborDomainPublicKey($item); }, $value['home_domain_keys'] === null ? array() : $value['home_domain_keys']) : null,
            'home_domain_key_revocations' => array_key_exists('home_domain_key_revocations', $value) ? array_map(function ($item) { return self::fromCborRevocationCertificate($item); }, $value['home_domain_key_revocations'] === null ? array() : $value['home_domain_key_revocations']) : null,
            'fetched_at' => array_key_exists('fetched_at', $value) ? $value['fetched_at'] : null,
            'revocations_checked_at' => array_key_exists('revocations_checked_at', $value) ? $value['revocations_checked_at'] : null,
            'cache_status' => array_key_exists('cache_status', $value) ? $value['cache_status'] : null,
        ));
    }

}
