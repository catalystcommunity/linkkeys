<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

use Csilgen\Generated\LocalRpEncryptedCallback;
use Csilgen\Generated\SignedLocalRpLoginRequest;

/**
 * URL-parameter helpers (Wire Precision, "URL and parameter conventions"):
 * every CBOR-in-URL value is base64url-encoded, unpadded, exactly like
 * `crates/liblinkkeys/src/encoding.rs`'s `Base64UrlUnpadded` helpers.
 */
final class Encoding
{
    /** Base64url, no padding. Rejects standard-alphabet input and padded input on decode. */
    public static function base64UrlEncodeUnpadded(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function base64UrlDecodeUnpadded(string $s): string
    {
        if (str_contains($s, '=')) {
            throw new \InvalidArgumentException('base64url input must not be padded');
        }
        if (str_contains($s, '+') || str_contains($s, '/')) {
            throw new \InvalidArgumentException('base64url input must use the URL-safe alphabet');
        }
        if (!preg_match('/^[A-Za-z0-9_-]*$/', $s)) {
            throw new \InvalidArgumentException('base64url input contains invalid characters');
        }
        $padded = $s . str_repeat('=', (4 - strlen($s) % 4) % 4);
        $decoded = base64_decode(strtr($padded, '-_', '+/'), true);
        if ($decoded === false) {
            throw new \InvalidArgumentException('invalid base64url input');
        }
        return $decoded;
    }

    /** `GET /auth/local-rp?signed_request=<this>`. */
    public static function signedLocalRpLoginRequestToUrlParam(SignedLocalRpLoginRequest $req): string
    {
        return self::base64UrlEncodeUnpadded(Wire::encodeSignedLocalRpLoginRequest($req));
    }

    public static function signedLocalRpLoginRequestFromUrlParam(string $param): SignedLocalRpLoginRequest
    {
        return Wire::decodeSignedLocalRpLoginRequest(self::base64UrlDecodeUnpadded($param));
    }

    /** The callback redirect's `&encrypted_token=` query-parameter value. */
    public static function localRpEncryptedCallbackToUrlParam(LocalRpEncryptedCallback $callback): string
    {
        return self::base64UrlEncodeUnpadded(Wire::encodeLocalRpEncryptedCallback($callback));
    }

    public static function localRpEncryptedCallbackFromUrlParam(string $param): LocalRpEncryptedCallback
    {
        return Wire::decodeLocalRpEncryptedCallback(self::base64UrlDecodeUnpadded($param));
    }
}
