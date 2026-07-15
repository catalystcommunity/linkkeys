<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

/**
 * Client-side TLS pinning: verify a peer's certificate by its SPKI public
 * key fingerprint against a DNS-published `fp=` set — no CA chain, matching
 * the trust model `crates/linkkeys/src/tcp/tls.rs` uses for every LinkKeys
 * TCP peer.
 *
 * `crates/linkkeys/src/tcp/tls.rs` pins
 * `sha256(spki.subject_public_key.data)` — the raw bytes of the
 * SubjectPublicKeyInfo's `subjectPublicKey` BIT STRING — and every LinkKeys
 * domain TLS certificate is generated from an **Ed25519** domain signing
 * key. Per RFC 8410, an Ed25519 SPKI is a fixed, 44-byte DER structure:
 * a constant 12-byte prefix (`302a300506032b6570032100` — SEQUENCE, the
 * Ed25519 AlgorithmIdentifier, and the BIT STRING header/unused-bits byte)
 * followed by exactly the 32 raw public key bytes, with no other
 * ASN.1 framing inside the bit string. `openssl_x509_parse()` does not
 * expose Ed25519 SPKI raw bytes (PHP's OpenSSL binding has no
 * `EVP_PKEY_get_raw_public_key` equivalent), so this class locates that
 * fixed prefix directly in the certificate's DER bytes and takes the
 * following 32 bytes — this SDK only ever needs to handle Ed25519 leaf
 * certificates, since that is the only key type in the LinkKeys TLS trust
 * model.
 *
 * PHP's streams SSL layer cannot express "verify only by SPKI pin, ignore
 * WebPKI/hostname" as a single flag, so this class disables the built-in
 * chain/hostname checks (`verify_peer`/`verify_peer_name` => false) and
 * performs the pin check itself, manually, as a **mandatory** post-handshake
 * step — an exception is thrown (and the caller is expected to close the
 * stream) before a single application byte is trusted if the pin doesn't
 * match.
 */
final class Tls
{
    private const ED25519_SPKI_PREFIX_HEX = '302a300506032b6570032100';

    public static function extractHostname(string $hostPort): string
    {
        $lastColon = strrpos($hostPort, ':');
        return $lastColon === false ? $hostPort : substr($hostPort, 0, $lastColon);
    }

    /**
     * Wrap an already-connected stream (from a {@see Transport}) in a TLS
     * client handshake pinned to `$expectedFingerprints`, presenting no
     * client certificate (public domain-key/revocation fetch and ticket
     * redemption must not require mutual TLS — design doc, "Required
     * Network Access"). Throws {@see TlsError} if the peer's certificate
     * does not pin to any of `$expectedFingerprints`; the caller should
     * close the stream on any exception from this method.
     *
     * @param resource $stream
     * @param string[] $expectedFingerprints
     * @return resource the same stream, now TLS-wrapped
     */
    public static function dialTlsPinned($stream, string $serverHostname, array $expectedFingerprints)
    {
        stream_context_set_option($stream, 'ssl', 'capture_peer_cert', true);
        stream_context_set_option($stream, 'ssl', 'verify_peer', false);
        stream_context_set_option($stream, 'ssl', 'verify_peer_name', false);
        stream_context_set_option($stream, 'ssl', 'allow_self_signed', true);
        stream_context_set_option($stream, 'ssl', 'peer_name', $serverHostname);
        stream_context_set_option($stream, 'ssl', 'SNI_enabled', true);

        $ok = @stream_socket_enable_crypto($stream, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        if ($ok !== true) {
            throw new TlsError('TLS handshake failed: ' . (error_get_last()['message'] ?? 'unknown error'));
        }

        $params = stream_context_get_params($stream);
        $certResource = $params['options']['ssl']['peer_certificate'] ?? null;
        if ($certResource === null) {
            throw new TlsError('peer presented no certificate');
        }

        $fp = self::leafPublicKeyFingerprint($certResource);

        $expectedLower = array_map('strtolower', $expectedFingerprints);
        if (!in_array(strtolower($fp), $expectedLower, true)) {
            throw new PinMismatchError("certificate fingerprint {$fp} does not match any expected fingerprint");
        }

        return $stream;
    }

    /**
     * Extract the SPKI raw public-key bytes from a peer certificate
     * resource/object and return their SHA-256 hex fingerprint — the same
     * value `crates/linkkeys/src/tcp/tls.rs` computes from
     * `spki.subject_public_key.data`.
     *
     * @param \OpenSSLCertificate|resource|string $cert
     */
    public static function leafPublicKeyFingerprint($cert): string
    {
        $parsed = openssl_x509_parse($cert);
        if ($parsed === false) {
            throw new TlsError('peer certificate could not be parsed');
        }
        $now = time();
        if (isset($parsed['validFrom_time_t'], $parsed['validTo_time_t'])) {
            if ($now < $parsed['validFrom_time_t'] || $now > $parsed['validTo_time_t']) {
                throw new CertificateExpiredError('peer certificate is not within its validity period');
            }
        }

        $pem = '';
        if (!openssl_x509_export($cert, $pem)) {
            throw new TlsError('peer certificate could not be exported to DER');
        }
        $der = self::pemToDer($pem);

        $prefix = hex2bin(self::ED25519_SPKI_PREFIX_HEX);
        $idx = strpos($der, $prefix);
        if ($idx === false) {
            throw new UnsupportedCertificateKeyTypeError('expected an Ed25519 certificate public key (RFC 8410 SPKI prefix not found)');
        }
        $rawPublicKey = substr($der, $idx + strlen($prefix), 32);
        if (strlen($rawPublicKey) !== 32) {
            throw new UnsupportedCertificateKeyTypeError('truncated Ed25519 SPKI in certificate DER');
        }

        return Crypto::fingerprint($rawPublicKey);
    }

    private static function pemToDer(string $pem): string
    {
        $lines = preg_split('/\r?\n/', trim($pem));
        $body = implode('', array_filter($lines, fn ($l) => !str_starts_with($l, '-----')));
        $der = base64_decode($body, true);
        if ($der === false) {
            throw new TlsError('certificate PEM body was not valid base64');
        }
        return $der;
    }
}

class TlsError extends \RuntimeException
{
}

final class PinMismatchError extends TlsError
{
}

final class UnsupportedCertificateKeyTypeError extends TlsError
{
}

final class CertificateExpiredError extends TlsError
{
}
