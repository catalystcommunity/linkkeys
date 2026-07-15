<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

/**
 * Crypto primitives for the local-RP SDK, mirroring
 * `crates/liblinkkeys/src/crypto.rs` for exactly the pieces this SDK needs
 * (design doc's PHP language-matrix row: `ext/sodium` for Ed25519/X25519,
 * `ext/openssl` for AES-256-GCM, `hash_hkdf()` for HKDF-SHA256). Every
 * function here is pure — no I/O, no network, no filesystem.
 *
 * ## sodium <-> liblinkkeys key-shape mapping
 *
 * - **Ed25519.** This protocol's canonical stored private key is the
 *   32-byte seed (`ed25519_dalek::SigningKey::to_bytes()`), but libsodium's
 *   "secret key" is 64 bytes (seed || public key). Every signing operation
 *   here therefore expands the 32-byte seed via
 *   `sodium_crypto_sign_seed_keypair()` first, uses the 64-byte secret key
 *   for `sodium_crypto_sign_detached()`, and always returns/stores only the
 *   32-byte seed as "the private key" — the 64-byte form never leaves this
 *   class.
 * - **X25519.** `sodium_crypto_scalarmult_base()` derives the public key
 *   from a raw 32-byte private scalar (libsodium clamps internally, matching
 *   `x25519-dalek`'s `StaticSecret`), and `sodium_crypto_scalarmult()` does
 *   ECDH. libsodium's `crypto_scalarmult` already rejects an all-zero
 *   (low-order) result internally (throws `SodiumException`), but this class
 *   also checks explicitly and raises `EncryptionFailed`/`DecryptionFailed`
 *   with the same message every other SDK uses, so behavior does not
 *   silently depend on a specific libsodium version's internal check.
 * - **AES-256-GCM** is NOT implemented via sodium (sodium's AES-256-GCM is
 *   AES-NI-hardware-gated and not portable — design doc, "Language Crypto
 *   Matrix" preamble); `ext/openssl`'s `openssl_encrypt`/`openssl_decrypt`
 *   with the `aes-256-gcm` cipher is used instead, which is portable
 *   (software fallback) on every OpenSSL build.
 * - **ChaCha20-Poly1305** uses sodium's IETF variant
 *   (`sodium_crypto_aead_chacha20poly1305_ietf_*`): 12-byte nonce, matching
 *   the vectors and the Rust `chacha20poly1305` crate's wire format
 *   (ciphertext with the 16-byte tag appended).
 */
final class Crypto
{
    public const ALGORITHM_ED25519 = 'ed25519';

    public const AEAD_SUITE_AES_256_GCM = 'aes-256-gcm';
    public const AEAD_SUITE_CHACHA20_POLY1305 = 'chacha20-poly1305';

    private const AEAD_TAG_LENGTH = 16;
    private const AEAD_NONCE_LENGTH = 12;

    // -------------------------------------------------------------------
    // Signing algorithm registry (Ed25519 only, forever — no versioning)
    // -------------------------------------------------------------------

    public static function parseSigningAlgorithm(string $s): ?string
    {
        return $s === self::ALGORITHM_ED25519 ? self::ALGORITHM_ED25519 : null;
    }

    /** @return string[] */
    public static function allSupportedSigningAlgorithms(): array
    {
        return [self::ALGORITHM_ED25519];
    }

    // -------------------------------------------------------------------
    // AEAD suite registry
    // -------------------------------------------------------------------

    public static function parseAeadSuite(string $s): ?string
    {
        return in_array($s, [self::AEAD_SUITE_AES_256_GCM, self::AEAD_SUITE_CHACHA20_POLY1305], true)
            ? $s
            : null;
    }

    /** @return string[] */
    public static function allSupportedAeadSuites(): array
    {
        return [self::AEAD_SUITE_AES_256_GCM, self::AEAD_SUITE_CHACHA20_POLY1305];
    }

    /**
     * First suite in `$advertised` (preference order) this implementation
     * supports. Never picks a suite outside `$advertised`, even if it is a
     * valid registry member.
     *
     * @param string[] $advertised
     */
    public static function selectSupportedAeadSuite(array $advertised): ?string
    {
        foreach ($advertised as $s) {
            $parsed = self::parseAeadSuite($s);
            if ($parsed !== null) {
                return $parsed;
            }
        }
        return null;
    }

    // -------------------------------------------------------------------
    // Ed25519
    // -------------------------------------------------------------------

    /** @return array{0: string, 1: string} [publicKey(32), privateSeed(32)] */
    public static function generateEd25519Keypair(): array
    {
        $kp = sodium_crypto_sign_keypair();
        $public = sodium_crypto_sign_publickey($kp);
        $secret = sodium_crypto_sign_secretkey($kp);
        // libsodium's 64-byte secret key is seed(32) || public(32); the
        // canonical stored private key in this protocol is the 32-byte seed.
        $seed = substr($secret, 0, 32);
        return [$public, $seed];
    }

    /** Derive the raw 32-byte Ed25519 public key for a raw 32-byte seed. */
    public static function ed25519PublicKeyFromSeed(string $seed): string
    {
        self::requireLen($seed, 32, 'Ed25519 private key seed');
        $kp = sodium_crypto_sign_seed_keypair($seed);
        return sodium_crypto_sign_publickey($kp);
    }

    /** Sign with an Ed25519 seed (32-byte raw private key). Returns a 64-byte signature. */
    public static function signEd25519(string $message, string $privateKeySeed): string
    {
        self::requireLen($privateKeySeed, 32, 'Ed25519 private key seed');
        $kp = sodium_crypto_sign_seed_keypair($privateKeySeed);
        $secret = sodium_crypto_sign_secretkey($kp);
        return sodium_crypto_sign_detached($message, $secret);
    }

    public static function signWithAlgorithm(string $algorithm, string $message, string $privateKeyBytes): string
    {
        if ($algorithm !== self::ALGORITHM_ED25519) {
            throw new UnsupportedAlgorithmError($algorithm);
        }
        return self::signEd25519($message, $privateKeyBytes);
    }

    /**
     * Verify an Ed25519 signature. Never throws for a malformed key/signature
     * length or a bad signature — returns `false` uniformly (mirrors the
     * TypeScript SDK's `verifyEd25519`), so callers can treat "invalid"
     * uniformly regardless of cause.
     */
    public static function verifyEd25519(string $message, string $signature, string $publicKey): bool
    {
        if (strlen($publicKey) !== 32 || strlen($signature) !== 64) {
            return false;
        }
        try {
            return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
        } catch (\SodiumException $e) {
            return false;
        }
    }

    public static function verifyWithAlgorithm(string $algorithm, string $message, string $signature, string $publicKeyBytes): void
    {
        if ($algorithm !== self::ALGORITHM_ED25519) {
            throw new UnsupportedAlgorithmError($algorithm);
        }
        if (!self::verifyEd25519($message, $signature, $publicKeyBytes)) {
            throw new VerificationFailedError();
        }
    }

    /**
     * Parse a wire-format algorithm string before verifying — the entry
     * point for assertion/claim/revocation verification paths.
     */
    public static function resolveAndVerify(string $algorithm, string $message, string $signature, string $publicKeyBytes): void
    {
        if (self::parseSigningAlgorithm($algorithm) === null) {
            throw new UnsupportedAlgorithmError($algorithm);
        }
        self::verifyWithAlgorithm($algorithm, $message, $signature, $publicKeyBytes);
    }

    // -------------------------------------------------------------------
    // X25519
    // -------------------------------------------------------------------

    /** @return array{0: string, 1: string} [publicKey(32), privateKey(32)] */
    public static function generateX25519Keypair(): array
    {
        $private = random_bytes(32);
        $public = sodium_crypto_scalarmult_base($private);
        return [$public, $private];
    }

    public static function x25519PublicFromPrivate(string $privateKey): string
    {
        self::requireLen($privateKey, 32, 'X25519 private key');
        return sodium_crypto_scalarmult_base($privateKey);
    }

    /**
     * X25519 Diffie-Hellman, rejecting a non-contributory (low-order)
     * result. libsodium's `crypto_scalarmult` already rejects an all-zero
     * output internally; this also checks explicitly so the behavior is not
     * silently dependent on that internal check alone.
     */
    public static function x25519DiffieHellman(string $privateKey, string $publicKey): string
    {
        self::requireLen($privateKey, 32, 'X25519 private key');
        self::requireLen($publicKey, 32, 'X25519 public key');
        try {
            $shared = sodium_crypto_scalarmult($privateKey, $publicKey);
        } catch (\SodiumException $e) {
            throw new EncryptionFailedError('non-contributory (low-order) public key rejected');
        }
        self::rejectLowOrder($shared);
        return $shared;
    }

    /** Reject an all-zero ECDH output — the signal a low-order X25519 public key forces. */
    public static function rejectLowOrder(string $sharedSecret): void
    {
        if ($sharedSecret === str_repeat("\x00", 32)) {
            throw new EncryptionFailedError('non-contributory (low-order) public key rejected');
        }
    }

    // -------------------------------------------------------------------
    // HKDF-SHA256
    // -------------------------------------------------------------------

    /**
     * Full HKDF-SHA256 (extract-then-expand), salt absent. PHP's
     * `hash_hkdf()` treats an empty-string salt as a zero-filled block of
     * hash length per RFC 5869, exactly matching the Rust `hkdf` crate's
     * `Hkdf::new(None, ikm)` and Python's `cryptography` HKDF with
     * `salt=None` — so this reproduces
     * `liblinkkeys::crypto::sealed_box_kdf` / `local_rp_callback_kdf`
     * byte-for-byte.
     */
    public static function hkdfSha256Expand(string $sharedSecret, string $info, int $length = 32): string
    {
        return hash_hkdf('sha256', $sharedSecret, $length, $info, '');
    }

    // -------------------------------------------------------------------
    // Fingerprint
    // -------------------------------------------------------------------

    /** `sha256(public_key_bytes)`, lowercase hex — the LinkKeys fingerprint format used everywhere. */
    public static function fingerprint(string $publicKeyBytes): string
    {
        return hash('sha256', $publicKeyBytes);
    }

    // -------------------------------------------------------------------
    // Signing key validity
    // -------------------------------------------------------------------

    public const KEY_VALID = 'valid';
    public const KEY_REVOKED = 'revoked';
    public const KEY_EXPIRED = 'expired';
    public const KEY_BAD_EXPIRY = 'bad_expiry';

    public static function signingKeyValidity(string $expiresAt, ?string $revokedAt, \DateTimeImmutable $now): string
    {
        if ($revokedAt !== null) {
            return self::KEY_REVOKED;
        }
        try {
            $expires = Time::parseRfc3339($expiresAt);
        } catch (\InvalidArgumentException $e) {
            return self::KEY_BAD_EXPIRY;
        }
        return $now > $expires ? self::KEY_EXPIRED : self::KEY_VALID;
    }

    // -------------------------------------------------------------------
    // AEAD dispatch
    // -------------------------------------------------------------------

    /** Encrypt under `suite`. Output is `ciphertext || 16-byte tag` (RustCrypto convention). */
    public static function aeadEncrypt(string $suite, string $key, string $nonce, string $aad, string $plaintext): string
    {
        self::requireLen($key, 32, 'AEAD key');
        self::requireLen($nonce, self::AEAD_NONCE_LENGTH, 'AEAD nonce');

        if ($suite === self::AEAD_SUITE_AES_256_GCM) {
            $tag = '';
            $ciphertext = openssl_encrypt(
                $plaintext,
                'aes-256-gcm',
                $key,
                OPENSSL_RAW_DATA,
                $nonce,
                $tag,
                $aad,
                self::AEAD_TAG_LENGTH
            );
            if ($ciphertext === false) {
                throw new EncryptionFailedError('AES-256-GCM encryption failed');
            }
            return $ciphertext . $tag;
        }
        if ($suite === self::AEAD_SUITE_CHACHA20_POLY1305) {
            return sodium_crypto_aead_chacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $key);
        }
        throw new UnsupportedAlgorithmError($suite);
    }

    /** Decrypt `ciphertext || tag` under `suite`. Throws on any authentication failure. */
    public static function aeadDecrypt(string $suite, string $key, string $nonce, string $aad, string $ciphertextWithTag): string
    {
        self::requireLen($key, 32, 'AEAD key');
        self::requireLen($nonce, self::AEAD_NONCE_LENGTH, 'AEAD nonce');
        if (strlen($ciphertextWithTag) < self::AEAD_TAG_LENGTH) {
            throw new DecryptionFailedError('ciphertext shorter than the AEAD tag');
        }

        if ($suite === self::AEAD_SUITE_AES_256_GCM) {
            $tag = substr($ciphertextWithTag, -self::AEAD_TAG_LENGTH);
            $ciphertext = substr($ciphertextWithTag, 0, -self::AEAD_TAG_LENGTH);
            $plaintext = openssl_decrypt(
                $ciphertext,
                'aes-256-gcm',
                $key,
                OPENSSL_RAW_DATA,
                $nonce,
                $tag,
                $aad
            );
            if ($plaintext === false) {
                throw new DecryptionFailedError('AEAD authentication failed');
            }
            return $plaintext;
        }
        if ($suite === self::AEAD_SUITE_CHACHA20_POLY1305) {
            try {
                return sodium_crypto_aead_chacha20poly1305_ietf_decrypt($ciphertextWithTag, $aad, $nonce, $key);
            } catch (\SodiumException $e) {
                throw new DecryptionFailedError('AEAD authentication failed', 0, $e);
            }
        }
        throw new UnsupportedAlgorithmError($suite);
    }

    private static function requireLen(string $bytes, int $len, string $what): void
    {
        if (strlen($bytes) !== $len) {
            throw new InvalidKeyLengthError("{$what} must be {$len} bytes, got " . strlen($bytes));
        }
    }
}

class CryptoError extends \RuntimeException
{
}

final class SigningFailedError extends CryptoError
{
}

final class VerificationFailedError extends CryptoError
{
    public function __construct()
    {
        parent::__construct('signature verification failed');
    }
}

final class UnsupportedAlgorithmError extends CryptoError
{
    public string $algorithm;

    public function __construct(string $algorithm)
    {
        parent::__construct("unsupported algorithm: {$algorithm}");
        $this->algorithm = $algorithm;
    }
}

final class EncryptionFailedError extends CryptoError
{
}

final class DecryptionFailedError extends CryptoError
{
}

final class InvalidKeyLengthError extends CryptoError
{
}
