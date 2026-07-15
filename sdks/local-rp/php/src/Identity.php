<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

use Csilgen\Generated\SignedLocalRpDescriptor;

/**
 * `generateLocalRpIdentity` and the raw-byte storage helpers (design doc:
 * "SDK API Shape", "Byte Storage Helpers").
 *
 * A local RP identity is exactly one Ed25519 signing keypair, one X25519
 * encryption keypair, and a self-signed `SignedLocalRpDescriptor` binding
 * them together. There is no continuity story across rotation — generating
 * a new identity means a new fingerprint, full stop.
 *
 * Security note (design doc, "Byte Storage Helpers"): the private key
 * fields in {@see LocalRpKeyMaterial} do not directly identify a user, but
 * they control this app's entire local RP identity — anyone holding them
 * can sign login requests and redeem claim tickets as this app. Store them
 * with ordinary application-secret care (the same care as a database
 * credential or API key), not merely as configuration.
 */
final class Identity
{
    /** Default local RP key lifetime: 10 years. Rotation is a deliberate operator event. */
    public const DEFAULT_LIFETIME_DAYS = 3650;

    /**
     * `generateLocalRpIdentity(config) -> LocalRpKeyMaterial` (design doc,
     * "SDK API Shape"). Generates a fresh Ed25519 signing keypair and a
     * *separate* X25519 encryption keypair (never algebraically derived),
     * builds and self-signs the descriptor binding them, and returns
     * everything the app needs to persist.
     */
    public static function generateLocalRpIdentity(GenerateLocalRpIdentityConfig $config): LocalRpKeyMaterial
    {
        if (trim($config->appName) === '') {
            throw new \InvalidArgumentException('app_name must not be empty');
        }

        [$signingPublicKey, $signingPrivateKey] = Crypto::generateEd25519Keypair();
        [$encryptionPublicKey, $encryptionPrivateKey] = Crypto::generateX25519Keypair();

        $suites = $config->supportedSuites ?? Crypto::allSupportedAeadSuites();
        if (empty($suites)) {
            throw new \InvalidArgumentException('supported_suites must not be empty');
        }

        $lifetimeDays = $config->lifetimeDays ?? self::DEFAULT_LIFETIME_DAYS;
        $createdAt = Time::toRfc3339($config->now);
        $expiresAt = Time::toRfc3339($config->now->add(new \DateInterval("P{$lifetimeDays}D")));

        $descriptor = LocalRp::buildLocalRpDescriptor(
            $config->appName,
            $config->localDomainHint,
            $signingPublicKey,
            $encryptionPublicKey,
            $suites,
            $createdAt,
            $expiresAt
        );
        $fingerprint = $descriptor->fingerprint;
        $signedDescriptor = LocalRp::signLocalRpDescriptor($descriptor, $signingPrivateKey);

        return new LocalRpKeyMaterial(
            $signingPrivateKey,
            $signingPublicKey,
            $encryptionPrivateKey,
            $encryptionPublicKey,
            $signedDescriptor,
            $fingerprint
        );
    }

    /**
     * `checkExpirations(identity, now) -> ExpirationStatus` (design doc,
     * "SDK API Shape" / "Expiration Helper"). Thin wrapper over
     * {@see LocalRp::checkExpirations}, taking the identity's descriptor
     * `expires_at` directly. The SDK reports facts; the app decides whether
     * to warn admins, warn users, block login, renew, or ignore.
     */
    public static function checkExpirations(LocalRpKeyMaterial $identity, \DateTimeImmutable $now): ExpirationStatus
    {
        $descriptor = Wire::decodeLocalRpDescriptor($identity->descriptor->descriptor);
        return LocalRp::checkExpirations($descriptor->expiresAt, $now);
    }

    // -------------------------------------------------------------------
    // Byte storage helpers (design doc: "Byte Storage Helpers")
    // -------------------------------------------------------------------

    public static function signingKeyToBytes(string $key): string
    {
        return $key;
    }

    public static function signingKeyFromBytes(string $bytes): string
    {
        if (strlen($bytes) !== 32) {
            throw new \InvalidArgumentException('signing key must be 32 bytes, got ' . strlen($bytes));
        }
        return $bytes;
    }

    public static function encryptionKeyToBytes(string $key): string
    {
        return $key;
    }

    public static function encryptionKeyFromBytes(string $bytes): string
    {
        if (strlen($bytes) !== 32) {
            throw new \InvalidArgumentException('encryption key must be 32 bytes, got ' . strlen($bytes));
        }
        return $bytes;
    }

    /** Pass-through: in this SDK the fingerprint IS a hex string, the canonical form. */
    public static function fingerprintToString(string $fingerprint): string
    {
        return $fingerprint;
    }

    /** Parse/validate a fingerprint string: exactly 64 lowercase-normalized hex characters. */
    public static function fingerprintFromString(string $s): string
    {
        if (!Dns::isValidFingerprint($s)) {
            throw new \InvalidArgumentException("not a valid fingerprint (want 64 hex chars): {$s}");
        }
        return strtolower($s);
    }

    /**
     * Magic prefix for the identity-bundle byte format below. This is an
     * SDK-local storage convenience, NOT a protocol wire format.
     */
    private const IDENTITY_BUNDLE_MAGIC = 'LKI1';

    /**
     * `localRpIdentityToBytes(identity) -> bytes` (design doc, "Byte
     * Storage Helpers": "identity bundle"). Packs both private keys and the
     * signed descriptor into one opaque blob an app can store as a single
     * secret/config value. Layout: `MAGIC(4) || signing_private_key(32) ||
     * encryption_private_key(32) || descriptor_len(4, BE) || descriptor_cbor`.
     */
    public static function localRpIdentityToBytes(LocalRpKeyMaterial $identity): string
    {
        $descriptorBytes = Wire::encodeSignedLocalRpDescriptor($identity->descriptor);
        return self::IDENTITY_BUNDLE_MAGIC
            . $identity->signingPrivateKey
            . $identity->encryptionPrivateKey
            . pack('N', strlen($descriptorBytes))
            . $descriptorBytes;
    }

    /**
     * `localRpIdentityFromBytes(bytes) -> LocalRpKeyMaterial` — the inverse
     * of {@see self::localRpIdentityToBytes}. Public keys and the
     * fingerprint are read back out of the embedded descriptor rather than
     * re-derived from the private keys. Does no signature/expiry
     * verification.
     */
    public static function localRpIdentityFromBytes(string $bytes): LocalRpKeyMaterial
    {
        $headerLen = 4 + 32 + 32 + 4;
        if (strlen($bytes) < $headerLen) {
            throw new \InvalidArgumentException('identity bundle too short');
        }
        if (substr($bytes, 0, 4) !== self::IDENTITY_BUNDLE_MAGIC) {
            throw new \InvalidArgumentException('identity bundle has an unrecognized magic prefix');
        }
        $signingPrivateKey = substr($bytes, 4, 32);
        $encryptionPrivateKey = substr($bytes, 36, 32);
        $descriptorLen = unpack('N', substr($bytes, 68, 4))[1];
        if (strlen($bytes) < $headerLen + $descriptorLen) {
            throw new \InvalidArgumentException('identity bundle descriptor length exceeds available bytes');
        }
        $descriptorBytes = substr($bytes, $headerLen, $descriptorLen);

        $signedDescriptor = Wire::decodeSignedLocalRpDescriptor($descriptorBytes);
        $descriptor = Wire::decodeLocalRpDescriptor($signedDescriptor->descriptor);

        if (strlen($descriptor->signingPublicKey) !== 32 || strlen($descriptor->encryptionPublicKey) !== 32) {
            throw new \InvalidArgumentException('descriptor public key was not 32 bytes');
        }

        return new LocalRpKeyMaterial(
            $signingPrivateKey,
            $descriptor->signingPublicKey,
            $encryptionPrivateKey,
            $descriptor->encryptionPublicKey,
            $signedDescriptor,
            $descriptor->fingerprint
        );
    }
}

/** Input to {@see Identity::generateLocalRpIdentity}. Big-config, single struct. */
final class GenerateLocalRpIdentityConfig
{
    public string $appName;
    public ?string $localDomainHint;
    /** @var string[]|null */
    public ?array $supportedSuites;
    public ?int $lifetimeDays;
    public \DateTimeImmutable $now;

    /** @param string[]|null $supportedSuites */
    public function __construct(
        string $appName,
        \DateTimeImmutable $now,
        ?string $localDomainHint = null,
        ?array $supportedSuites = null,
        ?int $lifetimeDays = null
    ) {
        $this->appName = $appName;
        $this->now = $now;
        $this->localDomainHint = $localDomainHint;
        $this->supportedSuites = $supportedSuites;
        $this->lifetimeDays = $lifetimeDays;
    }
}

/**
 * A local RP's full key material: signing keypair, encryption keypair, the
 * self-signed descriptor binding them, and the identity fingerprint.
 *
 * Private key fields are raw 32-byte strings — see {@see Identity}'s class
 * docs before persisting them.
 */
final class LocalRpKeyMaterial
{
    public string $signingPrivateKey;
    public string $signingPublicKey;
    public string $encryptionPrivateKey;
    public string $encryptionPublicKey;
    public SignedLocalRpDescriptor $descriptor;
    /** `sha256(signing_public_key)` hex — the canonical identity anchor. */
    public string $fingerprint;

    public function __construct(
        string $signingPrivateKey,
        string $signingPublicKey,
        string $encryptionPrivateKey,
        string $encryptionPublicKey,
        SignedLocalRpDescriptor $descriptor,
        string $fingerprint
    ) {
        $this->signingPrivateKey = $signingPrivateKey;
        $this->signingPublicKey = $signingPublicKey;
        $this->encryptionPrivateKey = $encryptionPrivateKey;
        $this->encryptionPublicKey = $encryptionPublicKey;
        $this->descriptor = $descriptor;
        $this->fingerprint = $fingerprint;
    }
}
