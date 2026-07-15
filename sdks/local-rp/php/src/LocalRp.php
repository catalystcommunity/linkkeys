<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

use Csilgen\Generated\DomainPublicKey;
use Csilgen\Generated\LocalRpCallbackHeader;
use Csilgen\Generated\LocalRpCallbackPayload;
use Csilgen\Generated\LocalRpDescriptor;
use Csilgen\Generated\LocalRpEncryptedCallback;
use Csilgen\Generated\LocalRpLoginRequest;
use Csilgen\Generated\LocalRpTicketRedemptionRequest;
use Csilgen\Generated\SignedLocalRpCallbackPayload;
use Csilgen\Generated\SignedLocalRpDescriptor;
use Csilgen\Generated\SignedLocalRpLoginRequest;
use Csilgen\Generated\SignedLocalRpTicketRedemptionRequest;

/**
 * DNS-less local RP identity: pure protocol helpers. Mirrors
 * `crates/liblinkkeys/src/local_rp.rs` byte-for-byte — see that file's
 * module docs and the design doc's "Wire Precision (Normative)" section.
 * Every "current time" is an explicit `now` parameter; this class performs
 * no I/O.
 */
final class LocalRp
{
    public const CTX_LOCAL_RP_DESCRIPTOR = 'linkkeys-local-rp-descriptor';
    public const CTX_LOCAL_RP_LOGIN_REQUEST = 'linkkeys-local-rp-login-request';
    public const CTX_LOCAL_RP_CALLBACK = 'linkkeys-local-rp-callback';
    public const CTX_LOCAL_RP_TICKET_REDEMPTION = 'linkkeys-local-rp-ticket-redemption';

    public const DEFAULT_CLOCK_SKEW_SECONDS = 300;

    private const LOCAL_RP_CALLBACK_BOX_TAG = 'linkkeys-local-rp-callback-box';

    /**
     * The signature input for every local-RP signed structure:
     * `CBOR([context, payload_bytes])` — a two-element array, context string
     * first (CBOR text string), payload second (CBOR byte string, never
     * re-serialized). Deliberately NOT a bare `context || payload`
     * concatenation.
     */
    public static function envelopeSignatureInput(string $context, string $payloadBytes): string
    {
        return Cbor::encode([$context, Cbor::bytes($payloadBytes)]);
    }

    private static function checkTimestamps(string $issuedAt, string $expiresAt, \DateTimeImmutable $now, int $skewSeconds): void
    {
        $issued = self::parseTimestamp($issuedAt);
        $expires = self::parseTimestamp($expiresAt);
        $skew = new \DateInterval('PT' . abs($skewSeconds) . 'S');

        $nowPlusSkew = (clone $now)->add($skew);
        if ($nowPlusSkew < $issued) {
            throw new LocalRpError(LocalRpError::NOT_YET_VALID);
        }
        $nowMinusSkew = (clone $now)->sub($skew);
        if ($nowMinusSkew > $expires) {
            throw new LocalRpError(LocalRpError::EXPIRED);
        }
    }

    private static function parseTimestamp(string $s): \DateTimeImmutable
    {
        try {
            return Time::parseRfc3339($s);
        } catch (\InvalidArgumentException $e) {
            throw new LocalRpError(LocalRpError::BAD_TIMESTAMP, $s);
        }
    }

    // -------------------------------------------------------------------
    // Expiration helper (design doc: "Expiration Helper")
    // -------------------------------------------------------------------

    public const EXPIRATION_OK = 'ok';
    public const EXPIRATION_NOTICE = 'notice';
    public const EXPIRATION_WARNING = 'warning';
    public const EXPIRATION_CRITICAL = 'critical';
    public const EXPIRATION_EXPIRED = 'expired';

    public static function checkExpirations(string $expiresAt, \DateTimeImmutable $now): ExpirationStatus
    {
        $expires = self::parseTimestamp($expiresAt);
        $remainingSeconds = $expires->getTimestamp() - $now->getTimestamp();

        if ($now->getTimestamp() >= $expires->getTimestamp()) {
            $level = self::EXPIRATION_EXPIRED;
        } elseif ($remainingSeconds <= 30 * 86400) {
            $level = self::EXPIRATION_CRITICAL;
        } elseif ($remainingSeconds <= 90 * 86400) {
            $level = self::EXPIRATION_WARNING;
        } elseif ($remainingSeconds <= 180 * 86400) {
            $level = self::EXPIRATION_NOTICE;
        } else {
            $level = self::EXPIRATION_OK;
        }

        return new ExpirationStatus($level, $expires, $now);
    }

    // -------------------------------------------------------------------
    // Post-verification checks
    // -------------------------------------------------------------------

    public static function verifyNonceState(string $expectedNonce, string $expectedState, string $actualNonce, string $actualState): void
    {
        if (!hash_equals($expectedNonce, $actualNonce)) {
            throw new LocalRpError(LocalRpError::NONCE_MISMATCH);
        }
        if (!hash_equals($expectedState, $actualState)) {
            throw new LocalRpError(LocalRpError::STATE_MISMATCH);
        }
    }

    public static function verifyAudience(string $payloadAudienceFingerprint, string $localRpFingerprint): void
    {
        if ($payloadAudienceFingerprint !== $localRpFingerprint) {
            throw new LocalRpError(LocalRpError::AUDIENCE_MISMATCH);
        }
    }

    public static function verifyIssuer(string $payloadUserDomain, string $expectedDomain): void
    {
        if ($payloadUserDomain !== $expectedDomain) {
            throw new LocalRpError(LocalRpError::ISSUER_MISMATCH);
        }
    }

    public static function verifyCallbackUrl(string $payloadCallbackUrl, string $arrivedUrl): void
    {
        if ($payloadCallbackUrl !== $arrivedUrl) {
            throw new LocalRpError(LocalRpError::CALLBACK_URL_MISMATCH);
        }
    }

    // -------------------------------------------------------------------
    // Descriptor
    // -------------------------------------------------------------------

    public static function buildLocalRpDescriptor(
        string $appName,
        ?string $localDomainHint,
        string $signingPublicKey,
        string $encryptionPublicKey,
        array $supportedSuites,
        string $createdAt,
        string $expiresAt
    ): LocalRpDescriptor {
        return new LocalRpDescriptor([
            'app_name' => $appName,
            'local_domain_hint' => $localDomainHint,
            'signing_public_key' => $signingPublicKey,
            'encryption_public_key' => $encryptionPublicKey,
            'fingerprint' => Crypto::fingerprint($signingPublicKey),
            'supported_suites' => $supportedSuites,
            'created_at' => $createdAt,
            'expires_at' => $expiresAt,
        ]);
    }

    public static function signLocalRpDescriptor(LocalRpDescriptor $descriptor, string $privateKeyBytes): SignedLocalRpDescriptor
    {
        $descriptorBytes = Wire::encodeLocalRpDescriptor($descriptor);
        $sigInput = self::envelopeSignatureInput(self::CTX_LOCAL_RP_DESCRIPTOR, $descriptorBytes);
        $signature = Crypto::signWithAlgorithm(Crypto::ALGORITHM_ED25519, $sigInput, $privateKeyBytes);
        return new SignedLocalRpDescriptor([
            'descriptor' => $descriptorBytes,
            'signature' => $signature,
        ]);
    }

    public static function verifyLocalRpDescriptor(SignedLocalRpDescriptor $signed, \DateTimeImmutable $now, int $skewSeconds): LocalRpDescriptor
    {
        $descriptor = Wire::decodeLocalRpDescriptor($signed->descriptor);

        if (strlen($descriptor->signingPublicKey) !== 32) {
            throw new LocalRpError(LocalRpError::INVALID_KEY_LENGTH);
        }

        $expectedFingerprint = Crypto::fingerprint($descriptor->signingPublicKey);
        if ($descriptor->fingerprint !== $expectedFingerprint) {
            throw new LocalRpError(LocalRpError::FINGERPRINT_MISMATCH);
        }

        $sigInput = self::envelopeSignatureInput(self::CTX_LOCAL_RP_DESCRIPTOR, $signed->descriptor);
        Crypto::verifyWithAlgorithm(Crypto::ALGORITHM_ED25519, $sigInput, $signed->signature, $descriptor->signingPublicKey);

        self::checkTimestamps($descriptor->createdAt, $descriptor->expiresAt, $now, $skewSeconds);

        return $descriptor;
    }

    // -------------------------------------------------------------------
    // Login request
    // -------------------------------------------------------------------

    public static function buildLocalRpLoginRequest(
        SignedLocalRpDescriptor $descriptor,
        string $callbackUrl,
        string $nonce,
        string $state,
        array $requestedClaims,
        array $requiredClaims,
        string $issuedAt,
        string $expiresAt
    ): LocalRpLoginRequest {
        return new LocalRpLoginRequest([
            'descriptor' => $descriptor,
            'callback_url' => $callbackUrl,
            'nonce' => $nonce,
            'state' => $state,
            'requested_claims' => $requestedClaims,
            'required_claims' => $requiredClaims,
            'issued_at' => $issuedAt,
            'expires_at' => $expiresAt,
        ]);
    }

    public static function signLocalRpLoginRequest(LocalRpLoginRequest $request, string $privateKeyBytes): SignedLocalRpLoginRequest
    {
        $requestBytes = Wire::encodeLocalRpLoginRequest($request);
        $sigInput = self::envelopeSignatureInput(self::CTX_LOCAL_RP_LOGIN_REQUEST, $requestBytes);
        $signature = Crypto::signWithAlgorithm(Crypto::ALGORITHM_ED25519, $sigInput, $privateKeyBytes);
        return new SignedLocalRpLoginRequest([
            'request' => $requestBytes,
            'signature' => $signature,
        ]);
    }

    public static function verifyLocalRpLoginRequest(SignedLocalRpLoginRequest $signed, \DateTimeImmutable $now, int $skewSeconds): LocalRpLoginRequest
    {
        $request = Wire::decodeLocalRpLoginRequest($signed->request);
        $descriptor = self::verifyLocalRpDescriptor($request->descriptor, $now, $skewSeconds);

        $sigInput = self::envelopeSignatureInput(self::CTX_LOCAL_RP_LOGIN_REQUEST, $signed->request);
        Crypto::verifyWithAlgorithm(Crypto::ALGORITHM_ED25519, $sigInput, $signed->signature, $descriptor->signingPublicKey);

        self::checkTimestamps($request->issuedAt, $request->expiresAt, $now, $skewSeconds);

        return $request;
    }

    // -------------------------------------------------------------------
    // Ticket redemption
    // -------------------------------------------------------------------

    public static function buildLocalRpTicketRedemptionRequest(string $claimTicket, string $fingerprint, string $issuedAt): LocalRpTicketRedemptionRequest
    {
        return new LocalRpTicketRedemptionRequest([
            'claim_ticket' => $claimTicket,
            'fingerprint' => $fingerprint,
            'issued_at' => $issuedAt,
        ]);
    }

    public static function signLocalRpTicketRedemptionRequest(LocalRpTicketRedemptionRequest $request, string $privateKeyBytes): SignedLocalRpTicketRedemptionRequest
    {
        $requestBytes = Wire::encodeLocalRpTicketRedemptionRequest($request);
        $sigInput = self::envelopeSignatureInput(self::CTX_LOCAL_RP_TICKET_REDEMPTION, $requestBytes);
        $signature = Crypto::signWithAlgorithm(Crypto::ALGORITHM_ED25519, $sigInput, $privateKeyBytes);
        return new SignedLocalRpTicketRedemptionRequest([
            'request' => $requestBytes,
            'signature' => $signature,
        ]);
    }

    public static function verifyLocalRpTicketRedemptionRequest(SignedLocalRpTicketRedemptionRequest $signed, string $signingPublicKey, string $expectedFingerprint): LocalRpTicketRedemptionRequest
    {
        $sigInput = self::envelopeSignatureInput(self::CTX_LOCAL_RP_TICKET_REDEMPTION, $signed->request);
        Crypto::verifyWithAlgorithm(Crypto::ALGORITHM_ED25519, $sigInput, $signed->signature, $signingPublicKey);

        $request = Wire::decodeLocalRpTicketRedemptionRequest($signed->request);

        $keyFingerprint = Crypto::fingerprint($signingPublicKey);
        if ($keyFingerprint !== $expectedFingerprint || $request->fingerprint !== $expectedFingerprint) {
            throw new LocalRpError(LocalRpError::FINGERPRINT_MISMATCH);
        }

        return $request;
    }

    // -------------------------------------------------------------------
    // Callback payload (domain-signed envelope)
    // -------------------------------------------------------------------

    public static function buildLocalRpCallbackPayload(
        string $userId,
        string $userDomain,
        string $claimTicket,
        string $audienceFingerprint,
        string $callbackUrl,
        string $nonce,
        string $state,
        string $issuedAt,
        string $expiresAt
    ): LocalRpCallbackPayload {
        return new LocalRpCallbackPayload([
            'user_id' => $userId,
            'user_domain' => $userDomain,
            'claim_ticket' => $claimTicket,
            'audience_fingerprint' => $audienceFingerprint,
            'callback_url' => $callbackUrl,
            'nonce' => $nonce,
            'state' => $state,
            'issued_at' => $issuedAt,
            'expires_at' => $expiresAt,
        ]);
    }

    /**
     * Sign a `LocalRpCallbackPayload` with one of the issuing domain's
     * signing keys (`$keyId` identifies which one — a domain holds several
     * signing keys). This is an IDP-side operation: this SDK's own runtime
     * (`Complete::completeLocalLogin`) only ever verifies a callback
     * payload, never signs one — this method exists so fixture/flow tests
     * can build a realistic signed callback without a real IDP, mirroring
     * `liblinkkeys::local_rp::sign_local_rp_callback_payload`.
     */
    public static function signLocalRpCallbackPayload(LocalRpCallbackPayload $payload, string $keyId, string $algorithm, string $privateKeyBytes): SignedLocalRpCallbackPayload
    {
        $payloadBytes = Wire::encodeLocalRpCallbackPayload($payload);
        $sigInput = self::envelopeSignatureInput(self::CTX_LOCAL_RP_CALLBACK, $payloadBytes);
        $signature = Crypto::signWithAlgorithm($algorithm, $sigInput, $privateKeyBytes);
        return new SignedLocalRpCallbackPayload([
            'payload' => $payloadBytes,
            'signing_key_id' => $keyId,
            'signature' => $signature,
        ]);
    }

    /**
     * Verify a domain-signed callback payload envelope against a set of
     * domain public keys: resolve `signing_key_id`, reject a
     * revoked/expired/non-signing key, verify the envelope signature,
     * decode, then check `issued_at`/`expires_at` bounds.
     *
     * @param DomainPublicKey[] $domainPublicKeys
     */
    public static function verifyLocalRpCallbackPayload(
        SignedLocalRpCallbackPayload $signed,
        array $domainPublicKeys,
        \DateTimeImmutable $now,
        int $skewSeconds
    ): LocalRpCallbackPayload {
        $key = null;
        foreach ($domainPublicKeys as $k) {
            if ($k->keyId === $signed->signingKeyId) {
                $key = $k;
                break;
            }
        }
        if ($key === null) {
            throw new LocalRpError(LocalRpError::KEY_NOT_FOUND, $signed->signingKeyId);
        }

        self::checkSigningKeyValid($key, $now);

        $sigInput = self::envelopeSignatureInput(self::CTX_LOCAL_RP_CALLBACK, $signed->payload);
        Crypto::resolveAndVerify($key->algorithm, $sigInput, $signed->signature, $key->publicKey);

        $payload = Wire::decodeLocalRpCallbackPayload($signed->payload);

        self::checkTimestamps($payload->issuedAt, $payload->expiresAt, $now, $skewSeconds);

        return $payload;
    }

    /**
     * Validity of a signing key at `now`, independent of any signature it
     * produced — mirrors `crate::assertions::check_signing_key_valid`.
     */
    public static function checkSigningKeyValid(DomainPublicKey $key, \DateTimeImmutable $now): void
    {
        if ($key->keyUsage !== 'sign') {
            throw new LocalRpError(LocalRpError::KEY_NOT_A_SIGNING_KEY, $key->keyId);
        }
        if ($key->revokedAt !== null) {
            throw new LocalRpError(LocalRpError::KEY_REVOKED, $key->keyId);
        }
        try {
            $expires = Time::parseRfc3339($key->expiresAt);
        } catch (\InvalidArgumentException $e) {
            throw new LocalRpError(LocalRpError::KEY_EXPIRED, $key->keyId);
        }
        if ($now > $expires) {
            throw new LocalRpError(LocalRpError::KEY_EXPIRED, $key->keyId);
        }
    }

    public static function checkCallbackHeaderMatchesPayload(LocalRpCallbackHeader $header, LocalRpCallbackPayload $payload): void
    {
        if ($header->fingerprint !== $payload->audienceFingerprint) {
            throw new LocalRpError(LocalRpError::HEADER_PAYLOAD_MISMATCH, 'fingerprint');
        }
        if ($header->nonce !== $payload->nonce) {
            throw new LocalRpError(LocalRpError::HEADER_PAYLOAD_MISMATCH, 'nonce');
        }
        if ($header->state !== $payload->state) {
            throw new LocalRpError(LocalRpError::HEADER_PAYLOAD_MISMATCH, 'state');
        }
        if ($header->issuedAt !== $payload->issuedAt) {
            throw new LocalRpError(LocalRpError::HEADER_PAYLOAD_MISMATCH, 'issued_at');
        }
        if ($header->expiresAt !== $payload->expiresAt) {
            throw new LocalRpError(LocalRpError::HEADER_PAYLOAD_MISMATCH, 'expires_at');
        }
    }

    // -------------------------------------------------------------------
    // Callback sealed box (Wire Precision: "Callback sealed box")
    // -------------------------------------------------------------------

    /**
     * Derive the AEAD key and construct the KDF `info`/AAD-prefix context:
     * `tag || suite_id_utf8 || ephemeral_public(32) || recipient_public(32)`.
     *
     * @return array{0: string, 1: string} [aeadKey(32), kdfContext]
     */
    /**
     * `public` (rather than the module-private helper `liblinkkeys` keeps
     * internal) so conformance tests can unit-test HKDF derivation
     * independent of a full decrypt, per the conformance README's
     * `kdf_context_hex` field.
     */
    public static function localRpCallbackKdf(string $suite, string $ephemeralPublic, string $recipientPublic, string $sharedSecret): array
    {
        $context = self::LOCAL_RP_CALLBACK_BOX_TAG . $suite . $ephemeralPublic . $recipientPublic;
        $key = Crypto::hkdfSha256Expand($sharedSecret, $context, 32);
        return [$key, $context];
    }

    /**
     * Seal a `SignedLocalRpCallbackPayload` into a `LocalRpEncryptedCallback`
     * for `recipientEncryptionPublicKey`, using `suite`.
     */
    public static function sealLocalRpCallback(
        SignedLocalRpCallbackPayload $signedPayload,
        string $suite,
        string $recipientEncryptionPublicKey,
        string $fingerprint,
        string $nonce,
        string $state,
        string $issuedAt,
        string $expiresAt,
        ?string $ephemeralPrivateKey = null,
        ?string $aeadNonce = null
    ): LocalRpEncryptedCallback {
        $ephemeralPrivateKey ??= random_bytes(32);
        $aeadNonce ??= random_bytes(12);

        $plaintext = Wire::encodeSignedLocalRpCallbackPayload($signedPayload);
        $ephemeralPublic = Crypto::x25519PublicFromPrivate($ephemeralPrivateKey);

        $sharedSecret = Crypto::x25519DiffieHellman($ephemeralPrivateKey, $recipientEncryptionPublicKey);

        $header = new LocalRpCallbackHeader([
            'fingerprint' => $fingerprint,
            'nonce' => $nonce,
            'state' => $state,
            'suite' => $suite,
            'ephemeral_public_key' => $ephemeralPublic,
            'aead_nonce' => $aeadNonce,
            'issued_at' => $issuedAt,
            'expires_at' => $expiresAt,
        ]);
        $headerBytes = Wire::encodeLocalRpCallbackHeader($header);

        [$aeadKey, $kdfContext] = self::localRpCallbackKdf($suite, $ephemeralPublic, $recipientEncryptionPublicKey, $sharedSecret);

        $aad = $kdfContext . $headerBytes;
        $ciphertext = Crypto::aeadEncrypt($suite, $aeadKey, $aeadNonce, $aad, $plaintext);

        return new LocalRpEncryptedCallback([
            'header' => $headerBytes,
            'ciphertext' => $ciphertext,
        ]);
    }

    /**
     * Open a `LocalRpEncryptedCallback` with the local RP's encryption
     * private key. `$allowedSuites` is the local RP's own supported-suite
     * list: a header advertising a suite NOT in that list is rejected even
     * if it is otherwise a valid registry id.
     *
     * @param string[] $allowedSuites
     * @return array{0: LocalRpCallbackHeader, 1: SignedLocalRpCallbackPayload}
     */
    public static function openLocalRpCallback(LocalRpEncryptedCallback $encrypted, string $recipientEncryptionPrivateKey, array $allowedSuites): array
    {
        $header = Wire::decodeLocalRpCallbackHeader($encrypted->header);

        $suite = Crypto::parseAeadSuite($header->suite);
        if ($suite === null) {
            throw new LocalRpError(LocalRpError::UNSUPPORTED_SUITE, $header->suite);
        }
        if (!in_array($suite, $allowedSuites, true)) {
            throw new LocalRpError(LocalRpError::SUITE_NOT_ADVERTISED, $header->suite);
        }

        if (strlen($header->ephemeralPublicKey) !== 32 || strlen($header->aeadNonce) !== 12) {
            throw new LocalRpError(LocalRpError::INVALID_KEY_LENGTH);
        }

        $recipientPublic = Crypto::x25519PublicFromPrivate($recipientEncryptionPrivateKey);
        $sharedSecret = Crypto::x25519DiffieHellman($recipientEncryptionPrivateKey, $header->ephemeralPublicKey);

        [$aeadKey, $kdfContext] = self::localRpCallbackKdf($suite, $header->ephemeralPublicKey, $recipientPublic, $sharedSecret);

        $aad = $kdfContext . $encrypted->header;

        try {
            $plaintext = Crypto::aeadDecrypt($suite, $aeadKey, $header->aeadNonce, $aad, $encrypted->ciphertext);
        } catch (CryptoError $e) {
            throw new LocalRpError(LocalRpError::CRYPTO, $e->getMessage(), $e);
        }

        $signedPayload = Wire::decodeSignedLocalRpCallbackPayload($plaintext);

        return [$header, $signedPayload];
    }
}

/**
 * Facts about a local RP identity's expiry as of `now` (design doc,
 * "Expiration Helper"): the SDK reports facts, the app decides whether to
 * warn admins, warn users, block login, renew, or ignore.
 */
final class ExpirationStatus
{
    public string $level;
    public \DateTimeImmutable $expiresAt;
    public \DateTimeImmutable $now;

    public function __construct(string $level, \DateTimeImmutable $expiresAt, \DateTimeImmutable $now)
    {
        $this->level = $level;
        $this->expiresAt = $expiresAt;
        $this->now = $now;
    }
}

/**
 * A local-RP protocol verification step failed (signature, envelope,
 * timestamp, nonce/state, audience, issuer, callback URL, suite
 * negotiation). Per the conformance suite's contract, only pass/fail is
 * portable across languages — the `$kind` constants exist for richer
 * app-side diagnostics only.
 */
final class LocalRpError extends \RuntimeException
{
    public const DECODE = 'decode';
    public const INVALID_KEY_LENGTH = 'invalid_key_length';
    public const FINGERPRINT_MISMATCH = 'fingerprint_mismatch';
    public const NOT_YET_VALID = 'not_yet_valid';
    public const EXPIRED = 'expired';
    public const BAD_TIMESTAMP = 'bad_timestamp';
    public const NONCE_MISMATCH = 'nonce_mismatch';
    public const STATE_MISMATCH = 'state_mismatch';
    public const AUDIENCE_MISMATCH = 'audience_mismatch';
    public const ISSUER_MISMATCH = 'issuer_mismatch';
    public const CALLBACK_URL_MISMATCH = 'callback_url_mismatch';
    public const UNSUPPORTED_SUITE = 'unsupported_suite';
    public const SUITE_NOT_ADVERTISED = 'suite_not_advertised';
    public const HEADER_PAYLOAD_MISMATCH = 'header_payload_mismatch';
    public const KEY_NOT_FOUND = 'key_not_found';
    public const KEY_REVOKED = 'key_revoked';
    public const KEY_EXPIRED = 'key_expired';
    public const KEY_NOT_A_SIGNING_KEY = 'key_not_a_signing_key';
    public const CRYPTO = 'crypto';
    /**
     * The ticket-redemption response's `user_id`/`user_domain` disagreed
     * with the verified callback payload's — the redemption response
     * corroborates the payload's identity, it never supplies it (design
     * doc, "Post-implementation security review", item 1).
     */
    public const REDEMPTION_IDENTITY_MISMATCH = 'redemption_identity_mismatch';
    /**
     * A returned claim's `user_id` disagreed with the verified callback
     * payload's `user_id` (design doc, "Post-implementation security
     * review", item 2).
     */
    public const CLAIM_OWNERSHIP_MISMATCH = 'claim_ownership_mismatch';
    /**
     * `PendingLogin::$requiredClaims` named a claim type that was
     * missing, or present but not signature-verified, among the
     * redemption's claims (design doc, "Post-implementation security
     * review", item 3).
     */
    public const REQUIRED_CLAIMS_NOT_SATISFIED = 'required_claims_not_satisfied';

    public string $kind;
    public ?string $detail;

    public function __construct(string $kind, ?string $detail = null, ?\Throwable $previous = null)
    {
        parent::__construct($detail !== null ? "{$kind}: {$detail}" : $kind, 0, $previous);
        $this->kind = $kind;
        $this->detail = $detail;
    }
}
