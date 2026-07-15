<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

use Csilgen\Generated\Claim;
use Csilgen\Generated\DomainPublicKey;

/**
 * Claim signature/revocation/expiry verification. Mirrors
 * `crates/liblinkkeys/src/claims.rs` for exactly the pieces
 * `complete_local_login` needs: per-signer-domain signature quorum,
 * revocation, and expiry.
 */
final class Claims
{
    public const CLAIM_PAYLOAD_TAG = 'linkkeys-claim-v2';

    /**
     * The subject is bound as the single full identity `user_id@subject_domain`
     * (not the bare user_id), so a claim about a user_id at one domain can't
     * be replayed as the same user_id at another. `signing_domain` — the
     * attestor for THIS signature — is bound per-signature.
     */
    public static function claimSignPayload(
        string $claimId,
        string $claimType,
        string $claimValue,
        string $userId,
        string $subjectDomain,
        string $signingDomain,
        ?string $expiresAt,
        string $attestedAt
    ): string {
        $subject = "{$userId}@{$subjectDomain}";
        return Cbor::encode([
            self::CLAIM_PAYLOAD_TAG,
            $claimId,
            $claimType,
            Cbor::bytes($claimValue),
            $subject,
            $signingDomain,
            $expiresAt,
            $attestedAt,
        ]);
    }

    /**
     * @param DomainKeySet[] $domainKeys
     */
    private static function verifyOneSignature(object $sig, string $payload, array $keys, \DateTimeImmutable $now): void
    {
        $key = null;
        foreach ($keys as $k) {
            if ($k->keyId === $sig->signedByKeyId) {
                $key = $k;
                break;
            }
        }
        if ($key === null) {
            throw new ClaimError(ClaimError::KEY_NOT_FOUND, $sig->signedByKeyId);
        }
        if ($key->keyUsage !== 'sign') {
            throw new ClaimError(ClaimError::SIGNATURE_INVALID, 'key is not a signing key');
        }

        // Gates the SIGNING KEY's own revocation/expiry (not the claim's,
        // which verifyClaim checks separately). Threads the caller's `now`
        // through rather than reading the system clock, matching the Python
        // port's documented deviation from `liblinkkeys`'s own
        // `Utc::now()`-reading `check_signing_key_valid` (see
        // conformance/README.md, "Note on clocks").
        $validity = Crypto::signingKeyValidity($key->expiresAt, $key->revokedAt, $now);
        if ($validity === Crypto::KEY_REVOKED) {
            throw new ClaimError(ClaimError::KEY_REVOKED, $key->keyId);
        }
        if ($validity === Crypto::KEY_EXPIRED || $validity === Crypto::KEY_BAD_EXPIRY) {
            throw new ClaimError(ClaimError::KEY_EXPIRED, $key->keyId);
        }

        try {
            Crypto::resolveAndVerify($key->algorithm, $payload, $sig->signature, $key->publicKey);
        } catch (UnsupportedAlgorithmError $e) {
            throw new ClaimError(ClaimError::UNSUPPORTED_ALGORITHM, $key->algorithm, $e);
        } catch (CryptoError $e) {
            throw new ClaimError(ClaimError::SIGNATURE_INVALID, 'claim signature verification failed', $e);
        }
    }

    /**
     * Every distinct domain that signed must contribute at least one
     * signature from a currently-valid key of that domain.
     *
     * @param DomainKeySet[] $domainKeys
     */
    public static function verifyClaimSignatures(Claim $claim, string $subjectDomain, array $domainKeys, \DateTimeImmutable $now): void
    {
        if (empty($claim->signatures)) {
            throw new ClaimError(ClaimError::UNSIGNED, 'claim has no signatures');
        }

        $domains = array_unique(array_map(fn ($s) => $s->domain, $claim->signatures));
        sort($domains);

        foreach ($domains as $signingDomain) {
            $keySet = null;
            foreach ($domainKeys as $s) {
                if ($s->domain === $signingDomain) {
                    $keySet = $s;
                    break;
                }
            }
            if ($keySet === null) {
                throw new ClaimError(ClaimError::DOMAIN_KEYS_UNAVAILABLE, $signingDomain);
            }

            $payload = self::claimSignPayload(
                $claim->claimId,
                $claim->claimType,
                $claim->claimValue,
                $claim->userId,
                $subjectDomain,
                $signingDomain,
                $claim->expiresAt,
                $claim->attestedAt
            );

            $satisfied = false;
            $lastErr = new ClaimError(ClaimError::DOMAIN_UNVERIFIED, $signingDomain);
            foreach ($claim->signatures as $sig) {
                if ($sig->domain !== $signingDomain) {
                    continue;
                }
                try {
                    self::verifyOneSignature($sig, $payload, $keySet->keys, $now);
                    $satisfied = true;
                    break;
                } catch (ClaimError $e) {
                    $lastErr = $e;
                }
            }
            if (!$satisfied) {
                throw $lastErr;
            }
        }
    }

    /**
     * Full claim verification: the cryptographic per-domain quorum plus the
     * claim's own revocation and expiry. All must pass.
     *
     * @param DomainKeySet[] $domainKeys
     */
    public static function verifyClaim(Claim $claim, string $subjectDomain, array $domainKeys, \DateTimeImmutable $now): void
    {
        self::verifyClaimSignatures($claim, $subjectDomain, $domainKeys, $now);

        if ($claim->revokedAt !== null) {
            throw new ClaimError(ClaimError::REVOKED, 'claim has been revoked');
        }
        if ($claim->expiresAt !== null) {
            try {
                $expires = Time::parseRfc3339($claim->expiresAt);
            } catch (\InvalidArgumentException $e) {
                throw new ClaimError(ClaimError::BAD_EXPIRY, 'claim has an invalid expires_at', $e);
            }
            if ($now > $expires) {
                throw new ClaimError(ClaimError::EXPIRED, 'claim has expired');
            }
        }
    }
}

/** A signer domain and the set of currently-fetched `DomainPublicKey`s for it. */
final class DomainKeySet
{
    public string $domain;
    /** @var DomainPublicKey[] */
    public array $keys;

    /** @param DomainPublicKey[] $keys */
    public function __construct(string $domain, array $keys)
    {
        $this->domain = $domain;
        $this->keys = $keys;
    }
}

final class ClaimError extends \RuntimeException
{
    public const SIGNATURE_INVALID = 'signature_invalid';
    public const UNSUPPORTED_ALGORITHM = 'unsupported_algorithm';
    public const KEY_NOT_FOUND = 'key_not_found';
    public const KEY_REVOKED = 'key_revoked';
    public const KEY_EXPIRED = 'key_expired';
    public const REVOKED = 'revoked';
    public const EXPIRED = 'expired';
    public const BAD_EXPIRY = 'bad_expiry';
    public const UNSIGNED = 'unsigned';
    public const DOMAIN_KEYS_UNAVAILABLE = 'domain_keys_unavailable';
    public const DOMAIN_UNVERIFIED = 'domain_unverified';

    public string $kind;

    public function __construct(string $kind, string $detail, ?\Throwable $previous = null)
    {
        parent::__construct("{$kind}: {$detail}", 0, $previous);
        $this->kind = $kind;
    }
}
