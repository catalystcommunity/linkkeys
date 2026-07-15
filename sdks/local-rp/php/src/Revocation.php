<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

use Csilgen\Generated\DomainPublicKey;
use Csilgen\Generated\RevocationCertificate;

/**
 * Sibling-signed key revocation certificate verification — mirrors
 * `crates/liblinkkeys/src/revocation.rs` (verification only; building/signing
 * a certificate is a domain-admin/server-side operation, out of scope for a
 * local-RP SDK). `complete_local_login` fetches revocation certificates
 * alongside domain keys and applies them so a key targeted by a
 * quorum-verified certificate is dropped from the trusted set no matter what
 * the fetched key entry itself says.
 */
final class Revocation
{
    public const QUORUM = 2;
    public const TAG = 'linkkeys-key-revocation-v1';

    /**
     * Canonical signed bytes: a FIVE-element CBOR array with the
     * domain-separation tag first — the older house tuple pattern, distinct
     * from the local-RP envelopes' two-element `CBOR([context, payload])`
     * framing. `signing_domain` is bound per-signature to stop cross-domain
     * signature reuse.
     */
    public static function revocationPayload(string $targetKeyId, string $targetFingerprint, string $revokedAt, string $signingDomain): string
    {
        return Cbor::encode([self::TAG, $targetKeyId, $targetFingerprint, $revokedAt, $signingDomain]);
    }

    /**
     * Verify a revocation certificate against a domain's public key set.
     * Requires at least {@see self::QUORUM} DISTINCT signing keys of
     * `$domain`, each currently valid and NOT the target key, to have
     * signed the canonical payload. Throws {@see RevocationError} unless the
     * quorum is met.
     *
     * @param DomainPublicKey[] $domainKeys
     */
    public static function verifyRevocationCertificate(RevocationCertificate $cert, array $domainKeys, string $domain): void
    {
        $count = self::countValidSigners($cert, $domainKeys, $domain);
        if ($count < self::QUORUM) {
            throw new RevocationError($count, self::QUORUM);
        }
    }

    /**
     * The number of distinct, currently-valid, non-self, domain-bound
     * signers whose signature verifies — exposed separately (not just the
     * pass/fail outcome) so tests can pinpoint exactly which filtering rule
     * a case is exercising, per the conformance vectors'
     * `expected_counted_signers`.
     *
     * @param DomainPublicKey[] $domainKeys
     */
    public static function countValidSigners(RevocationCertificate $cert, array $domainKeys, string $domain): int
    {
        $validSigners = [];

        foreach ($cert->signatures as $sig) {
            // A key can never authorize its own revocation.
            if ($sig->signedByKeyId === $cert->targetKeyId) {
                continue;
            }
            // The signature must be bound to this domain.
            if ($sig->domain !== $domain) {
                continue;
            }
            $key = null;
            foreach ($domainKeys as $k) {
                if ($k->keyId === $sig->signedByKeyId) {
                    $key = $k;
                    break;
                }
            }
            if ($key === null) {
                continue;
            }
            // Only a currently-valid signing key counts toward the quorum.
            try {
                LocalRp::checkSigningKeyValid($key, new \DateTimeImmutable('now', new \DateTimeZone('UTC')));
            } catch (LocalRpError $e) {
                continue;
            }

            $payload = self::revocationPayload($cert->targetKeyId, $cert->targetFingerprint, $cert->revokedAt, $sig->domain);
            try {
                Crypto::resolveAndVerify($key->algorithm, $payload, $sig->signature, $key->publicKey);
                $validSigners[$sig->signedByKeyId] = true;
            } catch (CryptoError $e) {
                // Not a valid signature; does not count.
            }
        }

        return count($validSigners);
    }
}

final class RevocationError extends \RuntimeException
{
    public int $got;
    public int $need;

    public function __construct(int $got, int $need)
    {
        parent::__construct("revocation certificate has {$got} valid sibling signatures; {$need} required");
        $this->got = $got;
        $this->need = $need;
    }
}
