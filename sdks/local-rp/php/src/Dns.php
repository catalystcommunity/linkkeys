<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

use Csilgen\Generated\DomainPublicKey;

/**
 * DNS TXT lookup seam + `_linkkeys`/`_linkkeys_apis` record parsing and key
 * pinning. Mirrors `crates/liblinkkeys/src/dns.rs`. Per the design doc's
 * "Required Network Access": the resolver is configurable, defaulting to the
 * system resolver — LAN resolver spoofing is an accepted, documented
 * tradeoff for this mode.
 */
final class Dns
{
    public const DEFAULT_TCP_PORT = 4987;

    public static function linkkeysDnsName(string $domain): string
    {
        return "_linkkeys.{$domain}";
    }

    public static function linkkeysApisDnsName(string $domain): string
    {
        return "_linkkeys_apis.{$domain}";
    }

    /** @param string[] $parts */
    private static function requireLk1Version(array $parts): void
    {
        $version = null;
        foreach ($parts as $p) {
            if (str_starts_with($p, 'v=')) {
                $version = substr($p, 2);
                break;
            }
        }
        if ($version === null) {
            throw new DnsParseError(DnsParseError::MISSING_VERSION, 'missing v= tag in TXT record');
        }
        if ($version !== 'lk1') {
            throw new DnsParseError(DnsParseError::UNSUPPORTED_VERSION, "unsupported linkkeys version: {$version}");
        }
    }

    /** @return string[] */
    public static function parseLinkKeysTxt(string $txt): array
    {
        $parts = preg_split('/\s+/', trim($txt), -1, PREG_SPLIT_NO_EMPTY);
        self::requireLk1Version($parts);
        $fingerprints = [];
        foreach ($parts as $p) {
            if (str_starts_with($p, 'fp=')) {
                $fingerprints[] = substr($p, 3);
            }
        }
        return $fingerprints;
    }

    private static function normalizeTcpEndpoint(string $value): string
    {
        if ($value === '' || str_contains($value, ':')) {
            return $value;
        }
        return "{$value}:" . self::DEFAULT_TCP_PORT;
    }

    /** @return array{tcp: ?string, https_base: ?string} */
    public static function parseLinkKeysApisTxt(string $txt): array
    {
        $parts = preg_split('/\s+/', trim($txt), -1, PREG_SPLIT_NO_EMPTY);
        self::requireLk1Version($parts);

        $tcp = null;
        $httpsBase = null;
        foreach ($parts as $p) {
            if ($tcp === null && str_starts_with($p, 'tcp=')) {
                $tcp = self::normalizeTcpEndpoint(substr($p, 4));
            }
            if ($httpsBase === null && str_starts_with($p, 'https=')) {
                $httpsBase = 'https://' . substr($p, 6);
            }
        }

        if ($tcp === null && $httpsBase === null) {
            throw new DnsParseError(DnsParseError::MISSING_APIS_ENDPOINT, '_linkkeys_apis record has neither tcp= nor https=');
        }

        return ['tcp' => $tcp, 'https_base' => $httpsBase];
    }

    public static function isValidFingerprint(string $fp): bool
    {
        return strlen($fp) === 64 && ctype_xdigit($fp);
    }

    /**
     * Recompute each candidate key's fingerprint (never trust the wire
     * `fingerprint` field) and keep only keys whose recomputed fingerprint
     * is a member of `$pinned`.
     *
     * @param DomainPublicKey[] $keys
     * @param string[] $pinned
     * @return DomainPublicKey[]
     */
    public static function pinKeysToFingerprints(array $keys, array $pinned): array
    {
        $pinnedLower = [];
        foreach ($pinned as $f) {
            if (self::isValidFingerprint($f)) {
                $pinnedLower[strtolower($f)] = true;
            }
        }
        return array_values(array_filter($keys, fn (DomainPublicKey $k) => isset($pinnedLower[strtolower(Crypto::fingerprint($k->publicKey))])));
    }

    private const KEY_VOUCH_TAG = 'linkkeys-key-vouch-v1alpha';

    public static function keyVouchPayload(string $encFingerprint, string $encExpiresAt): string
    {
        return Cbor::encode([self::KEY_VOUCH_TAG, $encFingerprint, $encExpiresAt]);
    }

    /**
     * Verify that `$signingKey` vouches for `$encKey` (encryption keys are
     * not published in DNS; they are trusted only via a DNS-pinned signing
     * key's vouch).
     */
    public static function verifyKeyVouch(DomainPublicKey $encKey, DomainPublicKey $signingKey, \DateTimeImmutable $now): bool
    {
        if ($encKey->signedByKeyId !== $signingKey->keyId) {
            return false;
        }
        if (Crypto::signingKeyValidity($signingKey->expiresAt, $signingKey->revokedAt, $now) !== Crypto::KEY_VALID) {
            return false;
        }
        if ($encKey->keySignature === null) {
            return false;
        }
        $recomputedFp = Crypto::fingerprint($encKey->publicKey);
        $payload = self::keyVouchPayload($recomputedFp, $encKey->expiresAt);
        try {
            Crypto::resolveAndVerify($signingKey->algorithm, $payload, $encKey->keySignature, $signingKey->publicKey);
            return true;
        } catch (CryptoError $e) {
            return false;
        }
    }

    /**
     * Establish the trusted key set from a fetched key list and the
     * DNS-pinned fingerprint set. Signing keys are pinned directly;
     * encryption keys are trusted only when a pinned signing key vouches
     * for them. Callers MUST treat an empty result as "no trustworthy keys"
     * and fail closed.
     *
     * @param DomainPublicKey[] $keys
     * @param string[] $pinned
     * @return DomainPublicKey[]
     */
    public static function trustKeys(array $keys, array $pinned, \DateTimeImmutable $now): array
    {
        $signing = array_values(array_filter($keys, fn (DomainPublicKey $k) => $k->keyUsage === 'sign'));
        $pinnedSigning = self::pinKeysToFingerprints($signing, $pinned);

        $trusted = $pinnedSigning;
        foreach ($keys as $k) {
            if ($k->keyUsage !== 'encrypt') {
                continue;
            }
            foreach ($pinnedSigning as $sk) {
                if (self::verifyKeyVouch($k, $sk, $now)) {
                    $trusted[] = $k;
                    break;
                }
            }
        }
        return $trusted;
    }
}

final class DnsParseError extends \RuntimeException
{
    public const MISSING_VERSION = 'missing_version';
    public const UNSUPPORTED_VERSION = 'unsupported_version';
    public const MISSING_APIS_ENDPOINT = 'missing_apis_endpoint';
    public const NO_LINKKEYS_RECORD = 'no_linkkeys_record';
    public const INVALID_FORMAT = 'invalid_format';

    public string $kind;

    public function __construct(string $kind, string $message)
    {
        parent::__construct($message);
        $this->kind = $kind;
    }
}

/**
 * Caller-injected DNS TXT lookup seam. Each returned string is one TXT
 * record's content (the concatenation of its character-strings).
 */
interface DnsResolver
{
    /** @return string[] */
    public function txtLookup(string $name): array;
}

/**
 * Default {@see DnsResolver}: the OS-configured resolver via
 * `dns_get_record(..., DNS_TXT)`. Per the design doc's "Decided" section,
 * resolver spoofing on a LAN is an accepted, documented tradeoff for this
 * mode; operators wanting hardening can inject their own `DnsResolver`
 * (e.g. a DoH client) instead.
 */
final class SystemDnsResolver implements DnsResolver
{
    public function txtLookup(string $name): array
    {
        // dns_get_record emits a PHP warning (not an exception) on lookup
        // failure; suppress it at the call site and surface our own
        // exception instead, matching every other seam in this SDK.
        $records = @dns_get_record($name, DNS_TXT);
        if ($records === false) {
            throw new \RuntimeException("DNS TXT lookup failed for {$name}");
        }
        $results = [];
        foreach ($records as $r) {
            // PHP's dns_get_record concatenates multi-string TXT records
            // into a single `txt` field already (unlike some lower-level
            // resolver APIs), matching the "concatenation of character
            // strings" contract this SDK's parsers expect.
            if (isset($r['txt'])) {
                $results[] = $r['txt'];
            } elseif (isset($r['entries']) && is_array($r['entries'])) {
                $results[] = implode('', $r['entries']);
            }
        }
        return $results;
    }
}
