<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

use Csilgen\Generated\ActAsCredential;
use Csilgen\Generated\ActAsGrantRequest;
use Csilgen\Generated\ActAsPresentation;
use Csilgen\Generated\ActAsRefreshRequest;
use Csilgen\Generated\ApplicationKeySignature;
use Csilgen\Generated\ApplicationRef;
use Csilgen\Generated\ClaimSignature;
use Csilgen\Generated\GranteeProof;
use Csilgen\Generated\GranteeRef;
use Csilgen\Generated\RefreshActAsGrantResponse;
use Csilgen\Generated\SignedActAsGrant;
use Csilgen\Generated\SignedActAsGrantRequest;
use Csilgen\Generated\SignedActAsPresentation;
use Csilgen\Generated\SignedActAsRefreshRequest;
use Csilgen\Generated\SignedActAsScopeSet;
use Csilgen\Generated\SignedLocalRpDescriptor;

/**
 * Act-as grants, grantee side only (docs/spec/reserved/act-as-grants.md).
 * Mirrors `crates/liblinkkeys/src/act_as.rs` (`GranteeSigner::LocalRp`,
 * `sign_grant_request`, `sign_refresh_request`, `present`).
 *
 * A local RP can be the GRANTEE of an act-as grant: a user lets this app act
 * as the user at an enrolled application (the audience). A local RP can
 * never be an audience, because a peer cannot resolve its keys through DNS.
 * The home domain accepts a local-RP grantee only after it approved that
 * local RP.
 *
 * Every signature covers `CBOR([tag, payload_bytes])` and is made with the
 * descriptor signing key. The proof carries the signed descriptor, and its
 * `signed_by_key_id` is the descriptor fingerprint.
 */
final class ActAs
{
    public const GRANT_REQUEST_TAG = 'linkkeys-act-as-grant-request-v1alpha';
    public const REFRESH_REQUEST_TAG = 'linkkeys-act-as-refresh-request-v1alpha';
    public const PRESENTATION_TAG = 'linkkeys-act-as-presentation-v1alpha';

    /** Default request window of a grant request, in seconds. */
    public const DEFAULT_REQUEST_WINDOW_SECONDS = 300;
    /** Largest request window the reference home domain accepts, in seconds. */
    public const MAX_REQUEST_WINDOW_SECONDS = 900;
    /** Request window of a refresh request, in seconds. */
    public const REFRESH_WINDOW_SECONDS = 300;

    /** Whole-second RFC3339 in UTC, ending in `Z` (`act_as::format_time`). */
    public static function formatTime(\DateTimeImmutable $t): string
    {
        return $t->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
    }

    /** SHA-256 of `SignedActAsGrant.grant`. A presentation binds this value. */
    public static function grantHash(string $grantBytes): string
    {
        return hash('sha256', $grantBytes, true);
    }

    /** The local-RP form of `GranteeRef`. */
    public static function localRpGrantee(LocalRpKeyMaterial $keyMaterial): GranteeRef
    {
        return new GranteeRef(['local_rp_descriptor_fingerprint' => $keyMaterial->fingerprint]);
    }

    private static function prove(LocalRpKeyMaterial $keyMaterial, string $tag, string $payload): GranteeProof
    {
        $signature = Crypto::signWithAlgorithm(
            Crypto::ALGORITHM_ED25519,
            LocalRp::envelopeSignatureInput($tag, $payload),
            $keyMaterial->signingPrivateKey
        );
        return new GranteeProof([
            'local_rp_descriptor' => $keyMaterial->descriptor,
            'signature' => new ApplicationKeySignature([
                'signed_by_key_id' => $keyMaterial->fingerprint,
                'signature' => $signature,
            ]),
        ]);
    }

    private static function freshNonce(): string
    {
        return Encoding::base64UrlEncodeUnpadded(random_bytes(32));
    }

    /** Sign an `ActAsGrantRequest` with the descriptor signing key. Pure. */
    public static function signGrantRequest(ActAsGrantRequest $request, LocalRpKeyMaterial $keyMaterial): SignedActAsGrantRequest
    {
        $bytes = ActAsWire::encodeActAsGrantRequest($request);
        return new SignedActAsGrantRequest([
            'request' => $bytes,
            'proof' => self::prove($keyMaterial, self::GRANT_REQUEST_TAG, $bytes),
        ]);
    }

    /** Sign an `ActAsRefreshRequest` with the descriptor signing key. Pure. */
    public static function signRefreshRequest(ActAsRefreshRequest $request, LocalRpKeyMaterial $keyMaterial): SignedActAsRefreshRequest
    {
        $bytes = ActAsWire::encodeActAsRefreshRequest($request);
        return new SignedActAsRefreshRequest([
            'request' => $bytes,
            'proof' => self::prove($keyMaterial, self::REFRESH_REQUEST_TAG, $bytes),
        ]);
    }

    /** `base64url-no-pad(CBOR(SignedActAsGrantRequest))`, the `signed_request` value. */
    public static function signedGrantRequestToUrlParam(SignedActAsGrantRequest $signed): string
    {
        return Encoding::base64UrlEncodeUnpadded(ActAsWire::encodeSignedActAsGrantRequest($signed));
    }

    private static function checkOptionalSeconds(string $name, ?int $value, int $minimum): void
    {
        if ($value !== null && $value < $minimum) {
            throw new \InvalidArgumentException("{$name} must be a whole number >= {$minimum}");
        }
    }

    /**
     * Sign an `ActAsGrantRequest` and return `[ActAsRedirect, PendingActAs]`.
     * The redirect sends the browser to the user's home domain
     * (`/auth/act-as`). Browser endpoint discovery and fallback are the same
     * as {@see Begin::beginLocalLogin}.
     *
     * @return array{0: ActAsRedirect, 1: PendingActAs}
     */
    public static function beginActAs(BeginActAsConfig $config): array
    {
        Begin::validateCallbackScheme($config->callbackUrl);
        [, $domain] = Begin::parseIdentityInput($config->userDomain);
        self::checkOptionalSeconds('requestedLifetimeSeconds', $config->requestedLifetimeSeconds, 1);
        self::checkOptionalSeconds('requestedRenewalWindowSeconds', $config->requestedRenewalWindowSeconds, 0);
        $window = $config->requestWindowSeconds;
        if ($window < 1 || $window > self::MAX_REQUEST_WINDOW_SECONDS) {
            throw new \InvalidArgumentException('requestWindowSeconds must be 1..' . self::MAX_REQUEST_WINDOW_SECONDS);
        }

        try {
            $scopeSet = ActAsWire::decodeSignedActAsScopeSet($config->scopeSet);
        } catch (CborException $e) {
            throw new LocalRpError(LocalRpError::DECODE, 'scope set: ' . $e->getMessage(), $e);
        }

        $nonce = self::freshNonce();
        $request = new ActAsGrantRequest([
            'grantee' => self::localRpGrantee($config->keyMaterial),
            'scope_set' => $scopeSet,
            'requested_lifetime_seconds' => $config->requestedLifetimeSeconds,
            'requested_renewal_window_seconds' => $config->requestedRenewalWindowSeconds,
            'callback_url' => $config->callbackUrl,
            'nonce' => $nonce,
            'requested_at' => self::formatTime($config->now),
            'expires_at' => self::formatTime($config->now->add(new \DateInterval('PT' . $window . 'S'))),
        ]);
        $signed = self::signGrantRequest($request, $config->keyMaterial);
        $dns = $config->dns ?? new SystemDnsResolver();
        $redirectUrl = Browser::resolveBrowserEndpoint($dns, $domain, Browser::ROUTE_ACT_AS, self::signedGrantRequestToUrlParam($signed));
        return [new ActAsRedirect($redirectUrl), new PendingActAs($nonce, $domain, $config->callbackUrl)];
    }

    /**
     * Read `act_as_grant_id` and `nonce` from the callback and return the
     * grant id. `$arrived` is the full callback URL, its query string, or an
     * array of query parameters (for example `$_GET`). The nonce must equal
     * the pending nonce (constant-time compare).
     *
     * @param string|array<string,mixed> $arrived
     */
    public static function completeActAsCallback(PendingActAs $pending, $arrived): string
    {
        if (is_array($arrived)) {
            $params = $arrived;
        } else {
            $query = str_contains($arrived, '://') ? (string) parse_url($arrived, PHP_URL_QUERY) : ltrim($arrived, '?');
            // parse_str keeps only the last of a repeated key. Read the pairs
            // directly so a repeated parameter is refused, not silently picked.
            $params = [];
            foreach ($query === '' ? [] : explode('&', $query) as $pair) {
                [$key, $value] = array_pad(explode('=', $pair, 2), 2, '');
                $key = urldecode($key);
                if (($key === 'act_as_grant_id' || $key === 'nonce') && array_key_exists($key, $params)) {
                    throw new \InvalidArgumentException('callback repeats an act-as parameter');
                }
                $params[$key] = urldecode($value);
            }
        }
        $grantId = $params['act_as_grant_id'] ?? null;
        $nonce = $params['nonce'] ?? null;
        if (!is_string($grantId) || $grantId === '' || !is_string($nonce)) {
            throw new \InvalidArgumentException('callback needs act_as_grant_id and nonce');
        }
        if (!hash_equals($pending->nonce, $nonce)) {
            throw new LocalRpError(LocalRpError::NONCE_MISMATCH);
        }
        return $grantId;
    }

    /**
     * Fetch the grant, or a renewed grant, with `ActAs/refresh-grant` on the
     * user's home domain ({@see PendingActAs::$userDomain}). Uses the same
     * discovery and pinned TCP path as claim-ticket redemption.
     */
    public static function refreshActAsGrant(
        LocalRpKeyMaterial $keyMaterial,
        string $userDomain,
        string $grantId,
        \DateTimeImmutable $now,
        ?Transport $transport = null,
        ?DnsResolver $dns = null
    ): ActAsRefreshResult {
        if ($grantId === '') {
            throw new \InvalidArgumentException('grantId must not be empty');
        }
        $request = new ActAsRefreshRequest([
            'grant_id' => $grantId,
            'grantee' => self::localRpGrantee($keyMaterial),
            'requested_at' => self::formatTime($now),
            'expires_at' => self::formatTime($now->add(new \DateInterval('PT' . self::REFRESH_WINDOW_SECONDS . 'S'))),
            'nonce' => self::freshNonce(),
        ]);
        $signed = self::signRefreshRequest($request, $keyMaterial);
        $response = Rpc::refreshActAsGrant(
            $transport ?? new StdTransport(),
            $dns ?? new SystemDnsResolver(),
            $userDomain,
            $signed
        );
        self::checkReturnedGrant($response->grant->grant, $grantId, $userDomain, $keyMaterial);
        return new ActAsRefreshResult($response->grant, $response->signed);
    }

    /**
     * The audience checks the grant signature. This only checks that the home
     * domain returned the grant the call asked for, so a confused or hostile
     * server cannot hand this grantee another grant.
     */
    private static function checkReturnedGrant(string $grantBytes, string $grantId, string $userDomain, LocalRpKeyMaterial $keyMaterial): void
    {
        try {
            $grant = Cbor::decode($grantBytes);
        } catch (CborException $e) {
            throw new LocalRpError(LocalRpError::DECODE, 'refresh-grant grant: ' . $e->getMessage(), $e);
        }
        if (!is_array($grant) || ($grant['grant_id'] ?? null) !== $grantId) {
            throw new LocalRpError(LocalRpError::GRANT_MISMATCH, 'refresh-grant returned another grant id');
        }
        $grantee = $grant['grantee'] ?? null;
        if (!is_array($grantee) || array_key_exists('application', $grantee)
            || ($grantee['local_rp_descriptor_fingerprint'] ?? null) !== $keyMaterial->fingerprint) {
            throw new LocalRpError(LocalRpError::GRANT_MISMATCH, 'refresh-grant returned a grant for another grantee');
        }
        $domain = $grant['subject_domain'] ?? null;
        // strtolower folds ASCII only (PHP 8.2+), like the other SDKs.
        if (!is_string($domain) || strtolower($domain) !== strtolower($userDomain)) {
            throw new LocalRpError(LocalRpError::GRANT_MISMATCH, 'refresh-grant returned a grant from another subject domain');
        }
    }

    /**
     * Build and sign the `ActAsCredential` for one call to the audience.
     * `$requestDigest` is defined by the audience's protocol. Use a fresh
     * `$nonce` per call. Pure.
     */
    public static function present(
        SignedActAsGrant $grant,
        ApplicationRef $audience,
        string $requestDigest,
        \DateTimeImmutable $now,
        string $nonce,
        LocalRpKeyMaterial $keyMaterial
    ): ActAsPresentationResult {
        $presentation = new ActAsPresentation([
            'grant_hash' => self::grantHash($grant->grant),
            'audience' => $audience,
            'request_digest' => $requestDigest,
            'presented_at' => self::formatTime($now),
            'nonce' => $nonce,
        ]);
        $bytes = ActAsWire::encodeActAsPresentation($presentation);
        $credential = new ActAsCredential([
            'grant' => $grant,
            'presentation' => new SignedActAsPresentation([
                'presentation' => $bytes,
                'proof' => self::prove($keyMaterial, self::PRESENTATION_TAG, $bytes),
            ]),
        ]);
        return new ActAsPresentationResult($credential, ActAsWire::encodeActAsCredential($credential));
    }
}

/** Input to {@see ActAs::beginActAs}. */
final class BeginActAsConfig
{
    public LocalRpKeyMaterial $keyMaterial;
    /** The user's login or domain. Only the domain is used. */
    public string $userDomain;
    /** The audience's `SignedActAsScopeSet` as CBOR bytes, exactly as the audience sent it. */
    public string $scopeSet;
    /** Where the home domain sends the browser back. Must be `http://` or `https://`. */
    public string $callbackUrl;
    public \DateTimeImmutable $now;
    public ?int $requestedLifetimeSeconds;
    public ?int $requestedRenewalWindowSeconds;
    /** `null` means `new SystemDnsResolver()`. */
    public ?DnsResolver $dns;
    /** Request window in seconds. Default 300, maximum 900. */
    public int $requestWindowSeconds;

    public function __construct(
        LocalRpKeyMaterial $keyMaterial,
        string $userDomain,
        string $scopeSet,
        string $callbackUrl,
        \DateTimeImmutable $now,
        ?int $requestedLifetimeSeconds = null,
        ?int $requestedRenewalWindowSeconds = null,
        ?DnsResolver $dns = null,
        int $requestWindowSeconds = ActAs::DEFAULT_REQUEST_WINDOW_SECONDS
    ) {
        $this->keyMaterial = $keyMaterial;
        $this->userDomain = $userDomain;
        $this->scopeSet = $scopeSet;
        $this->callbackUrl = $callbackUrl;
        $this->now = $now;
        $this->requestedLifetimeSeconds = $requestedLifetimeSeconds;
        $this->requestedRenewalWindowSeconds = $requestedRenewalWindowSeconds;
        $this->dns = $dns;
        $this->requestWindowSeconds = $requestWindowSeconds;
    }
}

final class ActAsRedirect
{
    public string $redirectUrl;

    public function __construct(string $redirectUrl)
    {
        $this->redirectUrl = $redirectUrl;
    }
}

/** State to keep between {@see ActAs::beginActAs} and {@see ActAs::completeActAsCallback}. Single-use. */
final class PendingActAs
{
    public string $nonce;
    public string $userDomain;
    public string $callbackUrl;

    public function __construct(string $nonce, string $userDomain, string $callbackUrl)
    {
        $this->nonce = $nonce;
        $this->userDomain = $userDomain;
        $this->callbackUrl = $callbackUrl;
    }

    /** @return array<string,string> */
    public function toArray(): array
    {
        return ['nonce' => $this->nonce, 'user_domain' => $this->userDomain, 'callback_url' => $this->callbackUrl];
    }

    /** @param array<string,string> $a */
    public static function fromArray(array $a): self
    {
        return new self($a['nonce'], $a['user_domain'], $a['callback_url']);
    }
}

final class ActAsRefreshResult
{
    public SignedActAsGrant $grant;
    /** True when the home domain made a new signature for this call. */
    public bool $signed;

    public function __construct(SignedActAsGrant $grant, bool $signed)
    {
        $this->grant = $grant;
        $this->signed = $signed;
    }
}

final class ActAsPresentationResult
{
    public ActAsCredential $credential;
    public string $credentialCbor;

    public function __construct(ActAsCredential $credential, string $credentialCbor)
    {
        $this->credential = $credential;
        $this->credentialCbor = $credentialCbor;
    }
}

/**
 * Hand-written CBOR (de)serialization for the act-as types, for the same
 * reason as {@see Wire}. Every map is emitted in canonical key order (shorter
 * key first, then bytewise), the order the generated Rust codec uses, so the
 * bytes match `sdks/regular-rp/conformance/act_as_grantee_signing.json`.
 * Optional fields are left out when absent. The decoders check value types,
 * because these maps come from an audience or a home domain.
 */
final class ActAsWire
{
    /**
     * @param array<string,mixed> $m
     * @return array<string,mixed>
     */
    private static function canonical(array $m): array
    {
        uksort($m, fn ($a, $b) => strlen((string) $a) <=> strlen((string) $b) ?: strcmp((string) $a, (string) $b));
        return $m;
    }

    /** @return array<string,mixed> */
    private static function map($v, string $name): array
    {
        if (!is_array($v) || ($v !== [] && array_is_list($v))) {
            throw new CborException("{$name}: expected a CBOR map");
        }
        return $v;
    }

    private static function text(array $m, string $key, bool $optional = false): ?string
    {
        $v = $m[$key] ?? null;
        if ($v === null && $optional) {
            return null;
        }
        if (!is_string($v)) {
            throw new CborException("{$key}: expected a string");
        }
        return $v;
    }

    private static function int(array $m, string $key, bool $optional = false): ?int
    {
        $v = $m[$key] ?? null;
        if ($v === null && $optional) {
            return null;
        }
        if (!is_int($v)) {
            throw new CborException("{$key}: expected an integer");
        }
        return $v;
    }

    /** @return array<int,mixed> */
    private static function listOf(array $m, string $key): array
    {
        $v = $m[$key] ?? null;
        if (!is_array($v) || ($v !== [] && !array_is_list($v))) {
            throw new CborException("{$key}: expected an array");
        }
        return $v;
    }

    /**
     * Decode a top-level map and check that each named field has the given
     * CBOR major type (2 = bytes, 3 = text), because {@see Cbor::decode}
     * returns both as a PHP string.
     *
     * @param array<string,int> $majors
     * @return array<string,mixed>
     */
    private static function decodeTyped(string $bytes, string $name, array $majors): array
    {
        [$m, $types] = Cbor::decodeMapWithValueTypes($bytes);
        foreach ($majors as $key => $major) {
            if (array_key_exists($key, $types) && $types[$key] !== $major) {
                throw new CborException("{$name}.{$key}: wrong CBOR type");
            }
        }
        return $m;
    }

    // ---- ApplicationRef / GranteeRef / ApplicationKeySignature / GranteeProof

    /** @return array<string,mixed> */
    public static function applicationRefToMap(ApplicationRef $v): array
    {
        return self::canonical([
            'subject_user_id' => $v->subjectUserId,
            'subject_domain' => $v->subjectDomain,
            'application_id' => $v->applicationId,
        ]);
    }

    public static function applicationRefFromMap($m): ApplicationRef
    {
        $m = self::map($m, 'ApplicationRef');
        return new ApplicationRef([
            'subject_user_id' => self::text($m, 'subject_user_id'),
            'subject_domain' => self::text($m, 'subject_domain'),
            'application_id' => self::text($m, 'application_id'),
        ]);
    }

    /** @return array<string,mixed> */
    public static function granteeRefToMap(GranteeRef $v): array
    {
        $out = [];
        if ($v->application !== null) {
            $out['application'] = self::applicationRefToMap($v->application);
        }
        if ($v->localRpDescriptorFingerprint !== null) {
            $out['local_rp_descriptor_fingerprint'] = $v->localRpDescriptorFingerprint;
        }
        return self::canonical($out);
    }

    public static function granteeRefFromMap($m): GranteeRef
    {
        $m = self::map($m, 'GranteeRef');
        return new GranteeRef([
            'application' => isset($m['application']) ? self::applicationRefFromMap($m['application']) : null,
            'local_rp_descriptor_fingerprint' => self::text($m, 'local_rp_descriptor_fingerprint', true),
        ]);
    }

    /** @return array<string,mixed> */
    public static function applicationKeySignatureToMap(ApplicationKeySignature $v): array
    {
        return self::canonical([
            'signed_by_key_id' => $v->signedByKeyId,
            'signature' => Cbor::bytes($v->signature),
        ]);
    }

    public static function applicationKeySignatureFromMap($m): ApplicationKeySignature
    {
        $m = self::map($m, 'ApplicationKeySignature');
        return new ApplicationKeySignature([
            'signed_by_key_id' => self::text($m, 'signed_by_key_id'),
            'signature' => self::text($m, 'signature'),
        ]);
    }

    /** @return array<string,mixed> */
    private static function signedLocalRpDescriptorToMap(SignedLocalRpDescriptor $v): array
    {
        return self::canonical([
            'descriptor' => Cbor::bytes($v->descriptor),
            'signature' => Cbor::bytes($v->signature),
        ]);
    }

    /** @return array<string,mixed> */
    public static function granteeProofToMap(GranteeProof $v): array
    {
        $out = ['signature' => self::applicationKeySignatureToMap($v->signature)];
        if ($v->applicationInstanceId !== null) {
            $out['application_instance_id'] = $v->applicationInstanceId;
        }
        if ($v->localRpDescriptor !== null) {
            $out['local_rp_descriptor'] = self::signedLocalRpDescriptorToMap($v->localRpDescriptor);
        }
        return self::canonical($out);
    }

    public static function granteeProofFromMap($m): GranteeProof
    {
        $m = self::map($m, 'GranteeProof');
        $descriptor = null;
        if (isset($m['local_rp_descriptor'])) {
            $d = self::map($m['local_rp_descriptor'], 'SignedLocalRpDescriptor');
            $descriptor = new SignedLocalRpDescriptor([
                'descriptor' => self::text($d, 'descriptor'),
                'signature' => self::text($d, 'signature'),
            ]);
        }
        return new GranteeProof([
            'application_instance_id' => self::text($m, 'application_instance_id', true),
            'local_rp_descriptor' => $descriptor,
            'signature' => self::applicationKeySignatureFromMap($m['signature'] ?? null),
        ]);
    }

    // ---- SignedActAsScopeSet

    /** @return array<string,mixed> */
    public static function signedActAsScopeSetToMap(SignedActAsScopeSet $v): array
    {
        return self::canonical([
            'scope_set' => Cbor::bytes($v->scopeSet),
            'signer_instance_id' => $v->signerInstanceId,
            'signatures' => array_map(
                fn (ApplicationKeySignature $s) => self::applicationKeySignatureToMap($s),
                $v->signatures
            ),
        ]);
    }

    public static function decodeSignedActAsScopeSet(string $bytes): SignedActAsScopeSet
    {
        [$m, $types, $spans] = Cbor::decodeMapWithValueTypes($bytes);
        if (($types['scope_set'] ?? null) !== 2 || ($types['signer_instance_id'] ?? null) !== 3 || ($types['signatures'] ?? null) !== 4) {
            throw new CborException('SignedActAsScopeSet: malformed');
        }
        // Check each nested signature's types on its own exact bytes.
        $signatures = [];
        foreach (Cbor::decodeArraySpans($spans['signatures']) as $span) {
            $sig = self::decodeTyped($span, 'ApplicationKeySignature', ['signature' => 2, 'signed_by_key_id' => 3]);
            $signatures[] = self::applicationKeySignatureFromMap($sig);
        }
        if ($signatures === []) {
            throw new CborException('SignedActAsScopeSet.signatures: expected at least one signature');
        }
        return new SignedActAsScopeSet([
            'scope_set' => $m['scope_set'],
            'signer_instance_id' => $m['signer_instance_id'],
            'signatures' => $signatures,
        ]);
    }

    public static function encodeSignedActAsScopeSet(SignedActAsScopeSet $v): string
    {
        return Cbor::encodeMap(self::signedActAsScopeSetToMap($v));
    }

    // ---- Grant request

    public static function encodeActAsGrantRequest(ActAsGrantRequest $v): string
    {
        $out = [
            'grantee' => self::granteeRefToMap($v->grantee),
            'scope_set' => self::signedActAsScopeSetToMap($v->scopeSet),
            'callback_url' => $v->callbackUrl,
            'nonce' => $v->nonce,
            'requested_at' => $v->requestedAt,
            'expires_at' => $v->expiresAt,
        ];
        if ($v->requestedLifetimeSeconds !== null) {
            $out['requested_lifetime_seconds'] = $v->requestedLifetimeSeconds;
        }
        if ($v->requestedRenewalWindowSeconds !== null) {
            $out['requested_renewal_window_seconds'] = $v->requestedRenewalWindowSeconds;
        }
        // `grantee_handle_claim` is never sent: it is a handle claim about the
        // account that enrolled an application grantee, and a local RP has none.
        return Cbor::encodeMap(self::canonical($out));
    }

    public static function decodeActAsGrantRequest(string $bytes): ActAsGrantRequest
    {
        $m = self::map(Cbor::decode($bytes), 'ActAsGrantRequest');
        $scopeSet = self::map($m['scope_set'] ?? null, 'SignedActAsScopeSet');
        return new ActAsGrantRequest([
            'grantee' => self::granteeRefFromMap($m['grantee'] ?? null),
            'scope_set' => new SignedActAsScopeSet([
                'scope_set' => self::text($scopeSet, 'scope_set'),
                'signer_instance_id' => self::text($scopeSet, 'signer_instance_id'),
                'signatures' => array_map(
                    fn ($s) => self::applicationKeySignatureFromMap($s),
                    self::listOf($scopeSet, 'signatures')
                ),
            ]),
            'requested_lifetime_seconds' => self::int($m, 'requested_lifetime_seconds', true),
            'requested_renewal_window_seconds' => self::int($m, 'requested_renewal_window_seconds', true),
            'callback_url' => self::text($m, 'callback_url'),
            'nonce' => self::text($m, 'nonce'),
            'requested_at' => self::text($m, 'requested_at'),
            'expires_at' => self::text($m, 'expires_at'),
        ]);
    }

    public static function encodeSignedActAsGrantRequest(SignedActAsGrantRequest $v): string
    {
        return Cbor::encodeMap(self::canonical([
            'request' => Cbor::bytes($v->request),
            'proof' => self::granteeProofToMap($v->proof),
        ]));
    }

    public static function decodeSignedActAsGrantRequest(string $bytes): SignedActAsGrantRequest
    {
        $m = self::map(Cbor::decode($bytes), 'SignedActAsGrantRequest');
        return new SignedActAsGrantRequest([
            'request' => self::text($m, 'request'),
            'proof' => self::granteeProofFromMap($m['proof'] ?? null),
        ]);
    }

    // ---- Refresh request / response

    public static function encodeActAsRefreshRequest(ActAsRefreshRequest $v): string
    {
        return Cbor::encodeMap(self::canonical([
            'grant_id' => $v->grantId,
            'grantee' => self::granteeRefToMap($v->grantee),
            'requested_at' => $v->requestedAt,
            'expires_at' => $v->expiresAt,
            'nonce' => $v->nonce,
        ]));
    }

    public static function decodeActAsRefreshRequest(string $bytes): ActAsRefreshRequest
    {
        $m = self::map(Cbor::decode($bytes), 'ActAsRefreshRequest');
        return new ActAsRefreshRequest([
            'grant_id' => self::text($m, 'grant_id'),
            'grantee' => self::granteeRefFromMap($m['grantee'] ?? null),
            'requested_at' => self::text($m, 'requested_at'),
            'expires_at' => self::text($m, 'expires_at'),
            'nonce' => self::text($m, 'nonce'),
        ]);
    }

    /** @return array<string,mixed> */
    private static function signedActAsRefreshRequestToMap(SignedActAsRefreshRequest $v): array
    {
        return self::canonical([
            'request' => Cbor::bytes($v->request),
            'proof' => self::granteeProofToMap($v->proof),
        ]);
    }

    public static function encodeSignedActAsRefreshRequest(SignedActAsRefreshRequest $v): string
    {
        return Cbor::encodeMap(self::signedActAsRefreshRequestToMap($v));
    }

    /** `RefreshActAsGrantRequest { request }`. */
    public static function encodeRefreshActAsGrantRequest(SignedActAsRefreshRequest $request): string
    {
        return Cbor::encodeMap(['request' => self::signedActAsRefreshRequestToMap($request)]);
    }

    /** Decode `RefreshActAsGrantRequest` and return its signed request. */
    public static function decodeRefreshActAsGrantRequest(string $bytes): SignedActAsRefreshRequest
    {
        $m = self::map(Cbor::decode($bytes), 'RefreshActAsGrantRequest');
        $r = self::map($m['request'] ?? null, 'SignedActAsRefreshRequest');
        return new SignedActAsRefreshRequest([
            'request' => self::text($r, 'request'),
            'proof' => self::granteeProofFromMap($r['proof'] ?? null),
        ]);
    }

    // ---- SignedActAsGrant

    /** @return array<string,mixed> */
    public static function signedActAsGrantToMap(SignedActAsGrant $v): array
    {
        return self::canonical([
            'grant' => Cbor::bytes($v->grant),
            'signatures' => array_map(fn (ClaimSignature $s) => self::canonical(Wire::encodeClaimSignature($s)), $v->signatures),
        ]);
    }

    public static function encodeSignedActAsGrant(SignedActAsGrant $v): string
    {
        return Cbor::encodeMap(self::signedActAsGrantToMap($v));
    }

    /** Decode `SignedActAsGrant`. `grant` stays the exact signed bytes. */
    public static function decodeSignedActAsGrant(string $bytes): SignedActAsGrant
    {
        $m = self::decodeTyped($bytes, 'SignedActAsGrant', ['grant' => 2, 'signatures' => 4]);
        $signatures = [];
        foreach ($m['signatures'] ?? [] as $s) {
            $s = self::map($s, 'ClaimSignature');
            $signatures[] = new ClaimSignature([
                'domain' => self::text($s, 'domain'),
                'signed_by_key_id' => self::text($s, 'signed_by_key_id'),
                'signature' => self::text($s, 'signature'),
            ]);
        }
        return new SignedActAsGrant(['grant' => self::text($m, 'grant'), 'signatures' => $signatures]);
    }

    public static function encodeRefreshActAsGrantResponse(RefreshActAsGrantResponse $v): string
    {
        return Cbor::encodeMap(self::canonical([
            'grant' => self::signedActAsGrantToMap($v->grant),
            'signed' => (bool) $v->signed,
        ]));
    }

    public static function decodeRefreshActAsGrantResponse(string $bytes): RefreshActAsGrantResponse
    {
        [$m, $types, $spans] = Cbor::decodeMapWithValueTypes($bytes);
        if (!is_bool($m['signed'] ?? null) || ($types['grant'] ?? null) !== 5) {
            throw new CborException('RefreshActAsGrantResponse: malformed');
        }
        return new RefreshActAsGrantResponse([
            'grant' => self::decodeSignedActAsGrant($spans['grant']),
            'signed' => $m['signed'],
        ]);
    }

    // ---- Presentation / credential

    /** @return array<string,mixed> */
    private static function actAsPresentationToMap(ActAsPresentation $v): array
    {
        return self::canonical([
            'grant_hash' => Cbor::bytes($v->grantHash),
            'audience' => self::applicationRefToMap($v->audience),
            'request_digest' => Cbor::bytes($v->requestDigest),
            'presented_at' => $v->presentedAt,
            'nonce' => Cbor::bytes($v->nonce),
        ]);
    }

    public static function encodeActAsPresentation(ActAsPresentation $v): string
    {
        return Cbor::encodeMap(self::actAsPresentationToMap($v));
    }

    public static function encodeActAsCredential(ActAsCredential $v): string
    {
        return Cbor::encodeMap(self::canonical([
            'grant' => self::signedActAsGrantToMap($v->grant),
            'presentation' => self::canonical([
                'presentation' => Cbor::bytes($v->presentation->presentation),
                'proof' => self::granteeProofToMap($v->presentation->proof),
            ]),
        ]));
    }
}
