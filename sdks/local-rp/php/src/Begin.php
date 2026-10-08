<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

/**
 * `beginLocalLogin` (design doc: "SDK API Shape", "Flow" steps 4-6).
 * Mirrors `sdks/local-rp/go/begin.go`.
 *
 * It generates a fresh nonce/state, builds and signs a `LocalRpLoginRequest`
 * around the identity's already-signed descriptor, and returns a redirect
 * URL plus the pending-login state the app must persist and treat as
 * single-use.
 *
 * The signing work is pure/offline. The one network touch is a DNS TXT
 * lookup of `_linkkeys_apis.<userDomain>` to discover the browser-facing
 * HTTPS endpoint (the identity domain is a trust domain, not necessarily
 * the host serving the login routes). The resolver is injectable via
 * {@see BeginLocalLoginConfig::$dns}; on any discovery failure the redirect
 * falls back to `https://<userDomain>`.
 */
final class Begin
{
    /** Default requested claims when the caller doesn't specify any (design doc, "Default Claim Set"). */
    public const DEFAULT_REQUESTED_CLAIMS = ['display_name', 'email', 'handle'];
    /** Default required claims (design doc, "Default Claim Set"). */
    public const DEFAULT_REQUIRED_CLAIMS = ['handle'];
    /** Default login-request lifetime in seconds: short-lived, matching the callback's own default lifetime. */
    public const DEFAULT_LOGIN_REQUEST_LIFETIME_SECONDS = 300;

    /**
     * `beginLocalLogin(config) -> [LocalLoginRedirect, PendingLogin]`
     * (design doc, "SDK API Shape"). Generates a fresh nonce/state, builds
     * and signs a `LocalRpLoginRequest`, and returns the full redirect URL
     * for the user's LinkKeys domain plus the pending-login state.
     *
     * The redirect host comes from a `_linkkeys_apis` DNS TXT lookup (see
     * the class docblock). The lookup never fails the call: on any
     * discovery failure the redirect falls back to `https://<userDomain>`.
     *
     * @return array{0: LocalLoginRedirect, 1: PendingLogin}
     */
    public static function beginLocalLogin(BeginLocalLoginConfig $config): array
    {
        self::validateCallbackScheme($config->callbackUrl);
        [$username, $domain] = self::parseIdentityInput($config->userDomain);

        $nonce = random_bytes(32);
        $state = random_bytes(32);

        $requestedClaims = $config->requestedClaims ?? self::DEFAULT_REQUESTED_CLAIMS;
        $requiredClaims = $config->requiredClaims ?? self::DEFAULT_REQUIRED_CLAIMS;
        $lifetimeSeconds = $config->requestLifetimeSeconds ?? self::DEFAULT_LOGIN_REQUEST_LIFETIME_SECONDS;
        $issuedAt = Time::toRfc3339($config->now);
        $expiresAt = Time::toRfc3339($config->now->add(new \DateInterval('PT' . $lifetimeSeconds . 'S')));

        $request = LocalRp::buildLocalRpLoginRequest(
            $config->keyMaterial->descriptor,
            $config->callbackUrl,
            $nonce,
            $state,
            $requestedClaims,
            $requiredClaims,
            $issuedAt,
            $expiresAt
        );
        $signed = LocalRp::signLocalRpLoginRequest($request, $config->keyMaterial->signingPrivateKey);

        $encoded = Encoding::signedLocalRpLoginRequestToUrlParam($signed);

        // Wire Precision: "Begin route: GET /auth/local-rp?signed_request=<...>"
        // — mirrors the existing GET /auth/authorize?signed_request=... shape.
        // The host comes from `_linkkeys_apis.<userDomain>` discovery (with a
        // fallback to the identity domain itself); PendingLogin::$userDomain
        // stays the identity domain — verification is bound to it, never to
        // the discovered service host.
        $dns = $config->dns ?? new SystemDnsResolver();
        $redirectUrl = Browser::resolveBrowserEndpoint($dns, $domain, Browser::ROUTE_LOCAL_RP, $encoded);
        if ($username !== null) {
            $redirectUrl = self::appendQueryParam($redirectUrl, 'username', $username);
        }

        return [
            new LocalLoginRedirect($redirectUrl),
            new PendingLogin($nonce, $state, $domain, $config->callbackUrl, $requiredClaims),
        ];
    }

    /** Add one query parameter to an already-built URL with `parse_url()` + `http_build_query()`. */
    private static function appendQueryParam(string $url, string $name, string $value): string
    {
        $u = parse_url($url);
        if ($u === false || !isset($u['scheme'], $u['host'])) {
            throw new \InvalidArgumentException('browser endpoint produced an invalid URL');
        }
        parse_str($u['query'] ?? '', $query);
        $query[$name] = $value;
        return Browser::unparseUrl($u, $u['path'] ?? '', http_build_query($query, '', '&', PHP_QUERY_RFC3986));
    }

    /** @internal Shared with {@see ActAs::beginActAs}. */
    public static function validateCallbackScheme(string $url): void
    {
        if (!str_starts_with($url, 'http://') && !str_starts_with($url, 'https://')) {
            throw new \InvalidArgumentException("callback_url must be http:// or https://, got: {$url}");
        }
    }

    /**
     * @internal Shared with {@see ActAs::beginActAs}.
     * @return array{0: ?string, 1: string}
     */
    public static function parseIdentityInput(string $value): array
    {
        $identity = trim($value);
        if ($identity === '' || preg_match('/[^\x00-\x7F]/', $identity) === 1 || substr_count($identity, '@') > 1) {
            throw new \InvalidArgumentException('identity must be a username@domain or a domain');
        }
        $parts = explode('@', $identity, 2);
        $username = count($parts) === 2 ? $parts[0] : null;
        $domain = count($parts) === 2 ? $parts[1] : $parts[0];
        if ($username !== null && preg_match("/^(?!\\.)(?!.*\\.\\.)[A-Za-z0-9!#$%&'*+\\-\\/=?^_`{|}~.]{1,64}(?<!\\.)$/D", $username) !== 1) {
            throw new \InvalidArgumentException('identity must be a username@domain or a domain');
        }
        if (preg_match('/^([^:]+)(?::([0-9]+))?$/D', $domain, $match) !== 1) {
            throw new \InvalidArgumentException('identity must be a username@domain or a domain');
        }
        $host = $match[1];
        $port = isset($match[2]) ? (int) $match[2] : null;
        $validHost = strlen($host) <= 253 && (str_contains($host, '.') || $port !== null);
        foreach (explode('.', $host) as $label) {
            $validHost = $validHost && strlen($label) >= 1 && strlen($label) <= 63
                && preg_match('/^(?!-)[A-Za-z0-9-]+(?<!-)$/D', $label) === 1;
        }
        if (!$validHost || strlen($domain) > 259 || ($port !== null && ($port < 1 || $port > 65535))) {
            throw new \InvalidArgumentException('identity must be a username@domain or a domain');
        }
        return [$username, strtolower($domain)];
    }
}

/** Input to {@see Begin::beginLocalLogin}. Big-config, single struct. */
final class BeginLocalLoginConfig
{
    public LocalRpKeyMaterial $keyMaterial;
    public string $callbackUrl;
    /** A LinkKeys login or domain. A full login adds a username hint. */
    public string $userDomain;
    /** @var string[]|null */
    public ?array $requestedClaims;
    /** @var string[]|null */
    public ?array $requiredClaims;
    public ?int $requestLifetimeSeconds;
    public \DateTimeImmutable $now;
    /**
     * The DNS TXT lookup seam for browser endpoint discovery
     * (`_linkkeys_apis.<userDomain>`, its `https=` endpoint). `null` means
     * `new SystemDnsResolver()`, same as {@see CompleteLocalLoginConfig::$dns}.
     */
    public ?DnsResolver $dns;

    /**
     * @param string[]|null $requestedClaims
     * @param string[]|null $requiredClaims
     */
    public function __construct(
        LocalRpKeyMaterial $keyMaterial,
        string $callbackUrl,
        string $userDomain,
        \DateTimeImmutable $now,
        ?array $requestedClaims = null,
        ?array $requiredClaims = null,
        ?int $requestLifetimeSeconds = null,
        ?DnsResolver $dns = null
    ) {
        $this->keyMaterial = $keyMaterial;
        $this->callbackUrl = $callbackUrl;
        $this->userDomain = $userDomain;
        $this->now = $now;
        $this->requestedClaims = $requestedClaims;
        $this->requiredClaims = $requiredClaims;
        $this->requestLifetimeSeconds = $requestLifetimeSeconds;
        $this->dns = $dns;
    }
}

/**
 * The redirect URL the app should send the user's browser to. The SDK never
 * performs the redirect itself (design doc: "Browser-only Flow").
 */
final class LocalLoginRedirect
{
    public string $redirectUrl;

    public function __construct(string $redirectUrl)
    {
        $this->redirectUrl = $redirectUrl;
    }
}

/**
 * The state `beginLocalLogin` returns for the app to persist (e.g. in a
 * server-side session tied to the browser) and pass unchanged to
 * `completeLocalLogin`. **Single-use**: the app must discard it after one
 * completion attempt — this class cannot enforce that itself (it owns no
 * storage).
 */
final class PendingLogin
{
    public string $nonce;
    public string $state;
    public string $userDomain;
    public string $callbackUrl;
    /**
     * The claim types `completeLocalLogin` must enforce are present (and
     * signature-verified) before returning success — retained from
     * `beginLocalLogin`'s `required_claims` so completion doesn't merely
     * trust whatever the IDP claims it enforced (design doc, "Post-
     * implementation security review", item 3).
     *
     * @var string[]
     */
    public array $requiredClaims;

    /** @param string[] $requiredClaims */
    public function __construct(string $nonce, string $state, string $userDomain, string $callbackUrl, array $requiredClaims = [])
    {
        $this->nonce = $nonce;
        $this->state = $state;
        $this->userDomain = $userDomain;
        $this->callbackUrl = $callbackUrl;
        $this->requiredClaims = $requiredClaims;
    }

    /** Serialize to a plain associative array (e.g. for a PHP session or JSON storage). */
    public function toArray(): array
    {
        return [
            'nonce' => base64_encode($this->nonce),
            'state' => base64_encode($this->state),
            'user_domain' => $this->userDomain,
            'callback_url' => $this->callbackUrl,
            'required_claims' => $this->requiredClaims,
        ];
    }

    public static function fromArray(array $a): self
    {
        return new self(
            base64_decode($a['nonce']),
            base64_decode($a['state']),
            $a['user_domain'],
            $a['callback_url'],
            $a['required_claims'] ?? []
        );
    }
}
