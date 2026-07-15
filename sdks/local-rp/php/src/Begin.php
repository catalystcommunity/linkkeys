<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

/**
 * `beginLocalLogin` (design doc: "SDK API Shape", "Flow" steps 4-6).
 *
 * Pure/offline: no network access happens here. It generates a fresh
 * nonce/state, builds and signs a `LocalRpLoginRequest` around the
 * identity's already-signed descriptor, and returns a redirect URL plus the
 * pending-login state the app must persist and treat as single-use.
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
     * @return array{0: LocalLoginRedirect, 1: PendingLogin}
     */
    public static function beginLocalLogin(BeginLocalLoginConfig $config): array
    {
        self::validateCallbackScheme($config->callbackUrl);
        if (trim($config->userDomain) === '') {
            throw new \InvalidArgumentException('user_domain must not be empty');
        }

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

        // Wire Precision: "Begin route: GET /auth/local-rp?signed_request=<...>".
        $redirectUrl = "https://{$config->userDomain}/auth/local-rp?signed_request={$encoded}";

        return [
            new LocalLoginRedirect($redirectUrl),
            new PendingLogin($nonce, $state, $config->userDomain, $config->callbackUrl, $requiredClaims),
        ];
    }

    private static function validateCallbackScheme(string $url): void
    {
        if (!str_starts_with($url, 'http://') && !str_starts_with($url, 'https://')) {
            throw new \InvalidArgumentException("callback_url must be http:// or https://, got: {$url}");
        }
    }
}

/** Input to {@see Begin::beginLocalLogin}. Big-config, single struct. */
final class BeginLocalLoginConfig
{
    public LocalRpKeyMaterial $keyMaterial;
    public string $callbackUrl;
    public string $userDomain;
    /** @var string[]|null */
    public ?array $requestedClaims;
    /** @var string[]|null */
    public ?array $requiredClaims;
    public ?int $requestLifetimeSeconds;
    public \DateTimeImmutable $now;

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
        ?int $requestLifetimeSeconds = null
    ) {
        $this->keyMaterial = $keyMaterial;
        $this->callbackUrl = $callbackUrl;
        $this->userDomain = $userDomain;
        $this->now = $now;
        $this->requestedClaims = $requestedClaims;
        $this->requiredClaims = $requiredClaims;
        $this->requestLifetimeSeconds = $requestLifetimeSeconds;
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
