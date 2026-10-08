<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

/**
 * Browser endpoint discovery: resolve an identity domain's browser-facing
 * HTTPS base from its `_linkkeys_apis` TXT record, and build browser route
 * URLs against it. Mirrors `sdks/local-rp/go/browser.go`.
 *
 * The identity domain (the domain the user selected, e.g. `todandlorna.com`)
 * is a trust and discovery domain. It is not necessarily the host that
 * serves the browser login routes — the `https=` endpoint of
 * `_linkkeys_apis.<identity-domain>` is (docs/spec/trust-and-anchors.md:
 * "`https=` is the browser-facing endpoint"). These helpers are shared by
 * {@see Begin::beginLocalLogin} (route {@see Browser::ROUTE_LOCAL_RP}) and
 * by regular-RP application glue (route {@see Browser::ROUTE_AUTHORIZE}), so
 * discovery is implemented once.
 */
final class Browser
{
    /** The browser route for the DNS-less local-RP login flow. */
    public const ROUTE_LOCAL_RP = '/auth/local-rp';

    /** The browser route for the regular (domain-keyed) RP login flow. */
    public const ROUTE_AUTHORIZE = '/auth/authorize';

    /** The browser route where a grantee asks the user for an act-as grant. */
    public const ROUTE_ACT_AS = '/auth/act-as';

    /**
     * Check that `$base` is a usable https browser base URL: parseable,
     * https scheme, a host, an optional path prefix, and nothing else. A
     * TXT record value must never smuggle in userinfo, a query, a fragment,
     * or (via {@see Dns::parseLinkKeysApisTxt}'s unconditional `https://`
     * prefix plus this check) a non-HTTPS scheme.
     *
     * @return array{scheme: string, host: string, port?: int, path?: string}
     */
    private static function validateBrowserBase(string $base): array
    {
        $u = parse_url($base);
        if ($u === false) {
            throw new \InvalidArgumentException("browser base \"{$base}\" is not a valid URL");
        }
        if (($u['scheme'] ?? '') !== 'https') {
            throw new \InvalidArgumentException("browser base \"{$base}\" must use https");
        }
        if (($u['host'] ?? '') === '') {
            throw new \InvalidArgumentException("browser base \"{$base}\" has no host");
        }
        if (isset($u['user']) || isset($u['pass']) || isset($u['query']) || isset($u['fragment'])
            || str_contains($base, '?') || str_contains($base, '#')) {
            throw new \InvalidArgumentException("browser base \"{$base}\" must be host[:port][/path] only");
        }
        return $u;
    }

    /**
     * Resolve `$identityDomain`'s browser-facing HTTPS base URL (e.g.
     * `https://linkkeys.todandlorna.com` or
     * `https://login.example.com/linkkeys`) from its
     * `_linkkeys_apis.<identityDomain>` TXT record.
     *
     * Selects the first LinkKeys v1 record whose `https=` endpoint is a
     * valid browser base; invalid TXT records and records without `https=`
     * are skipped. Throws when the lookup fails (the resolver's own
     * exception propagates) or when no record yields a valid base
     * ({@see DnsParseError} with kind `MISSING_APIS_ENDPOINT`) — the caller
     * decides the fallback ({@see Begin::beginLocalLogin} falls back to
     * `https://<identityDomain>`).
     *
     * The resolved base is a service location only. Identity verification
     * stays bound to the identity domain — never bind trust decisions to
     * the host this returns.
     */
    public static function resolveBrowserBase(DnsResolver $dns, string $identityDomain): string
    {
        $name = Dns::linkkeysApisDnsName($identityDomain);
        foreach ($dns->txtLookup($name) as $txt) {
            try {
                $httpsBase = Dns::parseLinkKeysApisTxt($txt)['https_base'];
            } catch (DnsParseError $e) {
                continue;
            }
            if ($httpsBase === null) {
                continue;
            }
            try {
                self::validateBrowserBase($httpsBase);
            } catch (\InvalidArgumentException $e) {
                continue;
            }
            return $httpsBase;
        }
        throw new DnsParseError(DnsParseError::MISSING_APIS_ENDPOINT, "no usable {$name} TXT record with an https= endpoint");
    }

    /**
     * Build the full browser URL for `$route` (e.g. {@see Browser::ROUTE_LOCAL_RP})
     * under `$browserBase`, carrying `$signedRequest` as the `signed_request`
     * query parameter. A path prefix in the base is preserved: base
     * `https://login.example.com/linkkeys` and route `/auth/local-rp`
     * produce `https://login.example.com/linkkeys/auth/local-rp?...`.
     *
     * The URL is assembled from `parse_url()` parts plus
     * `http_build_query()`. `signed_request` values are URL-param-encoded
     * (unpadded base64url) by construction, so RFC 3986 query encoding
     * passes them through byte-identically.
     */
    public static function buildBrowserEndpoint(string $browserBase, string $route, string $signedRequest): string
    {
        $u = self::validateBrowserBase($browserBase);
        if (!str_starts_with($route, '/')) {
            throw new \InvalidArgumentException("route \"{$route}\" must start with /");
        }
        $path = rtrim($u['path'] ?? '', '/') . $route;
        $query = http_build_query(['signed_request' => $signedRequest], '', '&', PHP_QUERY_RFC3986);
        return self::unparseUrl($u, $path, $query);
    }

    /**
     * The begin-flow composition: discover the identity domain's browser
     * base and build the route URL, falling back to `https://<identityDomain>`
     * when DNS lookup fails, no valid record carries `https=`, or the
     * discovered base is invalid. The fallback preserves the pre-discovery
     * behavior, so a domain that serves its browser routes at the apex
     * keeps working without a `_linkkeys_apis` record.
     */
    public static function resolveBrowserEndpoint(DnsResolver $dns, string $identityDomain, string $route, string $signedRequest): string
    {
        try {
            $base = self::resolveBrowserBase($dns, $identityDomain);
        } catch (\Throwable $e) {
            // Any lookup/selection failure falls back, as in Go.
            $base = 'https://' . $identityDomain;
        }
        return self::buildBrowserEndpoint($base, $route, $signedRequest);
    }

    /**
     * Reassemble a URL from `parse_url()` authority parts with a replaced
     * path and query. Only scheme/host/port are taken from `$u`; callers
     * have already rejected userinfo and fragments.
     *
     * @param array{scheme: string, host: string, port?: int} $u
     */
    public static function unparseUrl(array $u, string $path, string $query): string
    {
        $authority = $u['host'] . (isset($u['port']) ? ':' . $u['port'] : '');
        return $u['scheme'] . '://' . $authority . $path . ($query === '' ? '' : '?' . $query);
    }
}
