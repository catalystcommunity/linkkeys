<?php

declare(strict_types=1);

/**
 * Browser endpoint discovery tests, ported from
 * `sdks/local-rp/go/browser_test.go`. Every resolver here is a hermetic
 * fake with canned TXT answers — no test in this file performs a live DNS
 * request.
 */

require_once __DIR__ . '/bootstrap.php';

use LinkKeys\LocalRp\Wire;
use LinkKeys\LocalRp\Begin;
use LinkKeys\LocalRp\BeginLocalLoginConfig;
use LinkKeys\LocalRp\Browser;
use LinkKeys\LocalRp\DnsResolver;
use LinkKeys\LocalRp\Encoding;
use LinkKeys\LocalRp\GenerateLocalRpIdentityConfig;
use LinkKeys\LocalRp\Identity;
use LinkKeys\LocalRp\SystemDnsResolver;

/** A hermetic DnsResolver with canned TXT answers per name. */
final class MapDnsResolver implements DnsResolver
{
    /** @var array<string, string[]> */
    private array $records;
    private ?\Throwable $error;

    /** @param array<string, string[]> $records */
    public function __construct(array $records, ?\Throwable $error = null)
    {
        $this->records = $records;
        $this->error = $error;
    }

    public function txtLookup(string $name): array
    {
        if ($this->error !== null) {
            throw $this->error;
        }
        if (isset($this->records[$name])) {
            return $this->records[$name];
        }
        throw new \RuntimeException("no fake record for {$name}");
    }
}

const BROWSER_TEST_DOMAIN = 'ident.example.test';
const BROWSER_CALLBACK_URL = 'http://app.lan:8080/cb';

function browserApisResolver(string ...$txts): MapDnsResolver
{
    return new MapDnsResolver(['_linkkeys_apis.' . BROWSER_TEST_DOMAIN => $txts]);
}

function browserFailingResolver(): MapDnsResolver
{
    return new MapDnsResolver([], new \RuntimeException('SERVFAIL'));
}

/** @return array{0: \LinkKeys\LocalRp\LocalLoginRedirect, 1: \LinkKeys\LocalRp\PendingLogin, 2: BeginLocalLoginConfig} */
function browserBeginWith(DnsResolver $dns): array
{
    $now = new \DateTimeImmutable('2026-08-17T12:00:00Z');
    $identity = Identity::generateLocalRpIdentity(new GenerateLocalRpIdentityConfig('browser-test', $now));
    $config = new BeginLocalLoginConfig($identity, BROWSER_CALLBACK_URL, BROWSER_TEST_DOMAIN, $now, null, null, null, $dns);
    [$redirect, $pending] = Begin::beginLocalLogin($config);
    return [$redirect, $pending, $config];
}

// Case 1: a valid https= host is used for the redirect instead of the
// identity domain. Case 8: PendingLogin::$userDomain stays the identity
// domain — verification stays bound to it, not to the service host.
TestKit::test('browser.begin_uses_discovered_https_host', function () {
    [$redirect, $pending] = browserBeginWith(browserApisResolver(
        'v=lk1 tcp=linkkeys.ident.example.test https=linkkeys.ident.example.test'
    ));
    TestKit::assertTrue(str_starts_with($redirect->redirectUrl, 'https://linkkeys.ident.example.test/auth/local-rp?signed_request='), $redirect->redirectUrl);
    TestKit::assertFalse(str_starts_with($redirect->redirectUrl, 'https://' . BROWSER_TEST_DOMAIN . '/'), $redirect->redirectUrl);
    TestKit::assertEquals(BROWSER_TEST_DOMAIN, $pending->userDomain);
});

// Case 2: an https= value with a path prefix preserves that prefix.
TestKit::test('browser.begin_preserves_https_path_prefix', function () {
    [$redirect] = browserBeginWith(browserApisResolver('v=lk1 https=login.example.test/linkkeys'));
    TestKit::assertTrue(str_starts_with($redirect->redirectUrl, 'https://login.example.test/linkkeys/auth/local-rp?signed_request='), $redirect->redirectUrl);
});

// Case 3: a record with only tcp= falls back to the identity domain.
TestKit::test('browser.begin_tcp_only_record_falls_back_to_identity_domain', function () {
    [$redirect] = browserBeginWith(browserApisResolver('v=lk1 tcp=linkkeys.ident.example.test'));
    TestKit::assertTrue(str_starts_with($redirect->redirectUrl, 'https://' . BROWSER_TEST_DOMAIN . '/auth/local-rp?signed_request='), $redirect->redirectUrl);
});

// Case 4: a DNS lookup error falls back to the identity domain.
TestKit::test('browser.begin_dns_error_falls_back_to_identity_domain', function () {
    [$redirect] = browserBeginWith(browserFailingResolver());
    TestKit::assertTrue(str_starts_with($redirect->redirectUrl, 'https://' . BROWSER_TEST_DOMAIN . '/auth/local-rp?signed_request='), $redirect->redirectUrl);
});

// Cases 5 + 6: invalid TXT records are ignored, and across several records
// the FIRST valid record with https= is selected.
TestKit::test('browser.begin_selects_first_valid_https_across_records', function () {
    [$redirect] = browserBeginWith(browserApisResolver(
        'not a linkkeys record',
        'v=lk2 https=wrong-version.example.test',
        'v=lk1 tcp=tcp-only.example.test',
        'v=lk1 https=first.example.test',
        'v=lk1 https=second.example.test'
    ));
    TestKit::assertTrue(str_starts_with($redirect->redirectUrl, 'https://first.example.test/auth/local-rp?signed_request='), $redirect->redirectUrl);
});

// Case 7: signed_request rides the discovered URL unchanged — it decodes to
// the signed login request whose fields match this login.
TestKit::test('browser.begin_signed_request_survives_discovered_url', function () {
    [$redirect, $pending, $config] = browserBeginWith(browserApisResolver('v=lk1 https=login.example.test/linkkeys'));
    parse_str((string) parse_url($redirect->redirectUrl, PHP_URL_QUERY), $q);
    TestKit::assertTrue(isset($q['signed_request']) && $q['signed_request'] !== '', 'signed_request query parameter missing');
    $signed = Encoding::signedLocalRpLoginRequestFromUrlParam($q['signed_request']);
    $request = Wire::decodeLocalRpLoginRequest($signed->request);
    TestKit::assertEquals($config->callbackUrl, $request->callbackUrl);
    TestKit::assertEquals($pending->nonce, $request->nonce);
});

// Case 9: a config without a `$dns` argument still constructs (this test is
// that caller) and the default is the system resolver. The default path is
// not executed here — that would be a live DNS request.
TestKit::test('browser.begin_config_without_resolver_still_constructs', function () {
    $now = new \DateTimeImmutable('2026-08-17T12:00:00Z');
    $identity = Identity::generateLocalRpIdentity(new GenerateLocalRpIdentityConfig('browser-test', $now));
    $config = new BeginLocalLoginConfig($identity, BROWSER_CALLBACK_URL, BROWSER_TEST_DOMAIN, $now);
    TestKit::assertTrue($config->dns === null);
    TestKit::assertTrue(new SystemDnsResolver() instanceof DnsResolver);
});

// ---------------------------------------------------------------------
// Direct tests for the exported helpers
// ---------------------------------------------------------------------

TestKit::test('browser.resolve_browser_base', function () {
    $base = Browser::resolveBrowserBase(
        browserApisResolver('v=lk1 tcp=x.example.test https=login.example.test:8443/linkkeys'),
        BROWSER_TEST_DOMAIN
    );
    TestKit::assertEquals('https://login.example.test:8443/linkkeys', $base);

    // A record whose https= value smuggles URL structure is skipped; with
    // no other candidate, resolution throws so the caller can fall back.
    foreach ([
        'v=lk1 https=user@evil.example.test',
        'v=lk1 https=evil.example.test/x?y=1',
        'v=lk1 https=evil.example.test/x#frag',
        'v=lk1 tcp=only.example.test',
    ] as $hostile) {
        TestKit::assertThrows(fn () => Browser::resolveBrowserBase(browserApisResolver($hostile), BROWSER_TEST_DOMAIN), "accepted {$hostile}");
    }

    TestKit::assertThrows(fn () => Browser::resolveBrowserBase(browserFailingResolver(), BROWSER_TEST_DOMAIN), 'lookup failure must propagate');
});

TestKit::test('browser.build_browser_endpoint', function () {
    TestKit::assertEquals(
        'https://h.example.test/auth/local-rp?signed_request=PAYLOAD-123_abc',
        Browser::buildBrowserEndpoint('https://h.example.test', Browser::ROUTE_LOCAL_RP, 'PAYLOAD-123_abc')
    );

    // Path prefix, with and without a trailing slash, and the regular-RP
    // route — the same helper serves /auth/authorize glue.
    foreach (['https://h.example.test/pfx', 'https://h.example.test/pfx/'] as $base) {
        TestKit::assertEquals(
            'https://h.example.test/pfx/auth/authorize?signed_request=s',
            Browser::buildBrowserEndpoint($base, Browser::ROUTE_AUTHORIZE, 's')
        );
    }

    // A non-HTTPS scheme must never be selectable.
    foreach (['http://h.example.test', 'ftp://h.example.test', 'https://', 'https://u:p@h.example.test'] as $bad) {
        TestKit::assertThrows(fn () => Browser::buildBrowserEndpoint($bad, Browser::ROUTE_LOCAL_RP, 's'), "accepted {$bad}");
    }
    TestKit::assertThrows(fn () => Browser::buildBrowserEndpoint('https://h.example.test', 'auth/no-leading-slash', 's'));
});

exit(TestKit::summary('BrowserTest') === 0 ? 0 : 1);
