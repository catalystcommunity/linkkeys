<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use LinkKeys\LocalRp\Begin;
use LinkKeys\LocalRp\BeginLocalLoginConfig;
use LinkKeys\LocalRp\GenerateLocalRpIdentityConfig;
use LinkKeys\LocalRp\Identity;
use LinkKeys\LocalRp\PendingLogin;

function beginTestMaterial(): \LinkKeys\LocalRp\LocalRpKeyMaterial
{
    return Identity::generateLocalRpIdentity(new GenerateLocalRpIdentityConfig('Test App', new \DateTimeImmutable('now')));
}

TestKit::test('begin.defaults_claims_and_produces_pending_state', function () {
    $m = beginTestMaterial();
    [$redirect, $pending] = Begin::beginLocalLogin(new BeginLocalLoginConfig($m, 'http://localhost:8080/callback', 'example.com', new \DateTimeImmutable('now')));

    TestKit::assertTrue(str_starts_with($redirect->redirectUrl, 'https://example.com/auth/local-rp?signed_request='));
    TestKit::assertEquals('example.com', $pending->userDomain);
    TestKit::assertEquals('http://localhost:8080/callback', $pending->callbackUrl);
    TestKit::assertEquals(32, strlen($pending->nonce));
    TestKit::assertEquals(32, strlen($pending->state));
});

TestKit::test('begin.rejects_non_http_callback_scheme', function () {
    $m = beginTestMaterial();
    TestKit::assertThrows(fn () => Begin::beginLocalLogin(new BeginLocalLoginConfig($m, 'myapp://callback', 'example.com', new \DateTimeImmutable('now'))));
});

TestKit::test('begin.rejects_empty_user_domain', function () {
    $m = beginTestMaterial();
    TestKit::assertThrows(fn () => Begin::beginLocalLogin(new BeginLocalLoginConfig($m, 'http://localhost/callback', '', new \DateTimeImmutable('now'))));
});

TestKit::test('begin.two_calls_never_reuse_nonce_or_state', function () {
    $m = beginTestMaterial();
    [, $p1] = Begin::beginLocalLogin(new BeginLocalLoginConfig($m, 'http://localhost/callback', 'example.com', new \DateTimeImmutable('now')));
    [, $p2] = Begin::beginLocalLogin(new BeginLocalLoginConfig($m, 'http://localhost/callback', 'example.com', new \DateTimeImmutable('now')));
    TestKit::assertTrue($p1->nonce !== $p2->nonce);
    TestKit::assertTrue($p1->state !== $p2->state);
});

TestKit::test('begin.pending_login_array_round_trip', function () {
    $m = beginTestMaterial();
    [, $pending] = Begin::beginLocalLogin(new BeginLocalLoginConfig($m, 'http://localhost/callback', 'example.com', new \DateTimeImmutable('now')));
    $roundTripped = PendingLogin::fromArray($pending->toArray());
    TestKit::assertEquals($pending->nonce, $roundTripped->nonce);
    TestKit::assertEquals($pending->state, $roundTripped->state);
    TestKit::assertEquals($pending->userDomain, $roundTripped->userDomain);
    TestKit::assertEquals($pending->callbackUrl, $roundTripped->callbackUrl);
    TestKit::assertEquals($pending->requiredClaims, $roundTripped->requiredClaims);
});

TestKit::test('begin.pending_login_retains_required_claims', function () {
    $m = beginTestMaterial();
    [, $pending] = Begin::beginLocalLogin(new BeginLocalLoginConfig(
        $m,
        'http://localhost/callback',
        'example.com',
        new \DateTimeImmutable('now'),
        null,
        ['handle', 'email']
    ));
    TestKit::assertEquals(['handle', 'email'], $pending->requiredClaims);

    [, $defaultPending] = Begin::beginLocalLogin(new BeginLocalLoginConfig($m, 'http://localhost/callback', 'example.com', new \DateTimeImmutable('now')));
    TestKit::assertEquals(Begin::DEFAULT_REQUIRED_CLAIMS, $defaultPending->requiredClaims);
});

TestKit::test('begin.default_and_custom_claims', function () {
    $m = beginTestMaterial();
    TestKit::assertEquals(['display_name', 'email', 'handle'], Begin::DEFAULT_REQUESTED_CLAIMS);
    TestKit::assertEquals(['handle'], Begin::DEFAULT_REQUIRED_CLAIMS);
});

exit(TestKit::summary('BeginTest') === 0 ? 0 : 1);
