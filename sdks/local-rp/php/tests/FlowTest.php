<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/fixtures/FakeRpc.php';

use Csilgen\Generated\Claim;
use Csilgen\Generated\ClaimSignature;
use Csilgen\Generated\DomainPublicKey;
use Csilgen\Generated\GetDomainKeysResponse;
use Csilgen\Generated\LocalRpTicketRedemptionResponse;
use Csilgen\Generated\RevocationCertificate;
use LinkKeys\LocalRp\Begin;
use LinkKeys\LocalRp\BeginLocalLoginConfig;
use LinkKeys\LocalRp\Claims;
use LinkKeys\LocalRp\Complete;
use LinkKeys\LocalRp\CompleteLocalLoginConfig;
use LinkKeys\LocalRp\Crypto;
use LinkKeys\LocalRp\DnsResolver;
use LinkKeys\LocalRp\Encoding;
use LinkKeys\LocalRp\GenerateLocalRpIdentityConfig;
use LinkKeys\LocalRp\Identity;
use LinkKeys\LocalRp\LocalRp;
use LinkKeys\LocalRp\LocalRpError;
use LinkKeys\LocalRp\RevocationFetchError;
use LinkKeys\LocalRp\Time;
use LinkKeys\LocalRp\Wire;

const FLOW_USER_DOMAIN = 'example.test';
const FLOW_CALLBACK_URL = 'http://127.0.0.1:8080/callback';
const FLOW_DOMAIN_KEY_ID = 'test-domain-key-1';

final class FakeDnsResolver implements DnsResolver
{
    private string $linkkeysTxt;
    private string $apisTxt;

    public function __construct(string $linkkeysTxt, string $apisTxt)
    {
        $this->linkkeysTxt = $linkkeysTxt;
        $this->apisTxt = $apisTxt;
    }

    public function txtLookup(string $name): array
    {
        if ($name === '_linkkeys.' . FLOW_USER_DOMAIN) {
            return [$this->linkkeysTxt];
        }
        if ($name === '_linkkeys_apis.' . FLOW_USER_DOMAIN) {
            return [$this->apisTxt];
        }
        throw new \RuntimeException("no fake record for {$name}");
    }
}

/** Everything a test needs to build/tweak a fake IDP round trip. */
final class FlowFixture
{
    public $keyMaterial;
    public string $domainSigningPublic;
    public string $domainSigningPrivate;
    public string $domainFingerprint;
    public $pending;
    public $requestFromUrl; // decoded LocalRpLoginRequest
    public \DateTimeImmutable $now;
    public string $claimTicket;
    public FakeDnsResolver $dns;

    /** @var DomainPublicKey[] */
    public array $domainKeys;

    /**
     * Revocation certificates `flowResponder`'s `get-revocations` handler
     * returns by default. Empty unless a test opts in (e.g. the
     * certificate-revoked-signing-key hostile-IDP case).
     *
     * @var \Csilgen\Generated\RevocationCertificate[]
     */
    public array $revocations = [];
}

function flowSetup(\DateTimeImmutable $now): FlowFixture
{
    $fx = new FlowFixture();
    $fx->now = $now;
    $fx->keyMaterial = Identity::generateLocalRpIdentity(new GenerateLocalRpIdentityConfig('Flow Test App', $now));

    [$fx->domainSigningPublic, $fx->domainSigningPrivate] = Crypto::generateEd25519Keypair();
    $fx->domainFingerprint = Crypto::fingerprint($fx->domainSigningPublic);

    $linkkeysTxt = 'v=lk1 fp=' . $fx->domainFingerprint;
    $apisTxt = 'v=lk1 tcp=127.0.0.1:0';
    $fx->dns = new FakeDnsResolver($linkkeysTxt, $apisTxt);

    $fx->domainKeys = [new DomainPublicKey([
        'key_id' => FLOW_DOMAIN_KEY_ID,
        'public_key' => $fx->domainSigningPublic,
        'fingerprint' => $fx->domainFingerprint,
        'algorithm' => 'ed25519',
        'key_usage' => 'sign',
        'created_at' => Time::toRfc3339($now->sub(new \DateInterval('P1D'))),
        'expires_at' => Time::toRfc3339($now->add(new \DateInterval('P365D'))),
        'revoked_at' => null,
    ])];

    [$redirect, $pending] = Begin::beginLocalLogin(new BeginLocalLoginConfig($fx->keyMaterial, FLOW_CALLBACK_URL, FLOW_USER_DOMAIN, $now));
    $fx->pending = $pending;

    $query = parse_url($redirect->redirectUrl, PHP_URL_QUERY);
    parse_str($query, $q);
    $signedRequest = Encoding::signedLocalRpLoginRequestFromUrlParam($q['signed_request']);
    $fx->requestFromUrl = LocalRp::verifyLocalRpLoginRequest($signedRequest, $now, LocalRp::DEFAULT_CLOCK_SKEW_SECONDS);

    $fx->claimTicket = random_bytes(32);

    return $fx;
}

/**
 * Build the IDP's signed+sealed callback for `$fx`, with optional overrides
 * to construct negative cases.
 */
function flowBuildEncryptedToken(FlowFixture $fx, array $overrides = []): string
{
    $issuedAt = $overrides['issued_at'] ?? Time::toRfc3339($fx->now);
    $expiresAt = $overrides['expires_at'] ?? Time::toRfc3339($fx->now->add(new \DateInterval('PT5M')));
    $userDomain = $overrides['user_domain'] ?? FLOW_USER_DOMAIN;
    $callbackUrl = $overrides['callback_url'] ?? $fx->requestFromUrl->callbackUrl;
    $nonce = $overrides['nonce'] ?? $fx->requestFromUrl->nonce;
    $state = $overrides['state'] ?? $fx->requestFromUrl->state;
    $audienceFingerprint = $overrides['audience_fingerprint'] ?? $fx->keyMaterial->fingerprint;
    $recipientEncryptionPublicKey = $overrides['recipient_encryption_public_key'] ?? $fx->keyMaterial->encryptionPublicKey;
    $suite = $overrides['suite'] ?? Crypto::AEAD_SUITE_AES_256_GCM;

    $payload = LocalRp::buildLocalRpCallbackPayload(
        'user-1',
        $userDomain,
        $fx->claimTicket,
        $audienceFingerprint,
        $callbackUrl,
        $nonce,
        $state,
        $issuedAt,
        $expiresAt
    );
    $signedPayload = LocalRp::signLocalRpCallbackPayload($payload, FLOW_DOMAIN_KEY_ID, Crypto::ALGORITHM_ED25519, $fx->domainSigningPrivate);
    $encrypted = LocalRp::sealLocalRpCallback(
        $signedPayload,
        $suite,
        $recipientEncryptionPublicKey,
        $audienceFingerprint,
        $nonce,
        $state,
        $issuedAt,
        $expiresAt
    );
    return Encoding::localRpEncryptedCallbackToUrlParam($encrypted);
}

function flowArrivedUrl(FlowFixture $fx, string $encryptedToken): string
{
    return $fx->requestFromUrl->callbackUrl . '?encrypted_token=' . $encryptedToken;
}

/**
 * A responder that serves get-domain-keys and get-revocations from `$fx`
 * (revocations default to an empty list — see {@see FlowFixture::$revocations})
 * plus one canned ticket redemption response. `$rejectRevocations` forces
 * `get-revocations` itself to fail at the RPC layer, for the fail-closed
 * hostile-IDP test.
 */
function flowResponder(FlowFixture $fx, ?LocalRpTicketRedemptionResponse $redemptionResponse, bool $rejectRedemption = false, bool $rejectRevocations = false): callable
{
    return function (string $service, string $op, string $payload) use ($fx, $redemptionResponse, $rejectRedemption, $rejectRevocations) {
        if ($service === 'DomainKeys' && $op === 'get-domain-keys') {
            $resp = new GetDomainKeysResponse([
                'domain' => FLOW_USER_DOMAIN,
                'keys' => $fx->domainKeys,
                // Deliberately false/absent: revocation fetching must be
                // unconditional (never gated on this flag) — see
                // `flow.hostile_idp_get_revocations_error_fails_closed`.
                'recent_revocations_available' => false,
            ]);
            return [0, 'GetDomainKeysResponse', flowEncodeGetDomainKeysResponse($resp), null];
        }
        if ($service === 'DomainKeys' && $op === 'get-revocations') {
            if ($rejectRevocations) {
                return [6, null, '', 'revocations fetch rejected'];
            }
            return [0, 'GetRevocationsResponse', flowEncodeGetRevocationsResponse($fx->revocations), null];
        }
        if ($service === 'LocalRp' && $op === 'redeem-claim-ticket') {
            if ($rejectRedemption || $redemptionResponse === null) {
                return [6, null, '', 'ticket redemption rejected'];
            }
            $bytes = flowEncodeTicketRedemptionResponse($redemptionResponse);
            return [0, 'LocalRpTicketRedemptionResponse', $bytes, null];
        }
        return [2, null, '', "unknown op {$service}/{$op}"];
    };
}

function flowEncodeGetDomainKeysResponse(GetDomainKeysResponse $resp): string
{
    return \LinkKeys\LocalRp\Cbor::encode([
        'domain' => $resp->domain,
        'keys' => array_map(fn (DomainPublicKey $k) => [
            'key_id' => $k->keyId,
            'public_key' => \LinkKeys\LocalRp\Cbor::bytes($k->publicKey),
            'fingerprint' => $k->fingerprint,
            'algorithm' => $k->algorithm,
            'key_usage' => $k->keyUsage,
            'created_at' => $k->createdAt,
            'expires_at' => $k->expiresAt,
            'revoked_at' => $k->revokedAt,
        ], $resp->keys),
        'recent_revocations_available' => $resp->recentRevocationsAvailable,
    ]);
}

function flowEncodeTicketRedemptionResponse(LocalRpTicketRedemptionResponse $resp): string
{
    return \LinkKeys\LocalRp\Cbor::encode([
        'user_id' => $resp->userId,
        'user_domain' => $resp->userDomain,
        'claims' => array_map(fn (Claim $c) => [
            'claim_id' => $c->claimId,
            'user_id' => $c->userId,
            'claim_type' => $c->claimType,
            'claim_value' => \LinkKeys\LocalRp\Cbor::bytes($c->claimValue),
            'signatures' => array_map(fn (ClaimSignature $s) => [
                'domain' => $s->domain,
                'signed_by_key_id' => $s->signedByKeyId,
                'signature' => \LinkKeys\LocalRp\Cbor::bytes($s->signature),
            ], $c->signatures),
            'attested_at' => $c->attestedAt,
            'created_at' => $c->createdAt,
            'expires_at' => $c->expiresAt,
            'revoked_at' => $c->revokedAt,
        ], $resp->claims),
        'ticket_expires_at' => $resp->ticketExpiresAt,
    ]);
}

function flowEncodeGetRevocationsResponse(array $certs): string
{
    return \LinkKeys\LocalRp\Cbor::encode([
        'revocations' => array_map(fn (RevocationCertificate $c) => [
            'target_key_id' => $c->targetKeyId,
            'target_fingerprint' => $c->targetFingerprint,
            'revoked_at' => $c->revokedAt,
            'signatures' => array_map(fn (ClaimSignature $s) => [
                'domain' => $s->domain,
                'signed_by_key_id' => $s->signedByKeyId,
                'signature' => \LinkKeys\LocalRp\Cbor::bytes($s->signature),
            ], $c->signatures),
        ], $certs),
    ]);
}

/**
 * A quorum-verified ({@see \LinkKeys\LocalRp\Revocation::QUORUM}) revocation
 * certificate for `$targetKeyId`/`$targetFingerprint`, signed by
 * `$signerPrivateKeys` (each a `[keyId, privateKey]` pair, distinct from the
 * target).
 *
 * @param array<int, array{0: string, 1: string}> $signerPrivateKeys
 */
function flowMakeRevocationCertificate(string $targetKeyId, string $targetFingerprint, string $revokedAt, array $signerPrivateKeys): RevocationCertificate
{
    $payload = \LinkKeys\LocalRp\Revocation::revocationPayload($targetKeyId, $targetFingerprint, $revokedAt, FLOW_USER_DOMAIN);
    $sigs = array_map(function (array $signer) use ($payload) {
        [$keyId, $privateKey] = $signer;
        $sig = Crypto::signWithAlgorithm(Crypto::ALGORITHM_ED25519, $payload, $privateKey);
        return new ClaimSignature(['domain' => FLOW_USER_DOMAIN, 'signed_by_key_id' => $keyId, 'signature' => $sig]);
    }, $signerPrivateKeys);
    return new RevocationCertificate([
        'target_key_id' => $targetKeyId,
        'target_fingerprint' => $targetFingerprint,
        'revoked_at' => $revokedAt,
        'signatures' => $sigs,
    ]);
}

function flowMakeClaim(FlowFixture $fx, string $claimId, string $type, string $value, \DateTimeImmutable $now, string $userId = 'user-1'): Claim
{
    $attestedAt = Time::toRfc3339($now);
    $payload = Claims::claimSignPayload($claimId, $type, $value, $userId, FLOW_USER_DOMAIN, FLOW_USER_DOMAIN, null, $attestedAt);
    $sig = Crypto::signWithAlgorithm(Crypto::ALGORITHM_ED25519, $payload, $fx->domainSigningPrivate);
    return new Claim([
        'claim_id' => $claimId,
        'user_id' => $userId,
        'claim_type' => $type,
        'claim_value' => $value,
        'signatures' => [new ClaimSignature(['domain' => FLOW_USER_DOMAIN, 'signed_by_key_id' => FLOW_DOMAIN_KEY_ID, 'signature' => $sig])],
        'attested_at' => $attestedAt,
        'created_at' => $attestedAt,
        'expires_at' => null,
        'revoked_at' => null,
    ]);
}

/**
 * Asserts `$fn` throws a {@see LocalRpError} of exactly `$expectedKind` —
 * stronger than a bare "throws something", so a hostile-IDP test can't
 * pass because some unrelated exception happened to fire first.
 */
function flowAssertThrowsLocalRpErrorKind(callable $fn, string $expectedKind, string $message): void
{
    try {
        $fn();
    } catch (LocalRpError $e) {
        TestKit::assertEquals($expectedKind, $e->kind, $message);
        return;
    } catch (\Throwable $e) {
        throw new \RuntimeException("{$message}: expected LocalRpError({$expectedKind}), got " . get_class($e) . ': ' . $e->getMessage());
    }
    throw new \RuntimeException("{$message}: expected an exception, none was thrown");
}

function flowRunComplete(FlowFixture $fx, string $encryptedToken, callable $responder, ?\DateTimeImmutable $now = null): \LinkKeys\LocalRp\VerifiedLocalLogin
{
    // FakeTransport implements OpaqueTransport, so Rpc::dialTls() skips its
    // real TLS-pinning wrap for this transport instance only — no
    // process-global state to set up or reset (see OpaqueTransport's
    // docblock in src/Transport.php).
    $transport = new FakeTransport($responder);
    return Complete::completeLocalLogin(new CompleteLocalLoginConfig(
        $fx->keyMaterial,
        $fx->pending,
        $encryptedToken,
        flowArrivedUrl($fx, $encryptedToken),
        $now ?? $fx->now,
        $transport,
        $fx->dns
    ));
}

// ---------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------

TestKit::test('flow.happy_path_full_login_succeeds', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);
    $claims = [
        flowMakeClaim($fx, 'c1', 'handle', 'flowuser', $now),
        flowMakeClaim($fx, 'c2', 'email', 'flowuser@example.test', $now),
    ];
    $redemption = new LocalRpTicketRedemptionResponse([
        'user_id' => 'user-1',
        'user_domain' => FLOW_USER_DOMAIN,
        'claims' => $claims,
        'ticket_expires_at' => Time::toRfc3339($now->add(new \DateInterval('PT1H'))),
    ]);

    $token = flowBuildEncryptedToken($fx);
    $verified = flowRunComplete($fx, $token, flowResponder($fx, $redemption));

    TestKit::assertEquals('user-1', $verified->userId);
    TestKit::assertEquals(FLOW_USER_DOMAIN, $verified->userDomain);
    TestKit::assertEquals($fx->keyMaterial->fingerprint, $verified->localRpFingerprint);
    TestKit::assertEquals(2, count($verified->claims));
});

TestKit::test('flow.happy_path_chacha20_suite_succeeds', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);
    $redemption = new LocalRpTicketRedemptionResponse([
        'user_id' => 'user-1',
        'user_domain' => FLOW_USER_DOMAIN,
        'claims' => [flowMakeClaim($fx, 'c1', 'handle', 'flowuser', $now)],
        'ticket_expires_at' => Time::toRfc3339($now->add(new \DateInterval('PT1H'))),
    ]);

    $token = flowBuildEncryptedToken($fx, ['suite' => Crypto::AEAD_SUITE_CHACHA20_POLY1305]);
    $verified = flowRunComplete($fx, $token, flowResponder($fx, $redemption));
    TestKit::assertEquals('user-1', $verified->userId);
});

// ---------------------------------------------------------------------
// Failure modes
// ---------------------------------------------------------------------

TestKit::test('flow.wrong_recipient_encryption_key_fails', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);
    [$otherEncPub, ] = Crypto::generateX25519Keypair();
    $token = flowBuildEncryptedToken($fx, ['recipient_encryption_public_key' => $otherEncPub]);
    TestKit::assertThrows(fn () => flowRunComplete($fx, $token, flowResponder($fx, null)));
});

TestKit::test('flow.issuer_mismatch_fails', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);
    $token = flowBuildEncryptedToken($fx, ['user_domain' => 'evil.test']);
    TestKit::assertThrows(fn () => flowRunComplete($fx, $token, flowResponder($fx, null)));
});

TestKit::test('flow.callback_url_mismatch_fails', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);
    $token = flowBuildEncryptedToken($fx, ['callback_url' => 'http://127.0.0.1:9999/other']);
    TestKit::assertThrows(fn () => flowRunComplete($fx, $token, flowResponder($fx, null)));
});

TestKit::test('flow.nonce_mismatch_fails', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);
    $token = flowBuildEncryptedToken($fx, ['nonce' => random_bytes(32)]);
    TestKit::assertThrows(fn () => flowRunComplete($fx, $token, flowResponder($fx, null)));
});

TestKit::test('flow.expired_callback_fails', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);
    $token = flowBuildEncryptedToken($fx, [
        'issued_at' => Time::toRfc3339($now->sub(new \DateInterval('PT1H'))),
        'expires_at' => Time::toRfc3339($now->sub(new \DateInterval('PT30M'))),
    ]);
    TestKit::assertThrows(fn () => flowRunComplete($fx, $token, flowResponder($fx, null)));
});

TestKit::test('flow.audience_mismatch_fails', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);
    $token = flowBuildEncryptedToken($fx, ['audience_fingerprint' => str_repeat('a', 64)]);
    TestKit::assertThrows(fn () => flowRunComplete($fx, $token, flowResponder($fx, null)));
});

TestKit::test('flow.unadvertised_suite_rejected', function () {
    // A local RP identity that only ever advertised aes-256-gcm must refuse
    // a chacha20-poly1305 callback even though it is a real registry member.
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);
    $fx->keyMaterial = Identity::generateLocalRpIdentity(new GenerateLocalRpIdentityConfig(
        'Flow Test App',
        $now,
        null,
        [Crypto::AEAD_SUITE_AES_256_GCM]
    ));
    [$redirect, $pending] = Begin::beginLocalLogin(new BeginLocalLoginConfig($fx->keyMaterial, FLOW_CALLBACK_URL, FLOW_USER_DOMAIN, $now));
    $fx->pending = $pending;
    parse_str(parse_url($redirect->redirectUrl, PHP_URL_QUERY), $q);
    $fx->requestFromUrl = LocalRp::verifyLocalRpLoginRequest(Encoding::signedLocalRpLoginRequestFromUrlParam($q['signed_request']), $now, LocalRp::DEFAULT_CLOCK_SKEW_SECONDS);

    $token = flowBuildEncryptedToken($fx, ['suite' => Crypto::AEAD_SUITE_CHACHA20_POLY1305]);
    TestKit::assertThrows(fn () => flowRunComplete($fx, $token, flowResponder($fx, null)));
});

TestKit::test('flow.revoked_domain_signing_key_fails', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);
    // Mark the only domain signing key as already revoked in the fetched
    // key list: the callback envelope's signature must then be rejected.
    $fx->domainKeys = [new DomainPublicKey([
        'key_id' => FLOW_DOMAIN_KEY_ID,
        'public_key' => $fx->domainSigningPublic,
        'fingerprint' => $fx->domainFingerprint,
        'algorithm' => 'ed25519',
        'key_usage' => 'sign',
        'created_at' => Time::toRfc3339($now->sub(new \DateInterval('P1D'))),
        'expires_at' => Time::toRfc3339($now->add(new \DateInterval('P365D'))),
        'revoked_at' => Time::toRfc3339($now->sub(new \DateInterval('PT1H'))),
    ])];
    $token = flowBuildEncryptedToken($fx);
    TestKit::assertThrows(fn () => flowRunComplete($fx, $token, flowResponder($fx, null)));
});

TestKit::test('flow.ticket_redemption_rejected_fails', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);
    $token = flowBuildEncryptedToken($fx);
    TestKit::assertThrows(fn () => flowRunComplete($fx, $token, flowResponder($fx, null, true)));
});

TestKit::test('flow.claim_with_tampered_signature_fails', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);
    $claim = flowMakeClaim($fx, 'c1', 'handle', 'flowuser', $now);
    $tamperedSig = $claim->signatures[0]->signature;
    $tamperedSig[0] = chr(ord($tamperedSig[0]) ^ 0xff);
    $claim->signatures[0] = new ClaimSignature(['domain' => FLOW_USER_DOMAIN, 'signed_by_key_id' => FLOW_DOMAIN_KEY_ID, 'signature' => $tamperedSig]);
    $redemption = new LocalRpTicketRedemptionResponse([
        'user_id' => 'user-1',
        'user_domain' => FLOW_USER_DOMAIN,
        'claims' => [$claim],
        'ticket_expires_at' => Time::toRfc3339($now->add(new \DateInterval('PT1H'))),
    ]);
    $token = flowBuildEncryptedToken($fx);
    TestKit::assertThrows(fn () => flowRunComplete($fx, $token, flowResponder($fx, $redemption)));
});

// ---------------------------------------------------------------------
// Hostile-IDP tests (security review fixes, dns-less-local-rp-design.md
// "Post-implementation security review"): a fake IDP that behaves per
// protocol up through envelope verification, then tries to abuse the
// ticket-redemption response, claim set, or revocation channel. Every case
// here must fail closed.
// ---------------------------------------------------------------------

TestKit::test('flow.hostile_idp_redemption_identity_mismatch_fails_closed', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);
    // The signed callback payload names user-1 (flowBuildEncryptedToken's
    // hardcoded subject). The hostile IDP's ticket-redemption response
    // claims a DIFFERENT user entirely, trying to attach a login for one
    // user to another user's claims.
    $claims = [flowMakeClaim($fx, 'c1', 'handle', 'otheruser', $now, 'user-2')];
    $redemption = new LocalRpTicketRedemptionResponse([
        'user_id' => 'user-2',
        'user_domain' => FLOW_USER_DOMAIN,
        'claims' => $claims,
        'ticket_expires_at' => Time::toRfc3339($now->add(new \DateInterval('PT1H'))),
    ]);
    $token = flowBuildEncryptedToken($fx);
    flowAssertThrowsLocalRpErrorKind(
        fn () => flowRunComplete($fx, $token, flowResponder($fx, $redemption)),
        LocalRpError::REDEMPTION_IDENTITY_MISMATCH,
        'redemption user_id disagreeing with the signed payload must be fatal'
    );
});

TestKit::test('flow.hostile_idp_claim_user_id_mismatch_fails_closed', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);
    // Redemption identity matches the payload (user-1), but one of the
    // returned claims is validly signed for a DIFFERENT subject (user-2) —
    // a hostile IDP trying to attribute someone else's claim to this login.
    $claims = [
        flowMakeClaim($fx, 'c1', 'handle', 'flowuser', $now, 'user-1'),
        flowMakeClaim($fx, 'c2', 'email', 'other@example.test', $now, 'user-2'),
    ];
    $redemption = new LocalRpTicketRedemptionResponse([
        'user_id' => 'user-1',
        'user_domain' => FLOW_USER_DOMAIN,
        'claims' => $claims,
        'ticket_expires_at' => Time::toRfc3339($now->add(new \DateInterval('PT1H'))),
    ]);
    $token = flowBuildEncryptedToken($fx);
    flowAssertThrowsLocalRpErrorKind(
        fn () => flowRunComplete($fx, $token, flowResponder($fx, $redemption)),
        LocalRpError::CLAIM_OWNERSHIP_MISMATCH,
        'a claim whose user_id disagrees with the verified payload must be fatal'
    );
});

TestKit::test('flow.hostile_idp_required_claims_not_satisfied_fails_closed', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);
    // beginLocalLogin's default required_claims is ['handle']. The hostile
    // IDP returns a redemption with zero claims at all — advisory-only
    // enforcement would let this silently succeed as a partial login.
    $redemption = new LocalRpTicketRedemptionResponse([
        'user_id' => 'user-1',
        'user_domain' => FLOW_USER_DOMAIN,
        'claims' => [],
        'ticket_expires_at' => Time::toRfc3339($now->add(new \DateInterval('PT1H'))),
    ]);
    $token = flowBuildEncryptedToken($fx);
    flowAssertThrowsLocalRpErrorKind(
        fn () => flowRunComplete($fx, $token, flowResponder($fx, $redemption)),
        LocalRpError::REQUIRED_CLAIMS_NOT_SATISFIED,
        'an empty claim set when required_claims is non-empty must be fatal'
    );

    // Also insufficient: a non-empty claim set that never includes the
    // required claim type at all.
    $redemptionMissingHandle = new LocalRpTicketRedemptionResponse([
        'user_id' => 'user-1',
        'user_domain' => FLOW_USER_DOMAIN,
        'claims' => [flowMakeClaim($fx, 'c1', 'email', 'flowuser@example.test', $now)],
        'ticket_expires_at' => Time::toRfc3339($now->add(new \DateInterval('PT1H'))),
    ]);
    $token2 = flowBuildEncryptedToken($fx);
    flowAssertThrowsLocalRpErrorKind(
        fn () => flowRunComplete($fx, $token2, flowResponder($fx, $redemptionMissingHandle)),
        LocalRpError::REQUIRED_CLAIMS_NOT_SATISFIED,
        'a claim set missing a required claim type must be fatal'
    );
});

TestKit::test('flow.hostile_idp_get_revocations_error_fails_closed', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);
    $redemption = new LocalRpTicketRedemptionResponse([
        'user_id' => 'user-1',
        'user_domain' => FLOW_USER_DOMAIN,
        'claims' => [flowMakeClaim($fx, 'c1', 'handle', 'flowuser', $now)],
        'ticket_expires_at' => Time::toRfc3339($now->add(new \DateInterval('PT1H'))),
    ]);
    $token = flowBuildEncryptedToken($fx);
    // The hostile IDP's get-revocations RPC errors out. Revocation fetching
    // is unconditional and any failure to fetch it must fail the whole
    // login closed, not silently proceed as if no keys were revoked.
    try {
        flowRunComplete($fx, $token, flowResponder($fx, $redemption, false, true));
        throw new \RuntimeException('a get-revocations RPC error must fail the login closed: no exception was thrown');
    } catch (RevocationFetchError $e) {
        // Expected: fetchDomainKeys fails closed on a get-revocations error.
    }
});

TestKit::test('flow.hostile_idp_certificate_revoked_signing_key_fails_closed', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $fx = flowSetup($now);

    // Two sibling signing keys for the domain, distinct from the key that
    // signed the callback envelope — enough for Revocation::QUORUM (2).
    [$sibling1Public, $sibling1Private] = Crypto::generateEd25519Keypair();
    [$sibling2Public, $sibling2Private] = Crypto::generateEd25519Keypair();
    $makeSiblingKey = fn (string $id, string $pub) => new DomainPublicKey([
        'key_id' => $id,
        'public_key' => $pub,
        'fingerprint' => Crypto::fingerprint($pub),
        'algorithm' => 'ed25519',
        'key_usage' => 'sign',
        'created_at' => Time::toRfc3339($now->sub(new \DateInterval('P1D'))),
        'expires_at' => Time::toRfc3339($now->add(new \DateInterval('P365D'))),
        'revoked_at' => null,
    ]);
    $fx->domainKeys = array_merge($fx->domainKeys, [
        $makeSiblingKey('sibling-1', $sibling1Public),
        $makeSiblingKey('sibling-2', $sibling2Public),
    ]);
    // The siblings must ALSO be DNS-pinned: Dns::trustKeys only trusts a
    // *signing* key that is pinned directly (fp=), so an unpinned sibling
    // wouldn't count toward the revocation certificate's signer quorum at
    // all — this would make the certificate silently fail its own quorum
    // check rather than exercise the fail-closed path this test targets.
    $sibling1Fingerprint = Crypto::fingerprint($sibling1Public);
    $sibling2Fingerprint = Crypto::fingerprint($sibling2Public);
    $linkkeysTxt = "v=lk1 fp={$fx->domainFingerprint} fp={$sibling1Fingerprint} fp={$sibling2Fingerprint}";
    $apisTxt = 'v=lk1 tcp=127.0.0.1:0';
    $fx->dns = new FakeDnsResolver($linkkeysTxt, $apisTxt);

    // A quorum-verified certificate revoking the key that signs the
    // callback envelope below, served from get-revocations. Nothing in the
    // get-domain-keys response itself marks that key `revoked_at` — only
    // the sibling-signed certificate does.
    $revokedAt = Time::toRfc3339($now->sub(new \DateInterval('PT1H')));
    $fx->revocations = [flowMakeRevocationCertificate(
        FLOW_DOMAIN_KEY_ID,
        $fx->domainFingerprint,
        $revokedAt,
        [['sibling-1', $sibling1Private], ['sibling-2', $sibling2Private]]
    )];

    $token = flowBuildEncryptedToken($fx);
    // The trusted key set fetched for FLOW_USER_DOMAIN no longer contains
    // FLOW_DOMAIN_KEY_ID after the certificate above is applied, so envelope
    // verification can't even find the signing key it needs.
    flowAssertThrowsLocalRpErrorKind(
        fn () => flowRunComplete($fx, $token, flowResponder($fx, null)),
        LocalRpError::KEY_NOT_FOUND,
        'a callback signed by a certificate-revoked key must be fatal'
    );
});

exit(TestKit::summary('FlowTest') === 0 ? 0 : 1);
