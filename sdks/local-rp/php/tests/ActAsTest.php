<?php

declare(strict_types=1);

/**
 * Act-as grantee tests: the `local_rp_grantee` case of
 * `sdks/regular-rp/conformance/act_as_grantee_signing.json` byte for byte,
 * begin act-as browser discovery with fake DNS, the callback nonce check,
 * and the refresh call over the in-process fake RPC wire. No test here
 * touches the network.

 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/fixtures/FakeRpc.php';

use Csilgen\Generated\ActAsGrantRequest;
use Csilgen\Generated\ActAsRefreshRequest;
use Csilgen\Generated\ApplicationRef;
use Csilgen\Generated\ClaimSignature;
use Csilgen\Generated\GranteeRef;
use Csilgen\Generated\RefreshActAsGrantResponse;
use Csilgen\Generated\SignedActAsGrant;
use LinkKeys\LocalRp\ActAs;
use LinkKeys\LocalRp\ActAsWire;
use LinkKeys\LocalRp\BeginActAsConfig;
use LinkKeys\LocalRp\Cbor;
use LinkKeys\LocalRp\Crypto;
use LinkKeys\LocalRp\DnsResolver;
use LinkKeys\LocalRp\Encoding;
use LinkKeys\LocalRp\LocalRp;
use LinkKeys\LocalRp\LocalRpError;
use LinkKeys\LocalRp\LocalRpKeyMaterial;
use LinkKeys\LocalRp\RpcServerError;
use LinkKeys\LocalRp\Wire;

const ACT_AS_VECTORS = __DIR__ . '/../../../regular-rp/conformance/act_as_grantee_signing.json';
const ACT_AS_DOMAIN = 'ident.example.test';
const ACT_AS_CALLBACK = 'http://app.lan:8080/act-as/callback';

$vectors = loadJson(ACT_AS_VECTORS);
$case = null;
foreach ($vectors['cases'] as $c) {
    if ($c['name'] === 'local_rp_grantee') {
        $case = $c;
    }
}
$grantee = $vectors['local_rp_grantee'];

$descriptor = Wire::decodeSignedLocalRpDescriptor(hexToBytes($grantee['signed_descriptor_cbor_hex']));
$signingSeed = hexToBytes($grantee['signing_private_key_hex']);
$keyMaterial = new LocalRpKeyMaterial(
    $signingSeed,
    Wire::decodeLocalRpDescriptor($descriptor->descriptor)->signingPublicKey,
    str_repeat("\0", 32),
    str_repeat("\0", 32),
    $descriptor,
    $grantee['fingerprint']
);

final class ActAsMapDns implements DnsResolver
{
    /** @param array<string,string[]> $records */
    public function __construct(private array $records)
    {
    }

    public function txtLookup(string $name): array
    {
        if (!isset($this->records[$name])) {
            throw new \RuntimeException("no fake record for {$name}");
        }
        return $this->records[$name];
    }
}

function actAsBegin(LocalRpKeyMaterial $km, array $case, DnsResolver $dns, array $overrides = []): array
{
    $o = $overrides + [
        'user_domain' => 'alice@' . ACT_AS_DOMAIN,
        'scope_set' => hexToBytes($case['grant_request']['inputs']['scope_set_signed_cbor_hex']),
        'callback_url' => ACT_AS_CALLBACK,
        'lifetime' => 1800,
        'renewal' => null,
        'window' => ActAs::DEFAULT_REQUEST_WINDOW_SECONDS,
    ];
    return ActAs::beginActAs(new BeginActAsConfig(
        $km,
        $o['user_domain'],
        $o['scope_set'],
        $o['callback_url'],
        new \DateTimeImmutable($case['grant_request']['inputs']['requested_at']),
        $o['lifetime'],
        $o['renewal'],
        $dns,
        $o['window']
    ));
}

TestKit::test('act_as.vector_descriptor_round_trips', function () use ($case, $grantee, $keyMaterial) {
    TestKit::assertEquals($grantee['fingerprint'], $case['grantee']['local_rp_descriptor_fingerprint']);
    TestKit::assertEquals($grantee['fingerprint'], Crypto::fingerprint($keyMaterial->signingPublicKey));
    TestKit::assertEquals(Crypto::ed25519PublicKeyFromSeed($keyMaterial->signingPrivateKey), $keyMaterial->signingPublicKey);
});

TestKit::test('act_as.vector_grant_request', function () use ($case, $keyMaterial) {
    $inputs = $case['grant_request']['inputs'];
    $signed = ActAs::signGrantRequest(new ActAsGrantRequest([
        'grantee' => new GranteeRef(['local_rp_descriptor_fingerprint' => $keyMaterial->fingerprint]),
        'scope_set' => ActAsWire::decodeSignedActAsScopeSet(hexToBytes($inputs['scope_set_signed_cbor_hex'])),
        'requested_lifetime_seconds' => $inputs['requested_lifetime_seconds'],
        'requested_renewal_window_seconds' => $inputs['requested_renewal_window_seconds'],
        'callback_url' => $inputs['callback_url'],
        'nonce' => $inputs['nonce'],
        'requested_at' => $inputs['requested_at'],
        'expires_at' => $inputs['expires_at'],
    ]), $keyMaterial);
    TestKit::assertEquals($case['grant_request']['request_cbor_hex'], bin2hex($signed->request), 'request bytes');
    TestKit::assertEquals(
        $case['grant_request']['signature_input_cbor_hex'],
        bin2hex(LocalRp::envelopeSignatureInput(ActAs::GRANT_REQUEST_TAG, $signed->request)),
        'signature input'
    );
    TestKit::assertEquals($case['grant_request']['signed_cbor_hex'], bin2hex(ActAsWire::encodeSignedActAsGrantRequest($signed)), 'signed bytes');
    TestKit::assertEquals($case['grant_request']['url_param'], ActAs::signedGrantRequestToUrlParam($signed), 'url param');
});

TestKit::test('act_as.vector_refresh_request', function () use ($case, $keyMaterial) {
    $inputs = $case['refresh_request']['inputs'];
    $signed = ActAs::signRefreshRequest(new ActAsRefreshRequest([
        'grant_id' => $inputs['grant_id'],
        'grantee' => new GranteeRef(['local_rp_descriptor_fingerprint' => $keyMaterial->fingerprint]),
        'requested_at' => $inputs['requested_at'],
        'expires_at' => $inputs['expires_at'],
        'nonce' => $inputs['nonce'],
    ]), $keyMaterial);
    TestKit::assertEquals($case['refresh_request']['request_cbor_hex'], bin2hex($signed->request), 'request bytes');
    TestKit::assertEquals($case['refresh_request']['signed_cbor_hex'], bin2hex(ActAsWire::encodeSignedActAsRefreshRequest($signed)), 'signed bytes');
});

TestKit::test('act_as.vector_presentation_and_credential', function () use ($case, $keyMaterial) {
    $inputs = $case['presentation']['inputs'];
    $grant = ActAsWire::decodeSignedActAsGrant(hexToBytes($inputs['grant_signed_cbor_hex']));
    TestKit::assertEquals($inputs['grant_signed_cbor_hex'], bin2hex(ActAsWire::encodeSignedActAsGrant($grant)), 'grant round trip');
    TestKit::assertEquals($case['presentation']['grant_hash_hex'], bin2hex(ActAs::grantHash($grant->grant)), 'grant hash');
    $result = ActAs::present(
        $grant,
        new ApplicationRef($inputs['audience']),
        hexToBytes($inputs['request_digest_hex']),
        new \DateTimeImmutable($inputs['presented_at']),
        hexToBytes($inputs['nonce_hex']),
        $keyMaterial
    );
    TestKit::assertEquals($case['presentation']['presentation_cbor_hex'], bin2hex($result->credential->presentation->presentation), 'presentation');
    TestKit::assertEquals($case['presentation']['credential_cbor_hex'], bin2hex($result->credentialCbor), 'credential');
});

TestKit::test('act_as.format_time_drops_fraction', function () {
    TestKit::assertEquals('2026-10-06T12:05:00Z', ActAs::formatTime(new \DateTimeImmutable('2026-10-06T14:05:00.987+02:00')));
});

// ---------------------------------------------------------------------
// beginActAs
// ---------------------------------------------------------------------

TestKit::test('act_as.begin_uses_discovered_host_and_signs_verifiable_request', function () use ($case, $keyMaterial) {
    [$redirect, $pending] = actAsBegin($keyMaterial, $case, new ActAsMapDns([
        '_linkkeys_apis.' . ACT_AS_DOMAIN => ['v=lk1 https=login.example.test/linkkeys'],
    ]));
    $u = parse_url($redirect->redirectUrl);
    TestKit::assertEquals('https://login.example.test/linkkeys/auth/act-as', "{$u['scheme']}://{$u['host']}{$u['path']}");
    parse_str($u['query'], $q);
    TestKit::assertEquals(['signed_request'], array_keys($q));
    TestKit::assertEquals(ACT_AS_DOMAIN, $pending->userDomain);
    TestKit::assertEquals(ACT_AS_CALLBACK, $pending->callbackUrl);
    TestKit::assertEquals(43, strlen($pending->nonce));

    $signed = ActAsWire::decodeSignedActAsGrantRequest(Encoding::base64UrlDecodeUnpadded($q['signed_request']));
    $request = ActAsWire::decodeActAsGrantRequest($signed->request);
    $inputs = $case['grant_request']['inputs'];
    TestKit::assertEquals($pending->nonce, $request->nonce);
    TestKit::assertEquals($keyMaterial->fingerprint, $request->grantee->localRpDescriptorFingerprint);
    TestKit::assertTrue($request->grantee->application === null);
    TestKit::assertEquals($inputs['requested_at'], $request->requestedAt);
    TestKit::assertEquals($inputs['expires_at'], $request->expiresAt);
    TestKit::assertEquals(1800, $request->requestedLifetimeSeconds);
    TestKit::assertTrue($request->requestedRenewalWindowSeconds === null);
    TestKit::assertEquals(ACT_AS_CALLBACK, $request->callbackUrl);
    TestKit::assertEquals($inputs['scope_set_signed_cbor_hex'], bin2hex(ActAsWire::encodeSignedActAsScopeSet($request->scopeSet)));
    TestKit::assertEquals($keyMaterial->fingerprint, $signed->proof->signature->signedByKeyId);
    TestKit::assertTrue($signed->proof->localRpDescriptor->descriptor === $keyMaterial->descriptor->descriptor);
    TestKit::assertTrue($signed->proof->localRpDescriptor->signature === $keyMaterial->descriptor->signature);
    TestKit::assertTrue(Crypto::verifyEd25519(
        LocalRp::envelopeSignatureInput(ActAs::GRANT_REQUEST_TAG, $signed->request),
        $signed->proof->signature->signature,
        $keyMaterial->signingPublicKey
    ), 'grant request signature must verify with the descriptor key');
});

TestKit::test('act_as.begin_falls_back_to_identity_domain', function () use ($case, $keyMaterial) {
    [$redirect] = actAsBegin($keyMaterial, $case, new ActAsMapDns([]));
    TestKit::assertTrue(str_starts_with($redirect->redirectUrl, 'https://' . ACT_AS_DOMAIN . '/auth/act-as?signed_request='), $redirect->redirectUrl);
});

TestKit::test('act_as.begin_makes_fresh_nonce', function () use ($case, $keyMaterial) {
    [, $a] = actAsBegin($keyMaterial, $case, new ActAsMapDns([]));
    [, $b] = actAsBegin($keyMaterial, $case, new ActAsMapDns([]));
    TestKit::assertTrue($a->nonce !== $b->nonce);
});

TestKit::test('act_as.begin_rejects_bad_input', function () use ($case, $keyMaterial) {
    foreach ([
        ['window' => 901],
        ['window' => 0],
        ['callback_url' => 'javascript:alert(1)'],
        ['user_domain' => 'not a domain'],
        ['renewal' => -1],
        ['lifetime' => 0],
    ] as $overrides) {
        TestKit::assertThrows(
            fn () => actAsBegin($keyMaterial, $case, new ActAsMapDns([]), $overrides),
            'expected rejection for ' . json_encode($overrides)
        );
    }
    foreach (["\xff", "\x41\x00", hexToBytes('a0')] as $bad) {
        try {
            actAsBegin($keyMaterial, $case, new ActAsMapDns([]), ['scope_set' => $bad]);
            throw new \RuntimeException('expected a decode error for ' . bin2hex($bad));
        } catch (LocalRpError $e) {
            TestKit::assertEquals(LocalRpError::DECODE, $e->kind);
        }
    }
});

// ---------------------------------------------------------------------
// completeActAsCallback
// ---------------------------------------------------------------------

TestKit::test('act_as.callback_returns_grant_id_on_nonce_match', function () use ($case, $keyMaterial) {
    [, $pending] = actAsBegin($keyMaterial, $case, new ActAsMapDns([]));
    $arrived = ACT_AS_CALLBACK . '?act_as_grant_id=grant-42&nonce=' . $pending->nonce;
    TestKit::assertEquals('grant-42', ActAs::completeActAsCallback($pending, $arrived));
    TestKit::assertEquals('grant-42', ActAs::completeActAsCallback($pending, '?' . parse_url($arrived, PHP_URL_QUERY)));
    TestKit::assertEquals('grant-42', ActAs::completeActAsCallback($pending, ['act_as_grant_id' => 'grant-42', 'nonce' => $pending->nonce]));
});

TestKit::test('act_as.callback_rejects_nonce_mismatch_and_missing_parameters', function () use ($case, $keyMaterial) {
    [, $pending] = actAsBegin($keyMaterial, $case, new ActAsMapDns([]));
    $wrong = substr($pending->nonce, 0, -1) . (str_ends_with($pending->nonce, 'A') ? 'B' : 'A');
    foreach ([$wrong, 'short'] as $nonce) {
        try {
            ActAs::completeActAsCallback($pending, ACT_AS_CALLBACK . "?act_as_grant_id=grant-42&nonce={$nonce}");
            throw new \RuntimeException('expected a nonce mismatch');
        } catch (LocalRpError $e) {
            TestKit::assertEquals(LocalRpError::NONCE_MISMATCH, $e->kind);
        }
    }
    TestKit::assertThrows(fn () => ActAs::completeActAsCallback($pending, ACT_AS_CALLBACK . '?nonce=' . $pending->nonce));
    TestKit::assertThrows(fn () => ActAs::completeActAsCallback($pending, ACT_AS_CALLBACK . '?act_as_grant_id=grant-42'));
    TestKit::assertThrows(fn () => ActAs::completeActAsCallback($pending, ['act_as_grant_id' => 'grant-42', 'nonce' => ['x']]));
    // A repeated parameter is refused, even when one value is correct.
    TestKit::assertThrows(fn () => ActAs::completeActAsCallback(
        $pending,
        ACT_AS_CALLBACK . '?act_as_grant_id=evil&act_as_grant_id=grant-42&nonce=' . $pending->nonce
    ));
    TestKit::assertThrows(fn () => ActAs::completeActAsCallback(
        $pending,
        ACT_AS_CALLBACK . '?act_as_grant_id=grant-42&nonce=' . $pending->nonce . '&nonce=x'
    ));
});

// ---------------------------------------------------------------------
// refreshActAsGrant over the fake RPC wire
// ---------------------------------------------------------------------

function actAsRefreshDns(): DnsResolver
{
    return new ActAsMapDns([
        '_linkkeys.' . ACT_AS_DOMAIN => ['v=lk1 fp=' . str_repeat('ab', 32)],
        '_linkkeys_apis.' . ACT_AS_DOMAIN => ['v=lk1 tcp=127.0.0.1:0'],
    ]);
}

/** A grant as a home domain stores it. Only the identifying fields matter
 * to the grantee; the audience checks the signature. */
function actAsServedGrant(string $grantId, string $fingerprint, string $subjectDomain): SignedActAsGrant
{
    $grant = Cbor::encode([
        'grant_id' => $grantId,
        'user_id' => 'user-1',
        'subject_domain' => $subjectDomain,
        'grantee' => ['local_rp_descriptor_fingerprint' => $fingerprint],
        'audience' => ['subject_user_id' => 'audience-owner', 'subject_domain' => 'audience.test', 'application_id' => 'audience-app'],
        'scope_set' => [
            'scope_set' => Cbor::bytes("\xa0"),
            'signer_instance_id' => 'audience-inst',
            'signatures' => [['signed_by_key_id' => 'audience-key', 'signature' => Cbor::bytes(str_repeat("\x00", 64))]],
        ],
        'approved_scope' => ['read'],
        'issued_at' => '2026-10-06T12:00:00Z',
        'expires_at' => '2026-10-06T13:00:00Z',
        'series_issued_at' => '2026-10-06T12:00:00Z',
        'renewable_until' => '2026-10-06T13:00:00Z',
    ]);
    return new SignedActAsGrant([
        'grant' => $grant,
        'signatures' => [new ClaimSignature(['domain' => $subjectDomain, 'signed_by_key_id' => 'k1', 'signature' => str_repeat("\x09", 64)])],
    ]);
}

TestKit::test('act_as.refresh_refuses_another_grant', function () use ($keyMaterial) {
    foreach ([
        actAsServedGrant('grant-2', $keyMaterial->fingerprint, ACT_AS_DOMAIN),
        actAsServedGrant('grant-1', 'another-local-rp', ACT_AS_DOMAIN),
        actAsServedGrant('grant-1', $keyMaterial->fingerprint, 'other.test'),
    ] as $served) {
        $transport = new FakeTransport(function () use ($served) {
            $resp = new RefreshActAsGrantResponse(['grant' => $served, 'signed' => false]);
            return [0, 'RefreshActAsGrantResponse', ActAsWire::encodeRefreshActAsGrantResponse($resp), null];
        });
        try {
            ActAs::refreshActAsGrant($keyMaterial, ACT_AS_DOMAIN, 'grant-1', new \DateTimeImmutable('2026-10-06T12:40:00Z'), $transport, actAsRefreshDns());
            throw new \RuntimeException('expected a grant mismatch');
        } catch (LocalRpError $e) {
            TestKit::assertEquals(LocalRpError::GRANT_MISMATCH, $e->kind);
        }
    }
});

TestKit::test('act_as.refresh_calls_refresh_grant_with_verifiable_request', function () use ($keyMaterial) {
    $now = new \DateTimeImmutable('2026-10-06T12:40:00Z');
    $served = actAsServedGrant('grant-1', $keyMaterial->fingerprint, ACT_AS_DOMAIN);
    $seen = [];
    $transport = new FakeTransport(function (string $service, string $op, string $payload) use (&$seen, $served) {
        $seen[] = [$service, $op, $payload];
        if ($service === 'ActAs' && $op === 'refresh-grant') {
            $resp = new RefreshActAsGrantResponse(['grant' => $served, 'signed' => true]);
            return [0, 'RefreshActAsGrantResponse', ActAsWire::encodeRefreshActAsGrantResponse($resp), null];
        }
        return [5, null, '', "no handler for {$service}/{$op}"];
    });

    $result = ActAs::refreshActAsGrant($keyMaterial, ACT_AS_DOMAIN, 'grant-1', $now, $transport, actAsRefreshDns());

    TestKit::assertTrue($result->signed === true);
    TestKit::assertEquals(ActAsWire::encodeSignedActAsGrant($served), ActAsWire::encodeSignedActAsGrant($result->grant));
    TestKit::assertEquals(1, count($seen));
    [$service, $op, $payload] = $seen[0];
    TestKit::assertEquals('ActAs', $service);
    TestKit::assertEquals('refresh-grant', $op);
    $signed = ActAsWire::decodeRefreshActAsGrantRequest($payload);
    $request = ActAsWire::decodeActAsRefreshRequest($signed->request);
    TestKit::assertEquals('grant-1', $request->grantId);
    TestKit::assertEquals($keyMaterial->fingerprint, $request->grantee->localRpDescriptorFingerprint);
    TestKit::assertEquals('2026-10-06T12:40:00Z', $request->requestedAt);
    TestKit::assertEquals('2026-10-06T12:45:00Z', $request->expiresAt);
    TestKit::assertEquals(43, strlen($request->nonce));
    TestKit::assertEquals($keyMaterial->fingerprint, $signed->proof->signature->signedByKeyId);
    TestKit::assertTrue($signed->proof->applicationInstanceId === null);
    TestKit::assertTrue($signed->proof->localRpDescriptor->descriptor === $keyMaterial->descriptor->descriptor);
    TestKit::assertTrue(Crypto::verifyEd25519(
        LocalRp::envelopeSignatureInput(ActAs::REFRESH_REQUEST_TAG, $signed->request),
        $signed->proof->signature->signature,
        $keyMaterial->signingPublicKey
    ), 'refresh signature must verify with the descriptor key');
});

TestKit::test('act_as.refresh_surfaces_server_error', function () use ($keyMaterial) {
    $transport = new FakeTransport(fn () => [7, null, '', 'grant store unavailable']);
    try {
        ActAs::refreshActAsGrant($keyMaterial, ACT_AS_DOMAIN, 'grant-1', new \DateTimeImmutable('now'), $transport, actAsRefreshDns());
        throw new \RuntimeException('expected RpcServerError');
    } catch (RpcServerError $e) {
        TestKit::assertEquals(7, $e->status);
    }
});

exit(TestKit::summary('ActAsTest') === 0 ? 0 : 1);
