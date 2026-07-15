<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';

use Csilgen\Generated\ClaimSignature;
use Csilgen\Generated\DomainPublicKey;
use Csilgen\Generated\RevocationCertificate;
use Csilgen\Generated\SignedLocalRpCallbackPayload;
use LinkKeys\LocalRp\LocalRp;
use LinkKeys\LocalRp\Revocation;
use LinkKeys\LocalRp\RevocationError;
use LinkKeys\LocalRp\Time;
use LinkKeys\LocalRp\Wire;

$vectors = loadJson(__DIR__ . '/../../../conformance/revocations.json');

TestKit::test('revocations.constants', function () use ($vectors) {
    TestKit::assertEquals($vectors['tag'], Revocation::TAG);
    TestKit::assertEquals($vectors['quorum'], Revocation::QUORUM);
});

/** @return DomainPublicKey[] */
function revocationsDomainKeys(array $vectors): array
{
    $keys = [];
    foreach ($vectors['domain_keys'] as $k) {
        $keys[] = new DomainPublicKey([
            'key_id' => $k['key_id'],
            'public_key' => hexToBytes($k['public_key_hex']),
            'fingerprint' => $k['fingerprint_hex'],
            'algorithm' => $k['algorithm'],
            'key_usage' => $k['key_usage'],
            'created_at' => $k['created_at'],
            'expires_at' => $k['expires_at'],
            'revoked_at' => $k['revoked_at'],
        ]);
    }
    return $keys;
}

function revocationsCertFromCase(array $case): RevocationCertificate
{
    $c = $case['certificate'];
    $sigs = array_map(fn ($s) => new ClaimSignature([
        'domain' => $s['domain'],
        'signed_by_key_id' => $s['signed_by_key_id'],
        'signature' => hexToBytes($s['signature_hex']),
    ]), $c['signatures']);
    return new RevocationCertificate([
        'target_key_id' => $c['target_key_id'],
        'target_fingerprint' => $c['target_fingerprint'],
        'revoked_at' => $c['revoked_at'],
        'signatures' => $sigs,
    ]);
}

$domainKeys = revocationsDomainKeys($vectors);

foreach ($vectors['certificate_cases'] as $case) {
    TestKit::test('revocations.certificate_cases.' . $case['name'], function () use ($case, $domainKeys) {
        $cert = revocationsCertFromCase($case);
        $count = Revocation::countValidSigners($cert, $domainKeys, $case['verify_domain']);
        TestKit::assertEquals($case['expected_counted_signers'], $count, 'expected_counted_signers');

        if ($case['expected_valid']) {
            TestKit::assertDoesNotThrow(fn () => Revocation::verifyRevocationCertificate($cert, $domainKeys, $case['verify_domain']));
        } else {
            TestKit::assertThrows(fn () => Revocation::verifyRevocationCertificate($cert, $domainKeys, $case['verify_domain']));
        }
    });
}

TestKit::test('revocations.certificate_cbor_roundtrip', function () use ($vectors) {
    $case = null;
    foreach ($vectors['certificate_cases'] as $c) {
        if ($c['name'] === 'valid_quorum_two_siblings') {
            $case = $c;
            break;
        }
    }
    TestKit::assertTrue($case !== null);
    $cert = revocationsCertFromCase($case);
    $bytes = Wire::encodeRevocationCertificate($cert);
    $decoded = Wire::decodeRevocationCertificate($bytes);
    TestKit::assertEquals($cert->targetKeyId, $decoded->targetKeyId);
    TestKit::assertEquals($cert->targetFingerprint, $decoded->targetFingerprint);
    TestKit::assertEquals($cert->revokedAt, $decoded->revokedAt);
    TestKit::assertEquals(count($cert->signatures), count($decoded->signatures));
});

TestKit::test('revocations.application_case', function () use ($vectors, $domainKeys) {
    $app = $vectors['application_case'];
    $env = $app['envelope'];

    $signedPayload = new SignedLocalRpCallbackPayload([
        'payload' => hexToBytes($env['payload_cbor_hex']),
        'signing_key_id' => $env['signing_key_id'],
        'signature' => hexToBytes($env['signature_hex']),
    ]);
    $now = Time::parseRfc3339($app['verify_now']);
    $skew = $app['clock_skew_seconds'];

    // Before revocation: the fetched key list shows the target key with NO
    // revoked_at, so the envelope verifies.
    TestKit::assertDoesNotThrow(function () use ($signedPayload, $domainKeys, $now, $skew) {
        LocalRp::verifyLocalRpCallbackPayload($signedPayload, $domainKeys, $now, $skew);
    }, 'expected_valid_before_revocation');
    TestKit::assertEquals(true, $app['expected_valid_before_revocation']);

    // Apply the referenced certificate (quorum-verified) and mark its
    // target revoked; the SAME envelope must now fail.
    $certCase = null;
    foreach ($vectors['certificate_cases'] as $c) {
        if ($c['name'] === 'valid_quorum_two_siblings') {
            $certCase = $c;
            break;
        }
    }
    $cert = revocationsCertFromCase($certCase);
    Revocation::verifyRevocationCertificate($cert, $domainKeys, $vectors['domain']);

    $afterRevocation = array_map(function (DomainPublicKey $k) use ($cert) {
        if ($k->keyId !== $cert->targetKeyId) {
            return $k;
        }
        return new DomainPublicKey([
            'key_id' => $k->keyId,
            'public_key' => $k->publicKey,
            'fingerprint' => $k->fingerprint,
            'algorithm' => $k->algorithm,
            'key_usage' => $k->keyUsage,
            'created_at' => $k->createdAt,
            'expires_at' => $k->expiresAt,
            'revoked_at' => $cert->revokedAt,
        ]);
    }, $domainKeys);

    TestKit::assertThrows(function () use ($signedPayload, $afterRevocation, $now, $skew) {
        LocalRp::verifyLocalRpCallbackPayload($signedPayload, $afterRevocation, $now, $skew);
    }, 'expected_valid_after_revocation');
    TestKit::assertEquals(false, $app['expected_valid_after_revocation']);
});

exit(TestKit::summary('RevocationsTest') === 0 ? 0 : 1);
