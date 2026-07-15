<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';

use Csilgen\Generated\Claim;
use Csilgen\Generated\ClaimSignature;
use Csilgen\Generated\DomainPublicKey;
use LinkKeys\LocalRp\ClaimError;
use LinkKeys\LocalRp\Claims;
use LinkKeys\LocalRp\DomainKeySet;
use LinkKeys\LocalRp\Time;
use LinkKeys\LocalRp\Wire;

$vectors = loadJson(__DIR__ . '/../../../conformance/claims.json');

/**
 * Group a flat domain_keys[] vector (as in claims.json's file-level
 * default, or a negative_cases[].domain_keys override) into the
 * per-signing-domain DomainKeySet[] shape Claims::verifyClaim expects.
 *
 * @return DomainKeySet[]
 */
function claimsDomainKeySets(array $domainKeyEntries): array
{
    $byDomain = [];
    foreach ($domainKeyEntries as $k) {
        $byDomain[$k['domain']][] = new DomainPublicKey([
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
    $sets = [];
    foreach ($byDomain as $domain => $keys) {
        $sets[] = new DomainKeySet($domain, $keys);
    }
    return $sets;
}

function claimFromVector(array $c): Claim
{
    $sigs = array_map(fn ($s) => new ClaimSignature([
        'domain' => $s['domain'],
        'signed_by_key_id' => $s['signed_by_key_id'],
        'signature' => hexToBytes($s['signature_hex']),
    ]), $c['signatures']);
    return new Claim([
        'claim_id' => $c['claim_id'],
        'user_id' => $c['user_id'],
        'claim_type' => $c['claim_type'],
        'claim_value' => hexToBytes($c['claim_value_hex']),
        'signatures' => $sigs,
        'attested_at' => $c['attested_at'],
        'created_at' => $c['created_at'],
        'expires_at' => $c['expires_at'],
        'revoked_at' => $c['revoked_at'],
    ]);
}

/** @param Claim[] $claims */
function findClaimVectorCase(array $vectors, string $name): array
{
    foreach ($vectors['cases'] as $c) {
        if ($c['name'] === $name) {
            return $c;
        }
    }
    throw new \RuntimeException("no such case: {$name}");
}

$defaultDomainKeys = claimsDomainKeySets($vectors['domain_keys']);
// Any instant within every fixture key's/claim's validity window (keys and
// the far-future claim both run 2026-01-01..2126-01-01; the no-expiry claims
// have none to violate).
$now = Time::parseRfc3339('2026-06-01T00:00:00+00:00');

TestKit::test('claims.constants', function () use ($vectors) {
    TestKit::assertEquals($vectors['tag'], Claims::CLAIM_PAYLOAD_TAG);
});

// ---------------------------------------------------------------------
// cases[] — positive: wire round-trip (byte-exact re-encode), the signed
// payload construction per signature, and full verifyClaim().
// ---------------------------------------------------------------------

foreach ($vectors['cases'] as $case) {
    TestKit::test('claims.cases.' . $case['name'] . '.wire_roundtrip', function () use ($case) {
        $wireBytes = hexToBytes($case['claim_cbor_hex']);
        $decoded = Wire::decodeClaim($wireBytes);
        $expected = claimFromVector($case['claim']);

        TestKit::assertEquals($expected->claimId, $decoded->claimId, 'claim_id');
        TestKit::assertEquals($expected->userId, $decoded->userId, 'user_id');
        TestKit::assertEquals($expected->claimType, $decoded->claimType, 'claim_type');
        TestKit::assertEquals($expected->claimValue, $decoded->claimValue, 'claim_value');
        TestKit::assertEquals($expected->attestedAt, $decoded->attestedAt, 'attested_at');
        TestKit::assertEquals($expected->createdAt, $decoded->createdAt, 'created_at');
        TestKit::assertEquals($expected->expiresAt, $decoded->expiresAt, 'expires_at');
        TestKit::assertEquals($expected->revokedAt, $decoded->revokedAt, 'revoked_at');
        TestKit::assertEquals(count($expected->signatures), count($decoded->signatures), 'signature count');
        foreach ($expected->signatures as $i => $sig) {
            TestKit::assertEquals($sig->domain, $decoded->signatures[$i]->domain, "signatures[{$i}].domain");
            TestKit::assertEquals($sig->signedByKeyId, $decoded->signatures[$i]->signedByKeyId, "signatures[{$i}].signed_by_key_id");
            TestKit::assertEquals($sig->signature, $decoded->signatures[$i]->signature, "signatures[{$i}].signature");
        }

        // Decoding then re-encoding must reproduce claim_cbor_hex exactly —
        // this is the check a bstr/tstr-confused encoder cannot pass for
        // claim_non_utf8_binary_value.
        TestKit::assertEquals($wireBytes, Wire::encodeClaim($decoded), 'byte-exact re-encode');
    });

    TestKit::test('claims.cases.' . $case['name'] . '.signed_payload', function () use ($case) {
        $decoded = Wire::decodeClaim(hexToBytes($case['claim_cbor_hex']));
        foreach ($case['claim']['signatures'] as $sigVec) {
            $payload = Claims::claimSignPayload(
                $decoded->claimId,
                $decoded->claimType,
                $decoded->claimValue,
                $decoded->userId,
                $case['subject_domain'],
                $sigVec['domain'],
                $decoded->expiresAt,
                $decoded->attestedAt
            );
            TestKit::assertEquals(hexToBytes($sigVec['signed_payload_cbor_hex']), $payload, "signed_payload for signer {$sigVec['signed_by_key_id']}");
        }
    });

    TestKit::test('claims.cases.' . $case['name'] . '.verify', function () use ($case, $defaultDomainKeys, $now) {
        $decoded = Wire::decodeClaim(hexToBytes($case['claim_cbor_hex']));
        TestKit::assertEquals(true, $case['expected_valid']);
        TestKit::assertDoesNotThrow(
            fn () => Claims::verifyClaim($decoded, $case['subject_domain'], $defaultDomainKeys, $now),
            $case['description'] ?? ''
        );
    });
}

// ---------------------------------------------------------------------
// decode_negative_cases[] — must FAIL to decode at all (the tstr
// claim_value trap: byte-identical to a positive case except claim_value
// is a CBOR text string instead of a byte string).
// ---------------------------------------------------------------------

foreach ($vectors['decode_negative_cases'] as $case) {
    TestKit::test('claims.decode_negative.' . $case['name'], function () use ($case) {
        TestKit::assertEquals(false, $case['expected_decode_ok']);
        TestKit::assertThrows(
            fn () => Wire::decodeClaim(hexToBytes($case['claim_cbor_hex'])),
            $case['description'] ?? ''
        );
    });
}

// ---------------------------------------------------------------------
// negative_cases[] — decode succeeds (the wire bytes are well-formed) but
// verification must fail with the specific expected error kind. An
// optional per-case domain_keys overrides the file-level default.
// ---------------------------------------------------------------------

foreach ($vectors['negative_cases'] as $case) {
    TestKit::test('claims.negative_cases.' . $case['name'], function () use ($case, $defaultDomainKeys, $now) {
        $decoded = Wire::decodeClaim(hexToBytes($case['claim_cbor_hex']));
        $domainKeys = isset($case['domain_keys']) ? claimsDomainKeySets($case['domain_keys']) : $defaultDomainKeys;

        try {
            Claims::verifyClaim($decoded, $case['subject_domain'], $domainKeys, $now);
            throw new \RuntimeException("expected verifyClaim to throw a ClaimError({$case['expected_error']}), it did not throw");
        } catch (ClaimError $e) {
            TestKit::assertEquals($case['expected_error'], $e->kind, $case['description'] ?? '');
        }
    });
}

// ---------------------------------------------------------------------
// ticket_redemption_response — the actual wire message completeLocalLogin
// consumes: byte-exact round trip AND every embedded claim verifies.
// ---------------------------------------------------------------------

TestKit::test('claims.ticket_redemption_response', function () use ($vectors, $defaultDomainKeys, $now) {
    $trr = $vectors['ticket_redemption_response'];
    $wireBytes = hexToBytes($trr['response_cbor_hex']);
    $decoded = Wire::decodeLocalRpTicketRedemptionResponse($wireBytes);

    TestKit::assertEquals($trr['user_id'], $decoded->userId, 'user_id');
    TestKit::assertEquals($trr['user_domain'], $decoded->userDomain, 'user_domain');
    TestKit::assertEquals($trr['ticket_expires_at'], $decoded->ticketExpiresAt, 'ticket_expires_at');

    $expectedOrder = ['claim_utf8_text_value', 'claim_non_utf8_binary_value', 'claim_multiple_signatures'];
    TestKit::assertEquals(count($expectedOrder), count($decoded->claims), 'claim count');

    foreach ($expectedOrder as $i => $name) {
        $case = findClaimVectorCase($vectors, $name);
        $claim = $decoded->claims[$i];

        TestKit::assertEquals($case['claim']['claim_id'], $claim->claimId, "{$name}.claim_id");
        TestKit::assertEquals(hexToBytes($case['claim']['claim_value_hex']), $claim->claimValue, "{$name}.claim_value");

        // Decoding must reproduce each claim byte-exactly.
        TestKit::assertEquals(hexToBytes($case['claim_cbor_hex']), Wire::encodeClaim($claim), "{$name} byte-exact re-encode");

        // And every embedded claim's own signature(s) must verify.
        TestKit::assertDoesNotThrow(
            fn () => Claims::verifyClaim($claim, $vectors['subject_domain'], $defaultDomainKeys, $now),
            "{$name} embedded claim verify"
        );
    }

    // Re-encoding the whole response must reproduce response_cbor_hex exactly.
    TestKit::assertEquals($wireBytes, Wire::encodeLocalRpTicketRedemptionResponse($decoded), 'response byte-exact re-encode');
});

exit(TestKit::summary('ClaimsTest') === 0 ? 0 : 1);
