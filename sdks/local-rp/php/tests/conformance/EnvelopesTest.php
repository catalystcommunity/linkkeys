<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';

use LinkKeys\LocalRp\Cbor;
use LinkKeys\LocalRp\Crypto;
use LinkKeys\LocalRp\LocalRp;

$vectors = loadJson(__DIR__ . '/../../../conformance/envelopes.json');

function checkEnvelopeCase(array $case): void
{
    $context = $case['context'];
    $payload = hexToBytes($case['payload_cbor_hex']);
    $expectedSignatureInput = hexToBytes($case['signature_input_cbor_hex']);
    $signature = hexToBytes($case['signature_hex']);
    $verifyKey = hexToBytes($case['verify_key_hex']);
    $expectedValid = $case['expected_valid'];

    $sigInput = LocalRp::envelopeSignatureInput($context, $payload);
    TestKit::assertEquals($expectedSignatureInput, $sigInput, 'signature_input_cbor_hex mismatch for ' . ($case['name'] ?? $case['structure']));

    $valid = Crypto::verifyEd25519($sigInput, $signature, $verifyKey);
    TestKit::assertEquals($expectedValid, $valid, 'expected_valid mismatch for ' . ($case['name'] ?? $case['structure']));
}

foreach ($vectors['cases'] as $case) {
    TestKit::test('envelopes.cases.' . $case['structure'], fn () => checkEnvelopeCase($case));
}

foreach ($vectors['negative_cases'] as $case) {
    TestKit::test('envelopes.negative_cases.' . $case['name'], fn () => checkEnvelopeCase($case));
}

// The two-element CBOR array framing itself: context is a CBOR text string,
// payload is a CBOR byte string, and this is NOT a bare concatenation.
TestKit::test('envelopes.signature_input_is_cbor_array_not_concatenation', function () {
    $context = 'ctx';
    $payload = "\x01\x02\x03";
    $sigInput = LocalRp::envelopeSignatureInput($context, $payload);
    TestKit::assertTrue($sigInput !== $context . $payload, 'must not be a bare concatenation');
    $decoded = Cbor::decode($sigInput);
    TestKit::assertTrue(is_array($decoded) && count($decoded) === 2, 'must decode to a 2-element array');
    TestKit::assertEquals($context, $decoded[0]);
    TestKit::assertEquals($payload, $decoded[1]);
});

exit(TestKit::summary('EnvelopesTest') === 0 ? 0 : 1);
