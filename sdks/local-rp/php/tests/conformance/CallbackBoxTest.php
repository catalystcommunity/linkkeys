<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';

use Csilgen\Generated\LocalRpEncryptedCallback;
use LinkKeys\LocalRp\Crypto;
use LinkKeys\LocalRp\LocalRp;
use LinkKeys\LocalRp\LocalRpError;
use LinkKeys\LocalRp\Wire;

$vectors = loadJson(__DIR__ . '/../../../conformance/callback_box.json');

foreach ($vectors['positive_cases'] as $case) {
    TestKit::test('callback_box.positive.' . $case['suite'], function () use ($case) {
        $encrypted = new LocalRpEncryptedCallback([
            'header' => hexToBytes($case['header_cbor_hex']),
            'ciphertext' => hexToBytes($case['ciphertext_hex']),
        ]);
        $decryptKey = hexToBytes($case['decrypt_private_key_hex']);
        $allowedSuites = $case['allowed_suites'];

        [$header, $signedPayload] = LocalRp::openLocalRpCallback($encrypted, $decryptKey, $allowedSuites);

        TestKit::assertEquals($case['suite'], $header->suite);
        TestKit::assertEquals($case['fingerprint'], $header->fingerprint);
        TestKit::assertEquals(hexToBytes($case['nonce_hex']), $header->nonce);
        TestKit::assertEquals(hexToBytes($case['state_hex']), $header->state);

        $expectedSignedPayload = Wire::decodeSignedLocalRpCallbackPayload(hexToBytes($case['plaintext_cbor_hex']));
        TestKit::assertEquals($expectedSignedPayload->payload, $signedPayload->payload);
        TestKit::assertEquals($expectedSignedPayload->signingKeyId, $signedPayload->signingKeyId);
        TestKit::assertEquals($expectedSignedPayload->signature, $signedPayload->signature);

        // Independent HKDF/AAD-context check (README: "publish so you can
        // unit-test your own HKDF derivation independent of a full decrypt").
        [$aeadKey, $kdfContext] = LocalRp::localRpCallbackKdf(
            $case['suite'],
            hexToBytes($case['ephemeral_public_key_hex']),
            hexToBytes($case['recipient_public_key_hex']),
            Crypto::x25519DiffieHellman($decryptKey, hexToBytes($case['ephemeral_public_key_hex']))
        );
        TestKit::assertEquals(hexToBytes($case['kdf_context_hex']), $kdfContext, 'kdf_context_hex mismatch');
        $expectedAad = hexToBytes($case['kdf_context_hex']) . hexToBytes($case['header_cbor_hex']);
        TestKit::assertEquals(hexToBytes($case['aad_hex']), $expectedAad, 'aad_hex mismatch');
    });
}

foreach ($vectors['negative_cases'] as $case) {
    TestKit::test('callback_box.negative.' . $case['name'], function () use ($case) {
        $encrypted = new LocalRpEncryptedCallback([
            'header' => hexToBytes($case['header_cbor_hex']),
            'ciphertext' => hexToBytes($case['ciphertext_hex']),
        ]);
        $decryptKey = hexToBytes($case['decrypt_private_key_hex']);
        $allowedSuites = $case['allowed_suites'];

        TestKit::assertThrows(function () use ($encrypted, $decryptKey, $allowedSuites) {
            LocalRp::openLocalRpCallback($encrypted, $decryptKey, $allowedSuites);
        }, $case['name'] . ' should fail: ' . ($case['description'] ?? ''));
    });
}

exit(TestKit::summary('CallbackBoxTest') === 0 ? 0 : 1);
