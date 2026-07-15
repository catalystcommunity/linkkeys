<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';

use LinkKeys\LocalRp\Encoding;

$vectors = loadJson(__DIR__ . '/../../../conformance/url_params.json');

foreach ($vectors['cases'] as $case) {
    TestKit::test('url_params.cases.' . $case['name'], function () use ($case) {
        $cbor = hexToBytes($case['cbor_hex']);
        TestKit::assertEquals($case['base64url_unpadded'], Encoding::base64UrlEncodeUnpadded($cbor));
        TestKit::assertEquals($cbor, Encoding::base64UrlDecodeUnpadded($case['base64url_unpadded']));

        if ($case['name'] === 'signed_local_rp_login_request') {
            TestKit::assertDoesNotThrow(fn () => Encoding::signedLocalRpLoginRequestFromUrlParam($case['base64url_unpadded']));
        } elseif ($case['name'] === 'local_rp_encrypted_callback') {
            TestKit::assertDoesNotThrow(fn () => Encoding::localRpEncryptedCallbackFromUrlParam($case['base64url_unpadded']));
        }
    });
}

foreach ($vectors['negative_cases'] as $i => $case) {
    TestKit::test("url_params.negative.{$i}", function () use ($case) {
        TestKit::assertEquals(false, $case['expected_valid']);
        TestKit::assertThrows(fn () => Encoding::base64UrlDecodeUnpadded($case['input']));
    });
}

exit(TestKit::summary('UrlParamsTest') === 0 ? 0 : 1);
