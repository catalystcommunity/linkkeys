<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';

use LinkKeys\LocalRp\LocalRp;
use LinkKeys\LocalRp\LocalRpError;
use LinkKeys\LocalRp\Time;

$vectors = loadJson(__DIR__ . '/../../../conformance/expirations.json');

$ce = $vectors['check_expirations'];
foreach ($ce['cases'] as $i => $case) {
    TestKit::test("expirations.check_expirations.{$i}.{$case['expected_level']}", function () use ($ce, $case) {
        $now = Time::parseRfc3339($case['now']);
        $status = LocalRp::checkExpirations($ce['expires_at'], $now);
        TestKit::assertEquals($case['expected_level'], $status->level);
    });
}

$ct = $vectors['check_timestamps'];
foreach ($ct['cases'] as $i => $case) {
    TestKit::test("expirations.check_timestamps.{$i}", function () use ($ct, $case) {
        $now = Time::parseRfc3339($case['now']);
        // check_timestamps is exercised indirectly through the descriptor
        // envelope (which calls it with the same issued_at/expires_at/skew
        // shape) since it is a private helper of LocalRp; build a minimal
        // signed descriptor with the vector's timestamps and confirm the
        // pass/fail outcome matches expected_valid.
        [$pub, $priv] = \LinkKeys\LocalRp\Crypto::generateEd25519Keypair();
        [$encPub, ] = \LinkKeys\LocalRp\Crypto::generateX25519Keypair();
        $descriptor = LocalRp::buildLocalRpDescriptor('Test', null, $pub, $encPub, ['aes-256-gcm'], $ct['issued_at'], $ct['expires_at']);
        $signed = LocalRp::signLocalRpDescriptor($descriptor, $priv);

        if ($case['expected_valid']) {
            TestKit::assertDoesNotThrow(fn () => LocalRp::verifyLocalRpDescriptor($signed, $now, $ct['skew_seconds']), $case['description'] ?? '');
        } else {
            TestKit::assertThrows(fn () => LocalRp::verifyLocalRpDescriptor($signed, $now, $ct['skew_seconds']), $case['description'] ?? '');
        }
    });
}

exit(TestKit::summary('ExpirationsTest') === 0 ? 0 : 1);
