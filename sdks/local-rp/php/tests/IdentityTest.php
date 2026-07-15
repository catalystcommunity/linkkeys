<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use LinkKeys\LocalRp\Crypto;
use LinkKeys\LocalRp\GenerateLocalRpIdentityConfig;
use LinkKeys\LocalRp\Identity;
use LinkKeys\LocalRp\Wire;

TestKit::test('identity.generate_defaults_both_suites_and_ten_year_lifetime', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $material = Identity::generateLocalRpIdentity(new GenerateLocalRpIdentityConfig('Test App', $now));
    TestKit::assertEquals(64, strlen($material->fingerprint));
    TestKit::assertEquals(Crypto::fingerprint($material->signingPublicKey), $material->fingerprint);

    $descriptor = Wire::decodeLocalRpDescriptor($material->descriptor->descriptor);
    TestKit::assertEquals('Test App', $descriptor->appName);
    TestKit::assertEquals(Crypto::allSupportedAeadSuites(), $descriptor->supportedSuites);
    // 3650 DAYS (not calendar years) from 2026-01-01, matching
    // `DEFAULT_LIFETIME_DAYS`'s literal day-count semantics (mirroring the
    // Rust reference's `Duration::days(3650)`).
    TestKit::assertEquals('2035-12-30T00:00:00+00:00', $descriptor->expiresAt);
});

TestKit::test('identity.generate_rejects_empty_app_name', function () {
    $now = new \DateTimeImmutable('now');
    TestKit::assertThrows(fn () => Identity::generateLocalRpIdentity(new GenerateLocalRpIdentityConfig('', $now)));
});

TestKit::test('identity.generate_rejects_empty_suite_list', function () {
    $now = new \DateTimeImmutable('now');
    TestKit::assertThrows(fn () => Identity::generateLocalRpIdentity(new GenerateLocalRpIdentityConfig('Test App', $now, null, [])));
});

TestKit::test('identity.signing_and_encryption_key_byte_round_trips', function () {
    $key = str_repeat("\x07", 32);
    TestKit::assertEquals($key, Identity::signingKeyFromBytes(Identity::signingKeyToBytes($key)));
    TestKit::assertEquals($key, Identity::encryptionKeyFromBytes(Identity::encryptionKeyToBytes($key)));
    TestKit::assertThrows(fn () => Identity::signingKeyFromBytes(str_repeat("\x00", 31)));
    TestKit::assertThrows(fn () => Identity::encryptionKeyFromBytes(str_repeat("\x00", 33)));
});

TestKit::test('identity.fingerprint_string_round_trip_validates_hex', function () {
    $now = new \DateTimeImmutable('now');
    $material = Identity::generateLocalRpIdentity(new GenerateLocalRpIdentityConfig('Test App', $now));
    $s = Identity::fingerprintToString($material->fingerprint);
    TestKit::assertEquals($material->fingerprint, Identity::fingerprintFromString($s));
    TestKit::assertThrows(fn () => Identity::fingerprintFromString('not-hex'));
    TestKit::assertThrows(fn () => Identity::fingerprintFromString(str_repeat('a', 63)));
});

TestKit::test('identity.bundle_byte_round_trip', function () {
    $now = new \DateTimeImmutable('now');
    $material = Identity::generateLocalRpIdentity(new GenerateLocalRpIdentityConfig('Test App', $now));
    $bytes = Identity::localRpIdentityToBytes($material);
    $roundTripped = Identity::localRpIdentityFromBytes($bytes);
    TestKit::assertEquals($material->signingPrivateKey, $roundTripped->signingPrivateKey);
    TestKit::assertEquals($material->signingPublicKey, $roundTripped->signingPublicKey);
    TestKit::assertEquals($material->encryptionPrivateKey, $roundTripped->encryptionPrivateKey);
    TestKit::assertEquals($material->encryptionPublicKey, $roundTripped->encryptionPublicKey);
    TestKit::assertEquals($material->fingerprint, $roundTripped->fingerprint);
    TestKit::assertEquals($material->descriptor->descriptor, $roundTripped->descriptor->descriptor);
    TestKit::assertEquals($material->descriptor->signature, $roundTripped->descriptor->signature);
});

TestKit::test('identity.bundle_rejects_bad_magic_and_truncation', function () {
    $now = new \DateTimeImmutable('now');
    $material = Identity::generateLocalRpIdentity(new GenerateLocalRpIdentityConfig('Test App', $now));
    $bytes = Identity::localRpIdentityToBytes($material);
    $tampered = $bytes;
    $tampered[0] = chr(ord($tampered[0]) ^ 0xff);
    TestKit::assertThrows(fn () => Identity::localRpIdentityFromBytes($tampered));

    TestKit::assertThrows(fn () => Identity::localRpIdentityFromBytes(substr($bytes, 0, 10)));
});

TestKit::test('identity.check_expirations_thresholds', function () {
    $now = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    $material = Identity::generateLocalRpIdentity(new GenerateLocalRpIdentityConfig('Test App', $now, null, null, 100));
    $status = Identity::checkExpirations($material, $now);
    TestKit::assertEquals('notice', $status->level);

    $farFuture = $now->add(new \DateInterval('P200D'));
    $expired = Identity::checkExpirations($material, $farFuture);
    TestKit::assertEquals('expired', $expired->level);
});

exit(TestKit::summary('IdentityTest') === 0 ? 0 : 1);
