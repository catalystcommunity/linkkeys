<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';

use LinkKeys\LocalRp\Crypto;

$vectors = loadJson(__DIR__ . '/../../../conformance/keys.json');

TestKit::test('keys.local_rp.signing.seed_derives_public_key_and_fingerprint', function () use ($vectors) {
    $k = $vectors['local_rp']['signing'];
    $seed = hexToBytes($k['seed_hex']);
    TestKit::assertEquals(hexToBytes($k['private_key_hex']), $seed, 'seed == private_key for Ed25519');
    $pub = Crypto::ed25519PublicKeyFromSeed($seed);
    TestKit::assertEquals(hexToBytes($k['public_key_hex']), $pub);
    TestKit::assertEquals($k['fingerprint_hex'], Crypto::fingerprint($pub));
});

TestKit::test('keys.local_rp.encryption.private_derives_public', function () use ($vectors) {
    $k = $vectors['local_rp']['encryption'];
    $priv = hexToBytes($k['private_key_hex']);
    $pub = Crypto::x25519PublicFromPrivate($priv);
    TestKit::assertEquals(hexToBytes($k['public_key_hex']), $pub);
});

TestKit::test('keys.domain_signing_key.seed_derives_public_key_and_fingerprint', function () use ($vectors) {
    $k = $vectors['domain_signing_key'];
    $seed = hexToBytes($k['seed_hex']);
    $pub = Crypto::ed25519PublicKeyFromSeed($seed);
    TestKit::assertEquals(hexToBytes($k['public_key_hex']), $pub);
    TestKit::assertEquals($k['fingerprint_hex'], Crypto::fingerprint($pub));
});

TestKit::test('keys.domain_encryption_recipient.private_derives_public', function () use ($vectors) {
    $k = $vectors['domain_encryption_recipient'];
    $priv = hexToBytes($k['private_key_hex']);
    $pub = Crypto::x25519PublicFromPrivate($priv);
    TestKit::assertEquals(hexToBytes($k['public_key_hex']), $pub);
});

exit(TestKit::summary('KeysTest') === 0 ? 0 : 1);
