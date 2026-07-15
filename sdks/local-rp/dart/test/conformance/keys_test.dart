import 'dart:convert';

import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';
import 'package:linkkeys_local_rp/src/crypto/crypto.dart';
import 'package:test/test.dart';

import '../testutil/fixtures.dart';

void main() {
  group('keys.json conformance', () {
    test('fingerprints round trip through SDK fingerprint helpers', () async {
      final d = loadJson('keys.json') as Map<String, dynamic>;
      final nodes = [
        (d['local_rp'] as Map<String, dynamic>)['signing']
            as Map<String, dynamic>,
        d['domain_signing_key'] as Map<String, dynamic>,
      ];

      for (final node in nodes) {
        final seed = hex(node['seed_hex'] as String);
        final expectedPublic = hex(node['public_key_hex'] as String);
        final expectedFp = node['fingerprint_hex'] as String;

        final message = utf8.encode('conformance-check');
        final sig = await Crypto.signEd25519(message, seed);
        expect(
            await Crypto.verifyEd25519(message, sig, expectedPublic), isTrue);

        final computed = await Crypto.fingerprint(expectedPublic);
        expect(computed, equals(expectedFp));

        final s = fingerprintToString(computed);
        expect(fingerprintFromString(s), equals(expectedFp));

        expect(seed.length, equals(32));
      }

      expect(() => fingerprintFromString('deadbeef'),
          throwsA(isA<SdkException>()));
    });

    test('X25519 public keys derive from private keys', () async {
      final d = loadJson('keys.json') as Map<String, dynamic>;
      final nodes = [
        (d['local_rp'] as Map<String, dynamic>)['encryption']
            as Map<String, dynamic>,
        d['domain_encryption_recipient'] as Map<String, dynamic>,
      ];
      for (final node in nodes) {
        final priv = hex(node['private_key_hex'] as String);
        final expectedPublic = hex(node['public_key_hex'] as String);
        final got = await Crypto.derivePublicFromX25519Private(priv);
        expect(got, equals(expectedPublic));
      }
    });
  });
}
