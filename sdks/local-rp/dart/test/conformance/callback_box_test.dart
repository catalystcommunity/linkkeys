import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';
import 'package:linkkeys_local_rp/src/wire/codec.dart';
import 'package:test/test.dart';

import '../testutil/fixtures.dart';

List<AeadSuite> _parseAllowedSuites(Map<String, dynamic> c) {
  final out = <AeadSuite>[];
  for (final s in (c['allowed_suites'] as List).cast<String>()) {
    final suite = AeadSuite.parse(s);
    if (suite == null) {
      throw StateError('unregistered suite id in fixture: $s');
    }
    out.add(suite);
  }
  return out;
}

void main() {
  group('callback_box.json conformance', () {
    test('positive cases open via SDK dependency', () async {
      final d = loadJson('callback_box.json') as Map<String, dynamic>;
      final cases = (d['positive_cases'] as List).cast<Map<String, dynamic>>();
      expect(cases.length, equals(2));

      for (final c in cases) {
        final headerBytes = hex(c['header_cbor_hex'] as String);
        final ciphertext = hex(c['ciphertext_hex'] as String);
        final decryptKey = hex(c['decrypt_private_key_hex'] as String);
        final allowed = _parseAllowedSuites(c);

        final encrypted = LocalRpEncryptedCallback(
            header: headerBytes, ciphertext: ciphertext);
        final opened =
            await LocalRp.openLocalRpCallback(encrypted, decryptKey, allowed);

        expect(opened.header.suite, equals(c['suite']));
        expect(opened.header.fingerprint, equals(c['fingerprint']));
        expect(opened.header.nonce, equals(hex(c['nonce_hex'] as String)));
        expect(opened.header.state, equals(hex(c['state_hex'] as String)));
        expect(opened.header.issuedAt, equals(c['issued_at']));
        expect(opened.header.expiresAt, equals(c['expires_at']));

        final plaintext =
            Codec.encodeSignedLocalRpCallbackPayload(opened.signedPayload);
        expect(plaintext, equals(hex(c['plaintext_cbor_hex'] as String)));
      }
    });

    test('negative cases fail', () async {
      final d = loadJson('callback_box.json') as Map<String, dynamic>;
      final cases = (d['negative_cases'] as List).cast<Map<String, dynamic>>();
      expect(cases.length, equals(13));

      for (final c in cases) {
        final headerBytes = hex(c['header_cbor_hex'] as String);
        final ciphertext = hex(c['ciphertext_hex'] as String);
        final decryptKey = hex(c['decrypt_private_key_hex'] as String);
        final allowed = _parseAllowedSuites(c);

        final encrypted = LocalRpEncryptedCallback(
            header: headerBytes, ciphertext: ciphertext);
        await expectLater(
          LocalRp.openLocalRpCallback(encrypted, decryptKey, allowed),
          throwsA(anything),
          reason: 'negative case unexpectedly opened: ${c['name']}',
        );
      }
    });
  });
}
