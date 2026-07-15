import 'dart:convert';

import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';
import 'package:linkkeys_local_rp/src/wire/codec.dart';
import 'package:test/test.dart';

import '../testutil/fixtures.dart';

void main() {
  group('url_params.json conformance', () {
    test('cases round trip both directions', () {
      final d = loadJson('url_params.json') as Map<String, dynamic>;
      final cases = (d['cases'] as List).cast<Map<String, dynamic>>();
      expect(cases.length, equals(2));

      for (final c in cases) {
        final cbor = hex(c['cbor_hex'] as String);
        final b64 = c['base64url_unpadded'] as String;

        expect(base64Url.encode(cbor).replaceAll('=', ''), equals(b64));
        final padded = b64 + ('=' * ((4 - b64.length % 4) % 4));
        expect(base64Url.decode(padded), equals(cbor));

        final name = c['name'] as String;
        switch (name) {
          case 'signed_local_rp_login_request':
            final typed = Codec.decodeSignedLocalRpLoginRequest(cbor);
            expect(signedLocalRpLoginRequestToUrlParam(typed), equals(b64));
            final roundTripped = signedLocalRpLoginRequestFromUrlParam(b64);
            expect(roundTripped.request, equals(typed.request));
            expect(roundTripped.signature, equals(typed.signature));
          case 'local_rp_encrypted_callback':
            final typed = Codec.decodeLocalRpEncryptedCallback(cbor);
            expect(localRpEncryptedCallbackToUrlParam(typed), equals(b64));
            final roundTripped = localRpEncryptedCallbackFromUrlParam(b64);
            expect(roundTripped.header, equals(typed.header));
            expect(roundTripped.ciphertext, equals(typed.ciphertext));
          default:
            fail('unrecognized url_params.json case name: $name');
        }
      }
    });

    test('negative cases rejected', () {
      final d = loadJson('url_params.json') as Map<String, dynamic>;
      final cases = (d['negative_cases'] as List).cast<Map<String, dynamic>>();
      expect(cases.length, equals(2));
      for (final c in cases) {
        final input = c['input'] as String;
        expect(() => localRpEncryptedCallbackFromUrlParam(input),
            throwsA(anything));
      }
    });
  });
}
