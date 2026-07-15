import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';
import 'package:linkkeys_local_rp/src/crypto/crypto.dart';
import 'package:test/test.dart';

import '../testutil/fixtures.dart';

Future<void> _checkCase(Map<String, dynamic> c, bool expectValid) async {
  final context = c['context'] as String;
  final payload = hex(c['payload_cbor_hex'] as String);
  final expectedSigInput = hex(c['signature_input_cbor_hex'] as String);
  final signature = hex(c['signature_hex'] as String);
  final verifyKey = hex(c['verify_key_hex'] as String);

  final computedSigInput = LocalRp.envelopeSignatureInput(context, payload);
  expect(computedSigInput, equals(expectedSigInput),
      reason: 'signature_input_cbor_hex mismatch');

  final valid =
      await Crypto.verifyEd25519(computedSigInput, signature, verifyKey);
  expect(valid, equals(expectValid), reason: 'verify result mismatch');
}

void main() {
  group('envelopes.json conformance', () {
    test('positive cases verify', () async {
      final d = loadJson('envelopes.json') as Map<String, dynamic>;
      final cases = (d['cases'] as List).cast<Map<String, dynamic>>();
      expect(cases.length, equals(4));
      for (final c in cases) {
        expect(c['expected_valid'], isTrue);
        await _checkCase(c, true);
      }
    });

    test('negative cases fail', () async {
      final d = loadJson('envelopes.json') as Map<String, dynamic>;
      final cases = (d['negative_cases'] as List).cast<Map<String, dynamic>>();
      expect(cases.length, equals(20));
      for (final c in cases) {
        expect(c['expected_valid'], isFalse);
        await _checkCase(c, false);
      }
    });

    test('context strings match the four constants', () {
      final d = loadJson('envelopes.json') as Map<String, dynamic>;
      final ctx = d['context_strings'] as Map<String, dynamic>;
      expect(ctx['descriptor'], equals(LocalRp.ctxLocalRpDescriptor));
      expect(ctx['login_request'], equals(LocalRp.ctxLocalRpLoginRequest));
      expect(ctx['callback_payload'], equals(LocalRp.ctxLocalRpCallback));
      expect(
          ctx['ticket_redemption'], equals(LocalRp.ctxLocalRpTicketRedemption));
    });
  });
}
