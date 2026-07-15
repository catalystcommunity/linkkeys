import 'package:linkkeys_local_rp/src/crypto/crypto.dart';
import 'package:test/test.dart';

import '../testutil/fixtures.dart';

void main() {
  group('tickets.json conformance', () {
    test('hash pairs match fingerprint routine', () async {
      final d = loadJson('tickets.json') as Map<String, dynamic>;
      final cases = (d['cases'] as List).cast<Map<String, dynamic>>();
      expect(cases, isNotEmpty);
      for (final c in cases) {
        final ticket = hex(c['ticket_hex'] as String);
        expect(ticket.length, equals(32));
        expect(await Crypto.fingerprint(ticket), equals(c['sha256_hex']));
      }
    });
  });
}
