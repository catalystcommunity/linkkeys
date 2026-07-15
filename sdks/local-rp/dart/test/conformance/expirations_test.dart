import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';
import 'package:test/test.dart';

import '../testutil/fixtures.dart';

void main() {
  group('expirations.json conformance', () {
    test('check_expirations thresholds via SDK wrapper', () async {
      final d = (loadJson('expirations.json')
          as Map<String, dynamic>)['check_expirations'] as Map<String, dynamic>;
      final expiresAtStr = d['expires_at'] as String;
      final cases = (d['cases'] as List).cast<Map<String, dynamic>>();
      expect(cases.length, equals(11));

      // Build an identity whose descriptor expires at exactly `expiresAt`,
      // exercising `checkExpirations` end to end (identity -> descriptor ->
      // threshold logic), not the underlying LocalRp function directly.
      final expires = DateTime.parse(expiresAtStr).toUtc();
      final createdAt = expires.subtract(const Duration(days: 3650));
      final identity =
          await generateLocalRpIdentity(GenerateLocalRpIdentityConfig(
        appName: 'Conformance Test App',
        now: createdAt,
        lifetime: expires.difference(createdAt),
      ));

      for (final c in cases) {
        final now = DateTime.parse(c['now'] as String).toUtc();
        final status = checkExpirations(identity, now);
        expect(status.level.wireName, equals(c['expected_level']),
            reason: 'now=$now');
      }
    });

    test('check_timestamps skew boundaries are exact', () {
      final d = (loadJson('expirations.json')
          as Map<String, dynamic>)['check_timestamps'] as Map<String, dynamic>;
      final issuedAt = d['issued_at'] as String;
      final expiresAt = d['expires_at'] as String;
      final skew = d['skew_seconds'] as int;
      final cases = (d['cases'] as List).cast<Map<String, dynamic>>();
      expect(cases.length, equals(4));

      for (final c in cases) {
        final now = DateTime.parse(c['now'] as String).toUtc();
        final expectedValid = c['expected_valid'] as bool;
        var valid = true;
        try {
          LocalRp.checkTimestamps(issuedAt, expiresAt, now, skew);
        } on LocalRpError {
          valid = false;
        }
        expect(valid, equals(expectedValid), reason: 'now=$now');
      }
    });
  });
}
