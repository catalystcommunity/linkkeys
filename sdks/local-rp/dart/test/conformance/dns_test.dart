import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';
import 'package:test/test.dart';

import '../testutil/fixtures.dart';

void main() {
  group('dns.json conformance', () {
    test('linkkeys_txt cases', () {
      final d = (loadJson('dns.json') as Map<String, dynamic>)['linkkeys_txt']
          as Map<String, dynamic>;

      for (final c in (d['valid_cases'] as List).cast<Map<String, dynamic>>()) {
        final txt = c['txt'] as String;
        final record = parseLinkKeysTxt(txt);
        final expected = (c['expected_fingerprints'] as List).cast<String>();
        expect(record.fingerprints, equals(expected), reason: 'txt=$txt');
      }

      for (final c
          in (d['invalid_cases'] as List).cast<Map<String, dynamic>>()) {
        final txt = c['txt'] as String;
        try {
          parseLinkKeysTxt(txt);
          fail('expected DnsParseError for txt=$txt');
        } on DnsParseError catch (e) {
          expect(e.symbol, equals(c['expected_error']));
        }
      }

      expect(
          (d['no_record_case'] as Map<String, dynamic>)['documentation_only'],
          isTrue);
    });

    test('linkkeys_apis_txt cases', () {
      final d = (loadJson('dns.json')
          as Map<String, dynamic>)['linkkeys_apis_txt'] as Map<String, dynamic>;

      for (final c in (d['valid_cases'] as List).cast<Map<String, dynamic>>()) {
        final txt = c['txt'] as String;
        final apis = parseLinkKeysApisTxt(txt);
        expect(apis.tcp, equals(c['expected_tcp']), reason: 'txt=$txt');
        expect(apis.httpsBase, equals(c['expected_https_base']),
            reason: 'txt=$txt');
      }

      for (final c
          in (d['invalid_cases'] as List).cast<Map<String, dynamic>>()) {
        final txt = c['txt'] as String;
        try {
          parseLinkKeysApisTxt(txt);
          fail('expected DnsParseError for txt=$txt');
        } on DnsParseError catch (e) {
          expect(e.symbol, equals(c['expected_error']));
        }
      }

      final root = loadJson('dns.json') as Map<String, dynamic>;
      expect(root['default_tcp_port'], equals(defaultTcpPort));
    });
  });
}
