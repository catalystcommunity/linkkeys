// Browser endpoint discovery in `beginLocalLogin` (mirrors
// `sdks/local-rp/go/browser_test.go`). Every resolver here is a hermetic
// fake with canned TXT answers; no test performs a live DNS request.
import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';
import 'package:linkkeys_local_rp/src/wire/codec.dart';
import 'package:test/test.dart';

const _domain = 'ident.example.test';
const _callbackUrl = 'http://app.lan:8080/cb';

/// A hermetic [DnsResolver] with canned TXT answers per name.
class _MapDnsResolver implements DnsResolver {
  final Map<String, List<String>> records;
  final Object? error;
  _MapDnsResolver(this.records, {this.error});

  @override
  Future<List<String>> txtLookup(String name) async {
    if (error != null) throw error!;
    final txts = records[name];
    if (txts == null) {
      throw SdkException(SdkExceptionKind.dns, 'no fake record for $name');
    }
    return txts;
  }
}

_MapDnsResolver _apisResolver(List<String> txts) =>
    _MapDnsResolver({'_linkkeys_apis.$_domain': txts});

final _failingResolver = _MapDnsResolver(const {},
    error: SdkException(SdkExceptionKind.dns, 'SERVFAIL'));

Future<BeginResult> _beginWith(DnsResolver dns,
    {String userDomain = _domain}) async {
  final now = DateTime.utc(2026, 8, 17, 12);
  final identity = await generateLocalRpIdentity(
      GenerateLocalRpIdentityConfig(appName: 'browser-test', now: now));
  return beginLocalLogin(BeginLocalLoginConfig(
    keyMaterial: identity,
    callbackUrl: _callbackUrl,
    userDomain: userDomain,
    now: now,
    dns: dns,
  ));
}

void main() {
  group('Browser endpoint discovery in beginLocalLogin', () {
    // Case 1: a valid https= host is used for the redirect instead of the
    // identity domain. Case 8: PendingLogin.userDomain stays the identity
    // domain -- verification stays bound to it, not to the service host.
    test('uses the discovered https host; pending domain stays the identity',
        () async {
      final begun = await _beginWith(_apisResolver([
        'v=lk1 tcp=linkkeys.ident.example.test https=linkkeys.ident.example.test',
      ]));
      expect(
          begun.redirect.redirectUrl,
          startsWith(
              'https://linkkeys.ident.example.test/auth/local-rp?signed_request='));
      expect(
          begun.redirect.redirectUrl, isNot(startsWith('https://$_domain/')));
      expect(begun.pending.userDomain, equals(_domain));
    });

    // Case 2: an https= value with a path prefix preserves that prefix.
    test('preserves an https= path prefix', () async {
      final begun = await _beginWith(
          _apisResolver(['v=lk1 https=login.example.test/linkkeys']));
      expect(
          begun.redirect.redirectUrl,
          startsWith(
              'https://login.example.test/linkkeys/auth/local-rp?signed_request='));
    });

    // Case 3: a record with only tcp= falls back to the identity domain.
    test('tcp-only record falls back to the identity domain', () async {
      final begun = await _beginWith(
          _apisResolver(['v=lk1 tcp=linkkeys.ident.example.test']));
      expect(begun.redirect.redirectUrl,
          startsWith('https://$_domain/auth/local-rp?signed_request='));
    });

    // Case 4: a DNS lookup error falls back to the identity domain.
    test('DNS error falls back to the identity domain', () async {
      final begun = await _beginWith(_failingResolver);
      expect(begun.redirect.redirectUrl,
          startsWith('https://$_domain/auth/local-rp?signed_request='));
    });

    // Cases 5 + 6: invalid TXT records are ignored, and across several
    // records the FIRST valid record with https= is selected.
    test('ignores invalid records and selects the first valid https= record',
        () async {
      final begun = await _beginWith(_apisResolver([
        'not a linkkeys record',
        'v=lk2 https=wrong-version.example.test',
        'v=lk1 tcp=tcp-only.example.test',
        'v=lk1 https=first.example.test',
        'v=lk1 https=second.example.test',
      ]));
      expect(
          begun.redirect.redirectUrl,
          startsWith(
              'https://first.example.test/auth/local-rp?signed_request='));
    });

    // Case 7: signed_request rides the discovered URL unchanged -- it decodes
    // to the signed login request whose fields match this login.
    test('signed_request survives the discovered URL and decodes', () async {
      final begun = await _beginWith(
          _apisResolver(['v=lk1 https=login.example.test/linkkeys']));
      final param = Uri.parse(begun.redirect.redirectUrl)
          .queryParameters['signed_request'];
      expect(param, isNotNull);
      expect(param, isNotEmpty);
      final signed = signedLocalRpLoginRequestFromUrlParam(param!);
      final request = Codec.decodeLocalRpLoginRequest(signed.request);
      expect(request.callbackUrl, equals(_callbackUrl));
      expect(request.nonce, equals(begun.pending.nonce));
    });

    // The username hint still rides the discovered URL, after signed_request.
    test('username hint is appended to the discovered URL', () async {
      final begun = await _beginWith(
          _apisResolver(['v=lk1 https=login.example.test']),
          userDomain: 'Alice+work@$_domain');
      expect(
          begun.redirect.redirectUrl,
          startsWith(
              'https://login.example.test/auth/local-rp?signed_request='));
      expect(begun.redirect.redirectUrl, endsWith('&username=Alice%2Bwork'));
      expect(begun.pending.userDomain, equals(_domain));
    });

    // Case 9: a config without `dns` compiles unchanged (this test is that
    // caller) and the default is the memoized system resolver. The default
    // path is not executed here -- that would be a live DNS request.
    test('config without a resolver still compiles', () async {
      final now = DateTime.utc(2026, 8, 17, 12);
      final identity = await generateLocalRpIdentity(
          GenerateLocalRpIdentityConfig(appName: 'browser-test', now: now));
      final config = BeginLocalLoginConfig(
        keyMaterial: identity,
        callbackUrl: _callbackUrl,
        userDomain: _domain,
        now: now,
      );
      expect(config.dns, isNull);
      expect(defaultDnsResolver(), isA<SystemDnsResolver>());
    });
  });

  group('Browser helpers', () {
    test('resolveBrowserBase selects the first valid https= base', () async {
      final base = await resolveBrowserBase(
          _apisResolver([
            'v=lk1 tcp=x.example.test https=login.example.test:8443/linkkeys',
          ]),
          _domain);
      expect(base, equals('https://login.example.test:8443/linkkeys'));

      // A record whose https= value smuggles URL structure is skipped; with
      // no other candidate, resolution errors so the caller can fall back.
      for (final hostile in [
        'v=lk1 https=user@evil.example.test',
        'v=lk1 https=evil.example.test/x?y=1',
        'v=lk1 https=evil.example.test/x#frag',
      ]) {
        await expectLater(resolveBrowserBase(_apisResolver([hostile]), _domain),
            throwsA(isA<SdkException>()),
            reason: hostile);
      }

      await expectLater(
          resolveBrowserBase(
              _apisResolver(['v=lk1 tcp=only.example.test']), _domain),
          throwsA(isA<SdkException>()));
      await expectLater(resolveBrowserBase(_failingResolver, _domain),
          throwsA(isA<SdkException>()));
    });

    test('buildBrowserEndpoint joins base, route, and signed_request', () {
      expect(
          buildBrowserEndpoint(
              'https://h.example.test', browserRouteLocalRp, 'PAYLOAD-123_abc'),
          equals(
              'https://h.example.test/auth/local-rp?signed_request=PAYLOAD-123_abc'));

      // Path prefix, with and without a trailing slash, and the regular-RP
      // route -- the same helper serves /auth/authorize glue.
      for (final entry in {
        'https://h.example.test/pfx':
            'https://h.example.test/pfx/auth/authorize?signed_request=s',
        'https://h.example.test/pfx/':
            'https://h.example.test/pfx/auth/authorize?signed_request=s',
      }.entries) {
        expect(buildBrowserEndpoint(entry.key, browserRouteAuthorize, 's'),
            equals(entry.value),
            reason: entry.key);
      }

      // A non-HTTPS scheme must never be selectable.
      for (final bad in [
        'http://h.example.test',
        'ftp://h.example.test',
        'https://',
        'https://u:p@h.example.test',
      ]) {
        expect(() => buildBrowserEndpoint(bad, browserRouteLocalRp, 's'),
            throwsA(isA<SdkException>()),
            reason: bad);
      }
      expect(
          () => buildBrowserEndpoint(
              'https://h.example.test', 'auth/no-leading-slash', 's'),
          throwsA(isA<SdkException>()));
    });

    test('route constants match the wire routes', () {
      expect(browserRouteLocalRp, equals('/auth/local-rp'));
      expect(browserRouteAuthorize, equals('/auth/authorize'));
    });
  });
}
