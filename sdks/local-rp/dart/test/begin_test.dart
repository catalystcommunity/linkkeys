import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';
import 'package:test/test.dart';

Future<LocalRpKeyMaterial> _material() =>
    generateLocalRpIdentity(GenerateLocalRpIdentityConfig(
        appName: 'Test App', now: DateTime.now().toUtc()));

void main() {
  group('Begin', () {
    test('beginLocalLogin defaults claims and produces pending state',
        () async {
      final m = await _material();
      final result = await beginLocalLogin(BeginLocalLoginConfig(
        keyMaterial: m,
        callbackUrl: 'http://localhost:8080/callback',
        userDomain: 'example.com',
        now: DateTime.now().toUtc(),
      ));

      expect(result.redirect.redirectUrl,
          startsWith('https://example.com/auth/local-rp?signed_request='));
      expect(result.pending.userDomain, equals('example.com'));
      expect(
          result.pending.callbackUrl, equals('http://localhost:8080/callback'));
      expect(result.pending.nonce.length, equals(32));
      expect(result.pending.state.length, equals(32));
      expect(result.pending.requiredClaims, equals(defaultRequiredClaims));
    });

    // FIX A.1: `PendingLogin` must retain `requiredClaims` so
    // `completeLocalLogin` can enforce it later -- an app that persists and
    // reloads `PendingLogin` between `begin` and `complete` (its documented
    // responsibility) must get back exactly what the login was begun with,
    // not silently fall back to the defaults.
    test('beginLocalLogin retains caller-supplied required claims in pending',
        () async {
      final m = await _material();
      final result = await beginLocalLogin(BeginLocalLoginConfig(
        keyMaterial: m,
        callbackUrl: 'http://localhost/callback',
        userDomain: 'example.com',
        requiredClaims: const ['email', 'handle'],
        now: DateTime.now().toUtc(),
      ));
      expect(result.pending.requiredClaims, equals(['email', 'handle']));

      // Simulate the app persisting-and-reloading PendingLogin (its
      // documented responsibility -- this SDK owns no storage): rebuilding
      // it from the exact field values must round-trip requiredClaims.
      final reloaded = PendingLogin(
        nonce: result.pending.nonce,
        state: result.pending.state,
        userDomain: result.pending.userDomain,
        callbackUrl: result.pending.callbackUrl,
        requiredClaims: result.pending.requiredClaims,
      );
      expect(reloaded.requiredClaims, equals(result.pending.requiredClaims));
    });

    test('beginLocalLogin accepts empty required claims', () async {
      final m = await _material();
      final result = await beginLocalLogin(BeginLocalLoginConfig(
        keyMaterial: m,
        callbackUrl: 'http://localhost/callback',
        userDomain: 'example.com',
        requiredClaims: const [],
        now: DateTime.now().toUtc(),
      ));
      expect(result.pending.requiredClaims, isEmpty);
    });

    test('beginLocalLogin rejects non-http callback scheme', () async {
      final m = await _material();
      await expectLater(
        beginLocalLogin(BeginLocalLoginConfig(
          keyMaterial: m,
          callbackUrl: 'myapp://callback',
          userDomain: 'example.com',
          now: DateTime.now().toUtc(),
        )),
        throwsA(isA<SdkException>()),
      );
    });

    test('beginLocalLogin rejects empty user domain', () async {
      final m = await _material();
      await expectLater(
        beginLocalLogin(BeginLocalLoginConfig(
          keyMaterial: m,
          callbackUrl: 'http://localhost/callback',
          userDomain: '',
          now: DateTime.now().toUtc(),
        )),
        throwsA(isA<SdkException>()),
      );
    });

    test('beginLocalLogin two calls never reuse nonce or state', () async {
      final m = await _material();
      final r1 = await beginLocalLogin(BeginLocalLoginConfig(
        keyMaterial: m,
        callbackUrl: 'http://localhost/callback',
        userDomain: 'example.com',
        now: DateTime.now().toUtc(),
      ));
      final r2 = await beginLocalLogin(BeginLocalLoginConfig(
        keyMaterial: m,
        callbackUrl: 'http://localhost/callback',
        userDomain: 'example.com',
        now: DateTime.now().toUtc(),
      ));
      expect(r1.pending.nonce, isNot(equals(r2.pending.nonce)));
      expect(r1.pending.state, isNot(equals(r2.pending.state)));
    });
  });
}
