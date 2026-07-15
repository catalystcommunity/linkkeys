import 'dart:typed_data';

import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';
import 'package:linkkeys_local_rp/src/crypto/crypto.dart';
import 'package:linkkeys_local_rp/src/wire/codec.dart';
import 'package:test/test.dart';

Future<LocalRpKeyMaterial> _material() =>
    generateLocalRpIdentity(GenerateLocalRpIdentityConfig(
        appName: 'Test App', now: DateTime.now().toUtc()));

void main() {
  group('Identity', () {
    test('generateIdentity defaults both suites and ten-year lifetime',
        () async {
      final identity = await _material();
      expect(identity.fingerprint.length, equals(64));
      expect(identity.fingerprint,
          equals(await Crypto.fingerprint(identity.signingPublicKey)));

      final descriptor =
          Codec.decodeLocalRpDescriptor(identity.descriptor.descriptor);
      expect(descriptor.appName, equals('Test App'));
      expect(descriptor.supportedSuites, equals(AeadSuite.allSupported()));
    });

    test('generateIdentity rejects empty app name', () async {
      await expectLater(
        generateLocalRpIdentity(GenerateLocalRpIdentityConfig(
            appName: '', now: DateTime.now().toUtc())),
        throwsA(isA<SdkException>()),
      );
    });

    test('generateIdentity rejects empty suite list', () async {
      await expectLater(
        generateLocalRpIdentity(GenerateLocalRpIdentityConfig(
            appName: 'Test App',
            now: DateTime.now().toUtc(),
            supportedSuites: const [])),
        throwsA(isA<SdkException>()),
      );
    });

    test('signing and encryption key byte round trips', () {
      final key = Uint8List.fromList(List<int>.filled(32, 7));
      expect(signingKeyFromBytes(signingKeyToBytes(key)), equals(key));
      expect(encryptionKeyFromBytes(encryptionKeyToBytes(key)), equals(key));
      expect(() => signingKeyFromBytes(List<int>.filled(31, 0)),
          throwsA(isA<SdkException>()));
      expect(() => encryptionKeyFromBytes(List<int>.filled(33, 0)),
          throwsA(isA<SdkException>()));
    });

    test('fingerprint string round trip validates hex', () async {
      final identity = await _material();
      final s = fingerprintToString(identity.fingerprint);
      expect(fingerprintFromString(s), equals(identity.fingerprint));
      expect(
          () => fingerprintFromString('not-hex'), throwsA(isA<SdkException>()));
      expect(
          () => fingerprintFromString('a' * 63), throwsA(isA<SdkException>()));
    });

    test('identity bundle byte round trip', () async {
      final identity = await _material();
      final bytes = localRpIdentityToBytes(identity);
      final roundTripped = localRpIdentityFromBytes(bytes);

      expect(
          roundTripped.signingPrivateKey, equals(identity.signingPrivateKey));
      expect(roundTripped.signingPublicKey, equals(identity.signingPublicKey));
      expect(roundTripped.encryptionPrivateKey,
          equals(identity.encryptionPrivateKey));
      expect(roundTripped.encryptionPublicKey,
          equals(identity.encryptionPublicKey));
      expect(roundTripped.fingerprint, equals(identity.fingerprint));
      expect(roundTripped.descriptor.descriptor,
          equals(identity.descriptor.descriptor));
      expect(roundTripped.descriptor.signature,
          equals(identity.descriptor.signature));
    });

    test('identity bundle rejects bad magic and truncation', () async {
      final identity = await _material();
      final bytes = localRpIdentityToBytes(identity);
      final badMagic = List<int>.from(bytes);
      badMagic[0] ^= 0xff;
      expect(() => localRpIdentityFromBytes(badMagic),
          throwsA(isA<SdkException>()));

      final truncated = bytes.sublist(0, 10);
      expect(() => localRpIdentityFromBytes(truncated),
          throwsA(isA<SdkException>()));
    });

    test('checkExpirations wraps thresholds', () async {
      final identity = await generateLocalRpIdentity(
          GenerateLocalRpIdentityConfig(
              appName: 'Test App',
              now: DateTime.now().toUtc(),
              lifetime: const Duration(days: 100)));

      final status = checkExpirations(identity, DateTime.now().toUtc());
      expect(status.level, equals(ExpirationLevel.notice));

      final farFuture = DateTime.now().toUtc().add(const Duration(days: 200));
      final expired = checkExpirations(identity, farFuture);
      expect(expired.level, equals(ExpirationLevel.expired));
    });
  });
}
