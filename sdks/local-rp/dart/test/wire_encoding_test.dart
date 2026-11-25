// Wire-encoding rules that the conformance vectors do not cover directly:
// CSIL `timestamp` is CBOR tag 0 around strict RFC 3339 UTC text, a closed
// vocabulary is a CBOR unsigned integer, and a signed tuple timestamp must be
// whole seconds.
library;

import 'dart:typed_data';

import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';
import 'package:linkkeys_local_rp/src/claims.dart' as claims_impl;
import 'package:linkkeys_local_rp/src/crypto/crypto.dart';
import 'package:linkkeys_local_rp/src/wire/cbor.dart';
import 'package:linkkeys_local_rp/src/wire/codec.dart';
import 'package:test/test.dart';

DomainPublicKey _key(Uint8List publicKey, {DateTime? expiresAt}) =>
    DomainPublicKey(
      keyId: 'k1',
      publicKey: publicKey,
      fingerprint: 'fp',
      algorithm: KeyAlgorithm.ed25519,
      keyUsage: KeyUsage.sign,
      createdAt: DateTime.utc(2026, 1, 1),
      expiresAt: expiresAt ?? DateTime.utc(2126, 1, 1),
    );

/// Re-encode [data] (a CBOR map) with [key] replaced by [value].
Uint8List _withField(Uint8List data, String key, CborValue value) {
  final m = Cbor.decode(data) as CborMap;
  return Cbor.encode(Cbor.vmap([
    for (final e in m.entries)
      (e.key as CborText).value == key ? Cbor.entry(key, value) : e,
  ]));
}

void main() {
  group('timestamp text', () {
    test('encodes UTC with Z and 0, 3, or 6 fraction digits', () {
      expect(Cbor.formatTimestamp(DateTime.utc(2026, 1, 2, 3, 4, 5)),
          equals('2026-01-02T03:04:05Z'));
      expect(Cbor.formatTimestamp(DateTime.utc(2026, 1, 2, 3, 4, 5, 500)),
          equals('2026-01-02T03:04:05.500Z'));
      expect(Cbor.formatTimestamp(DateTime.utc(2026, 1, 2, 3, 4, 5, 0, 7)),
          equals('2026-01-02T03:04:05.000007Z'));
      expect(Cbor.encode(Cbor.vtime(DateTime.utc(2026))),
          equals([0xc0, 0x74, ...'2026-01-01T00:00:00Z'.codeUnits]));
    });

    test('decodes an offset into UTC', () {
      expect(Cbor.parseTimestamp('2026-01-01T02:00:00+02:00'),
          equals(DateTime.utc(2026)));
    });

    test('rejects text that is not strict RFC 3339', () {
      for (final bad in [
        '2026-01-01T00:00:00', // no offset
        '2026-02-30T00:00:00Z', // impossible date
        '2026-01-01T23:59:60Z', // leap second
        '2026-01-01T00:00:00+24:00', // offset out of range
        '2026-01-01',
      ]) {
        expect(
            () => Cbor.parseTimestamp(bad), throwsA(isA<CborDecodeException>()),
            reason: bad);
      }
    });
  });

  group('codec', () {
    final keyBytes = Codec.encodeDomainPublicKey(_key(Uint8List(32)));

    test('rejects a timestamp without tag 0', () {
      final bad = _withField(
          keyBytes, 'created_at', Cbor.vtext('2026-01-01T00:00:00Z'));
      expect(() => Codec.decodeDomainPublicKey(bad),
          throwsA(isA<CborDecodeException>()));
    });

    test('rejects a timestamp with a tag other than 0', () {
      final bad = _withField(keyBytes, 'created_at',
          Cbor.vtag(1, Cbor.vtext('2026-01-01T00:00:00Z')));
      expect(() => Codec.decodeDomainPublicKey(bad),
          throwsA(isA<CborDecodeException>()));
    });

    test('writes enums as numbers and rejects text or unknown numbers', () {
      final m = Cbor.decode(keyBytes);
      expect(Cbor.asInt(Cbor.require(m, 'algorithm')), equals(1));
      expect(Cbor.asInt(Cbor.require(m, 'key_usage')), equals(1));
      for (final v in [Cbor.vtext('ed25519'), Cbor.vint(99)]) {
        expect(
            () => Codec.decodeDomainPublicKey(
                _withField(keyBytes, 'algorithm', v)),
            throwsA(isA<CborDecodeException>()));
      }
    });

    test('a callback header with an unknown suite number fails to decode',
        () async {
      final identity = await generateLocalRpIdentity(
          GenerateLocalRpIdentityConfig(appName: 'App', now: DateTime.now()));
      final header = Codec.encodeLocalRpCallbackHeader(LocalRpCallbackHeader(
        fingerprint: identity.fingerprint,
        nonce: Uint8List(32),
        state: Uint8List(32),
        suite: AeadSuite.aes256Gcm,
        ephemeralPublicKey: Uint8List(32),
        aeadNonce: Uint8List(12),
        issuedAt: DateTime.utc(2026),
        expiresAt: DateTime.utc(2026, 1, 1, 0, 5),
      ));
      final bad = _withField(header, 'suite', Cbor.vint(99));
      await expectLater(
          LocalRp.openLocalRpCallback(
              LocalRpEncryptedCallback(header: bad, ciphertext: Uint8List(16)),
              identity.encryptionPrivateKey,
              AeadSuite.values),
          throwsA(isA<LocalRpError>()
              .having((e) => e.kind, 'kind', LocalRpErrorKind.decode)));
    });
  });

  group('signed timestamps', () {
    test('a claim with a fractional attested_at fails as badTimestamp',
        () async {
      final kp = await Crypto.generateEd25519KeyPair();
      final claim = await claims_impl.signClaim(
          claims_impl.ClaimSpec(
            claimId: 'c1',
            claimType: 'handle',
            claimValue: Uint8List.fromList([1]),
            userId: 'u1',
            subjectDomain: 'example.com',
            attestedAt: DateTime.utc(2026),
          ),
          [
            claims_impl.ClaimSigner(
                domain: 'example.com',
                keyId: 'k1',
                privateKeySeed: kp.privateKeySeed)
          ]);
      final keys = [
        claims_impl.DomainKeySet('example.com', [_key(kp.publicKey)])
      ];
      await claims_impl.verifyClaim(claim, 'example.com', keys);

      final fractional =
          claim.copyWith(attestedAt: DateTime.utc(2026, 1, 1, 0, 0, 0, 500));
      await expectLater(
          claims_impl.verifyClaim(fractional, 'example.com', keys),
          throwsA(isA<ClaimError>()
              .having((e) => e.kind, 'kind', ClaimErrorKind.badTimestamp)));
    });

    test('a revocation with a fractional revoked_at counts no signers',
        () async {
      final s1 = await Crypto.generateEd25519KeyPair();
      final s2 = await Crypto.generateEd25519KeyPair();
      final revokedAt = DateTime.utc(2026);
      final payload = revocationPayload('target', 'target-fp',
          revokedAt.millisecondsSinceEpoch ~/ 1000, 'example.com');
      final keys = [
        _key(s1.publicKey).copyWith(keyId: 's1'),
        _key(s2.publicKey).copyWith(keyId: 's2'),
      ];
      RevocationCertificate cert(DateTime at) => RevocationCertificate(
            targetKeyId: 'target',
            targetFingerprint: 'target-fp',
            revokedAt: at,
            signatures: [],
          );
      final sigs = [
        ClaimSignature(
            domain: 'example.com',
            signedByKeyId: 's1',
            signature: await Crypto.signEd25519(payload, s1.privateKeySeed)),
        ClaimSignature(
            domain: 'example.com',
            signedByKeyId: 's2',
            signature: await Crypto.signEd25519(payload, s2.privateKeySeed)),
      ];
      final good = cert(revokedAt);
      good.signatures.addAll(sigs);
      expect(await countValidSigners(good, keys, 'example.com'), equals(2));

      final fractional = cert(revokedAt.add(const Duration(milliseconds: 1)));
      fractional.signatures.addAll(sigs);
      expect(
          await countValidSigners(fractional, keys, 'example.com'), equals(0));
    });
  });
}
