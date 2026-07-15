// Unit tests for `src/rpc/tls_pinning.dart`'s certificate DER parsing and
// pin-fingerprint logic, directly against real `openssl`-minted certificate
// bytes.
//
// This is the fallback the task brief anticipated: `dart:io`'s TLS stack
// (BoringSSL) refuses to negotiate a handshake at all when the server
// presents an Ed25519 certificate (`NO_COMMON_SIGNATURE_ALGORITHMS`,
// verified empirically before writing this test), so a live end-to-end TLS
// handshake with an Ed25519 server certificate cannot be exercised
// in-process the way the Java reference SDK's flow test does. Instead, this
// file feeds the exact DER bytes an `openssl req -x509 -key <ed25519 key>`
// certificate produced directly into `extractEd25519PublicKeyFromCertDer`
// -- the same function `connectPinned` calls post-handshake in production
// -- so the ASN.1 walk and prefix/fingerprint logic are still verified
// against real certificate bytes, not synthetic ones. See
// `rpc/rpc_client.dart`'s `RpcCaller` docs, `flow_test.dart`, and the
// package README's "Known limitations" section for the full story.
//
// Fixture provenance (fixed test-only artifacts, not protocol conformance
// vectors -- no vector for TLS certificate parsing exists in
// `sdks/local-rp/conformance/`, since certificate minting is outside
// liblinkkeys' scope):
//   openssl genpkey -algorithm ed25519 -out key.pem
//   openssl req -new -x509 -key key.pem -days 3650 -subj "/CN=example.test" -out cert.pem
//   openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out rsakey.pem
//   openssl req -new -x509 -key rsakey.pem -days 3650 -subj "/CN=example.test" -out rsacert.pem
// then base64-decoding each PEM body to DER.
library;

import 'dart:typed_data';

import 'package:linkkeys_local_rp/src/crypto/crypto.dart';
import 'package:linkkeys_local_rp/src/crypto/hex.dart';
import 'package:linkkeys_local_rp/src/errors.dart';
import 'package:linkkeys_local_rp/src/rpc/tls_pinning.dart';
import 'package:test/test.dart';

const String edCertDerHex =
    '308201423081f5a00302010202142b134c3fa1624ee796d5e36753629175381ff62630050603'
    '2b657030173115301306035504030c0c6578616d706c652e74657374301e170d323630373133'
    '3037343630355a170d3336303731303037343630355a30173115301306035504030c0c657861'
    '6d706c652e74657374302a300506032b6570032100166c3e0db172fe0a2dbe9d0a3a627a8b04'
    '4b94eb5b6fd0b57bd64058807dc983a3533051301d0603551d0e041604149971f41e6d0dfa47'
    '8b604cba522d2e6d70ff7357301f0603551d230418301680149971f41e6d0dfa478b604cba52'
    '2d2e6d70ff7357300f0603551d130101ff040530030101ff300506032b657003410025bee419'
    'e02d9dec70ab4e114ed50b4dafcde9d2e8cd461640d30f9746ea33d9869e7a944fdb56c80cc6'
    '8c8d730bcad64380fcf8498852b6b02ee5c04586dd0e';

const String rsaCertDerHex =
    '3082030f308201f7a00302010202147feec2a61573dbcf9dc5ec45f4ecb153d1a23b02300d06'
    '092a864886f70d01010b050030173115301306035504030c0c6578616d706c652e7465737430'
    '1e170d3236303731333037343630355a170d3336303731303037343630355a30173115301306'
    '035504030c0c6578616d706c652e7465737430820122300d06092a864886f70d010101050003'
    '82010f003082010a0282010100be003770926645196a5afb557b2c2ed0ce432fa037d174b3c1'
    '5a76191481d8f7527ab45a2b701c34f010d456cc013e2d66bd3a0dd168d97349e5de52f30f29'
    'f4fcad031c3f5a4e814b556b126bab833cd0ebfac545402e26d55069aac830c6cd62ae32ebcc'
    '3e3f907242fb0cbb1c1ebb4466f61e43992c0fdafc8a9544d11c8bf820903786b75a9f917bbf'
    '3358a2f10a8962df312963a40a99485affbba404ba1e73fa38368ea7ee395678135e2e1d0491'
    '101c2e6c384aded29b79d236e5932ce57eb5f29d9f192ed443eb6fd60e066562fcd88ec994ea'
    'e1e37d79aba64e811b7a2297912820d9839c33773489ba8b669d4eb7341c617685e33ba503b3'
    '3755530203010001a3533051301d0603551d0e041604142460882c4675cd433d47a23a1afc3e'
    'adc9872bec301f0603551d230418301680142460882c4675cd433d47a23a1afc3eadc9872bec'
    '300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003820101000e'
    'c30bb300f0af7f2c0e2368565bbf2aff3c9a468e5e765da22c1ea31e75188abee8f4258e2036'
    '80bc63d589cdebcbcce6f2fc591585ac0d1bde900a95678a49ce3007398c6eb9fdbceb227a6a'
    '9ab596e5dc68e61b2f8e674c687702674fbe4351827068188809f33547814efa713b029e3b55'
    '0289274a61166ffe19d6d1caf57186643c0ffc415f040afdb5a773d6329d5b871d4ff278e924'
    '7a6bd2f93400d0bd244963078f9e0e240ccde592636105f18f7f66f3ff962925bb831fbb6485'
    '1c5f49f697634231d054199662f81d2f8c02a791859ba294be8c0293e8b9c24ddda2b8a13fa4'
    'b21e44e65505836a98a8dbd66433d442d5062cb83f0f608f389439';

const String expectedKeyHex =
    '166c3e0db172fe0a2dbe9d0a3a627a8b044b94eb5b6fd0b57bd64058807dc983';

int _indexOfSublist(List<int> haystack, List<int> needle) {
  for (var i = 0; i + needle.length <= haystack.length; i++) {
    var match = true;
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) {
        match = false;
        break;
      }
    }
    if (match) return i;
  }
  return -1;
}

void main() {
  group(
      'TlsPinning: extractEd25519PublicKeyFromCertDer against real openssl DER',
      () {
    test('extracts the exact raw 32-byte Ed25519 public key', () {
      final certDer = Hex.decode(edCertDerHex);
      final key = extractEd25519PublicKeyFromCertDer(certDer);
      expect(key.length, equals(32));
      expect(Hex.encode(key), equals(expectedKeyHex));
    });

    test('the extracted key fingerprints via the SDK fingerprint routine',
        () async {
      final certDer = Hex.decode(edCertDerHex);
      final key = extractEd25519PublicKeyFromCertDer(certDer);
      final fp = await Crypto.fingerprint(key);
      final expectedFp = await Crypto.fingerprint(Hex.decode(expectedKeyHex));
      expect(fp, equals(expectedFp));
      expect(fp.length, equals(64));
    });

    test('rejects a non-Ed25519 (RSA) certificate', () {
      final certDer = Hex.decode(rsaCertDerHex);
      expect(() => extractEd25519PublicKeyFromCertDer(certDer),
          throwsA(isA<SdkException>()));
    });

    test('rejects truncated DER input', () {
      final certDer = Hex.decode(edCertDerHex);
      final truncated = Uint8List.sublistView(certDer, 0, certDer.length ~/ 2);
      expect(() => extractEd25519PublicKeyFromCertDer(truncated),
          throwsA(isA<SdkException>()));
    });

    test('rejects a byte-flipped SPKI prefix', () {
      final certDer = Hex.decode(edCertDerHex);
      final keyBytes = Hex.decode(expectedKeyHex);
      final idx = _indexOfSublist(certDer, keyBytes);
      expect(idx, greaterThan(11));
      final corrupted = Uint8List.fromList(certDer);
      corrupted[idx - 1] ^= 0xff;
      expect(() => extractEd25519PublicKeyFromCertDer(corrupted),
          throwsA(isA<SdkException>()));
    });
  });
}
