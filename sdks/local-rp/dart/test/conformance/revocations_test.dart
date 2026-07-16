import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';
import 'package:test/test.dart';

import '../testutil/fixtures.dart';

DomainPublicKey _parseDomainKey(Map<String, dynamic> k) {
  return DomainPublicKey(
    keyId: k['key_id'] as String,
    publicKey: hex(k['public_key_hex'] as String),
    fingerprint: k['fingerprint_hex'] as String,
    algorithm: k['algorithm'] as String,
    keyUsage: k['key_usage'] as String,
    createdAt: k['created_at'] as String,
    expiresAt: k['expires_at'] as String,
    revokedAt: k['revoked_at'] as String?,
  );
}

RevocationCertificate _parseCertificate(Map<String, dynamic> certNode) {
  final signatures = <ClaimSignature>[];
  for (final s
      in (certNode['signatures'] as List).cast<Map<String, dynamic>>()) {
    signatures.add(ClaimSignature(
      domain: s['domain'] as String,
      signedByKeyId: s['signed_by_key_id'] as String,
      signature: hex(s['signature_hex'] as String),
    ));
  }
  return RevocationCertificate(
    targetKeyId: certNode['target_key_id'] as String,
    targetFingerprint: certNode['target_fingerprint'] as String,
    revokedAt: certNode['revoked_at'] as String,
    signatures: signatures,
  );
}

void main() {
  group('revocations.json conformance', () {
    test('certificate cases match expected validity and counted signers',
        () async {
      final d = loadJson('revocations.json') as Map<String, dynamic>;
      expect(d['quorum'], equals(revocationQuorum));
      expect(d['tag'], equals('linkkeys-key-revocation-v1alpha'));

      final domainKeys = (d['domain_keys'] as List)
          .cast<Map<String, dynamic>>()
          .map(_parseDomainKey)
          .toList();

      final cases =
          (d['certificate_cases'] as List).cast<Map<String, dynamic>>();
      expect(cases.length, equals(9));

      for (final c in cases) {
        final name = c['name'] as String;
        final cert =
            _parseCertificate(c['certificate'] as Map<String, dynamic>);
        final verifyDomain = c['verify_domain'] as String;
        final expectedValid = c['expected_valid'] as bool;
        final expectedCounted = c['expected_counted_signers'] as int;

        final counted = await countValidSigners(cert, domainKeys, verifyDomain);
        expect(counted, equals(expectedCounted),
            reason: 'expected_counted_signers mismatch for $name');

        if (expectedValid) {
          await verifyRevocationCertificate(cert, domainKeys, verifyDomain);
        } else {
          await expectLater(
            verifyRevocationCertificate(cert, domainKeys, verifyDomain),
            throwsA(isA<RevocationError>()),
            reason: '$name unexpectedly verified',
          );
        }
      }
    });

    test('application case revocation is applied to the key set', () async {
      final d = loadJson('revocations.json') as Map<String, dynamic>;
      final domain = d['domain'] as String;

      final domainKeys = (d['domain_keys'] as List)
          .cast<Map<String, dynamic>>()
          .map(_parseDomainKey)
          .toList();

      final quorumCase = (d['certificate_cases'] as List)
          .cast<Map<String, dynamic>>()
          .firstWhere((c) => c['name'] == 'valid_quorum_two_siblings');
      final cert =
          _parseCertificate(quorumCase['certificate'] as Map<String, dynamic>);

      final app = d['application_case'] as Map<String, dynamic>;
      final envelope = app['envelope'] as Map<String, dynamic>;
      final signedPayload = SignedLocalRpCallbackPayload(
        payload: hex(envelope['payload_cbor_hex'] as String),
        signingKeyId: envelope['signing_key_id'] as String,
        signature: hex(envelope['signature_hex'] as String),
      );
      final verifyNow = DateTime.parse(app['verify_now'] as String).toUtc();
      final skew = app['clock_skew_seconds'] as int;

      // Before applying the revocation certificate: the fetched key list
      // shows the target key with no revoked_at, so the envelope verifies.
      await LocalRp.verifyLocalRpCallbackPayload(
          signedPayload, domainKeys, verifyNow, skew);

      // Apply the quorum-verified certificate exactly as
      // Complete/RpcClient would: verify it, then drop its target from the
      // trusted key set.
      await verifyRevocationCertificate(cert, domainKeys, domain);
      final afterRevocation =
          domainKeys.where((k) => k.keyId != cert.targetKeyId).toList();

      // After applying: the same envelope must fail signature/key-lookup
      // verification, because its signing key is no longer in the trusted
      // set.
      await expectLater(
        LocalRp.verifyLocalRpCallbackPayload(
            signedPayload, afterRevocation, verifyNow, skew),
        throwsA(isA<LocalRpError>()),
      );
    });
  });
}
