// claims.json conformance: `Claim` wire encoding and claim-signature
// verification (see `sdks/local-rp/conformance/README.md`, "claims.json").
//
// This is the vector file that pins the trap described there: `claim_value`
// is CBOR bytes (bstr, major type 2), never text (tstr) -- both on the wire
// and inside the eight-element signed payload
// `CBOR([tag, claim_id, claim_type, claim_value, "user_id@subject_domain",
// signing_domain, expires_at_or_null, attested_at])`. A codec that is
// internally self-consistent (sign-wrong/verify-wrong) passes its own tests
// either way, so every case here is checked against the fixture's
// independently-computed bytes/signatures, not merely round-tripped through
// this SDK's own encoder.
library;

import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';
import 'package:linkkeys_local_rp/src/claims.dart' as claims_impl;
import 'package:linkkeys_local_rp/src/crypto/crypto.dart';
import 'package:linkkeys_local_rp/src/wire/cbor.dart';
import 'package:linkkeys_local_rp/src/wire/codec.dart';
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

List<DomainPublicKey> _parseDomainKeys(List<dynamic> list) =>
    list.cast<Map<String, dynamic>>().map(_parseDomainKey).toList();

ClaimSignature _parseClaimSignature(Map<String, dynamic> s) => ClaimSignature(
      domain: s['domain'] as String,
      signedByKeyId: s['signed_by_key_id'] as String,
      signature: hex(s['signature_hex'] as String),
    );

Claim _parseClaim(Map<String, dynamic> c) {
  return Claim(
    claimId: c['claim_id'] as String,
    userId: c['user_id'] as String,
    claimType: c['claim_type'] as String,
    claimValue: hex(c['claim_value_hex'] as String),
    signatures: (c['signatures'] as List)
        .cast<Map<String, dynamic>>()
        .map(_parseClaimSignature)
        .toList(),
    attestedAt: c['attested_at'] as String,
    createdAt: c['created_at'] as String,
    expiresAt: c['expires_at'] as String?,
    revokedAt: c['revoked_at'] as String?,
  );
}

/// Symbolic `expected_error` values this file's negative cases use, mapped
/// to this SDK's [ClaimErrorKind].
const Map<String, ClaimErrorKind> _expectedErrorKinds = {
  'signature_invalid': ClaimErrorKind.signatureInvalid,
  'key_not_found': ClaimErrorKind.keyNotFound,
};

void main() {
  group('claims.json conformance', () {
    final d = loadJson('claims.json') as Map<String, dynamic>;
    final defaultDomainKeys = _parseDomainKeys(d['domain_keys'] as List);
    const signingDomain = 'conformance.example';

    test('file-level constants match the README', () {
      expect(d['tag'], equals('linkkeys-claim-v2'));
      expect(d['subject_domain'], equals(signingDomain));
      expect(
        d['payload_layout'],
        equals(
          "CBOR([tag, claim_id, claim_type, claim_value(bstr), 'user_id@subject_domain', signing_domain, expires_at_or_null, attested_at])",
        ),
      );
    });

    test(
        'positive cases: byte-exact wire round-trip, independent Ed25519 '
        'verification of every signature, claimSignPayload audit, and full '
        'SDK verifyClaim', () async {
      final cases = (d['cases'] as List).cast<Map<String, dynamic>>();
      expect(cases.length, equals(3));

      for (final c in cases) {
        final name = c['name'] as String;
        expect(c['expected_valid'], isTrue, reason: name);
        final claimNode = c['claim'] as Map<String, dynamic>;
        final claim = _parseClaim(claimNode);
        final subjectDomain = c['subject_domain'] as String;
        final expectedWire = hex(c['claim_cbor_hex'] as String);

        // A claim built purely from the fixture's expanded fields encodes to
        // the fixture's wire bytes exactly.
        final encoded = Codec.encodeClaim(claim);
        expect(encoded, equals(expectedWire),
            reason: '$name: hand-built claim did not encode byte-exactly');

        // Decoding the fixture's wire bytes and re-encoding reproduces them
        // byte-identically -- the round-trip the README requires.
        final decoded = Codec.decodeClaim(expectedWire);
        expect(Codec.encodeClaim(decoded), equals(expectedWire),
            reason: '$name: decode/re-encode round trip mismatch');
        expect(decoded.claimValue, equals(claim.claimValue),
            reason: '$name: claim_value must decode as raw bytes, not text');

        // Every signature: independently verify signed_payload_cbor_hex
        // against signature_hex using the signer's Ed25519 public key from
        // domain_keys, entirely bypassing this SDK's own payload
        // construction, AND separately confirm claimSignPayload reproduces
        // the exact fixture payload bytes (the construction audit).
        final sigNodes =
            (claimNode['signatures'] as List).cast<Map<String, dynamic>>();
        expect(decoded.signatures.length, equals(sigNodes.length));
        for (var i = 0; i < sigNodes.length; i++) {
          final sigNode = sigNodes[i];
          final signedPayload =
              hex(sigNode['signed_payload_cbor_hex'] as String);
          final signature = hex(sigNode['signature_hex'] as String);
          final keyId = sigNode['signed_by_key_id'] as String;
          final signerKey =
              defaultDomainKeys.firstWhere((k) => k.keyId == keyId);

          final rawValid = await Crypto.verifyEd25519(
              signedPayload, signature, signerKey.publicKey);
          expect(rawValid, isTrue,
              reason:
                  '$name signature[$i]: independent Ed25519 verification failed');

          final ourPayload = claims_impl.claimSignPayload(
            claim.claimId,
            claim.claimType,
            claim.claimValue,
            claim.userId,
            subjectDomain,
            sigNode['domain'] as String,
            claim.expiresAt,
            claim.attestedAt,
          );
          expect(ourPayload, equals(signedPayload),
              reason:
                  '$name signature[$i]: claimSignPayload construction mismatch');
        }

        // Full SDK verification path -- exactly what completeLocalLogin
        // drives (`claims.verifyClaim(claim, redemption.userDomain,
        // domainKeySets)` in src/complete.dart).
        await verifyClaim(
          claim,
          subjectDomain,
          [DomainKeySet(signingDomain, defaultDomainKeys)],
        );
      }
    });

    test('decode-negative case: CBOR-text-typed claim_value must be rejected',
        () {
      final cases =
          (d['decode_negative_cases'] as List).cast<Map<String, dynamic>>();
      expect(cases.length, equals(1));
      for (final c in cases) {
        expect(c['expected_decode_ok'], isFalse);
        final bytes = hex(c['claim_cbor_hex'] as String);
        expect(
          () => Codec.decodeClaim(bytes),
          throwsA(isA<CborDecodeException>()),
          reason: c['name'] as String,
        );
      }
    });

    test('verification negatives: four cases, correct error kinds', () async {
      final cases = (d['negative_cases'] as List).cast<Map<String, dynamic>>();
      expect(cases.length, equals(4));

      for (final c in cases) {
        final name = c['name'] as String;
        final claim = Codec.decodeClaim(hex(c['claim_cbor_hex'] as String));
        final subjectDomain = c['subject_domain'] as String;
        final overrideKeys = c['domain_keys'] as List?;
        final domainKeys = overrideKeys == null
            ? defaultDomainKeys
            : _parseDomainKeys(overrideKeys);
        final expectedErrorName = c['expected_error'] as String;
        final expectedKind = _expectedErrorKinds[expectedErrorName];
        expect(expectedKind, isNotNull,
            reason: 'unrecognized expected_error symbol: $expectedErrorName');

        // Through the SDK's own claim verification path (verifyClaim), the
        // same one completeLocalLogin drives.
        await expectLater(
          verifyClaim(
            claim,
            subjectDomain,
            [DomainKeySet(signingDomain, domainKeys)],
          ),
          throwsA(isA<ClaimError>()
              .having((e) => e.kind, 'kind', equals(expectedKind))),
          reason: name,
        );
      }
    });

    test(
        'ticket_redemption_response: byte-exact round trip and embedded '
        'claim verification', () async {
      final node = d['ticket_redemption_response'] as Map<String, dynamic>;
      final expectedWire = hex(node['response_cbor_hex'] as String);

      final decoded = Codec.decodeLocalRpTicketRedemptionResponse(expectedWire);
      expect(decoded.userId, equals(node['user_id']));
      expect(decoded.userDomain, equals(node['user_domain']));
      expect(decoded.ticketExpiresAt, equals(node['ticket_expires_at']));

      final cases = (d['cases'] as List).cast<Map<String, dynamic>>();
      expect(decoded.claims.length, equals(cases.length));
      for (var i = 0; i < cases.length; i++) {
        final expectedClaim =
            _parseClaim(cases[i]['claim'] as Map<String, dynamic>);
        expect(decoded.claims[i].claimId, equals(expectedClaim.claimId));
        expect(decoded.claims[i].claimType, equals(expectedClaim.claimType));
        expect(decoded.claims[i].claimValue, equals(expectedClaim.claimValue),
            reason: 'claim[$i] claim_value must decode as raw bytes');
        expect(decoded.claims[i].signatures.length,
            equals(expectedClaim.signatures.length));
      }

      // Re-encoding the decoded response reproduces the exact wire bytes.
      final reencoded = Codec.encodeLocalRpTicketRedemptionResponse(decoded);
      expect(reencoded, equals(expectedWire));

      // Each embedded claim verifies through the SDK's own claim
      // verification path, exactly as completeLocalLogin drives it (using
      // the response's own user_domain as the authoritative subject
      // domain).
      for (final claim in decoded.claims) {
        await verifyClaim(
          claim,
          decoded.userDomain,
          [DomainKeySet(signingDomain, defaultDomainKeys)],
        );
      }
    });
  });
}
