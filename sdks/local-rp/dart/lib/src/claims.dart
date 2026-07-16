// Claim signature verification -- mirrors `crates/liblinkkeys/src/claims.rs`
// / the Rust/Go/Java reference SDKs' own `claims` modules. Only the
// verification half matters in production (claims are always signed by an
// IDP, server-side); `signClaim` is reproduced exactly (same tag, same tuple
// field order/CBOR shape) purely so test fixtures (fake IDPs) can build
// claims this SDK can verify against the real Rust wire format -- a genuine
// interop requirement, not internal self-consistency.
library;

import 'dart:typed_data';

import 'crypto/crypto.dart';
import 'errors.dart';
import 'rfc3339.dart';
import 'wire/cbor.dart';
import 'wire/types.dart';

const String _claimPayloadTag = 'linkkeys-claim-v1alpha';

/// Bound on distinct claim-signer domains a completion will fetch keys for;
/// see `complete.dart`.
const int maxClaimSignerDomains = 8;

/// The canonical bytes a single signature covers for a claim. The subject is
/// the single full identity `user_id@subject_domain` (not the bare
/// user_id), so a claim about a user_id at one domain can't be replayed as
/// the same user_id at another. `signingDomain` is bound per-signature so a
/// signature from domain A cannot satisfy a claim presented as signed by B.
Uint8List claimSignPayload(
  String claimId,
  String claimType,
  Uint8List claimValue,
  String userId,
  String subjectDomain,
  String signingDomain,
  String? expiresAt,
  String attestedAt,
) {
  final subject = '$userId@$subjectDomain';
  return Cbor.encode(Cbor.tuple([
    Cbor.vtext(_claimPayloadTag),
    Cbor.vtext(claimId),
    Cbor.vtext(claimType),
    Cbor.vbytes(claimValue),
    Cbor.vtext(subject),
    Cbor.vtext(signingDomain),
    Cbor.optTextItem(expiresAt),
    Cbor.vtext(attestedAt),
  ]));
}

/// What is being claimed, independent of who signs it. Mirrors
/// `liblinkkeys::claims::ClaimSpec`.
class ClaimSpec {
  final String claimId;
  final String claimType;
  final Uint8List claimValue;
  final String userId;
  final String subjectDomain;
  final String? expiresAt;
  final String attestedAt;

  const ClaimSpec({
    required this.claimId,
    required this.claimType,
    required this.claimValue,
    required this.userId,
    required this.subjectDomain,
    this.expiresAt,
    required this.attestedAt,
  });
}

/// One signer of a claim: a single key, owned by [domain].
class ClaimSigner {
  final String domain;
  final String keyId;
  final Uint8List privateKeySeed;
  const ClaimSigner(
      {required this.domain,
      required this.keyId,
      required this.privateKeySeed});
}

/// Sign a claim with one or more keys (test-fixture helper; see this
/// library's docs for why this is a pure protocol helper rather than
/// something the SDK calls in production).
Future<Claim> signClaim(ClaimSpec spec, List<ClaimSigner> signers) async {
  final signatures = <ClaimSignature>[];
  for (final signer in signers) {
    final payload = claimSignPayload(
      spec.claimId,
      spec.claimType,
      spec.claimValue,
      spec.userId,
      spec.subjectDomain,
      signer.domain,
      spec.expiresAt,
      spec.attestedAt,
    );
    final sig = await Crypto.signEd25519(payload, signer.privateKeySeed);
    signatures.add(ClaimSignature(
        domain: signer.domain, signedByKeyId: signer.keyId, signature: sig));
  }
  return Claim(
    claimId: spec.claimId,
    userId: spec.userId,
    claimType: spec.claimType,
    claimValue: spec.claimValue,
    signatures: signatures,
    attestedAt: spec.attestedAt,
    createdAt: Rfc3339.format(DateTime.now().toUtc()),
    expiresAt: spec.expiresAt,
    revokedAt: null,
  );
}

/// A domain and the set of its currently-known public keys, resolved by the
/// caller before verifying.
class DomainKeySet {
  final String domain;
  final List<DomainPublicKey> keys;
  const DomainKeySet(this.domain, this.keys);
}

Future<void> _verifyOneClaimSignature(
    ClaimSignature sig, Uint8List payload, List<DomainPublicKey> keys) async {
  DomainPublicKey? key;
  for (final k in keys) {
    if (k.keyId == sig.signedByKeyId) {
      key = k;
      break;
    }
  }
  if (key == null) {
    throw ClaimError(ClaimErrorKind.keyNotFound, sig.signedByKeyId);
  }

  if (key.keyUsage != 'sign') {
    throw ClaimError(
        ClaimErrorKind.signatureInvalid, 'key is not a signing key');
  }
  if (key.revokedAt != null) {
    throw ClaimError(ClaimErrorKind.keyRevoked, key.keyId);
  }
  final DateTime expires;
  try {
    expires = Rfc3339.parse('expires_at', key.expiresAt);
  } on LocalRpError {
    throw ClaimError(ClaimErrorKind.keyExpired, key.keyId);
  }
  if (DateTime.now().toUtc().isAfter(expires)) {
    throw ClaimError(ClaimErrorKind.keyExpired, key.keyId);
  }
  if (key.algorithm != 'ed25519') {
    throw ClaimError(ClaimErrorKind.unsupportedAlgorithm, key.algorithm);
  }
  if (!await Crypto.verifyEd25519(payload, sig.signature, key.publicKey)) {
    throw ClaimError(ClaimErrorKind.signatureInvalid, null);
  }
}

/// Verify only the cryptographic per-domain quorum: every domain that
/// signed must contribute at least one signature from a currently-valid key
/// of that domain. Does NOT check the claim's own revocation/expiry.
Future<void> _verifySignatureQuorum(
  List<ClaimSignature> signatures,
  List<DomainKeySet> domainKeys,
  Uint8List Function(String signingDomain) payloadFor,
) async {
  if (signatures.isEmpty) {
    throw ClaimError(ClaimErrorKind.unsigned, null);
  }
  final domains = <String>{};
  for (final s in signatures) {
    domains.add(s.domain);
  }
  final sortedDomains = domains.toList()..sort();

  for (final signingDomain in sortedDomains) {
    DomainKeySet? set;
    for (final d in domainKeys) {
      if (d.domain == signingDomain) {
        set = d;
        break;
      }
    }
    if (set == null) {
      throw ClaimError(ClaimErrorKind.domainKeysUnavailable, signingDomain);
    }

    final payload = payloadFor(signingDomain);

    ClaimError lastErr =
        ClaimError(ClaimErrorKind.domainUnverified, signingDomain);
    var satisfied = false;
    for (final sig in signatures) {
      if (sig.domain != signingDomain) continue;
      try {
        await _verifyOneClaimSignature(sig, payload, set.keys);
        satisfied = true;
        break;
      } on ClaimError catch (e) {
        lastErr = e;
      }
    }
    if (!satisfied) {
      throw lastErr;
    }
  }
}

/// Verify only the cryptographic per-domain quorum for [claim];
/// [subjectDomain] is the subject's home domain, supplied from authoritative
/// context (never attacker-controlled input).
Future<void> verifyClaimSignatures(
    Claim claim, String subjectDomain, List<DomainKeySet> domainKeys) async {
  await _verifySignatureQuorum(
    claim.signatures,
    domainKeys,
    (signingDomain) => claimSignPayload(
      claim.claimId,
      claim.claimType,
      claim.claimValue,
      claim.userId,
      subjectDomain,
      signingDomain,
      claim.expiresAt,
      claim.attestedAt,
    ),
  );
}

/// Full claim verification: the cryptographic per-domain quorum plus the
/// claim's own revocation and expiry.
Future<void> verifyClaim(
    Claim claim, String subjectDomain, List<DomainKeySet> domainKeys) async {
  await verifyClaimSignatures(claim, subjectDomain, domainKeys);

  if (claim.revokedAt != null) {
    throw ClaimError(ClaimErrorKind.revoked, null);
  }
  if (claim.expiresAt != null) {
    final DateTime expires;
    try {
      expires = Rfc3339.parse('expires_at', claim.expiresAt!);
    } on LocalRpError {
      throw ClaimError(ClaimErrorKind.badExpiry, null);
    }
    if (DateTime.now().toUtc().isAfter(expires)) {
      throw ClaimError(ClaimErrorKind.expired, null);
    }
  }
}
