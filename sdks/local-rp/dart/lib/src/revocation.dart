// Sibling-signed key revocation certificate verification -- mirrors
// `crates/liblinkkeys/src/revocation.rs` / the Rust/Go/Java reference SDKs'
// own `revocation` modules. Only verification is ported here (building/
// signing a revocation certificate is a domain-admin/server-side operation,
// out of scope for a local-RP SDK); this SDK verifies revocation
// certificates fetched alongside domain keys so it can drop a key a
// quorum-verified sibling revocation targets.
library;

import 'dart:typed_data';

import 'crypto/crypto.dart';
import 'errors.dart';
import 'local_rp.dart';
import 'wire/cbor.dart';
import 'wire/types.dart';

/// Minimum number of distinct sibling signatures required to revoke a key.
const int revocationQuorum = 2;

/// Domain-separation tag/version for the signed revocation payload.
const String _revocationTag = 'linkkeys-key-revocation-v1alpha';

/// The canonical signed bytes: the tag, the target key id + fingerprint, the
/// revocation instant, and the signing sibling's domain (bound per-signature
/// to stop cross-domain reuse of a signature). This is the OLDER house
/// tuple pattern -- a five-element array with the domain-separation tag
/// first -- NOT the two-element `CBOR([context, payload])` envelope framing
/// the four local-RP structures use.
Uint8List revocationPayload(String targetKeyId, String targetFingerprint,
    String revokedAt, String signingDomain) {
  return Cbor.encode(Cbor.tuple([
    Cbor.vtext(_revocationTag),
    Cbor.vtext(targetKeyId),
    Cbor.vtext(targetFingerprint),
    Cbor.vtext(revokedAt),
    Cbor.vtext(signingDomain),
  ]));
}

/// Verify a revocation certificate against a domain's public key set.
/// Requires at least [revocationQuorum] DISTINCT signing keys of [domain],
/// each currently valid and NOT the target key, to have signed the
/// canonical payload.
Future<void> verifyRevocationCertificate(RevocationCertificate cert,
    List<DomainPublicKey> domainKeys, String domain) async {
  final counted = await countValidSigners(cert, domainKeys, domain);
  if (counted < revocationQuorum) {
    throw RevocationError(counted, revocationQuorum);
  }
}

/// The number of distinct, currently-valid, non-self, correctly-signed
/// sibling signatures the certificate carries for [domain]. Exposed so
/// conformance tests can pinpoint exactly which filtering rule an
/// implementation got wrong, per `revocations.json`'s
/// `expected_counted_signers` field; [verifyRevocationCertificate] is the
/// only entry point production code should call.
Future<int> countValidSigners(RevocationCertificate cert,
    List<DomainPublicKey> domainKeys, String domain) async {
  final validSigners = <String>{};

  for (final sig in cert.signatures) {
    // A key can never authorize its own revocation.
    if (sig.signedByKeyId == cert.targetKeyId) continue;
    // The signature must be bound to this domain.
    if (sig.domain != domain) continue;

    DomainPublicKey? key;
    for (final k in domainKeys) {
      if (k.keyId == sig.signedByKeyId) {
        key = k;
        break;
      }
    }
    if (key == null) continue;

    // Only a currently-valid signing key counts toward the quorum.
    try {
      LocalRp.checkSigningKeyValid(key);
    } on LocalRpError {
      continue;
    }

    final payload = revocationPayload(
        cert.targetKeyId, cert.targetFingerprint, cert.revokedAt, sig.domain);
    if (key.algorithm == 'ed25519' &&
        key.publicKey.length == 32 &&
        await Crypto.verifyEd25519(payload, sig.signature, key.publicKey)) {
      validSigners.add(sig.signedByKeyId);
    }
  }

  return validSigners.length;
}
