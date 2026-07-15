// TLS transport for CSIL-RPC, pinned to a domain's DNS `fp=` records -- the
// same trust anchor `crates/linkkeys/src/tcp/tls.rs` uses for the S2S path.
// WebPKI certificate-chain validity is NOT the trust anchor here (there is
// no CA chain for a domain's TCP-service certificate to begin with); the
// DNS-pinned SPKI fingerprint is.
//
// ## Why accepting any certificate chain is safe here
//
// [SecureSocket.secure]'s `onBadCertificate` callback returning `true`
// would be a severe vulnerability in almost any other context, because it
// lets a network attacker present ANY certificate and have it accepted.
// That is not what happens here: bypassing dart:io's normal WebPKI chain
// validation (which would otherwise reject a certificate we have no CA
// basis to validate) is only step one. Before any application data is sent
// or read, [connectPinned] MANDATORILY recomputes the SHA-256 fingerprint
// of the peer certificate's raw Ed25519 SPKI public-key bytes and requires
// it to be a member of the caller-supplied pinned set (from a DNS `fp=` TXT
// lookup already verified by the caller). The pin, not the chain, is the
// anchor -- exactly the posture the Rust/Go/Java/TypeScript reference SDKs
// take. Skipping the mandatory post-handshake pin check would defeat the
// entire construction, so [connectPinned] always performs it before
// returning the socket.
//
// ## Extracting the raw Ed25519 key from a certificate
//
// `dart:io`'s `X509Certificate` exposes only the full certificate DER
// (`.der`) -- unlike Node's `X509Certificate`, it has no direct
// `.publicKey`/SPKI accessor. This library therefore hand-walks the
// minimal ASN.1 DER structure of an X.509 `Certificate` (RFC 5280) down to
// `TBSCertificate.subjectPublicKeyInfo`, then matches it against the fixed
// 12-byte RFC 8410 SubjectPublicKeyInfo prefix for id-Ed25519
// (`302a300506032b6570032100`) followed by the raw 32-byte public key --
// the same prefix the Java/TypeScript SDKs strip from their own
// certificate/key export paths.
library;

import 'dart:io';
import 'dart:typed_data';

import '../crypto/crypto.dart';
import '../crypto/hex.dart';
import '../errors.dart';

/// The fixed 12-byte RFC 8410 Ed25519 SubjectPublicKeyInfo DER prefix
/// (SEQUENCE header + AlgorithmIdentifier SEQUENCE + BIT STRING header)
/// preceding the raw 32-byte public key. RFC 8410 defines a single,
/// parameterless AlgorithmIdentifier for id-Ed25519, so this prefix never
/// varies.
final Uint8List ed25519SpkiPrefix = Hex.decode('302a300506032b6570032100');
const int _ed25519SpkiTotalLen = 12 + 32;

class _DerTlv {
  final int tag;
  final int contentStart;
  final int contentEnd;
  final int tlvEnd;
  const _DerTlv(this.tag, this.contentStart, this.contentEnd, this.tlvEnd);
}

_DerTlv _readTlv(Uint8List data, int pos) {
  if (pos >= data.length) {
    throw SdkException(SdkExceptionKind.tls, 'DER: unexpected end of input');
  }
  final tag = data[pos];
  var p = pos + 1;
  if (p >= data.length) {
    throw SdkException(SdkExceptionKind.tls, 'DER: truncated length');
  }
  final firstLenByte = data[p];
  p += 1;
  int length;
  if ((firstLenByte & 0x80) == 0) {
    length = firstLenByte;
  } else {
    final numBytes = firstLenByte & 0x7f;
    if (numBytes == 0 || numBytes > 4 || p + numBytes > data.length) {
      throw SdkException(
          SdkExceptionKind.tls, 'DER: unsupported/invalid long-form length');
    }
    length = 0;
    for (var i = 0; i < numBytes; i++) {
      length = (length << 8) | data[p + i];
    }
    p += numBytes;
  }
  final contentStart = p;
  final contentEnd = contentStart + length;
  if (contentEnd > data.length) {
    throw SdkException(SdkExceptionKind.tls, 'DER: length exceeds input');
  }
  return _DerTlv(tag, contentStart, contentEnd, contentEnd);
}

/// Extract the raw 32-byte Ed25519 public key from a certificate's DER
/// encoding by walking down to `TBSCertificate.subjectPublicKeyInfo`.
/// Throws [SdkException] (kind `tls`) if the certificate is not a
/// straightforward Ed25519-keyed X.509 certificate.
Uint8List extractEd25519PublicKeyFromCertDer(Uint8List certDer) {
  try {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    final cert = _readTlv(certDer, 0);
    // TBSCertificate ::= SEQUENCE { ... }
    final tbs = _readTlv(certDer, cert.contentStart);

    var pos = tbs.contentStart;
    // Optional explicit [0] version tag.
    if (pos < tbs.contentEnd && (certDer[pos] & 0xff) == 0xa0) {
      final version = _readTlv(certDer, pos);
      pos = version.tlvEnd;
    }
    // serialNumber INTEGER
    pos = _readTlv(certDer, pos).tlvEnd;
    // signature AlgorithmIdentifier SEQUENCE
    pos = _readTlv(certDer, pos).tlvEnd;
    // issuer Name SEQUENCE
    pos = _readTlv(certDer, pos).tlvEnd;
    // validity SEQUENCE
    pos = _readTlv(certDer, pos).tlvEnd;
    // subject Name SEQUENCE
    pos = _readTlv(certDer, pos).tlvEnd;
    // subjectPublicKeyInfo SEQUENCE -- this is what we want, raw TLV bytes.
    final spki = _readTlv(certDer, pos);
    final spkiBytes = Uint8List.sublistView(certDer, pos, spki.tlvEnd);

    if (spkiBytes.length != _ed25519SpkiTotalLen) {
      throw SdkException(SdkExceptionKind.tls,
          'peer certificate is not a 32-byte Ed25519 SPKI key (SPKI DER length ${spkiBytes.length})');
    }
    for (var i = 0; i < ed25519SpkiPrefix.length; i++) {
      if (spkiBytes[i] != ed25519SpkiPrefix[i]) {
        throw SdkException(SdkExceptionKind.tls,
            'peer certificate SPKI does not match the expected RFC 8410 Ed25519 prefix');
      }
    }
    return Uint8List.sublistView(spkiBytes, 12, 44);
  } on SdkException {
    rethrow;
  } catch (e) {
    throw SdkException(
        SdkExceptionKind.tls, 'failed to parse certificate DER: $e',
        cause: e);
  }
}

/// Compute the pin fingerprint (lowercase hex SHA-256) of a peer
/// certificate's raw Ed25519 SPKI key.
Future<String> certFingerprint(X509Certificate cert) async {
  final rawKey = extractEd25519PublicKeyFromCertDer(cert.der);
  return Crypto.fingerprint(rawKey);
}

/// Wrap an already-connected raw socket in TLS, complete the handshake, and
/// MANDATORILY verify the peer certificate's SPKI fingerprint is a member
/// of [pinnedFingerprints] before returning. Throws (and closes the
/// underlying socket) on any failure (handshake failure, non-Ed25519 cert,
/// or pin mismatch) -- a caller never receives a socket that has not passed
/// this check.
Future<SecureSocket> connectPinned(
    Socket raw, String hostname, List<String> pinnedFingerprints) async {
  SecureSocket tls;
  try {
    tls = await SecureSocket.secure(
      raw,
      host: hostname,
      onBadCertificate: (X509Certificate cert) => true,
    );
  } catch (e) {
    raw.destroy();
    throw SdkException(SdkExceptionKind.tls, 'TLS handshake failed: $e',
        cause: e);
  }

  final peerCert = tls.peerCertificate;
  if (peerCert == null) {
    tls.destroy();
    throw SdkException(SdkExceptionKind.tls, 'peer presented no certificate');
  }

  final String fp;
  try {
    fp = await certFingerprint(peerCert);
  } on SdkException {
    tls.destroy();
    rethrow;
  }

  final pinned = pinnedFingerprints.any((p) => p.toLowerCase() == fp);
  if (!pinned) {
    tls.destroy();
    throw SdkException(SdkExceptionKind.tls,
        'certificate fingerprint $fp does not match any pinned fingerprint for this domain');
  }
  return tls;
}
