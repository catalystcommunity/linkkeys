// Hand-written wire types for exactly the CSIL structures the DNS-less
// local-RP protocol needs. Hand-written, pending a csilgen Dart target (see
// this library's sibling `cbor.dart` docs and the filed csilgen request) --
// field names and shapes mirror `csil/linkkeys.csil` and the generated
// Rust/Go/Java types exactly.
//
// These are plain data carriers, not builders: optional fields are `null`
// when absent (mirroring Rust `Option::None`), and byte-array fields are raw,
// unencoded bytes. Encoding/decoding lives in `codec.dart`.
library;

import 'dart:typed_data';

class EmptyRequest {
  const EmptyRequest();
}

class DomainPublicKey {
  final String keyId;
  final Uint8List publicKey;
  final String fingerprint;
  final String algorithm;
  final String keyUsage;
  final String createdAt;
  final String expiresAt;
  final String? revokedAt;
  final String? signedByKeyId;
  final Uint8List? keySignature;

  const DomainPublicKey({
    required this.keyId,
    required this.publicKey,
    required this.fingerprint,
    required this.algorithm,
    required this.keyUsage,
    required this.createdAt,
    required this.expiresAt,
    this.revokedAt,
    this.signedByKeyId,
    this.keySignature,
  });

  DomainPublicKey copyWith({
    String? keyId,
    Uint8List? publicKey,
    String? fingerprint,
    String? algorithm,
    String? keyUsage,
    String? createdAt,
    String? expiresAt,
    Object? revokedAt = _sentinel,
    Object? signedByKeyId = _sentinel,
    Object? keySignature = _sentinel,
  }) {
    return DomainPublicKey(
      keyId: keyId ?? this.keyId,
      publicKey: publicKey ?? this.publicKey,
      fingerprint: fingerprint ?? this.fingerprint,
      algorithm: algorithm ?? this.algorithm,
      keyUsage: keyUsage ?? this.keyUsage,
      createdAt: createdAt ?? this.createdAt,
      expiresAt: expiresAt ?? this.expiresAt,
      revokedAt: identical(revokedAt, _sentinel)
          ? this.revokedAt
          : revokedAt as String?,
      signedByKeyId: identical(signedByKeyId, _sentinel)
          ? this.signedByKeyId
          : signedByKeyId as String?,
      keySignature: identical(keySignature, _sentinel)
          ? this.keySignature
          : keySignature as Uint8List?,
    );
  }
}

const _sentinel = Object();

class GetDomainKeysResponse {
  final String domain;
  final List<DomainPublicKey> keys;
  final bool? recentRevocationsAvailable;

  const GetDomainKeysResponse({
    required this.domain,
    required this.keys,
    this.recentRevocationsAvailable,
  });
}

class GetRevocationsRequest {
  final String? since;
  const GetRevocationsRequest({this.since});
}

class ClaimSignature {
  final String domain;
  final String signedByKeyId;
  final Uint8List signature;

  const ClaimSignature({
    required this.domain,
    required this.signedByKeyId,
    required this.signature,
  });
}

class RevocationCertificate {
  final String targetKeyId;
  final String targetFingerprint;
  final String revokedAt;
  final List<ClaimSignature> signatures;

  const RevocationCertificate({
    required this.targetKeyId,
    required this.targetFingerprint,
    required this.revokedAt,
    required this.signatures,
  });
}

class GetRevocationsResponse {
  final List<RevocationCertificate> revocations;
  const GetRevocationsResponse({required this.revocations});
}

class Claim {
  final String claimId;
  final String userId;
  final String claimType;
  final Uint8List claimValue;
  final List<ClaimSignature> signatures;
  final String attestedAt;
  final String createdAt;
  final String? expiresAt;
  final String? revokedAt;

  const Claim({
    required this.claimId,
    required this.userId,
    required this.claimType,
    required this.claimValue,
    required this.signatures,
    required this.attestedAt,
    required this.createdAt,
    this.expiresAt,
    this.revokedAt,
  });

  Claim copyWith({
    String? claimId,
    String? userId,
    String? claimType,
    Uint8List? claimValue,
    List<ClaimSignature>? signatures,
    String? attestedAt,
    String? createdAt,
    Object? expiresAt = _sentinel,
    Object? revokedAt = _sentinel,
  }) {
    return Claim(
      claimId: claimId ?? this.claimId,
      userId: userId ?? this.userId,
      claimType: claimType ?? this.claimType,
      claimValue: claimValue ?? this.claimValue,
      signatures: signatures ?? this.signatures,
      attestedAt: attestedAt ?? this.attestedAt,
      createdAt: createdAt ?? this.createdAt,
      expiresAt: identical(expiresAt, _sentinel)
          ? this.expiresAt
          : expiresAt as String?,
      revokedAt: identical(revokedAt, _sentinel)
          ? this.revokedAt
          : revokedAt as String?,
    );
  }
}

class LocalRpDescriptor {
  final String appName;
  final String? localDomainHint;
  final Uint8List signingPublicKey;
  final Uint8List encryptionPublicKey;
  final String fingerprint;
  final List<String> supportedSuites;
  final String createdAt;
  final String expiresAt;

  const LocalRpDescriptor({
    required this.appName,
    this.localDomainHint,
    required this.signingPublicKey,
    required this.encryptionPublicKey,
    required this.fingerprint,
    required this.supportedSuites,
    required this.createdAt,
    required this.expiresAt,
  });
}

class SignedLocalRpDescriptor {
  final Uint8List descriptor;
  final Uint8List signature;
  const SignedLocalRpDescriptor(
      {required this.descriptor, required this.signature});
}

class LocalRpLoginRequest {
  final SignedLocalRpDescriptor descriptor;
  final String callbackUrl;
  final Uint8List nonce;
  final Uint8List state;
  final List<String> requestedClaims;
  final List<String> requiredClaims;
  final String issuedAt;
  final String expiresAt;

  const LocalRpLoginRequest({
    required this.descriptor,
    required this.callbackUrl,
    required this.nonce,
    required this.state,
    required this.requestedClaims,
    required this.requiredClaims,
    required this.issuedAt,
    required this.expiresAt,
  });
}

class SignedLocalRpLoginRequest {
  final Uint8List request;
  final Uint8List signature;
  const SignedLocalRpLoginRequest(
      {required this.request, required this.signature});
}

class LocalRpCallbackHeader {
  final String fingerprint;
  final Uint8List nonce;
  final Uint8List state;
  final String suite;
  final Uint8List ephemeralPublicKey;
  final Uint8List aeadNonce;
  final String issuedAt;
  final String expiresAt;

  const LocalRpCallbackHeader({
    required this.fingerprint,
    required this.nonce,
    required this.state,
    required this.suite,
    required this.ephemeralPublicKey,
    required this.aeadNonce,
    required this.issuedAt,
    required this.expiresAt,
  });
}

class LocalRpEncryptedCallback {
  final Uint8List header;
  final Uint8List ciphertext;
  const LocalRpEncryptedCallback(
      {required this.header, required this.ciphertext});
}

class LocalRpCallbackPayload {
  final String userId;
  final String userDomain;
  final Uint8List claimTicket;
  final String audienceFingerprint;
  final String callbackUrl;
  final Uint8List nonce;
  final Uint8List state;
  final String issuedAt;
  final String expiresAt;

  const LocalRpCallbackPayload({
    required this.userId,
    required this.userDomain,
    required this.claimTicket,
    required this.audienceFingerprint,
    required this.callbackUrl,
    required this.nonce,
    required this.state,
    required this.issuedAt,
    required this.expiresAt,
  });
}

class SignedLocalRpCallbackPayload {
  final Uint8List payload;
  final String signingKeyId;
  final Uint8List signature;

  const SignedLocalRpCallbackPayload({
    required this.payload,
    required this.signingKeyId,
    required this.signature,
  });
}

class LocalRpTicketRedemptionRequest {
  final Uint8List claimTicket;
  final String fingerprint;
  final String issuedAt;

  const LocalRpTicketRedemptionRequest({
    required this.claimTicket,
    required this.fingerprint,
    required this.issuedAt,
  });
}

class SignedLocalRpTicketRedemptionRequest {
  final Uint8List request;
  final Uint8List signature;
  const SignedLocalRpTicketRedemptionRequest(
      {required this.request, required this.signature});
}

class LocalRpTicketRedemptionResponse {
  final String userId;
  final String userDomain;
  final List<Claim> claims;
  final String ticketExpiresAt;

  const LocalRpTicketRedemptionResponse({
    required this.userId,
    required this.userDomain,
    required this.claims,
    required this.ticketExpiresAt,
  });
}
