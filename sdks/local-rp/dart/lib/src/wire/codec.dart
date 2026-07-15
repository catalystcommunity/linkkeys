// Canonical CSIL CBOR encode/decode for every `types.dart` wire structure
// this SDK needs. Hand-written, pending a csilgen Dart target -- see
// `cbor.dart`'s library docs. Field order within each map is irrelevant (the
// [Cbor] encoder always sorts to RFC 8949 canonical order), so this file
// lists fields in natural struct order rather than hand-tracking the
// canonical order the Go/Rust generators bake in at codegen time.
library;

import 'dart:typed_data';

import 'cbor.dart';
import 'types.dart';

class Codec {
  Codec._();

  // -----------------------------------------------------------------
  // EmptyRequest
  // -----------------------------------------------------------------

  static Uint8List encodeEmptyRequest(EmptyRequest v) =>
      Cbor.encode(Cbor.vmap(const []));

  static EmptyRequest decodeEmptyRequest(Uint8List data) {
    Cbor.decode(data);
    return const EmptyRequest();
  }

  // -----------------------------------------------------------------
  // DomainPublicKey
  // -----------------------------------------------------------------

  static CborValue _encDomainPublicKey(DomainPublicKey v) {
    final e = <CborMapEntry>[];
    Cbor.putText(e, 'key_id', v.keyId);
    Cbor.putBytes(e, 'public_key', v.publicKey);
    Cbor.putText(e, 'fingerprint', v.fingerprint);
    Cbor.putText(e, 'algorithm', v.algorithm);
    Cbor.putText(e, 'key_usage', v.keyUsage);
    Cbor.putText(e, 'created_at', v.createdAt);
    Cbor.putText(e, 'expires_at', v.expiresAt);
    Cbor.putOptText(e, 'revoked_at', v.revokedAt);
    Cbor.putOptText(e, 'signed_by_key_id', v.signedByKeyId);
    Cbor.putOptBytes(e, 'key_signature', v.keySignature);
    return Cbor.vmap(e);
  }

  static DomainPublicKey _decDomainPublicKey(CborValue m) {
    return DomainPublicKey(
      keyId: Cbor.requireText(m, 'key_id'),
      publicKey: Cbor.requireBytes(m, 'public_key'),
      fingerprint: Cbor.requireText(m, 'fingerprint'),
      algorithm: Cbor.requireText(m, 'algorithm'),
      keyUsage: Cbor.requireText(m, 'key_usage'),
      createdAt: Cbor.requireText(m, 'created_at'),
      expiresAt: Cbor.requireText(m, 'expires_at'),
      revokedAt: Cbor.optText(m, 'revoked_at'),
      signedByKeyId: Cbor.optText(m, 'signed_by_key_id'),
      keySignature: Cbor.optBytes(m, 'key_signature'),
    );
  }

  static Uint8List encodeDomainPublicKey(DomainPublicKey v) =>
      Cbor.encode(_encDomainPublicKey(v));

  static DomainPublicKey decodeDomainPublicKey(Uint8List data) =>
      _decDomainPublicKey(Cbor.decode(data));

  // -----------------------------------------------------------------
  // GetDomainKeysResponse
  // -----------------------------------------------------------------

  static Uint8List encodeGetDomainKeysResponse(GetDomainKeysResponse v) {
    final e = <CborMapEntry>[];
    Cbor.putText(e, 'domain', v.domain);
    e.add(Cbor.entry(
        'keys', Cbor.varray(v.keys.map(_encDomainPublicKey).toList())));
    Cbor.putOptBool(
        e, 'recent_revocations_available', v.recentRevocationsAvailable);
    return Cbor.encode(Cbor.vmap(e));
  }

  static GetDomainKeysResponse decodeGetDomainKeysResponse(Uint8List data) {
    final m = Cbor.decode(data);
    return GetDomainKeysResponse(
      domain: Cbor.requireText(m, 'domain'),
      keys: Cbor.asArray(Cbor.require(m, 'keys'))
          .map(_decDomainPublicKey)
          .toList(),
      recentRevocationsAvailable:
          Cbor.optBool(m, 'recent_revocations_available'),
    );
  }

  // -----------------------------------------------------------------
  // GetRevocationsRequest / GetRevocationsResponse
  // -----------------------------------------------------------------

  static Uint8List encodeGetRevocationsRequest(GetRevocationsRequest v) {
    final e = <CborMapEntry>[];
    Cbor.putOptText(e, 'since', v.since);
    return Cbor.encode(Cbor.vmap(e));
  }

  static GetRevocationsRequest decodeGetRevocationsRequest(Uint8List data) {
    final m = Cbor.decode(data);
    return GetRevocationsRequest(since: Cbor.optText(m, 'since'));
  }

  static CborValue _encClaimSignature(ClaimSignature v) {
    final e = <CborMapEntry>[];
    Cbor.putText(e, 'domain', v.domain);
    Cbor.putText(e, 'signed_by_key_id', v.signedByKeyId);
    Cbor.putBytes(e, 'signature', v.signature);
    return Cbor.vmap(e);
  }

  static ClaimSignature _decClaimSignature(CborValue m) {
    return ClaimSignature(
      domain: Cbor.requireText(m, 'domain'),
      signedByKeyId: Cbor.requireText(m, 'signed_by_key_id'),
      signature: Cbor.requireBytes(m, 'signature'),
    );
  }

  static CborValue _encRevocationCertificate(RevocationCertificate v) {
    final e = <CborMapEntry>[];
    Cbor.putText(e, 'target_key_id', v.targetKeyId);
    Cbor.putText(e, 'target_fingerprint', v.targetFingerprint);
    Cbor.putText(e, 'revoked_at', v.revokedAt);
    e.add(Cbor.entry('signatures',
        Cbor.varray(v.signatures.map(_encClaimSignature).toList())));
    return Cbor.vmap(e);
  }

  static RevocationCertificate _decRevocationCertificate(CborValue m) {
    return RevocationCertificate(
      targetKeyId: Cbor.requireText(m, 'target_key_id'),
      targetFingerprint: Cbor.requireText(m, 'target_fingerprint'),
      revokedAt: Cbor.requireText(m, 'revoked_at'),
      signatures: Cbor.asArray(Cbor.require(m, 'signatures'))
          .map(_decClaimSignature)
          .toList(),
    );
  }

  static Uint8List encodeGetRevocationsResponse(GetRevocationsResponse v) {
    final e = <CborMapEntry>[];
    e.add(Cbor.entry('revocations',
        Cbor.varray(v.revocations.map(_encRevocationCertificate).toList())));
    return Cbor.encode(Cbor.vmap(e));
  }

  static GetRevocationsResponse decodeGetRevocationsResponse(Uint8List data) {
    final m = Cbor.decode(data);
    return GetRevocationsResponse(
      revocations: Cbor.asArray(Cbor.require(m, 'revocations'))
          .map(_decRevocationCertificate)
          .toList(),
    );
  }

  // -----------------------------------------------------------------
  // Claim
  // -----------------------------------------------------------------

  static CborValue _encClaim(Claim v) {
    final e = <CborMapEntry>[];
    Cbor.putText(e, 'claim_id', v.claimId);
    Cbor.putText(e, 'user_id', v.userId);
    Cbor.putText(e, 'claim_type', v.claimType);
    Cbor.putBytes(e, 'claim_value', v.claimValue);
    e.add(Cbor.entry('signatures',
        Cbor.varray(v.signatures.map(_encClaimSignature).toList())));
    Cbor.putText(e, 'attested_at', v.attestedAt);
    Cbor.putText(e, 'created_at', v.createdAt);
    Cbor.putOptText(e, 'expires_at', v.expiresAt);
    Cbor.putOptText(e, 'revoked_at', v.revokedAt);
    return Cbor.vmap(e);
  }

  static Claim _decClaim(CborValue m) {
    return Claim(
      claimId: Cbor.requireText(m, 'claim_id'),
      userId: Cbor.requireText(m, 'user_id'),
      claimType: Cbor.requireText(m, 'claim_type'),
      claimValue: Cbor.requireBytes(m, 'claim_value'),
      signatures: Cbor.asArray(Cbor.require(m, 'signatures'))
          .map(_decClaimSignature)
          .toList(),
      attestedAt: Cbor.requireText(m, 'attested_at'),
      createdAt: Cbor.requireText(m, 'created_at'),
      expiresAt: Cbor.optText(m, 'expires_at'),
      revokedAt: Cbor.optText(m, 'revoked_at'),
    );
  }

  static Uint8List encodeClaim(Claim v) => Cbor.encode(_encClaim(v));

  static Claim decodeClaim(Uint8List data) => _decClaim(Cbor.decode(data));

  // -----------------------------------------------------------------
  // LocalRpDescriptor / SignedLocalRpDescriptor
  // -----------------------------------------------------------------

  static CborValue _encLocalRpDescriptor(LocalRpDescriptor v) {
    final e = <CborMapEntry>[];
    Cbor.putText(e, 'app_name', v.appName);
    Cbor.putOptText(e, 'local_domain_hint', v.localDomainHint);
    Cbor.putBytes(e, 'signing_public_key', v.signingPublicKey);
    Cbor.putBytes(e, 'encryption_public_key', v.encryptionPublicKey);
    Cbor.putText(e, 'fingerprint', v.fingerprint);
    e.add(Cbor.entry('supported_suites',
        Cbor.varray(v.supportedSuites.map(Cbor.vtext).toList())));
    Cbor.putText(e, 'created_at', v.createdAt);
    Cbor.putText(e, 'expires_at', v.expiresAt);
    return Cbor.vmap(e);
  }

  static LocalRpDescriptor _decLocalRpDescriptor(CborValue m) {
    final suites = Cbor.asArray(Cbor.require(m, 'supported_suites'));
    return LocalRpDescriptor(
      appName: Cbor.requireText(m, 'app_name'),
      localDomainHint: Cbor.optText(m, 'local_domain_hint'),
      signingPublicKey: Cbor.requireBytes(m, 'signing_public_key'),
      encryptionPublicKey: Cbor.requireBytes(m, 'encryption_public_key'),
      fingerprint: Cbor.requireText(m, 'fingerprint'),
      supportedSuites: suites.map(Cbor.asText).toList(),
      createdAt: Cbor.requireText(m, 'created_at'),
      expiresAt: Cbor.requireText(m, 'expires_at'),
    );
  }

  static Uint8List encodeLocalRpDescriptor(LocalRpDescriptor v) =>
      Cbor.encode(_encLocalRpDescriptor(v));

  static LocalRpDescriptor decodeLocalRpDescriptor(Uint8List data) =>
      _decLocalRpDescriptor(Cbor.decode(data));

  static CborValue _encSignedLocalRpDescriptor(SignedLocalRpDescriptor v) {
    final e = <CborMapEntry>[];
    Cbor.putBytes(e, 'descriptor', v.descriptor);
    Cbor.putBytes(e, 'signature', v.signature);
    return Cbor.vmap(e);
  }

  static SignedLocalRpDescriptor _decSignedLocalRpDescriptor(CborValue m) {
    return SignedLocalRpDescriptor(
      descriptor: Cbor.requireBytes(m, 'descriptor'),
      signature: Cbor.requireBytes(m, 'signature'),
    );
  }

  static Uint8List encodeSignedLocalRpDescriptor(SignedLocalRpDescriptor v) =>
      Cbor.encode(_encSignedLocalRpDescriptor(v));

  static SignedLocalRpDescriptor decodeSignedLocalRpDescriptor(
          Uint8List data) =>
      _decSignedLocalRpDescriptor(Cbor.decode(data));

  // -----------------------------------------------------------------
  // LocalRpLoginRequest / SignedLocalRpLoginRequest
  // -----------------------------------------------------------------

  static CborValue _encLocalRpLoginRequest(LocalRpLoginRequest v) {
    final e = <CborMapEntry>[];
    e.add(Cbor.entry('descriptor', _encSignedLocalRpDescriptor(v.descriptor)));
    Cbor.putText(e, 'callback_url', v.callbackUrl);
    Cbor.putBytes(e, 'nonce', v.nonce);
    Cbor.putBytes(e, 'state', v.state);
    e.add(Cbor.entry('requested_claims',
        Cbor.varray(v.requestedClaims.map(Cbor.vtext).toList())));
    e.add(Cbor.entry('required_claims',
        Cbor.varray(v.requiredClaims.map(Cbor.vtext).toList())));
    Cbor.putText(e, 'issued_at', v.issuedAt);
    Cbor.putText(e, 'expires_at', v.expiresAt);
    return Cbor.vmap(e);
  }

  static LocalRpLoginRequest _decLocalRpLoginRequest(CborValue m) {
    return LocalRpLoginRequest(
      descriptor: _decSignedLocalRpDescriptor(Cbor.require(m, 'descriptor')),
      callbackUrl: Cbor.requireText(m, 'callback_url'),
      nonce: Cbor.requireBytes(m, 'nonce'),
      state: Cbor.requireBytes(m, 'state'),
      requestedClaims: Cbor.asArray(Cbor.require(m, 'requested_claims'))
          .map(Cbor.asText)
          .toList(),
      requiredClaims: Cbor.asArray(Cbor.require(m, 'required_claims'))
          .map(Cbor.asText)
          .toList(),
      issuedAt: Cbor.requireText(m, 'issued_at'),
      expiresAt: Cbor.requireText(m, 'expires_at'),
    );
  }

  static Uint8List encodeLocalRpLoginRequest(LocalRpLoginRequest v) =>
      Cbor.encode(_encLocalRpLoginRequest(v));

  static LocalRpLoginRequest decodeLocalRpLoginRequest(Uint8List data) =>
      _decLocalRpLoginRequest(Cbor.decode(data));

  static CborValue _encSignedLocalRpLoginRequest(SignedLocalRpLoginRequest v) {
    final e = <CborMapEntry>[];
    Cbor.putBytes(e, 'request', v.request);
    Cbor.putBytes(e, 'signature', v.signature);
    return Cbor.vmap(e);
  }

  static SignedLocalRpLoginRequest _decSignedLocalRpLoginRequest(CborValue m) {
    return SignedLocalRpLoginRequest(
      request: Cbor.requireBytes(m, 'request'),
      signature: Cbor.requireBytes(m, 'signature'),
    );
  }

  static Uint8List encodeSignedLocalRpLoginRequest(
          SignedLocalRpLoginRequest v) =>
      Cbor.encode(_encSignedLocalRpLoginRequest(v));

  static SignedLocalRpLoginRequest decodeSignedLocalRpLoginRequest(
          Uint8List data) =>
      _decSignedLocalRpLoginRequest(Cbor.decode(data));

  // -----------------------------------------------------------------
  // LocalRpCallbackHeader / LocalRpEncryptedCallback
  // -----------------------------------------------------------------

  static CborValue _encLocalRpCallbackHeader(LocalRpCallbackHeader v) {
    final e = <CborMapEntry>[];
    Cbor.putText(e, 'fingerprint', v.fingerprint);
    Cbor.putBytes(e, 'nonce', v.nonce);
    Cbor.putBytes(e, 'state', v.state);
    Cbor.putText(e, 'suite', v.suite);
    Cbor.putBytes(e, 'ephemeral_public_key', v.ephemeralPublicKey);
    Cbor.putBytes(e, 'aead_nonce', v.aeadNonce);
    Cbor.putText(e, 'issued_at', v.issuedAt);
    Cbor.putText(e, 'expires_at', v.expiresAt);
    return Cbor.vmap(e);
  }

  static LocalRpCallbackHeader _decLocalRpCallbackHeader(CborValue m) {
    return LocalRpCallbackHeader(
      fingerprint: Cbor.requireText(m, 'fingerprint'),
      nonce: Cbor.requireBytes(m, 'nonce'),
      state: Cbor.requireBytes(m, 'state'),
      suite: Cbor.requireText(m, 'suite'),
      ephemeralPublicKey: Cbor.requireBytes(m, 'ephemeral_public_key'),
      aeadNonce: Cbor.requireBytes(m, 'aead_nonce'),
      issuedAt: Cbor.requireText(m, 'issued_at'),
      expiresAt: Cbor.requireText(m, 'expires_at'),
    );
  }

  static Uint8List encodeLocalRpCallbackHeader(LocalRpCallbackHeader v) =>
      Cbor.encode(_encLocalRpCallbackHeader(v));

  static LocalRpCallbackHeader decodeLocalRpCallbackHeader(Uint8List data) =>
      _decLocalRpCallbackHeader(Cbor.decode(data));

  static CborValue _encLocalRpEncryptedCallback(LocalRpEncryptedCallback v) {
    final e = <CborMapEntry>[];
    Cbor.putBytes(e, 'header', v.header);
    Cbor.putBytes(e, 'ciphertext', v.ciphertext);
    return Cbor.vmap(e);
  }

  static LocalRpEncryptedCallback _decLocalRpEncryptedCallback(CborValue m) {
    return LocalRpEncryptedCallback(
      header: Cbor.requireBytes(m, 'header'),
      ciphertext: Cbor.requireBytes(m, 'ciphertext'),
    );
  }

  static Uint8List encodeLocalRpEncryptedCallback(LocalRpEncryptedCallback v) =>
      Cbor.encode(_encLocalRpEncryptedCallback(v));

  static LocalRpEncryptedCallback decodeLocalRpEncryptedCallback(
          Uint8List data) =>
      _decLocalRpEncryptedCallback(Cbor.decode(data));

  // -----------------------------------------------------------------
  // LocalRpCallbackPayload / SignedLocalRpCallbackPayload
  // -----------------------------------------------------------------

  static CborValue _encLocalRpCallbackPayload(LocalRpCallbackPayload v) {
    final e = <CborMapEntry>[];
    Cbor.putText(e, 'user_id', v.userId);
    Cbor.putText(e, 'user_domain', v.userDomain);
    Cbor.putBytes(e, 'claim_ticket', v.claimTicket);
    Cbor.putText(e, 'audience_fingerprint', v.audienceFingerprint);
    Cbor.putText(e, 'callback_url', v.callbackUrl);
    Cbor.putBytes(e, 'nonce', v.nonce);
    Cbor.putBytes(e, 'state', v.state);
    Cbor.putText(e, 'issued_at', v.issuedAt);
    Cbor.putText(e, 'expires_at', v.expiresAt);
    return Cbor.vmap(e);
  }

  static LocalRpCallbackPayload _decLocalRpCallbackPayload(CborValue m) {
    return LocalRpCallbackPayload(
      userId: Cbor.requireText(m, 'user_id'),
      userDomain: Cbor.requireText(m, 'user_domain'),
      claimTicket: Cbor.requireBytes(m, 'claim_ticket'),
      audienceFingerprint: Cbor.requireText(m, 'audience_fingerprint'),
      callbackUrl: Cbor.requireText(m, 'callback_url'),
      nonce: Cbor.requireBytes(m, 'nonce'),
      state: Cbor.requireBytes(m, 'state'),
      issuedAt: Cbor.requireText(m, 'issued_at'),
      expiresAt: Cbor.requireText(m, 'expires_at'),
    );
  }

  static Uint8List encodeLocalRpCallbackPayload(LocalRpCallbackPayload v) =>
      Cbor.encode(_encLocalRpCallbackPayload(v));

  static LocalRpCallbackPayload decodeLocalRpCallbackPayload(Uint8List data) =>
      _decLocalRpCallbackPayload(Cbor.decode(data));

  static CborValue _encSignedLocalRpCallbackPayload(
      SignedLocalRpCallbackPayload v) {
    final e = <CborMapEntry>[];
    Cbor.putBytes(e, 'payload', v.payload);
    Cbor.putText(e, 'signing_key_id', v.signingKeyId);
    Cbor.putBytes(e, 'signature', v.signature);
    return Cbor.vmap(e);
  }

  static SignedLocalRpCallbackPayload _decSignedLocalRpCallbackPayload(
      CborValue m) {
    return SignedLocalRpCallbackPayload(
      payload: Cbor.requireBytes(m, 'payload'),
      signingKeyId: Cbor.requireText(m, 'signing_key_id'),
      signature: Cbor.requireBytes(m, 'signature'),
    );
  }

  static Uint8List encodeSignedLocalRpCallbackPayload(
          SignedLocalRpCallbackPayload v) =>
      Cbor.encode(_encSignedLocalRpCallbackPayload(v));

  static SignedLocalRpCallbackPayload decodeSignedLocalRpCallbackPayload(
          Uint8List data) =>
      _decSignedLocalRpCallbackPayload(Cbor.decode(data));

  // -----------------------------------------------------------------
  // LocalRpTicketRedemptionRequest / SignedLocalRpTicketRedemptionRequest
  // -----------------------------------------------------------------

  static CborValue _encLocalRpTicketRedemptionRequest(
      LocalRpTicketRedemptionRequest v) {
    final e = <CborMapEntry>[];
    Cbor.putBytes(e, 'claim_ticket', v.claimTicket);
    Cbor.putText(e, 'fingerprint', v.fingerprint);
    Cbor.putText(e, 'issued_at', v.issuedAt);
    return Cbor.vmap(e);
  }

  static LocalRpTicketRedemptionRequest _decLocalRpTicketRedemptionRequest(
      CborValue m) {
    return LocalRpTicketRedemptionRequest(
      claimTicket: Cbor.requireBytes(m, 'claim_ticket'),
      fingerprint: Cbor.requireText(m, 'fingerprint'),
      issuedAt: Cbor.requireText(m, 'issued_at'),
    );
  }

  static Uint8List encodeLocalRpTicketRedemptionRequest(
          LocalRpTicketRedemptionRequest v) =>
      Cbor.encode(_encLocalRpTicketRedemptionRequest(v));

  static LocalRpTicketRedemptionRequest decodeLocalRpTicketRedemptionRequest(
          Uint8List data) =>
      _decLocalRpTicketRedemptionRequest(Cbor.decode(data));

  static CborValue _encSignedLocalRpTicketRedemptionRequest(
      SignedLocalRpTicketRedemptionRequest v) {
    final e = <CborMapEntry>[];
    Cbor.putBytes(e, 'request', v.request);
    Cbor.putBytes(e, 'signature', v.signature);
    return Cbor.vmap(e);
  }

  static SignedLocalRpTicketRedemptionRequest
      _decSignedLocalRpTicketRedemptionRequest(CborValue m) {
    return SignedLocalRpTicketRedemptionRequest(
      request: Cbor.requireBytes(m, 'request'),
      signature: Cbor.requireBytes(m, 'signature'),
    );
  }

  static Uint8List encodeSignedLocalRpTicketRedemptionRequest(
          SignedLocalRpTicketRedemptionRequest v) =>
      Cbor.encode(_encSignedLocalRpTicketRedemptionRequest(v));

  static SignedLocalRpTicketRedemptionRequest
      decodeSignedLocalRpTicketRedemptionRequest(Uint8List data) =>
          _decSignedLocalRpTicketRedemptionRequest(Cbor.decode(data));

  // -----------------------------------------------------------------
  // LocalRpTicketRedemptionResponse
  // -----------------------------------------------------------------

  static CborValue _encLocalRpTicketRedemptionResponse(
      LocalRpTicketRedemptionResponse v) {
    final e = <CborMapEntry>[];
    Cbor.putText(e, 'user_id', v.userId);
    Cbor.putText(e, 'user_domain', v.userDomain);
    e.add(Cbor.entry('claims', Cbor.varray(v.claims.map(_encClaim).toList())));
    Cbor.putText(e, 'ticket_expires_at', v.ticketExpiresAt);
    return Cbor.vmap(e);
  }

  static LocalRpTicketRedemptionResponse _decLocalRpTicketRedemptionResponse(
      CborValue m) {
    return LocalRpTicketRedemptionResponse(
      userId: Cbor.requireText(m, 'user_id'),
      userDomain: Cbor.requireText(m, 'user_domain'),
      claims: Cbor.asArray(Cbor.require(m, 'claims')).map(_decClaim).toList(),
      ticketExpiresAt: Cbor.requireText(m, 'ticket_expires_at'),
    );
  }

  static Uint8List encodeLocalRpTicketRedemptionResponse(
          LocalRpTicketRedemptionResponse v) =>
      Cbor.encode(_encLocalRpTicketRedemptionResponse(v));

  static LocalRpTicketRedemptionResponse decodeLocalRpTicketRedemptionResponse(
          Uint8List data) =>
      _decLocalRpTicketRedemptionResponse(Cbor.decode(data));
}
