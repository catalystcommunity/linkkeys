// Act-as grant wire types and their canonical CBOR codecs
// (`csil/linkkeys.csil`, "Act-as grants";
// `docs/spec/reserved/act-as-grants.md`). Hand-written, like the rest of
// `lib/src/wire/`, pending a csilgen Dart target. Field order inside each
// map does not matter: [Cbor.encode] always sorts keys to RFC 8949 canonical
// order. Optional fields are omitted when absent, exactly as the generated
// Rust codec does.
//
// Only the grantee side of the protocol is here. A local RP can never be an
// audience, so the SDK never decodes a scope set or a grant beyond the
// envelope it embeds or hashes.
library;

import 'dart:typed_data';

import 'cbor.dart';
import 'codec.dart';
import 'types.dart';

/// An application, as an application-key attestation binds it.
class ApplicationRef {
  final String subjectUserId;
  final String subjectDomain;
  final String applicationId;
  const ApplicationRef({
    required this.subjectUserId,
    required this.subjectDomain,
    required this.applicationId,
  });
}

/// The party that can act. Exactly one field is present. This SDK always
/// builds the local-RP form.
class GranteeRef {
  final ApplicationRef? application;
  final String? localRpDescriptorFingerprint;
  const GranteeRef({this.application, this.localRpDescriptorFingerprint});
}

/// One signature by an application key, or by a local RP's descriptor
/// signing key (then `signedByKeyId` is the descriptor fingerprint).
class ApplicationKeySignature {
  final String signedByKeyId;
  final Uint8List signature;
  const ApplicationKeySignature(
      {required this.signedByKeyId, required this.signature});
}

/// Proof that a grantee key signed something.
class GranteeProof {
  final String? applicationInstanceId;
  final SignedLocalRpDescriptor? localRpDescriptor;
  final ApplicationKeySignature signature;
  const GranteeProof({
    this.applicationInstanceId,
    this.localRpDescriptor,
    required this.signature,
  });
}

/// The audience's signed scope set. `scopeSet` is the exact CBOR of an
/// `ActAsScopeSet`; the SDK embeds it unchanged.
class SignedActAsScopeSet {
  final Uint8List scopeSet;
  final String signerInstanceId;

  /// One or more signatures by the audience instance's keys. One valid
  /// signature is enough for a verifier.
  final List<ApplicationKeySignature> signatures;
  const SignedActAsScopeSet({
    required this.scopeSet,
    required this.signerInstanceId,
    required this.signatures,
  });
}

/// A local RP never sends the optional `grantee_handle_claim` (it has no
/// enrolling account), so this class does not carry it and the encoder always
/// omits it.
class ActAsGrantRequest {
  final GranteeRef grantee;
  final SignedActAsScopeSet scopeSet;
  final int? requestedLifetimeSeconds;
  final int? requestedRenewalWindowSeconds;
  final String callbackUrl;
  final String nonce;
  final String requestedAt;
  final String expiresAt;
  const ActAsGrantRequest({
    required this.grantee,
    required this.scopeSet,
    this.requestedLifetimeSeconds,
    this.requestedRenewalWindowSeconds,
    required this.callbackUrl,
    required this.nonce,
    required this.requestedAt,
    required this.expiresAt,
  });
}

class SignedActAsGrantRequest {
  final Uint8List request;
  final GranteeProof proof;
  const SignedActAsGrantRequest({required this.request, required this.proof});
}

class ActAsRefreshRequest {
  final String grantId;
  final GranteeRef grantee;
  final String requestedAt;
  final String expiresAt;
  final String nonce;
  const ActAsRefreshRequest({
    required this.grantId,
    required this.grantee,
    required this.requestedAt,
    required this.expiresAt,
    required this.nonce,
  });
}

class SignedActAsRefreshRequest {
  final Uint8List request;
  final GranteeProof proof;
  const SignedActAsRefreshRequest({required this.request, required this.proof});
}

class RefreshActAsGrantRequest {
  final SignedActAsRefreshRequest request;
  const RefreshActAsGrantRequest(this.request);
}

/// A grant as the home domain signed it. `grant` is the exact CBOR of an
/// `ActAsGrant`; the SDK keeps it as bytes.
class SignedActAsGrant {
  final Uint8List grant;
  final List<ClaimSignature> signatures;
  const SignedActAsGrant({required this.grant, required this.signatures});
}

class RefreshActAsGrantResponse {
  final SignedActAsGrant grant;

  /// True when the home domain made a new signature for this call.
  final bool signed;
  const RefreshActAsGrantResponse({required this.grant, required this.signed});
}

class ActAsPresentation {
  final Uint8List grantHash;
  final ApplicationRef audience;
  final Uint8List requestDigest;
  final String presentedAt;
  final Uint8List nonce;
  const ActAsPresentation({
    required this.grantHash,
    required this.audience,
    required this.requestDigest,
    required this.presentedAt,
    required this.nonce,
  });
}

class SignedActAsPresentation {
  final Uint8List presentation;
  final GranteeProof proof;
  const SignedActAsPresentation(
      {required this.presentation, required this.proof});
}

/// What the grantee sends the audience with each call.
class ActAsCredential {
  final SignedActAsGrant grant;
  final SignedActAsPresentation presentation;
  const ActAsCredential({required this.grant, required this.presentation});
}

/// Canonical CBOR encode/decode for the act-as wire types.
class ActAsCodec {
  ActAsCodec._();

  // -- shared pieces --------------------------------------------------

  static CborValue _encApplicationRef(ApplicationRef v) {
    final e = <CborMapEntry>[];
    Cbor.putText(e, 'subject_user_id', v.subjectUserId);
    Cbor.putText(e, 'subject_domain', v.subjectDomain);
    Cbor.putText(e, 'application_id', v.applicationId);
    return Cbor.vmap(e);
  }

  static ApplicationRef _decApplicationRef(CborValue m) => ApplicationRef(
        subjectUserId: Cbor.requireText(m, 'subject_user_id'),
        subjectDomain: Cbor.requireText(m, 'subject_domain'),
        applicationId: Cbor.requireText(m, 'application_id'),
      );

  static CborValue _encGranteeRef(GranteeRef v) {
    final e = <CborMapEntry>[];
    if (v.application != null) {
      e.add(Cbor.entry('application', _encApplicationRef(v.application!)));
    }
    Cbor.putOptText(
        e, 'local_rp_descriptor_fingerprint', v.localRpDescriptorFingerprint);
    return Cbor.vmap(e);
  }

  static GranteeRef _decGranteeRef(CborValue m) {
    final app = Cbor.mapGet(m, 'application');
    return GranteeRef(
      application: app == null ? null : _decApplicationRef(app),
      localRpDescriptorFingerprint:
          Cbor.optText(m, 'local_rp_descriptor_fingerprint'),
    );
  }

  static CborValue _encApplicationKeySignature(ApplicationKeySignature v) {
    final e = <CborMapEntry>[];
    Cbor.putText(e, 'signed_by_key_id', v.signedByKeyId);
    Cbor.putBytes(e, 'signature', v.signature);
    return Cbor.vmap(e);
  }

  static ApplicationKeySignature _decApplicationKeySignature(CborValue m) =>
      ApplicationKeySignature(
        signedByKeyId: Cbor.requireText(m, 'signed_by_key_id'),
        signature: Cbor.requireBytes(m, 'signature'),
      );

  static CborValue _encGranteeProof(GranteeProof v) {
    final e = <CborMapEntry>[];
    Cbor.putOptText(e, 'application_instance_id', v.applicationInstanceId);
    if (v.localRpDescriptor != null) {
      // Re-use the main codec's encoding of the descriptor envelope so the
      // two can never drift apart.
      e.add(Cbor.entry(
          'local_rp_descriptor',
          Cbor.decode(
              Codec.encodeSignedLocalRpDescriptor(v.localRpDescriptor!))));
    }
    e.add(Cbor.entry('signature', _encApplicationKeySignature(v.signature)));
    return Cbor.vmap(e);
  }

  static GranteeProof _decGranteeProof(CborValue m) {
    final desc = Cbor.mapGet(m, 'local_rp_descriptor');
    return GranteeProof(
      applicationInstanceId: Cbor.optText(m, 'application_instance_id'),
      localRpDescriptor: desc == null
          ? null
          : Codec.decodeSignedLocalRpDescriptor(Cbor.encode(desc)),
      signature: _decApplicationKeySignature(Cbor.require(m, 'signature')),
    );
  }

  static CborValue _encClaimSignature(ClaimSignature v) {
    final e = <CborMapEntry>[];
    Cbor.putText(e, 'domain', v.domain);
    Cbor.putText(e, 'signed_by_key_id', v.signedByKeyId);
    Cbor.putBytes(e, 'signature', v.signature);
    return Cbor.vmap(e);
  }

  static ClaimSignature _decClaimSignature(CborValue m) => ClaimSignature(
        domain: Cbor.requireText(m, 'domain'),
        signedByKeyId: Cbor.requireText(m, 'signed_by_key_id'),
        signature: Cbor.requireBytes(m, 'signature'),
      );

  // -- SignedActAsScopeSet --------------------------------------------

  static CborValue _encSignedActAsScopeSet(SignedActAsScopeSet v) {
    final e = <CborMapEntry>[];
    Cbor.putBytes(e, 'scope_set', v.scopeSet);
    Cbor.putText(e, 'signer_instance_id', v.signerInstanceId);
    e.add(Cbor.entry('signatures',
        Cbor.varray(v.signatures.map(_encApplicationKeySignature).toList())));
    return Cbor.vmap(e);
  }

  static SignedActAsScopeSet _decSignedActAsScopeSet(CborValue m) {
    final signatures = Cbor.asArray(Cbor.require(m, 'signatures'))
        .map(_decApplicationKeySignature)
        .toList();
    if (signatures.isEmpty) {
      throw CborDecodeException('SignedActAsScopeSet.signatures is empty');
    }
    return SignedActAsScopeSet(
      scopeSet: Cbor.requireBytes(m, 'scope_set'),
      signerInstanceId: Cbor.requireText(m, 'signer_instance_id'),
      signatures: signatures,
    );
  }

  static Uint8List encodeSignedActAsScopeSet(SignedActAsScopeSet v) =>
      Cbor.encode(_encSignedActAsScopeSet(v));

  static SignedActAsScopeSet decodeSignedActAsScopeSet(Uint8List data) =>
      _decSignedActAsScopeSet(Cbor.decode(data));

  // -- ActAsGrantRequest / SignedActAsGrantRequest --------------------

  static Uint8List encodeActAsGrantRequest(ActAsGrantRequest v) {
    final e = <CborMapEntry>[];
    e.add(Cbor.entry('grantee', _encGranteeRef(v.grantee)));
    e.add(Cbor.entry('scope_set', _encSignedActAsScopeSet(v.scopeSet)));
    if (v.requestedLifetimeSeconds != null) {
      e.add(Cbor.entry('requested_lifetime_seconds',
          Cbor.vint(v.requestedLifetimeSeconds!)));
    }
    if (v.requestedRenewalWindowSeconds != null) {
      e.add(Cbor.entry('requested_renewal_window_seconds',
          Cbor.vint(v.requestedRenewalWindowSeconds!)));
    }
    Cbor.putText(e, 'callback_url', v.callbackUrl);
    Cbor.putText(e, 'nonce', v.nonce);
    Cbor.putText(e, 'requested_at', v.requestedAt);
    Cbor.putText(e, 'expires_at', v.expiresAt);
    return Cbor.encode(Cbor.vmap(e));
  }

  static ActAsGrantRequest decodeActAsGrantRequest(Uint8List data) {
    final m = Cbor.decode(data);
    final lifetime = Cbor.mapGet(m, 'requested_lifetime_seconds');
    final window = Cbor.mapGet(m, 'requested_renewal_window_seconds');
    return ActAsGrantRequest(
      grantee: _decGranteeRef(Cbor.require(m, 'grantee')),
      scopeSet: _decSignedActAsScopeSet(Cbor.require(m, 'scope_set')),
      requestedLifetimeSeconds: lifetime == null ? null : Cbor.asInt(lifetime),
      requestedRenewalWindowSeconds: window == null ? null : Cbor.asInt(window),
      callbackUrl: Cbor.requireText(m, 'callback_url'),
      nonce: Cbor.requireText(m, 'nonce'),
      requestedAt: Cbor.requireText(m, 'requested_at'),
      expiresAt: Cbor.requireText(m, 'expires_at'),
    );
  }

  static CborValue _encSignedRequest(Uint8List request, GranteeProof proof) {
    final e = <CborMapEntry>[];
    Cbor.putBytes(e, 'request', request);
    e.add(Cbor.entry('proof', _encGranteeProof(proof)));
    return Cbor.vmap(e);
  }

  static Uint8List encodeSignedActAsGrantRequest(SignedActAsGrantRequest v) =>
      Cbor.encode(_encSignedRequest(v.request, v.proof));

  static SignedActAsGrantRequest decodeSignedActAsGrantRequest(Uint8List data) {
    final m = Cbor.decode(data);
    return SignedActAsGrantRequest(
      request: Cbor.requireBytes(m, 'request'),
      proof: _decGranteeProof(Cbor.require(m, 'proof')),
    );
  }

  // -- ActAsRefreshRequest / SignedActAsRefreshRequest ----------------

  static Uint8List encodeActAsRefreshRequest(ActAsRefreshRequest v) {
    final e = <CborMapEntry>[];
    Cbor.putText(e, 'grant_id', v.grantId);
    e.add(Cbor.entry('grantee', _encGranteeRef(v.grantee)));
    Cbor.putText(e, 'requested_at', v.requestedAt);
    Cbor.putText(e, 'expires_at', v.expiresAt);
    Cbor.putText(e, 'nonce', v.nonce);
    return Cbor.encode(Cbor.vmap(e));
  }

  static ActAsRefreshRequest decodeActAsRefreshRequest(Uint8List data) {
    final m = Cbor.decode(data);
    return ActAsRefreshRequest(
      grantId: Cbor.requireText(m, 'grant_id'),
      grantee: _decGranteeRef(Cbor.require(m, 'grantee')),
      requestedAt: Cbor.requireText(m, 'requested_at'),
      expiresAt: Cbor.requireText(m, 'expires_at'),
      nonce: Cbor.requireText(m, 'nonce'),
    );
  }

  static SignedActAsRefreshRequest _decSignedActAsRefreshRequest(CborValue m) =>
      SignedActAsRefreshRequest(
        request: Cbor.requireBytes(m, 'request'),
        proof: _decGranteeProof(Cbor.require(m, 'proof')),
      );

  static Uint8List encodeSignedActAsRefreshRequest(
          SignedActAsRefreshRequest v) =>
      Cbor.encode(_encSignedRequest(v.request, v.proof));

  static SignedActAsRefreshRequest decodeSignedActAsRefreshRequest(
          Uint8List data) =>
      _decSignedActAsRefreshRequest(Cbor.decode(data));

  static Uint8List encodeRefreshActAsGrantRequest(RefreshActAsGrantRequest v) {
    final e = <CborMapEntry>[];
    e.add(Cbor.entry(
        'request', _encSignedRequest(v.request.request, v.request.proof)));
    return Cbor.encode(Cbor.vmap(e));
  }

  static RefreshActAsGrantRequest decodeRefreshActAsGrantRequest(
      Uint8List data) {
    final m = Cbor.decode(data);
    return RefreshActAsGrantRequest(
        _decSignedActAsRefreshRequest(Cbor.require(m, 'request')));
  }

  // -- SignedActAsGrant / RefreshActAsGrantResponse -------------------

  static CborValue _encSignedActAsGrant(SignedActAsGrant v) {
    final e = <CborMapEntry>[];
    Cbor.putBytes(e, 'grant', v.grant);
    e.add(Cbor.entry('signatures',
        Cbor.varray(v.signatures.map(_encClaimSignature).toList())));
    return Cbor.vmap(e);
  }

  static SignedActAsGrant _decSignedActAsGrant(CborValue m) => SignedActAsGrant(
        grant: Cbor.requireBytes(m, 'grant'),
        signatures: Cbor.asArray(Cbor.require(m, 'signatures'))
            .map(_decClaimSignature)
            .toList(),
      );

  static Uint8List encodeSignedActAsGrant(SignedActAsGrant v) =>
      Cbor.encode(_encSignedActAsGrant(v));

  static SignedActAsGrant decodeSignedActAsGrant(Uint8List data) =>
      _decSignedActAsGrant(Cbor.decode(data));

  /// The fields of an `ActAsGrant` that name it: its id, its grantee, and its
  /// home domain. The rest of the grant is not decoded.
  static ({String grantId, GranteeRef grantee, String subjectDomain})
      decodeGrantIdentity(Uint8List data) {
    final m = Cbor.decode(data);
    return (
      grantId: Cbor.requireText(m, 'grant_id'),
      grantee: _decGranteeRef(Cbor.require(m, 'grantee')),
      subjectDomain: Cbor.requireText(m, 'subject_domain'),
    );
  }

  static Uint8List encodeRefreshActAsGrantResponse(
      RefreshActAsGrantResponse v) {
    final e = <CborMapEntry>[];
    e.add(Cbor.entry('grant', _encSignedActAsGrant(v.grant)));
    Cbor.putBool(e, 'signed', v.signed);
    return Cbor.encode(Cbor.vmap(e));
  }

  static RefreshActAsGrantResponse decodeRefreshActAsGrantResponse(
      Uint8List data) {
    final m = Cbor.decode(data);
    return RefreshActAsGrantResponse(
      grant: _decSignedActAsGrant(Cbor.require(m, 'grant')),
      signed: Cbor.asBool(Cbor.require(m, 'signed')),
    );
  }

  // -- ActAsPresentation / ActAsCredential ----------------------------

  static Uint8List encodeActAsPresentation(ActAsPresentation v) {
    final e = <CborMapEntry>[];
    Cbor.putBytes(e, 'grant_hash', v.grantHash);
    e.add(Cbor.entry('audience', _encApplicationRef(v.audience)));
    Cbor.putBytes(e, 'request_digest', v.requestDigest);
    Cbor.putText(e, 'presented_at', v.presentedAt);
    Cbor.putBytes(e, 'nonce', v.nonce);
    return Cbor.encode(Cbor.vmap(e));
  }

  static ActAsPresentation decodeActAsPresentation(Uint8List data) {
    final m = Cbor.decode(data);
    return ActAsPresentation(
      grantHash: Cbor.requireBytes(m, 'grant_hash'),
      audience: _decApplicationRef(Cbor.require(m, 'audience')),
      requestDigest: Cbor.requireBytes(m, 'request_digest'),
      presentedAt: Cbor.requireText(m, 'presented_at'),
      nonce: Cbor.requireBytes(m, 'nonce'),
    );
  }

  static Uint8List encodeActAsCredential(ActAsCredential v) {
    final p = <CborMapEntry>[];
    Cbor.putBytes(p, 'presentation', v.presentation.presentation);
    p.add(Cbor.entry('proof', _encGranteeProof(v.presentation.proof)));
    final e = <CborMapEntry>[];
    e.add(Cbor.entry('grant', _encSignedActAsGrant(v.grant)));
    e.add(Cbor.entry('presentation', Cbor.vmap(p)));
    return Cbor.encode(Cbor.vmap(e));
  }

  static ActAsCredential decodeActAsCredential(Uint8List data) {
    final m = Cbor.decode(data);
    final p = Cbor.require(m, 'presentation');
    return ActAsCredential(
      grant: _decSignedActAsGrant(Cbor.require(m, 'grant')),
      presentation: SignedActAsPresentation(
        presentation: Cbor.requireBytes(p, 'presentation'),
        proof: _decGranteeProof(Cbor.require(p, 'proof')),
      ),
    );
  }
}
