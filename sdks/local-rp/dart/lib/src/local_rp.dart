// DNS-less local RP identity: pure protocol helpers. Mirrors
// `crates/liblinkkeys/src/local_rp.rs` / the Rust/Go/Java reference SDKs'
// own modules of the same name, byte-for-byte per
// `dns-less-local-rp-design.md`'s "Wire Precision (Normative)" section --
// read that first. Summary of the shape:
//
//   * Every signed structure uses the envelope pattern: the payload is
//     CBOR-encoded once, and the signature covers
//     `CBOR([context: tstr, payload: bstr])` -- a two-element CBOR array,
//     never a bare `context || payload` concatenation.
//   * Four mandatory, structure-specific context strings stop a signature
//     over one structure from ever verifying as another.
//   * The descriptor, login request, and ticket-redemption envelopes verify
//     against the local RP's own signing key (self-asserted identity,
//     SSH-host style). The callback payload envelope verifies against
//     DOMAIN public keys, keyed by `signing_key_id`.
//   * The callback ciphertext is a variant of a sealed-box construction,
//     extended with negotiated-suite selection and cleartext-header AAD
//     binding.
//
// This module performs no I/O and (aside from `checkSigningKeyValid`'s
// deliberate wall-clock exception, mirroring
// `liblinkkeys::crypto::check_signing_key_valid`) never reads the system
// clock: every "current time" is an explicit `now` parameter. Every method
// that touches `Crypto` is async -- see `crypto/crypto.dart`'s library docs.
library;

import 'dart:typed_data';

import 'crypto/aead_suite.dart';
import 'crypto/crypto.dart';
import 'errors.dart';
import 'rfc3339.dart';
import 'wire/cbor.dart';
import 'wire/codec.dart';
import 'wire/types.dart';

class LocalRp {
  LocalRp._();

  // Signature contexts for the four local-RP signed structures.
  static const String ctxLocalRpDescriptor = 'linkkeys-local-rp-descriptor';
  static const String ctxLocalRpLoginRequest =
      'linkkeys-local-rp-login-request';
  static const String ctxLocalRpCallback = 'linkkeys-local-rp-callback';
  static const String ctxLocalRpTicketRedemption =
      'linkkeys-local-rp-ticket-redemption';

  /// Default bounded clock-skew tolerance (seconds), design doc: "+/-300
  /// seconds".
  static const int defaultClockSkewSeconds = 300;

  static const String _localRpCallbackBoxTag = 'linkkeys-local-rp-callback-box';

  // -----------------------------------------------------------------
  // Envelope signature input
  // -----------------------------------------------------------------

  /// The signature input for every local-RP signed structure:
  /// `CBOR([context, payload_bytes])` -- a two-element array with the
  /// domain-separation context string first and the exact payload bytes
  /// second (encoded as a CBOR byte string, never re-serialized).
  /// Deliberately NOT a bare `context || payload` concatenation.
  static Uint8List envelopeSignatureInput(
      String context, List<int> payloadBytes) {
    return Cbor.encode(
        Cbor.tuple([Cbor.vtext(context), Cbor.vbytes(payloadBytes)]));
  }

  // -----------------------------------------------------------------
  // Timestamps / expirations
  // -----------------------------------------------------------------

  static void checkTimestamps(
      String issuedAt, String expiresAt, DateTime now, int skewSeconds) {
    final issued = Rfc3339.parse('issued_at', issuedAt);
    final expires = Rfc3339.parse('expires_at', expiresAt);
    final skew = Duration(seconds: skewSeconds);
    if (now.add(skew).isBefore(issued)) {
      throw LocalRpError(LocalRpErrorKind.notYetValid, null);
    }
    if (now.subtract(skew).isAfter(expires)) {
      throw LocalRpError(LocalRpErrorKind.expired, null);
    }
  }

  static ExpirationStatus checkExpirations(String expiresAt, DateTime now) {
    final expires = Rfc3339.parse('expires_at', expiresAt);
    final remaining = expires.difference(now);
    final ExpirationLevel level;
    if (!now.isBefore(expires)) {
      level = ExpirationLevel.expired;
    } else if (remaining <= const Duration(days: 30)) {
      level = ExpirationLevel.critical;
    } else if (remaining <= const Duration(days: 90)) {
      level = ExpirationLevel.warning;
    } else if (remaining <= const Duration(days: 180)) {
      level = ExpirationLevel.notice;
    } else {
      level = ExpirationLevel.ok;
    }
    return ExpirationStatus(level, expires, now);
  }

  // -----------------------------------------------------------------
  // Nonce/state/audience/issuer/callback-url checks
  // -----------------------------------------------------------------

  /// Uses [Crypto.constantTimeEquals] (fixed-length XOR-accumulate, no
  /// early return), not a short-circuiting byte compare -- nonce/state gate
  /// CSRF/replay protection, so how many leading bytes matched must not
  /// leak via timing.
  static void verifyNonceState(List<int> expectedNonce, List<int> expectedState,
      List<int> actualNonce, List<int> actualState) {
    if (!Crypto.constantTimeEquals(expectedNonce, actualNonce)) {
      throw LocalRpError(LocalRpErrorKind.nonceMismatch, null);
    }
    if (!Crypto.constantTimeEquals(expectedState, actualState)) {
      throw LocalRpError(LocalRpErrorKind.stateMismatch, null);
    }
  }

  static void verifyAudience(
      String payloadAudienceFingerprint, String localRpFingerprint) {
    if (payloadAudienceFingerprint != localRpFingerprint) {
      throw LocalRpError(LocalRpErrorKind.audienceMismatch, null);
    }
  }

  static void verifyIssuer(String payloadUserDomain, String expectedDomain) {
    if (payloadUserDomain != expectedDomain) {
      throw LocalRpError(LocalRpErrorKind.issuerMismatch, null);
    }
  }

  static void verifyCallbackUrl(String payloadCallbackUrl, String arrivedUrl) {
    if (payloadCallbackUrl != arrivedUrl) {
      throw LocalRpError(LocalRpErrorKind.callbackUrlMismatch, null);
    }
  }

  // -----------------------------------------------------------------
  // Signing-key validity (mirrors liblinkkeys::crypto::check_signing_key_valid
  // exactly, including its use of the real wall clock rather than an
  // explicit `now` parameter)
  // -----------------------------------------------------------------

  /// Rejects a signing key that is not usable as a signer: wrong
  /// `key_usage`, revoked, or expired (wall clock).
  static void checkSigningKeyValid(DomainPublicKey key) {
    if (key.keyUsage != 'sign') {
      throw LocalRpError(
          LocalRpErrorKind.signatureInvalid, "key_usage is not 'sign'");
    }
    if (key.revokedAt != null) {
      throw LocalRpError(LocalRpErrorKind.keyRevoked, key.keyId);
    }
    final DateTime expires;
    try {
      expires = Rfc3339.parse('expires_at', key.expiresAt);
    } on LocalRpError {
      throw LocalRpError(LocalRpErrorKind.keyExpired, key.keyId);
    }
    if (DateTime.now().toUtc().isAfter(expires)) {
      throw LocalRpError(LocalRpErrorKind.keyExpired, key.keyId);
    }
  }

  // -----------------------------------------------------------------
  // Descriptor
  // -----------------------------------------------------------------

  static Future<LocalRpDescriptor> buildLocalRpDescriptor(
    String appName,
    String? localDomainHint,
    Uint8List signingPublicKey,
    Uint8List encryptionPublicKey,
    List<String> supportedSuites,
    String createdAt,
    String expiresAt,
  ) async {
    final fp = await Crypto.fingerprint(signingPublicKey);
    return LocalRpDescriptor(
      appName: appName,
      localDomainHint: localDomainHint,
      signingPublicKey: signingPublicKey,
      encryptionPublicKey: encryptionPublicKey,
      fingerprint: fp,
      supportedSuites: supportedSuites,
      createdAt: createdAt,
      expiresAt: expiresAt,
    );
  }

  static Future<SignedLocalRpDescriptor> signLocalRpDescriptor(
      LocalRpDescriptor descriptor, List<int> privateKeySeed) async {
    final descriptorBytes = Codec.encodeLocalRpDescriptor(descriptor);
    final sigInput =
        envelopeSignatureInput(ctxLocalRpDescriptor, descriptorBytes);
    final signature = await Crypto.signEd25519(sigInput, privateKeySeed);
    return SignedLocalRpDescriptor(
        descriptor: descriptorBytes, signature: signature);
  }

  static Future<LocalRpDescriptor> verifyLocalRpDescriptor(
      SignedLocalRpDescriptor signed, DateTime now, int skewSeconds) async {
    final LocalRpDescriptor descriptor;
    try {
      descriptor = Codec.decodeLocalRpDescriptor(signed.descriptor);
    } catch (e) {
      throw LocalRpError(LocalRpErrorKind.decode, e.toString(), cause: e);
    }
    if (descriptor.signingPublicKey.length != 32) {
      throw LocalRpError(LocalRpErrorKind.invalidKeyLength, null);
    }
    final expectedFingerprint =
        await Crypto.fingerprint(descriptor.signingPublicKey);
    if (descriptor.fingerprint != expectedFingerprint) {
      throw LocalRpError(LocalRpErrorKind.fingerprintMismatch, null);
    }
    final sigInput =
        envelopeSignatureInput(ctxLocalRpDescriptor, signed.descriptor);
    if (!await Crypto.verifyEd25519(
        sigInput, signed.signature, descriptor.signingPublicKey)) {
      throw LocalRpError(LocalRpErrorKind.signatureInvalid, null);
    }
    checkTimestamps(
        descriptor.createdAt, descriptor.expiresAt, now, skewSeconds);
    return descriptor;
  }

  // -----------------------------------------------------------------
  // Login request
  // -----------------------------------------------------------------

  static LocalRpLoginRequest buildLocalRpLoginRequest(
    SignedLocalRpDescriptor descriptor,
    String callbackUrl,
    Uint8List nonce,
    Uint8List state,
    List<String> requestedClaims,
    List<String> requiredClaims,
    String issuedAt,
    String expiresAt,
  ) {
    return LocalRpLoginRequest(
      descriptor: descriptor,
      callbackUrl: callbackUrl,
      nonce: nonce,
      state: state,
      requestedClaims: requestedClaims,
      requiredClaims: requiredClaims,
      issuedAt: issuedAt,
      expiresAt: expiresAt,
    );
  }

  static Future<SignedLocalRpLoginRequest> signLocalRpLoginRequest(
      LocalRpLoginRequest request, List<int> privateKeySeed) async {
    final requestBytes = Codec.encodeLocalRpLoginRequest(request);
    final sigInput =
        envelopeSignatureInput(ctxLocalRpLoginRequest, requestBytes);
    final signature = await Crypto.signEd25519(sigInput, privateKeySeed);
    return SignedLocalRpLoginRequest(
        request: requestBytes, signature: signature);
  }

  static Future<LocalRpLoginRequest> verifyLocalRpLoginRequest(
      SignedLocalRpLoginRequest signed, DateTime now, int skewSeconds) async {
    final LocalRpLoginRequest request;
    try {
      request = Codec.decodeLocalRpLoginRequest(signed.request);
    } catch (e) {
      throw LocalRpError(LocalRpErrorKind.decode, e.toString(), cause: e);
    }
    final descriptor =
        await verifyLocalRpDescriptor(request.descriptor, now, skewSeconds);

    final sigInput =
        envelopeSignatureInput(ctxLocalRpLoginRequest, signed.request);
    if (!await Crypto.verifyEd25519(
        sigInput, signed.signature, descriptor.signingPublicKey)) {
      throw LocalRpError(LocalRpErrorKind.signatureInvalid, null);
    }
    checkTimestamps(request.issuedAt, request.expiresAt, now, skewSeconds);
    return request;
  }

  // -----------------------------------------------------------------
  // Ticket redemption
  // -----------------------------------------------------------------

  static LocalRpTicketRedemptionRequest buildLocalRpTicketRedemptionRequest(
      Uint8List claimTicket, String fingerprint, String issuedAt) {
    return LocalRpTicketRedemptionRequest(
      claimTicket: claimTicket,
      fingerprint: fingerprint,
      issuedAt: issuedAt,
    );
  }

  static Future<SignedLocalRpTicketRedemptionRequest>
      signLocalRpTicketRedemptionRequest(LocalRpTicketRedemptionRequest request,
          List<int> privateKeySeed) async {
    final requestBytes = Codec.encodeLocalRpTicketRedemptionRequest(request);
    final sigInput =
        envelopeSignatureInput(ctxLocalRpTicketRedemption, requestBytes);
    final signature = await Crypto.signEd25519(sigInput, privateKeySeed);
    return SignedLocalRpTicketRedemptionRequest(
        request: requestBytes, signature: signature);
  }

  /// Verify a ticket-redemption request's possession proof: `signingPublicKey`
  /// is the key the caller resolved for `expectedFingerprint` -- the
  /// signature must verify against it, AND that key's own fingerprint plus
  /// the request's embedded fingerprint field must both equal
  /// `expectedFingerprint`.
  static Future<LocalRpTicketRedemptionRequest>
      verifyLocalRpTicketRedemptionRequest(
          SignedLocalRpTicketRedemptionRequest signed,
          Uint8List signingPublicKey,
          String expectedFingerprint) async {
    final sigInput =
        envelopeSignatureInput(ctxLocalRpTicketRedemption, signed.request);
    if (!await Crypto.verifyEd25519(
        sigInput, signed.signature, signingPublicKey)) {
      throw LocalRpError(LocalRpErrorKind.signatureInvalid, null);
    }
    final LocalRpTicketRedemptionRequest request;
    try {
      request = Codec.decodeLocalRpTicketRedemptionRequest(signed.request);
    } catch (e) {
      throw LocalRpError(LocalRpErrorKind.decode, e.toString(), cause: e);
    }
    final keyFingerprint = await Crypto.fingerprint(signingPublicKey);
    if (keyFingerprint != expectedFingerprint ||
        request.fingerprint != expectedFingerprint) {
      throw LocalRpError(LocalRpErrorKind.fingerprintMismatch, null);
    }
    return request;
  }

  // -----------------------------------------------------------------
  // Callback payload (domain-signed envelope)
  // -----------------------------------------------------------------

  static LocalRpCallbackPayload buildLocalRpCallbackPayload(
    String userId,
    String userDomain,
    Uint8List claimTicket,
    String audienceFingerprint,
    String callbackUrl,
    Uint8List nonce,
    Uint8List state,
    String issuedAt,
    String expiresAt,
  ) {
    return LocalRpCallbackPayload(
      userId: userId,
      userDomain: userDomain,
      claimTicket: claimTicket,
      audienceFingerprint: audienceFingerprint,
      callbackUrl: callbackUrl,
      nonce: nonce,
      state: state,
      issuedAt: issuedAt,
      expiresAt: expiresAt,
    );
  }

  /// Sign a callback payload with one of the issuing domain's signing keys.
  /// Server-side (IDP) operation, exposed here only because it is a pure
  /// protocol helper -- a local-RP SDK never calls this in production, only
  /// test fixtures (fake IDPs) do.
  static Future<SignedLocalRpCallbackPayload> signLocalRpCallbackPayload(
      LocalRpCallbackPayload payload,
      String keyId,
      List<int> privateKeySeed) async {
    final payloadBytes = Codec.encodeLocalRpCallbackPayload(payload);
    final sigInput = envelopeSignatureInput(ctxLocalRpCallback, payloadBytes);
    final signature = await Crypto.signEd25519(sigInput, privateKeySeed);
    return SignedLocalRpCallbackPayload(
        payload: payloadBytes, signingKeyId: keyId, signature: signature);
  }

  /// Verify a domain-signed callback payload envelope against a set of
  /// domain public keys: resolve `signing_key_id`, reject a
  /// revoked/expired/non-signing key, verify the envelope signature, decode,
  /// then check `issued_at`/`expires_at` bounds.
  static Future<LocalRpCallbackPayload> verifyLocalRpCallbackPayload(
      SignedLocalRpCallbackPayload signed,
      List<DomainPublicKey> domainPublicKeys,
      DateTime now,
      int skewSeconds) async {
    DomainPublicKey? key;
    for (final k in domainPublicKeys) {
      if (k.keyId == signed.signingKeyId) {
        key = k;
        break;
      }
    }
    if (key == null) {
      throw LocalRpError(LocalRpErrorKind.keyNotFound, signed.signingKeyId);
    }

    checkSigningKeyValid(key);

    if (key.algorithm != 'ed25519') {
      throw LocalRpError(LocalRpErrorKind.unsupportedAlgorithm, key.algorithm);
    }
    final sigInput = envelopeSignatureInput(ctxLocalRpCallback, signed.payload);
    if (!await Crypto.verifyEd25519(
        sigInput, signed.signature, key.publicKey)) {
      throw LocalRpError(LocalRpErrorKind.signatureInvalid, null);
    }

    final LocalRpCallbackPayload payload;
    try {
      payload = Codec.decodeLocalRpCallbackPayload(signed.payload);
    } catch (e) {
      throw LocalRpError(LocalRpErrorKind.decode, e.toString(), cause: e);
    }
    checkTimestamps(payload.issuedAt, payload.expiresAt, now, skewSeconds);
    return payload;
  }

  /// Cross-check the cleartext callback header's routing fields against the
  /// authoritative copies inside the decrypted, domain-signature-verified
  /// payload. The header is already bound as AEAD associated data, but a
  /// verifier must still consult the signed copies rather than trusting the
  /// header alone.
  static void checkCallbackHeaderMatchesPayload(
      LocalRpCallbackHeader header, LocalRpCallbackPayload payload) {
    if (header.fingerprint != payload.audienceFingerprint) {
      throw LocalRpError(LocalRpErrorKind.headerPayloadMismatch, 'fingerprint');
    }
    if (!Crypto.constantTimeEquals(header.nonce, payload.nonce)) {
      throw LocalRpError(LocalRpErrorKind.headerPayloadMismatch, 'nonce');
    }
    if (!Crypto.constantTimeEquals(header.state, payload.state)) {
      throw LocalRpError(LocalRpErrorKind.headerPayloadMismatch, 'state');
    }
    if (header.issuedAt != payload.issuedAt) {
      throw LocalRpError(LocalRpErrorKind.headerPayloadMismatch, 'issued_at');
    }
    if (header.expiresAt != payload.expiresAt) {
      throw LocalRpError(LocalRpErrorKind.headerPayloadMismatch, 'expires_at');
    }
  }

  // -----------------------------------------------------------------
  // Callback sealed box (Wire Precision: "Callback sealed box")
  // -----------------------------------------------------------------

  static Future<_KdfResult> _localRpCallbackKdf(
      AeadSuite suite,
      Uint8List ephemeralPublic,
      Uint8List recipientPublic,
      Uint8List sharedSecret) async {
    final tagBytes = _asciiBytes(_localRpCallbackBoxTag);
    final suiteIdBytes = _asciiBytes(suite.wireId);
    final context = Uint8List(tagBytes.length + suiteIdBytes.length + 32 + 32);
    var pos = 0;
    context.setAll(pos, tagBytes);
    pos += tagBytes.length;
    context.setAll(pos, suiteIdBytes);
    pos += suiteIdBytes.length;
    context.setAll(pos, ephemeralPublic);
    pos += 32;
    context.setAll(pos, recipientPublic);

    final key = await Crypto.hkdfSha256(sharedSecret, context, 32);
    return _KdfResult(key, context);
  }

  static Uint8List _asciiBytes(String s) => Uint8List.fromList(s.codeUnits);

  /// Seal a [SignedLocalRpCallbackPayload] into a [LocalRpEncryptedCallback]
  /// for `recipientEncryptionPublicKey`, using `suite`. Production path:
  /// fresh random ephemeral X25519 keypair and AEAD nonce.
  static Future<LocalRpEncryptedCallback> sealLocalRpCallback(
    SignedLocalRpCallbackPayload signedPayload,
    AeadSuite suite,
    Uint8List recipientEncryptionPublicKey,
    String fingerprint,
    Uint8List nonce,
    Uint8List state,
    String issuedAt,
    String expiresAt,
  ) async {
    final ephemeral = await Crypto.generateX25519KeyPair();
    final aeadNonce = Crypto.randomBytes(12);
    return _sealLocalRpCallbackInner(
      signedPayload,
      suite,
      recipientEncryptionPublicKey,
      fingerprint,
      nonce,
      state,
      issuedAt,
      expiresAt,
      ephemeral.privateKey,
      ephemeral.publicKey,
      aeadNonce,
    );
  }

  /// Deterministic variant of [sealLocalRpCallback]: the caller supplies the
  /// ephemeral X25519 private key and AEAD nonce instead of sourcing them
  /// from the CSPRNG. Production code must always use [sealLocalRpCallback];
  /// this variant exists solely so tests can reproduce the checked-in
  /// conformance vectors' exact ciphertexts.
  static Future<LocalRpEncryptedCallback> sealLocalRpCallbackWithRandomness(
    SignedLocalRpCallbackPayload signedPayload,
    AeadSuite suite,
    Uint8List recipientEncryptionPublicKey,
    String fingerprint,
    Uint8List nonce,
    Uint8List state,
    String issuedAt,
    String expiresAt,
    Uint8List ephemeralPrivateKey,
    Uint8List aeadNonce,
  ) async {
    final ephemeralPublic =
        await Crypto.derivePublicFromX25519Private(ephemeralPrivateKey);
    return _sealLocalRpCallbackInner(
      signedPayload,
      suite,
      recipientEncryptionPublicKey,
      fingerprint,
      nonce,
      state,
      issuedAt,
      expiresAt,
      ephemeralPrivateKey,
      ephemeralPublic,
      aeadNonce,
    );
  }

  static Future<LocalRpEncryptedCallback> _sealLocalRpCallbackInner(
    SignedLocalRpCallbackPayload signedPayload,
    AeadSuite suite,
    Uint8List recipientEncryptionPublicKey,
    String fingerprint,
    Uint8List nonce,
    Uint8List state,
    String issuedAt,
    String expiresAt,
    Uint8List ephemeralPrivateKey,
    Uint8List ephemeralPublicKey,
    Uint8List aeadNonce,
  ) async {
    final plaintext = Codec.encodeSignedLocalRpCallbackPayload(signedPayload);

    final sharedSecret = await Crypto.x25519DiffieHellman(
        ephemeralPrivateKey, recipientEncryptionPublicKey);

    final header = LocalRpCallbackHeader(
      fingerprint: fingerprint,
      nonce: nonce,
      state: state,
      suite: suite.wireId,
      ephemeralPublicKey: ephemeralPublicKey,
      aeadNonce: aeadNonce,
      issuedAt: issuedAt,
      expiresAt: expiresAt,
    );
    final headerBytes = Codec.encodeLocalRpCallbackHeader(header);

    final kdf = await _localRpCallbackKdf(
        suite, ephemeralPublicKey, recipientEncryptionPublicKey, sharedSecret);

    final aad = Uint8List(kdf.context.length + headerBytes.length);
    aad.setAll(0, kdf.context);
    aad.setAll(kdf.context.length, headerBytes);

    final ciphertext =
        await Crypto.aeadEncrypt(suite, kdf.key, aeadNonce, aad, plaintext);
    return LocalRpEncryptedCallback(
        header: headerBytes, ciphertext: ciphertext);
  }

  /// Open a [LocalRpEncryptedCallback] with the local RP's encryption
  /// private key. `allowedSuites` is the local RP's own supported-suite list
  /// (from its descriptor): a header advertising a suite NOT in that list is
  /// rejected even if it is otherwise a valid registry id.
  ///
  /// Returns the decoded header and the still domain-signature-unverified
  /// [SignedLocalRpCallbackPayload] -- callers must still call
  /// [verifyLocalRpCallbackPayload] against fetched domain keys, and then
  /// [checkCallbackHeaderMatchesPayload], before trusting the result.
  static Future<OpenedCallback> openLocalRpCallback(
      LocalRpEncryptedCallback encrypted,
      Uint8List recipientEncryptionPrivateKey,
      List<AeadSuite> allowedSuites) async {
    final LocalRpCallbackHeader header;
    try {
      header = Codec.decodeLocalRpCallbackHeader(encrypted.header);
    } catch (e) {
      throw LocalRpError(LocalRpErrorKind.decode, e.toString(), cause: e);
    }

    final suite = AeadSuite.parse(header.suite);
    if (suite == null) {
      throw LocalRpError(LocalRpErrorKind.unsupportedSuite, header.suite);
    }
    if (!allowedSuites.contains(suite)) {
      throw LocalRpError(LocalRpErrorKind.suiteNotAdvertised, header.suite);
    }

    if (header.ephemeralPublicKey.length != 32) {
      throw LocalRpError(LocalRpErrorKind.invalidKeyLength, null);
    }
    if (header.aeadNonce.length != 12) {
      throw LocalRpError(LocalRpErrorKind.invalidKeyLength, null);
    }

    final recipientPublic = await Crypto.derivePublicFromX25519Private(
        recipientEncryptionPrivateKey);

    final Uint8List sharedSecret;
    try {
      sharedSecret = await Crypto.x25519DiffieHellman(
          recipientEncryptionPrivateKey, header.ephemeralPublicKey);
    } on CryptoException catch (e) {
      throw LocalRpError(
          LocalRpErrorKind.crypto, 'non-contributory ephemeral key',
          cause: e);
    }

    final kdf = await _localRpCallbackKdf(
        suite, header.ephemeralPublicKey, recipientPublic, sharedSecret);

    final aad = Uint8List(kdf.context.length + encrypted.header.length);
    aad.setAll(0, kdf.context);
    aad.setAll(kdf.context.length, encrypted.header);

    final Uint8List plaintext;
    try {
      plaintext = await Crypto.aeadDecrypt(
          suite, kdf.key, header.aeadNonce, aad, encrypted.ciphertext);
    } on CryptoException catch (e) {
      throw LocalRpError(LocalRpErrorKind.crypto, 'decrypt failed', cause: e);
    }

    final SignedLocalRpCallbackPayload signedPayload;
    try {
      signedPayload = Codec.decodeSignedLocalRpCallbackPayload(plaintext);
    } catch (e) {
      throw LocalRpError(LocalRpErrorKind.decode, e.toString(), cause: e);
    }

    return OpenedCallback(header, signedPayload);
  }
}

class _KdfResult {
  final Uint8List key;
  final Uint8List context;
  const _KdfResult(this.key, this.context);
}

class OpenedCallback {
  final LocalRpCallbackHeader header;
  final SignedLocalRpCallbackPayload signedPayload;
  const OpenedCallback(this.header, this.signedPayload);
}

enum ExpirationLevel {
  ok,
  notice,
  warning,
  critical,
  expired;

  String get wireName => name;
}

class ExpirationStatus {
  final ExpirationLevel level;
  final DateTime expiresAt;
  final DateTime now;
  const ExpirationStatus(this.level, this.expiresAt, this.now);
}
