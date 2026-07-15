// `generateLocalRpIdentity` and the raw-byte storage helpers (design doc:
// "SDK API Shape", "Byte Storage Helpers").
//
// A local RP identity is exactly one Ed25519 signing keypair, one X25519
// encryption keypair, and a self-signed [SignedLocalRpDescriptor] binding
// them together. There is no continuity story across rotation: generating a
// new identity means a new fingerprint, full stop.
//
// Security note (design doc, "Byte Storage Helpers"): the private key
// fields in [LocalRpKeyMaterial] do not directly identify a user, but they
// control this app's entire local RP identity -- anyone holding them can
// sign login requests and redeem claim tickets as this app. Store them with
// ordinary application-secret care (the same care as a database credential
// or API key), not merely as configuration.
library;

import 'dart:typed_data';

import 'crypto/aead_suite.dart';
import 'crypto/crypto.dart';
import 'dns/dns.dart';
import 'errors.dart';
import 'local_rp.dart';
import 'rfc3339.dart';
import 'wire/codec.dart';
import 'wire/types.dart';

/// Default local RP key lifetime: 10 years (design doc: "Default lifetime:
/// 10 years").
const Duration defaultLifetime = Duration(days: 3650);

/// Input to [generateLocalRpIdentity]. Big-config, single class, per the
/// design doc's "SDK API Shape".
class GenerateLocalRpIdentityConfig {
  /// Display name shown on the IDP's consent screen. NOT identity --
  /// display/audit metadata only.
  final String appName;

  /// Optional local domain/origin hint, also display/audit metadata.
  final String? localDomainHint;

  /// AEAD suites this app can decrypt callbacks with, preference order.
  /// Defaults to both registry suites.
  final List<String>? supportedSuites;

  /// Key/descriptor lifetime from [now]. Defaults to [defaultLifetime].
  final Duration? lifetime;

  /// The current time -- never read from the system clock inside this
  /// module (aside from `LocalRp.checkSigningKeyValid`'s documented wall-
  /// clock exception, which this module never calls).
  final DateTime now;

  const GenerateLocalRpIdentityConfig({
    required this.appName,
    this.localDomainHint,
    this.supportedSuites,
    this.lifetime,
    required this.now,
  });
}

/// A local RP's full key material: signing keypair, encryption keypair, the
/// self-signed descriptor binding them (which also carries `appName`,
/// `localDomainHint`, `supportedSuites`, and the created/expires
/// timestamps), and the identity fingerprint.
class LocalRpKeyMaterial {
  final Uint8List signingPrivateKey;
  final Uint8List signingPublicKey;
  final Uint8List encryptionPrivateKey;
  final Uint8List encryptionPublicKey;
  final SignedLocalRpDescriptor descriptor;
  final String fingerprint;

  const LocalRpKeyMaterial({
    required this.signingPrivateKey,
    required this.signingPublicKey,
    required this.encryptionPrivateKey,
    required this.encryptionPublicKey,
    required this.descriptor,
    required this.fingerprint,
  });
}

/// `generate_local_rp_identity(config) -> LocalRpKeyMaterial` (design doc,
/// "SDK API Shape"). Generates a fresh Ed25519 signing keypair and a
/// *separate* X25519 encryption keypair (never algebraically derived),
/// builds and self-signs the descriptor binding them.
Future<LocalRpKeyMaterial> generateLocalRpIdentity(
    GenerateLocalRpIdentityConfig config) async {
  if (config.appName.trim().isEmpty) {
    throw SdkException(
        SdkExceptionKind.invalidInput, 'app_name must not be empty');
  }

  final signing = await Crypto.generateEd25519KeyPair();
  final encryption = await Crypto.generateX25519KeyPair();

  final suites = config.supportedSuites ?? AeadSuite.allSupported();
  if (suites.isEmpty) {
    throw SdkException(
        SdkExceptionKind.invalidInput, 'supported_suites must not be empty');
  }

  final lifetime = config.lifetime ?? defaultLifetime;
  final createdAt = Rfc3339.format(config.now);
  final expiresAt = Rfc3339.format(config.now.add(lifetime));

  final descriptor = await LocalRp.buildLocalRpDescriptor(
    config.appName,
    config.localDomainHint,
    signing.publicKey,
    encryption.publicKey,
    suites,
    createdAt,
    expiresAt,
  );
  final fingerprint = descriptor.fingerprint;
  final signedDescriptor =
      await LocalRp.signLocalRpDescriptor(descriptor, signing.privateKeySeed);

  return LocalRpKeyMaterial(
    signingPrivateKey: signing.privateKeySeed,
    signingPublicKey: signing.publicKey,
    encryptionPrivateKey: encryption.privateKey,
    encryptionPublicKey: encryption.publicKey,
    descriptor: signedDescriptor,
    fingerprint: fingerprint,
  );
}

// -----------------------------------------------------------------
// Byte storage helpers (design doc: "Byte Storage Helpers")
// -----------------------------------------------------------------

Uint8List signingKeyToBytes(Uint8List key) => Uint8List.fromList(key);

Uint8List signingKeyFromBytes(List<int> bytes) {
  if (bytes.length != 32) {
    throw SdkException(SdkExceptionKind.invalidInput,
        'signing key must be 32 bytes, got ${bytes.length}');
  }
  return Uint8List.fromList(bytes);
}

Uint8List encryptionKeyToBytes(Uint8List key) => Uint8List.fromList(key);

Uint8List encryptionKeyFromBytes(List<int> bytes) {
  if (bytes.length != 32) {
    throw SdkException(SdkExceptionKind.invalidInput,
        'encryption key must be 32 bytes, got ${bytes.length}');
  }
  return Uint8List.fromList(bytes);
}

/// The canonical fingerprint string form -- a pass-through, since the
/// fingerprint IS a hex string already.
String fingerprintToString(String fingerprint) => fingerprint;

/// Parse/validate a fingerprint string: exactly 64 lowercase-normalized hex
/// characters (a SHA-256 digest).
String fingerprintFromString(String s) {
  if (!isValidFingerprint(s)) {
    throw SdkException(SdkExceptionKind.invalidInput,
        'not a valid fingerprint (want 64 hex chars): $s');
  }
  return s.toLowerCase();
}

/// Magic prefix for the identity-bundle byte format below. This is an
/// SDK-local storage convenience, NOT a protocol wire format -- nothing in
/// the design doc's Wire Precision governs it, and no conformance vector
/// covers it.
final Uint8List _identityBundleMagic = Uint8List.fromList('LKI1'.codeUnits);
const int _headerLen = 4 + 32 + 32 + 4;

/// `local_rp_identity_to_bytes(identity) -> bytes` (design doc, "SDK API
/// Shape" + "Byte Storage Helpers"). Layout:
/// `MAGIC(4) || signing_private_key(32) || encryption_private_key(32) ||
/// descriptor_len(4, BE) || descriptor_cbor`.
Uint8List localRpIdentityToBytes(LocalRpKeyMaterial identity) {
  final descriptorBytes =
      Codec.encodeSignedLocalRpDescriptor(identity.descriptor);
  final buf = Uint8List(_headerLen + descriptorBytes.length);
  var pos = 0;
  buf.setAll(pos, _identityBundleMagic);
  pos += 4;
  buf.setAll(pos, identity.signingPrivateKey);
  pos += 32;
  buf.setAll(pos, identity.encryptionPrivateKey);
  pos += 32;
  final bd = ByteData(4);
  bd.setUint32(0, descriptorBytes.length, Endian.big);
  buf.setAll(pos, bd.buffer.asUint8List());
  pos += 4;
  buf.setAll(pos, descriptorBytes);
  return buf;
}

/// `local_rp_identity_from_bytes(bytes) -> LocalRpIdentity` -- the inverse
/// of [localRpIdentityToBytes]. Public keys and the fingerprint are read
/// back out of the embedded descriptor rather than re-derived from the
/// private keys. Does no signature/expiry verification (that is
/// `checkExpirations`'s and the protocol verification chain's job).
LocalRpKeyMaterial localRpIdentityFromBytes(List<int> bytesIn) {
  final bytes = Uint8List.fromList(bytesIn);
  if (bytes.length < _headerLen) {
    throw SdkException(
        SdkExceptionKind.invalidInput, 'identity bundle too short');
  }
  for (var i = 0; i < 4; i++) {
    if (bytes[i] != _identityBundleMagic[i]) {
      throw SdkException(SdkExceptionKind.invalidInput,
          'identity bundle has an unrecognized magic prefix');
    }
  }
  final signingPrivateKey = Uint8List.sublistView(bytes, 4, 36);
  final encryptionPrivateKey = Uint8List.sublistView(bytes, 36, 68);
  final descriptorLen =
      ByteData.sublistView(bytes, 68, 72).getUint32(0, Endian.big);
  if (_headerLen + descriptorLen > bytes.length) {
    throw SdkException(SdkExceptionKind.invalidInput,
        'identity bundle descriptor length exceeds available bytes');
  }
  final descriptorBytes =
      Uint8List.sublistView(bytes, _headerLen, _headerLen + descriptorLen);

  final signedDescriptor = Codec.decodeSignedLocalRpDescriptor(descriptorBytes);
  final descriptor = Codec.decodeLocalRpDescriptor(signedDescriptor.descriptor);

  if (descriptor.signingPublicKey.length != 32) {
    throw SdkException(SdkExceptionKind.invalidInput,
        'descriptor signing_public_key was not 32 bytes');
  }
  if (descriptor.encryptionPublicKey.length != 32) {
    throw SdkException(SdkExceptionKind.invalidInput,
        'descriptor encryption_public_key was not 32 bytes');
  }

  return LocalRpKeyMaterial(
    signingPrivateKey: Uint8List.fromList(signingPrivateKey),
    signingPublicKey: descriptor.signingPublicKey,
    encryptionPrivateKey: Uint8List.fromList(encryptionPrivateKey),
    encryptionPublicKey: descriptor.encryptionPublicKey,
    descriptor: signedDescriptor,
    fingerprint: descriptor.fingerprint,
  );
}
