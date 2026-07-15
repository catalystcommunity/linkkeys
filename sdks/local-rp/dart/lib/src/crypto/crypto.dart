// package:cryptography_plus-backed crypto primitives this SDK needs
// (design doc, Language Crypto Matrix, "Dart" row): Ed25519 sign/verify,
// X25519 ECDH, AES-256-GCM / ChaCha20-Poly1305 AEAD, SHA-256 fingerprinting,
// HKDF-SHA256, and CSPRNG bytes.
//
// See the package README for the health-check evidence behind choosing
// `cryptography_plus` over the original `cryptography` (dint-dev) package.
//
// ## Everything here is async
//
// `cryptography_plus`'s entire API surface is `Future`-based (there is a
// `toSync()` escape hatch on some algorithms, but it is not exposed
// uniformly across Ed25519/X25519/AEAD/HKDF, and mixing sync/async call
// styles inside one SDK is its own footgun). Every method in this class is
// therefore `Future`-returning, including `fingerprint` -- the one operation
// every other reference SDK exposes synchronously. This is a deliberate,
// Dart-idiomatic tradeoff: pure non-crypto logic elsewhere in this SDK (CBOR
// codec, timestamp/expiry checks, DNS TXT parsing) stays synchronous, but
// nothing that touches `cryptography_plus` can be.
//
// ## The raw-key-import/export footgun (SimpleKeyPairData / SimplePublicKey)
//
// `cryptography_plus`'s `Ed25519`/`X25519` algorithms both take a raw 32-byte
// seed directly via `newKeyPairFromSeed(seed)` -- no DER/JWK wrapping dance
// needed, unlike Java's JCA or Node's `crypto` module. The resulting
// `SimpleKeyPairData.publicKey` is a `SimplePublicKey` whose `.bytes` are
// already the raw 32-byte wire format this protocol uses. This is the
// friendliest raw-key story of any language in the matrix -- BUT there is
// still a real footgun:
//
// `DartX25519.newKeyPairFromSeed` immediately clamps the seed per RFC 7748
// (clears the low 3 bits, sets bit 254, clears bit 255) and stores the
// CLAMPED bytes as the key pair's private-key bytes -- so
// `extractPrivateKeyBytes()` on an X25519 key pair does NOT return the
// original seed you passed in unless it happened to already be clamped. This
// is harmless for every operation this SDK performs (public-key derivation
// and Diffie-Hellman both re-clamp internally and clamping is idempotent, so
// a fixed conformance-vector private key still derives the correct public
// key and shared secret), but it means an app must never assume
// `localRpIdentityFromBytes(localRpIdentityToBytes(identity))` round-trips
// the exact original X25519 private-key bytes bit-for-bit if it obtained
// them from `extractPrivateKeyBytes()` after key generation elsewhere; this
// SDK always stores exactly the bytes `generateX25519KeyPair` returned, so
// the round trip IS stable for identities this SDK itself generated.
// Verified against `keys.json`'s fixed seeds before building the rest of the
// SDK on this package.
//
// ## Low-order X25519 rejection
//
// Unlike Java's JDK XDH `KeyAgreement` (which throws for several known
// low-order inputs during `doPhase`), `cryptography_plus`'s pure-Dart
// `DartX25519.sharedSecretSync` performs the RFC 7748 scalar multiplication
// unconditionally and returns whatever it computes -- including an all-zero
// shared secret for a malicious all-zero (or other low-order) ephemeral
// public key. The package does NOT reject this itself. This SDK therefore
// adds an explicit all-zero check after every X25519 Diffie-Hellman
// (`x25519DiffieHellman` below), exactly matching
// `callback_box.json`'s `low_order_ephemeral_key_rejected` case.
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart' as cg;

import '../errors.dart';
import 'aead_suite.dart';
import 'hex.dart';

class Ed25519KeyPair {
  final Uint8List publicKey;
  final Uint8List privateKeySeed;
  const Ed25519KeyPair(this.publicKey, this.privateKeySeed);
}

class X25519KeyPair {
  final Uint8List publicKey;
  final Uint8List privateKey;
  const X25519KeyPair(this.publicKey, this.privateKey);
}

class Crypto {
  Crypto._();

  static final cg.Ed25519 _ed25519 = cg.Ed25519();
  static final cg.X25519 _x25519 = cg.X25519();
  static final cg.Sha256 _sha256 = cg.Sha256();
  static final Random _random = Random.secure();

  // -----------------------------------------------------------------
  // Fingerprint / randomness
  // -----------------------------------------------------------------

  /// `sha256(public_key_bytes)`, lowercase hex -- the canonical LinkKeys
  /// fingerprint format, everywhere.
  static Future<String> fingerprint(List<int> publicKeyBytes) async {
    final hash = await _sha256.hash(publicKeyBytes);
    return Hex.encode(hash.bytes);
  }

  /// CSPRNG bytes (`dart:math` `Random.secure()`, the Dart-stdlib equivalent
  /// of `OsRng`/`rand::random`). Synchronous: `Random.secure()` is a plain
  /// stdlib facility, not part of `cryptography_plus`.
  static Uint8List randomBytes(int length) {
    final out = Uint8List(length);
    for (var i = 0; i < length; i++) {
      out[i] = _random.nextInt(256);
    }
    return out;
  }

  static void _requireLen(List<int> b, int len, String what) {
    if (b.length != len) {
      throw CryptoException('$what must be $len bytes, got ${b.length}');
    }
  }

  // -----------------------------------------------------------------
  // Ed25519
  // -----------------------------------------------------------------

  /// Generate a fresh Ed25519 keypair, returning raw 32-byte public key and
  /// 32-byte private seed.
  static Future<Ed25519KeyPair> generateEd25519KeyPair() async {
    final seed = randomBytes(32);
    return ed25519KeyPairFromSeed(seed);
  }

  /// Derive the full keypair (including the public key) for a raw 32-byte
  /// Ed25519 private key seed.
  static Future<Ed25519KeyPair> ed25519KeyPairFromSeed(List<int> seed) async {
    _requireLen(seed, 32, 'Ed25519 private key seed');
    final kp = await _ed25519.newKeyPairFromSeed(seed);
    final data = await kp.extract();
    return Ed25519KeyPair(
      Uint8List.fromList(data.publicKey.bytes),
      Uint8List.fromList(seed),
    );
  }

  /// Sign `message` with an Ed25519 seed (raw 32-byte private key). Returns
  /// a 64-byte signature.
  static Future<Uint8List> signEd25519(
      List<int> message, List<int> privateKeySeed) async {
    _requireLen(privateKeySeed, 32, 'Ed25519 private key seed');
    final kp = await _ed25519.newKeyPairFromSeed(privateKeySeed);
    final sig = await _ed25519.sign(message, keyPair: kp);
    return Uint8List.fromList(sig.bytes);
  }

  /// Verify an Ed25519 signature. Never throws for a malformed
  /// key/signature -- returns `false` uniformly, so callers can treat every
  /// failure mode alike.
  static Future<bool> verifyEd25519(
      List<int> message, List<int> signature, List<int> publicKey) async {
    if (publicKey.length != 32 || signature.length != 64) {
      return false;
    }
    try {
      final sig = cg.Signature(
        signature,
        publicKey: cg.SimplePublicKey(publicKey, type: cg.KeyPairType.ed25519),
      );
      return await _ed25519.verify(message, signature: sig);
    } catch (_) {
      return false;
    }
  }

  // -----------------------------------------------------------------
  // X25519 (ECDH)
  // -----------------------------------------------------------------

  /// Generate a fresh X25519 encryption keypair -- a *separate* key from any
  /// signing key.
  static Future<X25519KeyPair> generateX25519KeyPair() async {
    final kp = await _x25519.newKeyPair();
    final data = await kp.extract();
    final privBytes = await kp.extractPrivateKeyBytes();
    return X25519KeyPair(
      Uint8List.fromList(data.publicKey.bytes),
      Uint8List.fromList(privBytes),
    );
  }

  /// Derive the raw 32-byte X25519 public key for a raw 32-byte private key
  /// (scalar). Needed on the decrypting side of the callback sealed box,
  /// which must feed its OWN public key (not the ephemeral sender's) into
  /// the KDF/AAD construction.
  static Future<Uint8List> derivePublicFromX25519Private(
      List<int> privateKey) async {
    _requireLen(privateKey, 32, 'X25519 private key');
    final kp = await _x25519.newKeyPairFromSeed(privateKey);
    final pub = await kp.extractPublicKey();
    return Uint8List.fromList(pub.bytes);
  }

  /// X25519 Diffie-Hellman, rejecting a non-contributory (low-order) result
  /// (Wire Precision: "reject an all-zero shared secret"). See this
  /// library's docs for why the explicit all-zero check is necessary with
  /// `cryptography_plus` specifically.
  static Future<Uint8List> x25519DiffieHellman(
      List<int> privateKey, List<int> publicKey) async {
    _requireLen(privateKey, 32, 'X25519 private key');
    _requireLen(publicKey, 32, 'X25519 public key');
    try {
      final kp = await _x25519.newKeyPairFromSeed(privateKey);
      final remote = cg.SimplePublicKey(publicKey, type: cg.KeyPairType.x25519);
      final shared =
          await _x25519.sharedSecretKey(keyPair: kp, remotePublicKey: remote);
      final bytes = await shared.extractBytes();
      _rejectLowOrder(bytes);
      return Uint8List.fromList(bytes);
    } on CryptoException {
      rethrow;
    } catch (e) {
      throw CryptoException('X25519 key agreement failed', cause: e);
    }
  }

  static void _rejectLowOrder(List<int> sharedSecret) {
    var allZero = true;
    for (final b in sharedSecret) {
      if (b != 0) {
        allZero = false;
        break;
      }
    }
    if (allZero) {
      throw CryptoException('non-contributory (low-order) X25519 key rejected');
    }
  }

  // -----------------------------------------------------------------
  // HKDF-SHA256
  // -----------------------------------------------------------------

  /// `HKDF-SHA256(salt=none, ikm).expand(info, length)`. `cryptography_plus`'s
  /// `Hkdf.deriveKey` calls its `nonce` parameter the salt.
  ///
  /// Empirically verified (not merely inferred from the RFC): the package's
  /// `DartHmac` throws `ArgumentError` for an EMPTY secret key ("Secret key
  /// must be non-empty"), so the default `nonce: const []` is NOT usable as
  /// a stand-in for "no salt" the way it is in some other HMAC
  /// implementations. This method therefore passes an explicit
  /// hash-length (32-byte) all-zero salt, exactly matching RFC 5869's "if
  /// not provided, salt is set to a string of HashLen zero bytes" -- the
  /// same convention `hkdf::Hkdf::<Sha256>::new(None, ikm)` uses on the Rust
  /// side. Verified against `callback_box.json`'s derived AEAD keys.
  static Future<Uint8List> hkdfSha256(
      List<int> ikm, List<int> info, int length) async {
    final hkdf = cg.Hkdf(hmac: cg.Hmac.sha256(), outputLength: length);
    final zeroSalt = Uint8List(32);
    final out = await hkdf.deriveKey(
        secretKey: cg.SecretKey(ikm), nonce: zeroSalt, info: info);
    return Uint8List.fromList(out.bytes);
  }

  // -----------------------------------------------------------------
  // AEAD dispatch (AES-256-GCM baseline, ChaCha20-Poly1305 optional)
  // -----------------------------------------------------------------

  static const int _aeadTagLength = 16;

  static cg.Cipher _aeadCipher(AeadSuite suite) {
    return switch (suite) {
      AeadSuite.aes256Gcm => cg.AesGcm.with256bits(),
      AeadSuite.chacha20Poly1305 => cg.Chacha20.poly1305Aead(),
    };
  }

  /// Encrypt under `suite`. Output is `ciphertext || 16-byte tag`
  /// (RustCrypto/JCA/Node convention -- this SDK concatenates them itself,
  /// since `cryptography_plus` returns them as separate `SecretBox` fields).
  static Future<Uint8List> aeadEncrypt(AeadSuite suite, List<int> key,
      List<int> nonce, List<int> aad, List<int> plaintext) async {
    _requireLen(key, 32, 'AEAD key');
    _requireLen(nonce, 12, 'AEAD nonce');
    final cipher = _aeadCipher(suite);
    final box = await cipher.encrypt(
      plaintext,
      secretKey: cg.SecretKey(key),
      nonce: nonce,
      aad: aad,
    );
    final out = Uint8List(box.cipherText.length + box.mac.bytes.length);
    out.setAll(0, box.cipherText);
    out.setAll(box.cipherText.length, box.mac.bytes);
    return out;
  }

  /// Decrypt `ciphertext || tag` under `suite`. Throws [CryptoException] on
  /// any authentication failure (tampering, wrong key/nonce/AAD, truncation)
  /// -- never returns unauthenticated plaintext.
  static Future<Uint8List> aeadDecrypt(AeadSuite suite, List<int> key,
      List<int> nonce, List<int> aad, List<int> ciphertextWithTag) async {
    _requireLen(key, 32, 'AEAD key');
    _requireLen(nonce, 12, 'AEAD nonce');
    if (ciphertextWithTag.length < _aeadTagLength) {
      throw CryptoException('ciphertext shorter than the AEAD tag');
    }
    final tagStart = ciphertextWithTag.length - _aeadTagLength;
    final cipherText = ciphertextWithTag.sublist(0, tagStart);
    final tag = ciphertextWithTag.sublist(tagStart);
    try {
      final cipher = _aeadCipher(suite);
      final box = cg.SecretBox(cipherText, nonce: nonce, mac: cg.Mac(tag));
      final plaintext =
          await cipher.decrypt(box, secretKey: cg.SecretKey(key), aad: aad);
      return Uint8List.fromList(plaintext);
    } catch (e) {
      throw CryptoException(
          'AEAD decryption failed (tampering, wrong key, or wrong AAD)',
          cause: e);
    }
  }

  /// Constant-time byte-array equality: fixed-length XOR-accumulate, no
  /// early return on a byte mismatch (only on a length mismatch, which is
  /// not secret data worth hiding). Dart's standard library has no
  /// constant-time compare, unlike e.g. Node's `crypto.timingSafeEqual` or
  /// Go's `crypto/subtle.ConstantTimeCompare` -- `LocalRp.verifyNonceState`
  /// and `LocalRp.checkCallbackHeaderMatchesPayload` use this rather than a
  /// short-circuiting loop for the nonce/state comparisons that gate
  /// CSRF/replay protection, so how many leading bytes matched can't leak
  /// via timing. Signature/MAC verification already goes through
  /// `cryptography_plus`'s own constant-time primitives and doesn't need
  /// this helper.
  static bool constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
