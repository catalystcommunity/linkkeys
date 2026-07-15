// node:crypto-only cryptographic primitives, mirroring
// `crates/liblinkkeys/src/crypto.rs`'s subset this SDK needs: Ed25519
// sign/verify, X25519 ECDH, the AEAD suite registry, HKDF-SHA256, AES-256-GCM
// / ChaCha20-Poly1305, SHA-256 fingerprinting, and CSPRNG bytes. Zero runtime
// npm dependencies — Node's stdlib `crypto` module covers every primitive
// this protocol needs (see the design doc's Language Crypto Matrix, "Node:
// Strong, Node-only").
//
// ## The raw-key-import footgun
//
// Node's WebCrypto/legacy `crypto` APIs do not accept raw 32-byte
// Ed25519/X25519 keys directly (unlike, say, `ed25519-dalek`'s
// `SigningKey::from_bytes`). Two ways around this were evaluated:
//
// 1. JWK import (`{kty:"OKP", crv:"Ed25519"|"X25519", d, x}`) — works for a
//    *complete* keypair, but Node's private-key JWK import requires both `d`
//    (private) and `x` (public) fields; it rejects a private JWK carrying
//    only `d`, which is exactly the shape this SDK needs to support (a raw
//    32-byte seed loaded back from app storage, per "Byte Storage Helpers" —
//    the design doc explicitly stores ONLY the 32-byte private key, never a
//    bundled public key).
// 2. DER wrapping — a raw Ed25519/X25519 private key (seed) or public key is
//    exactly the "raw" payload of a well-known, fixed-length PKCS8
//    (private)/SPKI (public) ASN.1 structure for these curves (RFC 8410):
//    the algorithm identifier and lengths are constant, so the DER bytes are
//    just `FIXED_PREFIX || raw_32_bytes`. Node's `createPrivateKey`/
//    `createPublicKey` accept this directly, and — critically — PKCS8
//    private-key import needs ONLY the private scalar; Node derives the
//    public key internally. This is the approach used below.
//
// Verified empirically against this SDK's own conformance vectors
// (`sdks/local-rp/conformance/`) before writing the rest of the SDK: DER
// wrapping + `crypto.sign`/`crypto.verify`/`crypto.diffieHellman` reproduce
// byte-identical results against `envelopes.json` (Ed25519) and
// `callback_box.json` (X25519 + HKDF + AES-256-GCM/ChaCha20-Poly1305).

import * as nodeCrypto from "node:crypto";

export class CryptoError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "CryptoError";
  }
}

// ---------------------------------------------------------------------
// Fingerprint (crypto::fingerprint)
// ---------------------------------------------------------------------

/** `sha256(public_key_bytes)`, lowercase hex — the existing LinkKeys fingerprint format, everywhere. */
export function fingerprint(publicKeyBytes: Uint8Array): string {
  return nodeCrypto.createHash("sha256").update(publicKeyBytes).digest("hex");
}

/** CSPRNG bytes (`rand::random`/`OsRng` equivalent). */
export function randomBytes(length: number): Uint8Array {
  return new Uint8Array(nodeCrypto.randomBytes(length));
}

/**
 * Constant-time byte equality (`crypto.timingSafeEqual`) for comparing
 * security-relevant values (nonce/state) where a length-then-byte-by-byte
 * short-circuiting compare could leak how many leading bytes matched via
 * timing. Length is checked first and short-circuits — `timingSafeEqual`
 * itself throws (rather than returning `false`) on a length mismatch, and a
 * length difference is not secret data worth hiding here.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return nodeCrypto.timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------
// DER wrapping for raw Ed25519 / X25519 key bytes (RFC 8410)
// ---------------------------------------------------------------------

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function requireLen(bytes: Uint8Array, len: number, what: string): void {
  if (bytes.length !== len) {
    throw new CryptoError(`${what} must be ${len} bytes, got ${bytes.length}`);
  }
}

function ed25519PrivateKeyObject(seed: Uint8Array): nodeCrypto.KeyObject {
  requireLen(seed, 32, "Ed25519 private key seed");
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  return nodeCrypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function ed25519PublicKeyObject(publicKey: Uint8Array): nodeCrypto.KeyObject {
  requireLen(publicKey, 32, "Ed25519 public key");
  const der = Buffer.concat([ED25519_SPKI_PREFIX, publicKey]);
  return nodeCrypto.createPublicKey({ key: der, format: "der", type: "spki" });
}

function x25519PrivateKeyObject(privateKey: Uint8Array): nodeCrypto.KeyObject {
  requireLen(privateKey, 32, "X25519 private key");
  const der = Buffer.concat([X25519_PKCS8_PREFIX, privateKey]);
  return nodeCrypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function x25519PublicKeyObject(publicKey: Uint8Array): nodeCrypto.KeyObject {
  requireLen(publicKey, 32, "X25519 public key");
  const der = Buffer.concat([X25519_SPKI_PREFIX, publicKey]);
  return nodeCrypto.createPublicKey({ key: der, format: "der", type: "spki" });
}

/** Export a KeyObject's raw OKP key bytes (the JWK `x`/`d` field, decoded). */
function rawOkpBytes(key: nodeCrypto.KeyObject, field: "x" | "d"): Uint8Array {
  const jwk = key.export({ format: "jwk" }) as { x?: string; d?: string };
  const value = jwk[field];
  if (!value) {
    throw new CryptoError(`key export did not carry a JWK '${field}' field`);
  }
  return new Uint8Array(Buffer.from(value, "base64url"));
}

// ---------------------------------------------------------------------
// Ed25519 signing
// ---------------------------------------------------------------------

export interface Ed25519KeyPair {
  publicKey: Uint8Array;
  /** The 32-byte seed — "the private key IS the 32-byte seed" (conformance README). */
  privateKey: Uint8Array;
}

export function generateEd25519KeyPair(): Ed25519KeyPair {
  const priv = nodeCrypto.generateKeyPairSync("ed25519").privateKey;
  const pub = nodeCrypto.createPublicKey(priv);
  return {
    publicKey: rawOkpBytes(pub, "x"),
    privateKey: rawOkpBytes(priv, "d"),
  };
}

/** Derive the raw 32-byte Ed25519 public key for a raw 32-byte private key (seed). */
export function derivePublicKeyFromEd25519PrivateKey(privateKeySeed: Uint8Array): Uint8Array {
  const priv = ed25519PrivateKeyObject(privateKeySeed);
  const pub = nodeCrypto.createPublicKey(priv);
  return rawOkpBytes(pub, "x");
}

/** Sign with an Ed25519 seed (raw 32-byte private key). Returns a 64-byte signature. */
export function signEd25519(message: Uint8Array, privateKeySeed: Uint8Array): Uint8Array {
  const key = ed25519PrivateKeyObject(privateKeySeed);
  return new Uint8Array(nodeCrypto.sign(null, message, key));
}

/**
 * Verify an Ed25519 signature. Never throws — returns `false` for any
 * malformed input (wrong-length key/signature) or verification failure, so
 * callers can treat "invalid" uniformly regardless of cause.
 */
export function verifyEd25519(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    const key = ed25519PublicKeyObject(publicKey);
    return nodeCrypto.verify(null, message, key, signature);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------
// X25519 key agreement
// ---------------------------------------------------------------------

export interface X25519KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function generateX25519KeyPair(): X25519KeyPair {
  const priv = nodeCrypto.generateKeyPairSync("x25519").privateKey;
  const pub = nodeCrypto.createPublicKey(priv);
  return {
    publicKey: rawOkpBytes(pub, "x"),
    privateKey: rawOkpBytes(priv, "d"),
  };
}

/**
 * Derive the raw 32-byte X25519 public key for a raw 32-byte private key.
 * Needed on the callback-opening side of the sealed box, which must feed
 * its OWN public key (not the ephemeral sender's) into the KDF/AAD
 * construction — mirrors `local_rp.rs::open_local_rp_callback`'s
 * `X25519PublicKey::from(&recipient_secret)`.
 */
export function derivePublicKeyFromX25519PrivateKey(privateKey: Uint8Array): Uint8Array {
  const priv = x25519PrivateKeyObject(privateKey);
  const pub = nodeCrypto.createPublicKey(priv);
  return rawOkpBytes(pub, "x");
}

/**
 * X25519 Diffie-Hellman, rejecting a non-contributory (low-order) result —
 * mirrors `crates/liblinkkeys/src/crypto.rs`'s `reject_low_order`. OpenSSL
 * (Node's backend) already throws for the classic all-zero-output low-order
 * case during derivation itself (verified empirically: deriving against an
 * all-zero X25519 public key raises `ERR_OSSL_EVP_*`/"failed during
 * derivation" rather than silently returning zero bytes) — this function
 * treats that failure identically to an explicit all-zero check, so the
 * rejection happens whether OpenSSL catches it internally or the output
 * merely happens to be all-zero on some future Node/OpenSSL combination.
 */
export function x25519DiffieHellman(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  let shared: Buffer;
  try {
    shared = nodeCrypto.diffieHellman({
      privateKey: x25519PrivateKeyObject(privateKey),
      publicKey: x25519PublicKeyObject(publicKey),
    });
  } catch (e) {
    throw new CryptoError("non-contributory (low-order) public key rejected", { cause: e });
  }
  const out = new Uint8Array(shared);
  if (out.every((b) => b === 0)) {
    throw new CryptoError("non-contributory (low-order) public key rejected");
  }
  return out;
}

// ---------------------------------------------------------------------
// HKDF-SHA256
// ---------------------------------------------------------------------

/** HKDF-SHA256 with no salt, expanded to `length` bytes — matches `hkdf::Hkdf::<Sha256>::new(None, ikm).expand(info, ...)`. */
export function hkdfSha256Expand(ikm: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const out = nodeCrypto.hkdfSync("sha256", ikm, new Uint8Array(0), info, length);
  return new Uint8Array(out);
}

// ---------------------------------------------------------------------
// AEAD suite registry (crypto::AeadSuite)
// ---------------------------------------------------------------------

export const AEAD_SUITE_AES_256_GCM = "aes-256-gcm";
export const AEAD_SUITE_CHACHA20_POLY1305 = "chacha20-poly1305";

export type AeadSuite = typeof AEAD_SUITE_AES_256_GCM | typeof AEAD_SUITE_CHACHA20_POLY1305;

const ALL_SUITES: readonly AeadSuite[] = [AEAD_SUITE_AES_256_GCM, AEAD_SUITE_CHACHA20_POLY1305];

/** Parse a wire-format suite id string. Returns `undefined` for anything outside the registry — never "close enough". */
export function parseAeadSuite(s: string): AeadSuite | undefined {
  return (ALL_SUITES as readonly string[]).includes(s) ? (s as AeadSuite) : undefined;
}

export function allSupportedAeadSuites(): readonly AeadSuite[] {
  return ALL_SUITES;
}

/** First suite in `advertised` (preference order) that is a known registry member. Never picks outside `advertised`. */
export function selectSupportedAeadSuite(advertised: readonly string[]): AeadSuite | undefined {
  for (const s of advertised) {
    const parsed = parseAeadSuite(s);
    if (parsed) return parsed;
  }
  return undefined;
}

const AEAD_TAG_LENGTH = 16;
const AEAD_NONCE_LENGTH = 12;

/** Encrypt under the negotiated suite. Output is `ciphertext || 16-byte tag` (matches RustCrypto's `aes-gcm`/`chacha20poly1305` crate convention). */
export function aeadEncrypt(
  suite: AeadSuite,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  requireLen(key, 32, "AEAD key");
  requireLen(nonce, AEAD_NONCE_LENGTH, "AEAD nonce");
  // Branched (rather than passing `suite` straight through) so TypeScript
  // narrows to the matching `createCipheriv` overload: overload resolution
  // does not split a union-typed argument across Node's separate
  // CipherGCMTypes / CipherChaCha20Poly1305Types overloads.
  const cipher =
    suite === AEAD_SUITE_AES_256_GCM
      ? nodeCrypto.createCipheriv(suite, key, nonce, { authTagLength: AEAD_TAG_LENGTH })
      : nodeCrypto.createCipheriv(suite, key, nonce, { authTagLength: AEAD_TAG_LENGTH });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return new Uint8Array(Buffer.concat([ciphertext, tag]));
}

/** Decrypt `ciphertext || tag` under the negotiated suite. Throws `CryptoError` on any authentication failure (tampering, wrong key/nonce/AAD, truncation). */
export function aeadDecrypt(
  suite: AeadSuite,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertextWithTag: Uint8Array,
): Uint8Array {
  requireLen(key, 32, "AEAD key");
  requireLen(nonce, AEAD_NONCE_LENGTH, "AEAD nonce");
  if (ciphertextWithTag.length < AEAD_TAG_LENGTH) {
    throw new CryptoError("ciphertext shorter than the AEAD tag");
  }
  const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - AEAD_TAG_LENGTH);
  const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - AEAD_TAG_LENGTH);
  try {
    const decipher =
      suite === AEAD_SUITE_AES_256_GCM
        ? nodeCrypto.createDecipheriv(suite, key, nonce, { authTagLength: AEAD_TAG_LENGTH })
        : nodeCrypto.createDecipheriv(suite, key, nonce, { authTagLength: AEAD_TAG_LENGTH });
    decipher.setAAD(aad, { plaintextLength: ciphertext.length });
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return new Uint8Array(plaintext);
  } catch (e) {
    throw new CryptoError("AEAD decryption failed (tampering, wrong key, or wrong AAD)", {
      cause: e,
    });
  }
}
