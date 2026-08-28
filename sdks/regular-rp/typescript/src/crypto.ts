import * as nodeCrypto from "node:crypto";

export class CryptoError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "CryptoError";
  }
}

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function requireLength(bytes: Uint8Array, length: number, name: string): void {
  if (bytes.length !== length) throw new CryptoError(`${name} must be ${length} bytes`);
}

function privateKey(seed: Uint8Array): nodeCrypto.KeyObject {
  requireLength(seed, 32, "Ed25519 private key seed");
  return nodeCrypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function publicKey(raw: Uint8Array): nodeCrypto.KeyObject {
  requireLength(raw, 32, "Ed25519 public key");
  return nodeCrypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

/** Return the LinkKeys SHA-256 fingerprint for raw public-key bytes. */
export function fingerprint(publicKeyBytes: Uint8Array): string {
  return nodeCrypto.createHash("sha256").update(publicKeyBytes).digest("hex");
}

/** Derive a raw Ed25519 public key from a raw 32-byte seed. */
export function derivePublicKeyFromEd25519PrivateKey(seed: Uint8Array): Uint8Array {
  const key = nodeCrypto.createPublicKey(privateKey(seed));
  const jwk = key.export({ format: "jwk" }) as { x?: string };
  if (!jwk.x) throw new CryptoError("the public key export has no x value");
  return new Uint8Array(Buffer.from(jwk.x, "base64url"));
}

/** Sign bytes with a raw Ed25519 seed. */
export function signEd25519(message: Uint8Array, seed: Uint8Array): Uint8Array {
  return new Uint8Array(nodeCrypto.sign(null, message, privateKey(seed)));
}

/** Verify an Ed25519 signature. Return false for malformed input. */
export function verifyEd25519(
  message: Uint8Array,
  signature: Uint8Array,
  rawPublicKey: Uint8Array,
): boolean {
  try {
    return nodeCrypto.verify(null, message, publicKey(rawPublicKey), signature);
  } catch {
    return false;
  }
}
