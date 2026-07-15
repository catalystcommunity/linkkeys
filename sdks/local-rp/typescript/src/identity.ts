// `generateLocalRpIdentity` and the raw-byte storage helpers (design doc:
// "SDK API Shape", "Byte Storage Helpers"). Mirrors
// `sdks/local-rp/rust/src/identity.rs`.
//
// Security note (design doc, "Byte Storage Helpers"): the private key
// fields in `LocalRpKeyMaterial` do not directly identify a user, but they
// control this app's entire local RP identity — anyone holding them can
// sign login requests and redeem claim tickets as this app. Store them with
// ordinary application-secret care (the same tier as a database credential
// or API key), not merely as configuration.

import { allSupportedAeadSuites, generateEd25519KeyPair, generateX25519KeyPair } from "./crypto.ts";
import * as generated from "./generated/codec.gen.ts";
import type { SignedLocalRpDescriptor } from "./generated/types.gen.ts";
import { isValidFingerprint } from "./dnsRecords.ts";
import { buildLocalRpDescriptor, signLocalRpDescriptor } from "./localRp.ts";

/** Default local RP key lifetime: 10 years (design doc: "Default lifetime: 10 years."). */
export const DEFAULT_LIFETIME_MS = 3650 * 24 * 60 * 60 * 1000;

export class InvalidInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidInputError";
  }
}

/** Input to `generateLocalRpIdentity`. Big-config, single object, per the design doc's "SDK API Shape". */
export interface GenerateLocalRpIdentityConfig {
  /** Display name shown on the IDP's consent screen. NOT identity — display/audit metadata only. */
  appName: string;
  /** Optional local domain/origin hint (e.g. `jukebox.lan`), also display/audit metadata. */
  localDomainHint?: string;
  /** AEAD suites this app can decrypt callbacks with, in preference order. Defaults to both registry suites when omitted. */
  supportedSuites?: readonly string[];
  /** Key/descriptor lifetime from `now`, in milliseconds. Defaults to `DEFAULT_LIFETIME_MS`. */
  lifetimeMs?: number;
  now: Date;
}

/** A local RP's full key material: signing keypair, encryption keypair, the self-signed descriptor, and the identity fingerprint. */
export interface LocalRpKeyMaterial {
  signingPrivateKey: Uint8Array;
  signingPublicKey: Uint8Array;
  encryptionPrivateKey: Uint8Array;
  encryptionPublicKey: Uint8Array;
  descriptor: SignedLocalRpDescriptor;
  fingerprint: string;
}

/**
 * `generate_local_rp_identity(config) -> LocalRpKeyMaterial`. Generates a
 * fresh Ed25519 signing keypair and a SEPARATE X25519 encryption keypair
 * (never algebraically derived — design doc, "Encryption Key Is Separate,
 * Not Derived"), builds and self-signs the descriptor binding them.
 */
export function generateLocalRpIdentity(config: GenerateLocalRpIdentityConfig): LocalRpKeyMaterial {
  if (config.appName.trim().length === 0) {
    throw new InvalidInputError("appName must not be empty");
  }

  const signing = generateEd25519KeyPair();
  const encryption = generateX25519KeyPair();

  const suites = config.supportedSuites ?? allSupportedAeadSuites();
  if (suites.length === 0) {
    throw new InvalidInputError("supportedSuites must not be empty");
  }

  const lifetimeMs = config.lifetimeMs ?? DEFAULT_LIFETIME_MS;
  const createdAt = config.now.toISOString();
  const expiresAt = new Date(config.now.getTime() + lifetimeMs).toISOString();

  const descriptor = buildLocalRpDescriptor(
    config.appName,
    config.localDomainHint,
    signing.publicKey,
    encryption.publicKey,
    suites,
    createdAt,
    expiresAt,
  );
  const fp = descriptor.fingerprint;
  const signedDescriptor = signLocalRpDescriptor(descriptor, signing.privateKey);

  return {
    signingPrivateKey: signing.privateKey,
    signingPublicKey: signing.publicKey,
    encryptionPrivateKey: encryption.privateKey,
    encryptionPublicKey: encryption.publicKey,
    descriptor: signedDescriptor,
    fingerprint: fp,
  };
}

// ---------------------------------------------------------------------
// Byte storage helpers (design doc: "Byte Storage Helpers")
// ---------------------------------------------------------------------

function requireKeyLength(bytes: Uint8Array, what: string): Uint8Array {
  if (bytes.length !== 32) {
    throw new InvalidInputError(`${what} must be 32 bytes, got ${bytes.length}`);
  }
  return bytes;
}

export function signingKeyToBytes(key: Uint8Array): Uint8Array {
  return key;
}

export function signingKeyFromBytes(bytes: Uint8Array): Uint8Array {
  return requireKeyLength(bytes, "signing key");
}

export function encryptionKeyToBytes(key: Uint8Array): Uint8Array {
  return key;
}

export function encryptionKeyFromBytes(bytes: Uint8Array): Uint8Array {
  return requireKeyLength(bytes, "encryption key");
}

/** The canonical fingerprint string form — a pass-through, since the fingerprint IS a hex string. */
export function fingerprintToString(fp: string): string {
  return fp;
}

/** Parse/validate a fingerprint string: exactly 64 lowercase-normalized hex characters. */
export function fingerprintFromString(s: string): string {
  if (!isValidFingerprint(s)) {
    throw new InvalidInputError(`not a valid fingerprint (want 64 hex chars): ${JSON.stringify(s)}`);
  }
  return s.toLowerCase();
}

/**
 * Magic prefix for the identity-bundle byte format below. SDK-local storage
 * convenience, NOT a protocol wire format — no conformance vector governs
 * it. Versioned so a future incompatible layout change fails loudly instead
 * of silently misparsing.
 */
const IDENTITY_BUNDLE_MAGIC = new TextEncoder().encode("LKI1");
const HEADER_LEN = 4 + 32 + 32 + 4;

/**
 * `local_rp_identity_to_bytes(identity) -> bytes`. Packs both private keys
 * and the signed descriptor into one opaque blob: `MAGIC(4) ||
 * signing_private_key(32) || encryption_private_key(32) ||
 * descriptor_len(4, BE) || descriptor_cbor`.
 */
export function localRpIdentityToBytes(identity: LocalRpKeyMaterial): Uint8Array {
  const descriptorBytes = generated.toSignedLocalRpDescriptorCbor(identity.descriptor);
  const out = new Uint8Array(HEADER_LEN + descriptorBytes.length);
  let offset = 0;
  out.set(IDENTITY_BUNDLE_MAGIC, offset);
  offset += 4;
  out.set(requireKeyLength(identity.signingPrivateKey, "signing private key"), offset);
  offset += 32;
  out.set(requireKeyLength(identity.encryptionPrivateKey, "encryption private key"), offset);
  offset += 32;
  new DataView(out.buffer, out.byteOffset + offset, 4).setUint32(0, descriptorBytes.length, false);
  offset += 4;
  out.set(descriptorBytes, offset);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** The inverse of `localRpIdentityToBytes`. Does no signature/expiry verification — see `checkExpirations` and the protocol verification chain for that. */
export function localRpIdentityFromBytes(bytes: Uint8Array): LocalRpKeyMaterial {
  if (bytes.length < HEADER_LEN) {
    throw new InvalidInputError("identity bundle too short");
  }
  if (!bytesEqual(bytes.subarray(0, 4), IDENTITY_BUNDLE_MAGIC)) {
    throw new InvalidInputError("identity bundle has an unrecognized magic prefix");
  }
  const signingPrivateKey = bytes.subarray(4, 36);
  const encryptionPrivateKey = bytes.subarray(36, 68);
  const descriptorLen = new DataView(bytes.buffer, bytes.byteOffset + 68, 4).getUint32(0, false);
  const descriptorBytes = bytes.subarray(HEADER_LEN, HEADER_LEN + descriptorLen);
  if (descriptorBytes.length !== descriptorLen) {
    throw new InvalidInputError("identity bundle descriptor length exceeds available bytes");
  }

  let signedDescriptor: SignedLocalRpDescriptor;
  let descriptor;
  try {
    signedDescriptor = generated.fromSignedLocalRpDescriptorCbor(descriptorBytes);
    descriptor = generated.fromLocalRpDescriptorCbor(signedDescriptor.descriptor);
  } catch (e) {
    throw new InvalidInputError(`identity bundle descriptor decode failed: ${e}`);
  }

  if (descriptor.signingPublicKey.length !== 32 || descriptor.encryptionPublicKey.length !== 32) {
    throw new InvalidInputError("descriptor public key was not 32 bytes");
  }

  return {
    signingPrivateKey: new Uint8Array(signingPrivateKey),
    signingPublicKey: descriptor.signingPublicKey,
    encryptionPrivateKey: new Uint8Array(encryptionPrivateKey),
    encryptionPublicKey: descriptor.encryptionPublicKey,
    descriptor: signedDescriptor,
    fingerprint: descriptor.fingerprint,
  };
}
