// Pure DNS-less local RP protocol helpers — the TypeScript twin of
// `crates/liblinkkeys/src/local_rp.rs`. See `dns-less-local-rp-design.md` at
// the repo root, especially "Wire Precision (Normative)", which this module
// implements byte-for-byte. No I/O happens here: every "current time" is an
// explicit `now: Date` parameter.

import { encodeCborTuple, text, bytes as tupleBytes } from "./cborTuple.ts";
import {
  aeadDecrypt,
  aeadEncrypt,
  constantTimeEqual,
  derivePublicKeyFromX25519PrivateKey,
  fingerprint,
  generateX25519KeyPair,
  hkdfSha256Expand,
  parseAeadSuite,
  randomBytes,
  signEd25519,
  verifyEd25519,
  x25519DiffieHellman,
  type AeadSuite,
} from "./crypto.ts";
import * as generated from "./generated/codec.gen.ts";
import type {
  DomainPublicKey,
  LocalRpCallbackHeader,
  LocalRpCallbackPayload,
  LocalRpDescriptor,
  LocalRpEncryptedCallback,
  LocalRpLoginRequest,
  LocalRpTicketRedemptionRequest,
  SignedLocalRpCallbackPayload,
  SignedLocalRpDescriptor,
  SignedLocalRpLoginRequest,
  SignedLocalRpTicketRedemptionRequest,
} from "./generated/types.gen.ts";

export const CTX_LOCAL_RP_DESCRIPTOR = "linkkeys-local-rp-descriptor";
export const CTX_LOCAL_RP_LOGIN_REQUEST = "linkkeys-local-rp-login-request";
export const CTX_LOCAL_RP_CALLBACK = "linkkeys-local-rp-callback";
export const CTX_LOCAL_RP_TICKET_REDEMPTION = "linkkeys-local-rp-ticket-redemption";

/** Default bounded clock-skew tolerance (seconds) for timestamp checks. */
export const DEFAULT_CLOCK_SKEW_SECONDS = 300;

const LOCAL_RP_CALLBACK_BOX_TAG = new TextEncoder().encode("linkkeys-local-rp-callback-box");

export type LocalRpErrorCode =
  | "decode"
  | "invalid-key-length"
  | "fingerprint-mismatch"
  | "not-yet-valid"
  | "expired"
  | "bad-timestamp"
  | "nonce-mismatch"
  | "state-mismatch"
  | "audience-mismatch"
  | "issuer-mismatch"
  | "callback-url-mismatch"
  | "unsupported-suite"
  | "suite-not-advertised"
  | "header-payload-mismatch"
  | "signature-invalid"
  | "key-not-found"
  | "key-revoked"
  | "key-expired"
  | "redemption-identity-mismatch"
  | "claim-identity-mismatch"
  | "required-claim-missing";

export class LocalRpError extends Error {
  readonly code: LocalRpErrorCode;
  constructor(code: LocalRpErrorCode, message?: string, options?: { cause?: unknown }) {
    super(message ?? code, options);
    this.name = "LocalRpError";
    this.code = code;
  }
}

/**
 * The signature input for every local-RP signed structure:
 * `CBOR([context, payload_bytes])` — a two-element array, context string
 * first, exact payload bytes second (as a CBOR byte string). Deliberately
 * NOT a bare `context || payload` concatenation (Wire Precision, "Signature
 * input bytes").
 */
export function envelopeSignatureInput(context: string, payloadBytes: Uint8Array): Uint8Array {
  return encodeCborTuple([text(context), tupleBytes(payloadBytes)]);
}

function parseTimestamp(s: string): Date {
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) {
    throw new LocalRpError("bad-timestamp", `invalid RFC3339 timestamp: ${s}`);
  }
  return d;
}

/** Check `(issuedAt, expiresAt)` against `now`, tolerant of `skewSeconds` clock skew in either direction. Boundaries are inclusive. */
export function checkTimestamps(
  issuedAt: string,
  expiresAt: string,
  now: Date,
  skewSeconds: number,
): void {
  const issued = parseTimestamp(issuedAt);
  const expires = parseTimestamp(expiresAt);
  const skewMs = skewSeconds * 1000;

  if (now.getTime() + skewMs < issued.getTime()) {
    throw new LocalRpError("not-yet-valid");
  }
  if (now.getTime() - skewMs > expires.getTime()) {
    throw new LocalRpError("expired");
  }
}

export type ExpirationLevel = "ok" | "notice" | "warning" | "critical" | "expired";

export interface ExpirationStatus {
  level: ExpirationLevel;
  expiresAt: Date;
  now: Date;
}

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * `check_expirations(identity, now) -> ExpirationStatus` (design doc,
 * "Expiration Helper"): `notice` at 180 days remaining, `warning` at 90,
 * `critical` at 30, `expired` once `now >= expiresAt`. No clock-skew
 * tolerance (advisory, day-scale thresholds, not a freshness security
 * boundary).
 */
export function checkExpirations(expiresAt: string, now: Date): ExpirationStatus {
  const expires = parseTimestamp(expiresAt);
  const remainingMs = expires.getTime() - now.getTime();
  let level: ExpirationLevel;
  if (now.getTime() >= expires.getTime()) {
    level = "expired";
  } else if (remainingMs <= 30 * DAY_MS) {
    level = "critical";
  } else if (remainingMs <= 90 * DAY_MS) {
    level = "warning";
  } else if (remainingMs <= 180 * DAY_MS) {
    level = "notice";
  } else {
    level = "ok";
  }
  return { level, expiresAt: expires, now };
}

/**
 * Nonce/state equality against the pending login state. Uses
 * `constantTimeEqual` (`crypto.timingSafeEqual`), not a short-circuiting
 * byte compare — these values gate CSRF/replay protection, so how many
 * leading bytes matched must not leak via timing.
 */
export function verifyNonceState(
  expectedNonce: Uint8Array,
  expectedState: Uint8Array,
  actualNonce: Uint8Array,
  actualState: Uint8Array,
): void {
  if (!constantTimeEqual(expectedNonce, actualNonce)) {
    throw new LocalRpError("nonce-mismatch");
  }
  if (!constantTimeEqual(expectedState, actualState)) {
    throw new LocalRpError("state-mismatch");
  }
}

export function verifyAudience(payloadAudienceFingerprint: string, localRpFingerprint: string): void {
  if (payloadAudienceFingerprint !== localRpFingerprint) {
    throw new LocalRpError("audience-mismatch");
  }
}

export function verifyIssuer(payloadUserDomain: string, expectedDomain: string): void {
  if (payloadUserDomain !== expectedDomain) {
    throw new LocalRpError("issuer-mismatch");
  }
}

export function verifyCallbackUrl(payloadCallbackUrl: string, arrivedUrl: string): void {
  if (payloadCallbackUrl !== arrivedUrl) {
    throw new LocalRpError("callback-url-mismatch");
  }
}

// ---------------------------------------------------------------------
// Descriptor
// ---------------------------------------------------------------------

export function buildLocalRpDescriptor(
  appName: string,
  localDomainHint: string | undefined,
  signingPublicKey: Uint8Array,
  encryptionPublicKey: Uint8Array,
  supportedSuites: readonly string[],
  createdAt: string,
  expiresAt: string,
): LocalRpDescriptor {
  return {
    appName,
    localDomainHint,
    signingPublicKey,
    encryptionPublicKey,
    fingerprint: fingerprint(signingPublicKey),
    supportedSuites: [...supportedSuites],
    createdAt,
    expiresAt,
  };
}

export function signLocalRpDescriptor(
  descriptor: LocalRpDescriptor,
  privateKeySeed: Uint8Array,
): SignedLocalRpDescriptor {
  const descriptorBytes = generated.toLocalRpDescriptorCbor(descriptor);
  const signatureInput = envelopeSignatureInput(CTX_LOCAL_RP_DESCRIPTOR, descriptorBytes);
  return {
    descriptor: descriptorBytes,
    signature: signEd25519(signatureInput, privateKeySeed),
  };
}

export function verifyLocalRpDescriptor(
  signed: SignedLocalRpDescriptor,
  now: Date,
  skewSeconds: number,
): LocalRpDescriptor {
  let descriptor: LocalRpDescriptor;
  try {
    descriptor = generated.fromLocalRpDescriptorCbor(signed.descriptor);
  } catch (e) {
    throw new LocalRpError("decode", `descriptor: ${e}`, { cause: e });
  }

  if (descriptor.signingPublicKey.length !== 32) {
    throw new LocalRpError("invalid-key-length");
  }

  const expectedFingerprint = fingerprint(descriptor.signingPublicKey);
  if (descriptor.fingerprint !== expectedFingerprint) {
    throw new LocalRpError("fingerprint-mismatch");
  }

  const signatureInput = envelopeSignatureInput(CTX_LOCAL_RP_DESCRIPTOR, signed.descriptor);
  if (!verifyEd25519(signatureInput, signed.signature, descriptor.signingPublicKey)) {
    throw new LocalRpError("signature-invalid");
  }

  checkTimestamps(descriptor.createdAt, descriptor.expiresAt, now, skewSeconds);

  return descriptor;
}

// ---------------------------------------------------------------------
// Login request
// ---------------------------------------------------------------------

export function buildLocalRpLoginRequest(
  descriptor: SignedLocalRpDescriptor,
  callbackUrl: string,
  nonce: Uint8Array,
  state: Uint8Array,
  requestedClaims: readonly string[],
  requiredClaims: readonly string[],
  issuedAt: string,
  expiresAt: string,
): LocalRpLoginRequest {
  return {
    descriptor,
    callbackUrl,
    nonce,
    state,
    requestedClaims: [...requestedClaims],
    requiredClaims: [...requiredClaims],
    issuedAt,
    expiresAt,
  };
}

export function signLocalRpLoginRequest(
  request: LocalRpLoginRequest,
  privateKeySeed: Uint8Array,
): SignedLocalRpLoginRequest {
  const requestBytes = generated.toLocalRpLoginRequestCbor(request);
  const signatureInput = envelopeSignatureInput(CTX_LOCAL_RP_LOGIN_REQUEST, requestBytes);
  return {
    request: requestBytes,
    signature: signEd25519(signatureInput, privateKeySeed),
  };
}

export function verifyLocalRpLoginRequest(
  signed: SignedLocalRpLoginRequest,
  now: Date,
  skewSeconds: number,
): LocalRpLoginRequest {
  let request: LocalRpLoginRequest;
  try {
    request = generated.fromLocalRpLoginRequestCbor(signed.request);
  } catch (e) {
    throw new LocalRpError("decode", `login request: ${e}`, { cause: e });
  }

  const descriptor = verifyLocalRpDescriptor(request.descriptor, now, skewSeconds);

  const signatureInput = envelopeSignatureInput(CTX_LOCAL_RP_LOGIN_REQUEST, signed.request);
  if (!verifyEd25519(signatureInput, signed.signature, descriptor.signingPublicKey)) {
    throw new LocalRpError("signature-invalid");
  }

  checkTimestamps(request.issuedAt, request.expiresAt, now, skewSeconds);

  return request;
}

// ---------------------------------------------------------------------
// Ticket redemption
// ---------------------------------------------------------------------

export function buildLocalRpTicketRedemptionRequest(
  claimTicket: Uint8Array,
  fp: string,
  issuedAt: string,
): LocalRpTicketRedemptionRequest {
  return { claimTicket, fingerprint: fp, issuedAt };
}

export function signLocalRpTicketRedemptionRequest(
  request: LocalRpTicketRedemptionRequest,
  privateKeySeed: Uint8Array,
): SignedLocalRpTicketRedemptionRequest {
  const requestBytes = generated.toLocalRpTicketRedemptionRequestCbor(request);
  const signatureInput = envelopeSignatureInput(CTX_LOCAL_RP_TICKET_REDEMPTION, requestBytes);
  return {
    request: requestBytes,
    signature: signEd25519(signatureInput, privateKeySeed),
  };
}

// ---------------------------------------------------------------------
// Callback payload (domain-signed envelope)
// ---------------------------------------------------------------------

export function buildLocalRpCallbackPayload(
  userId: string,
  userDomain: string,
  claimTicket: Uint8Array,
  audienceFingerprint: string,
  callbackUrl: string,
  nonce: Uint8Array,
  state: Uint8Array,
  issuedAt: string,
  expiresAt: string,
): LocalRpCallbackPayload {
  return {
    userId,
    userDomain,
    claimTicket,
    audienceFingerprint,
    callbackUrl,
    nonce,
    state,
    issuedAt,
    expiresAt,
  };
}

export function signLocalRpCallbackPayload(
  payload: LocalRpCallbackPayload,
  keyId: string,
  privateKeySeed: Uint8Array,
): SignedLocalRpCallbackPayload {
  const payloadBytes = generated.toLocalRpCallbackPayloadCbor(payload);
  const signatureInput = envelopeSignatureInput(CTX_LOCAL_RP_CALLBACK, payloadBytes);
  return {
    payload: payloadBytes,
    signingKeyId: keyId,
    signature: signEd25519(signatureInput, privateKeySeed),
  };
}

/** Validity of a signing key at `now`: revoked keys reject outright; `expiresAt` is the automatic backstop. Mirrors `crypto::signing_key_validity`. */
function isSigningKeyCurrentlyValid(key: DomainPublicKey, now: Date): "valid" | "revoked" | "expired" {
  if (key.revokedAt !== undefined) return "revoked";
  const expires = new Date(key.expiresAt);
  if (Number.isNaN(expires.getTime())) return "expired";
  return now.getTime() > expires.getTime() ? "expired" : "valid";
}

function checkSigningKeyValid(key: DomainPublicKey, now: Date): void {
  if (key.keyUsage !== "sign") {
    throw new LocalRpError("signature-invalid");
  }
  const validity = isSigningKeyCurrentlyValid(key, now);
  if (validity === "revoked") throw new LocalRpError("key-revoked", key.keyId);
  if (validity === "expired") throw new LocalRpError("key-expired", key.keyId);
}

/**
 * Verify a domain-signed callback payload envelope against a set of domain
 * public keys: resolve `signingKeyId`, reject a revoked/expired/non-signing
 * key, verify the envelope signature (Ed25519 only — the only algorithm this
 * registry defines), decode, then check `issuedAt`/`expiresAt` bounds.
 */
export function verifyLocalRpCallbackPayload(
  signed: SignedLocalRpCallbackPayload,
  domainPublicKeys: readonly DomainPublicKey[],
  now: Date,
  skewSeconds: number,
): LocalRpCallbackPayload {
  const key = domainPublicKeys.find((k) => k.keyId === signed.signingKeyId);
  if (!key) {
    throw new LocalRpError("key-not-found", signed.signingKeyId);
  }
  checkSigningKeyValid(key, now);

  if (key.algorithm !== "ed25519") {
    throw new LocalRpError("signature-invalid", `unsupported algorithm: ${key.algorithm}`);
  }

  const signatureInput = envelopeSignatureInput(CTX_LOCAL_RP_CALLBACK, signed.payload);
  if (!verifyEd25519(signatureInput, signed.signature, key.publicKey)) {
    throw new LocalRpError("signature-invalid");
  }

  let payload: LocalRpCallbackPayload;
  try {
    payload = generated.fromLocalRpCallbackPayloadCbor(signed.payload);
  } catch (e) {
    throw new LocalRpError("decode", `callback payload: ${e}`, { cause: e });
  }

  checkTimestamps(payload.issuedAt, payload.expiresAt, now, skewSeconds);

  return payload;
}

/**
 * Cross-check the cleartext callback header's routing fields against the
 * authoritative copies inside the decrypted, signature-verified payload. The
 * header is already bound as AEAD associated data, but a verifier must still
 * consult the signed copies rather than trusting the header alone.
 */
export function checkCallbackHeaderMatchesPayload(
  header: LocalRpCallbackHeader,
  payload: LocalRpCallbackPayload,
): void {
  if (header.fingerprint !== payload.audienceFingerprint) {
    throw new LocalRpError("header-payload-mismatch", "fingerprint");
  }
  if (!constantTimeEqual(header.nonce, payload.nonce)) {
    throw new LocalRpError("header-payload-mismatch", "nonce");
  }
  if (!constantTimeEqual(header.state, payload.state)) {
    throw new LocalRpError("header-payload-mismatch", "state");
  }
  if (header.issuedAt !== payload.issuedAt) {
    throw new LocalRpError("header-payload-mismatch", "issuedAt");
  }
  if (header.expiresAt !== payload.expiresAt) {
    throw new LocalRpError("header-payload-mismatch", "expiresAt");
  }
}

// ---------------------------------------------------------------------
// Callback sealed box (Wire Precision: "Callback sealed box")
// ---------------------------------------------------------------------

/**
 * Derive the AEAD key and KDF `info`/AAD-prefix context for the local-RP
 * callback sealed box: `tag || suite_id_utf8 || ephemeral_public(32) ||
 * recipient_public(32)`. HKDF-SHA256, no salt, expanded to 32 bytes.
 */
function localRpCallbackKdf(
  suite: AeadSuite,
  ephemeralPublic: Uint8Array,
  recipientPublic: Uint8Array,
  sharedSecret: Uint8Array,
): { aeadKey: Uint8Array; context: Uint8Array } {
  const suiteId = new TextEncoder().encode(suite);
  const context = new Uint8Array(
    LOCAL_RP_CALLBACK_BOX_TAG.length + suiteId.length + ephemeralPublic.length + recipientPublic.length,
  );
  let offset = 0;
  context.set(LOCAL_RP_CALLBACK_BOX_TAG, offset);
  offset += LOCAL_RP_CALLBACK_BOX_TAG.length;
  context.set(suiteId, offset);
  offset += suiteId.length;
  context.set(ephemeralPublic, offset);
  offset += ephemeralPublic.length;
  context.set(recipientPublic, offset);

  const aeadKey = hkdfSha256Expand(sharedSecret, context, 32);
  return { aeadKey, context };
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Seal a `SignedLocalRpCallbackPayload` (the exact bytes to encrypt) into a
 * `LocalRpEncryptedCallback` for `recipientEncryptionPublicKey`, under
 * `suite`. Fresh ephemeral X25519 keypair and AEAD nonce every call.
 */
export function sealLocalRpCallback(
  signedPayload: SignedLocalRpCallbackPayload,
  suite: AeadSuite,
  recipientEncryptionPublicKey: Uint8Array,
  fp: string,
  nonce: Uint8Array,
  state: Uint8Array,
  issuedAt: string,
  expiresAt: string,
): LocalRpEncryptedCallback {
  const ephemeral = generateX25519KeyPair();
  const aeadNonce = randomBytes(12);
  return sealLocalRpCallbackInner(
    signedPayload,
    suite,
    recipientEncryptionPublicKey,
    fp,
    nonce,
    state,
    issuedAt,
    expiresAt,
    ephemeral,
    aeadNonce,
  );
}

function sealLocalRpCallbackInner(
  signedPayload: SignedLocalRpCallbackPayload,
  suite: AeadSuite,
  recipientEncryptionPublicKey: Uint8Array,
  fp: string,
  nonce: Uint8Array,
  state: Uint8Array,
  issuedAt: string,
  expiresAt: string,
  ephemeral: { publicKey: Uint8Array; privateKey: Uint8Array },
  aeadNonce: Uint8Array,
): LocalRpEncryptedCallback {
  const plaintext = generated.toSignedLocalRpCallbackPayloadCbor(signedPayload);

  const sharedSecret = x25519DiffieHellman(ephemeral.privateKey, recipientEncryptionPublicKey);

  const header: LocalRpCallbackHeader = {
    fingerprint: fp,
    nonce,
    state,
    suite,
    ephemeralPublicKey: ephemeral.publicKey,
    aeadNonce,
    issuedAt,
    expiresAt,
  };
  const headerBytes = generated.toLocalRpCallbackHeaderCbor(header);

  const { aeadKey, context } = localRpCallbackKdf(
    suite,
    ephemeral.publicKey,
    recipientEncryptionPublicKey,
    sharedSecret,
  );
  const aad = concatBytes(context, headerBytes);

  const ciphertext = aeadEncrypt(suite, aeadKey, aeadNonce, aad, plaintext);

  return { header: headerBytes, ciphertext };
}

/**
 * Open a `LocalRpEncryptedCallback` with the local RP's encryption private
 * key. `allowedSuites` is this identity's own advertised-suite list: a
 * header naming a suite NOT in that list is rejected even if it is otherwise
 * a valid registry id (Wire Precision).
 *
 * Returns the decoded header and the still-signature-unverified
 * `SignedLocalRpCallbackPayload` — callers must still call
 * `verifyLocalRpCallbackPayload` against fetched domain keys, then
 * `checkCallbackHeaderMatchesPayload`, before trusting the result.
 */
export function openLocalRpCallback(
  encrypted: LocalRpEncryptedCallback,
  recipientEncryptionPrivateKey: Uint8Array,
  allowedSuites: readonly AeadSuite[],
): { header: LocalRpCallbackHeader; signedPayload: SignedLocalRpCallbackPayload } {
  let header: LocalRpCallbackHeader;
  try {
    header = generated.fromLocalRpCallbackHeaderCbor(encrypted.header);
  } catch (e) {
    throw new LocalRpError("decode", `callback header: ${e}`, { cause: e });
  }

  const suite = parseAeadSuite(header.suite);
  if (!suite) {
    throw new LocalRpError("unsupported-suite", header.suite);
  }
  if (!allowedSuites.includes(suite)) {
    throw new LocalRpError("suite-not-advertised", header.suite);
  }

  if (header.ephemeralPublicKey.length !== 32 || header.aeadNonce.length !== 12) {
    throw new LocalRpError("invalid-key-length");
  }

  const recipientPublic = derivePublicKeyFromX25519PrivateKey(recipientEncryptionPrivateKey);
  const sharedSecret = x25519DiffieHellman(recipientEncryptionPrivateKey, header.ephemeralPublicKey);

  const { aeadKey, context } = localRpCallbackKdf(
    suite,
    header.ephemeralPublicKey,
    recipientPublic,
    sharedSecret,
  );
  const aad = concatBytes(context, encrypted.header);

  let plaintext: Uint8Array;
  try {
    plaintext = aeadDecrypt(suite, aeadKey, header.aeadNonce, aad, encrypted.ciphertext);
  } catch (e) {
    throw new LocalRpError("decode", `callback AEAD open failed: ${e}`, { cause: e });
  }

  let signedPayload: SignedLocalRpCallbackPayload;
  try {
    signedPayload = generated.fromSignedLocalRpCallbackPayloadCbor(plaintext);
  } catch (e) {
    throw new LocalRpError("decode", `signed callback payload: ${e}`, { cause: e });
  }

  return { header, signedPayload };
}
