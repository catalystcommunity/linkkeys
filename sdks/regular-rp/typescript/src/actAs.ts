// Act-as grants: a user lets one application (the grantee) act as the user at
// a second application (the audience). The user's home domain signs the
// user's decision. The audience defines, signs, and enforces the scope.
//
// This file is the TypeScript port of `crates/liblinkkeys/src/act_as.rs`. The
// rules, their order, and their boundaries are the same as in Rust. Read
// `docs/spec/reserved/act-as-grants.md` for the protocol.
//
// Pure functions only: no network, no storage, no clock of its own. Every
// temporal function takes `now`. The home-domain signing side (build, sign,
// and renew a grant, sign a revocation) is not ported. An application never
// holds a domain key.
//
// One difference from Rust: Rust checks a DOMAIN signing key's validity
// against the wall clock. This SDK takes `now` for that check, the same as
// the existing `verifyAttestationSignature`. Pass the current time. The same
// holds for a handle claim's expiry in `verifyHandleClaim`.
//
// One addition: `signGrantRequest` refuses a handle claim that
// `verifyGrantRequest` would refuse, so the grantee sees the error before it
// sends the request.

import {
  fromActAsCredentialCbor,
  fromActAsGrantCbor,
  fromActAsGrantRequestCbor,
  fromActAsGrantRevocationCbor,
  fromActAsPresentationCbor,
  fromActAsRefreshRequestCbor,
  fromActAsScopeSetCbor,
  fromLocalRpDescriptorCbor,
  toActAsGrantRequestCbor,
  toActAsPresentationCbor,
  toActAsRefreshRequestCbor,
  toActAsScopeSetCbor,
} from "../generated/codec.gen.ts";
import type {
  ActAsCredential,
  ActAsGrant,
  ActAsGrantRequest,
  ActAsGrantRevocation,
  ActAsRefreshRequest,
  ActAsScopeSet,
  ApplicationKeySignature,
  ApplicationRef,
  Claim,
  ClaimSignature,
  DomainPublicKey,
  GranteeProof,
  GranteeRef,
  LocalRpDescriptor,
  SignedActAsGrant,
  SignedActAsGrantRequest,
  SignedActAsGrantRevocation,
  SignedActAsRefreshRequest,
  SignedActAsScopeSet,
  SignedLocalRpDescriptor,
} from "../generated/types.gen.ts";
import { KEY_USAGE_SIGN, type ApplicationKeyRef, type VerifiedApplicationKeySet } from "./applicationKeys.ts";
import { bytes as bytesElem, encodeCborTuple, text } from "./cborTuple.ts";
import { verifyClaim } from "./claims.ts";
import { fingerprint, signEd25519, verifyEd25519 } from "./crypto.ts";
import { createHash } from "node:crypto";

// ---------------------------------------------------------------------------
// Domain-separation tags
// ---------------------------------------------------------------------------

/** The audience's signature over the scope set it offers one grantee. */
export const ACT_AS_SCOPE_SET_TAG = "linkkeys-act-as-scope-set-v1alpha";
/** The home domain's signature over a grant. */
export const ACT_AS_GRANT_TAG = "linkkeys-act-as-grant-v1alpha";
/** The grantee's signature over a grant request. */
export const ACT_AS_GRANT_REQUEST_TAG = "linkkeys-act-as-grant-request-v1alpha";
/** The grantee's signature over a refresh request. */
export const ACT_AS_REFRESH_REQUEST_TAG = "linkkeys-act-as-refresh-request-v1alpha";
/** The grantee's signature over one presentation to the audience. */
export const ACT_AS_PRESENTATION_TAG = "linkkeys-act-as-presentation-v1alpha";
/** The home domain's signature over a grant revocation. */
export const ACT_AS_GRANT_REVOCATION_TAG = "linkkeys-act-as-grant-revocation-v1alpha";
/** A local RP's signature over its own descriptor (`local_rp.rs`). */
export const LOCAL_RP_DESCRIPTOR_TAG = "linkkeys-local-rp-descriptor-v1alpha";

// ---------------------------------------------------------------------------
// Defaults and bounds
// ---------------------------------------------------------------------------

/** Default grant lifetime: one hour. */
export const ACT_AS_DEFAULT_LIFETIME_SECONDS = 3_600;
/** Default largest lifetime a user can choose: one day. */
export const ACT_AS_DEFAULT_MAX_LIFETIME_SECONDS = 86_400;
/** Default renewal window: no renewal. */
export const ACT_AS_DEFAULT_RENEWAL_WINDOW_SECONDS = 0;
/** Default largest renewal window a user can choose: 30 days. */
export const ACT_AS_DEFAULT_MAX_RENEWAL_WINDOW_SECONDS = 30 * 86_400;
/** Most grant ids one revocation read accepts. */
export const ACT_AS_MAX_REVOCATION_LOOKUP_IDS = 100;
/** Most entries one scope set can carry. */
export const ACT_AS_MAX_SCOPE_ENTRIES = 64;
/** Longest scope string, in UTF-8 bytes. */
export const ACT_AS_MAX_SCOPE_BYTES = 256;
/** Longest scope description, in UTF-8 bytes. */
export const ACT_AS_MAX_DESCRIPTION_BYTES = 1_024;
/**
 * Largest encoded credential `decodeActAsCredential` accepts. A full scope
 * set (64 entries at the byte limits) is about 82 KiB, and a credential
 * carries it once inside the grant, so 256 KiB leaves room without letting a
 * caller hand the decoder an unbounded buffer.
 */
export const ACT_AS_MAX_CREDENTIAL_BYTES = 256 * 1024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export type ActAsErrorCode =
  | "decode"
  | "bad-timestamp"
  | "malformed-grantee"
  | "proof-does-not-match-grantee"
  | "untrusted-signer"
  | "bad-signature"
  | "no-valid-signature"
  | "bad-handle-claim"
  | "mismatch"
  | "bad-scope-set"
  | "bad-approved-scope"
  | "request-expired"
  | "scope-set-expired"
  | "grant-expired"
  | "grant-revoked"
  | "bad-terms"
  | "device-binding-unsupported";

export class ActAsError extends Error {
  readonly code: ActAsErrorCode;

  constructor(code: ActAsErrorCode, detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = "ActAsError";
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

/** Date.UTC without its 0-99 => 1900-1999 year mapping. */
function utcMs(year: number, month: number, day: number, hour = 0, minute = 0, second = 0, ms = 0): number {
  const d = new Date(0);
  d.setUTCFullYear(year, month - 1, day);
  d.setUTCHours(hour, minute, second, ms);
  return d.getTime();
}

function daysInMonth(year: number, month: number): number {
  const d = new Date(utcMs(year, month + 1, 0));
  return d.getUTCDate();
}

/** Parse a strict RFC3339 timestamp to epoch milliseconds, or undefined. */
export function parseRfc3339(value: string): number | undefined {
  const m = RFC3339.exec(value);
  if (!m) return undefined;
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number) as [
    number, number, number, number, number, number,
  ];
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) return undefined;
  if (hour > 23 || minute > 59 || second > 59) return undefined;
  const fraction = m[7] ? Math.floor(Number(`0${m[7]}`) * 1000) : 0;
  let offsetMs = 0;
  const zone = m[8]!;
  if (zone !== "Z" && zone !== "z") {
    const sign = zone.startsWith("-") ? -1 : 1;
    const oh = Number(zone.slice(1, 3));
    const om = Number(zone.slice(4, 6));
    if (oh > 23 || om > 59) return undefined;
    offsetMs = sign * (oh * 60 + om) * 60_000;
  }
  return utcMs(year, month, day, hour, minute, second, fraction) - offsetMs;
}

function parseTime(value: string): number {
  const ms = parseRfc3339(value);
  if (ms === undefined) throw new ActAsError("bad-timestamp", "act-as timestamp is not RFC3339");
  return ms;
}

/** Whole-second RFC3339 in UTC with a trailing `Z`, so a timestamp survives storage unchanged. */
export function formatActAsTime(t: Date | number): string {
  const ms = typeof t === "number" ? t : t.getTime();
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function checkWindow(startsAt: string, endsAt: string, nowMs: number, skewSeconds: number): void {
  const start = parseTime(startsAt);
  const end = parseTime(endsAt);
  if (end <= start) throw new ActAsError("request-expired");
  const skew = skewSeconds * 1000;
  if (nowMs + skew < start || nowMs - skew > end) throw new ActAsError("request-expired");
}

/** `CBOR([tag, payload_bytes])`: the bytes every act-as signature covers. */
export function actAsSignatureInput(tag: string, payload: Uint8Array): Uint8Array {
  return encodeCborTuple([text(tag), bytesElem(payload)]);
}

/** SHA-256 of a grant's signed bytes. A presentation binds this value. */
export function grantHash(grantBytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(grantBytes).digest());
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function utf8Length(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function decodeWith<T>(decoder: (bytes: Uint8Array) => T, input: Uint8Array, what: string): T {
  try {
    return decoder(input);
  } catch (err) {
    throw new ActAsError("decode", `${what} did not decode: ${(err as Error).message}`);
  }
}

/** Ed25519 is the only signing algorithm (`crypto::resolve_and_verify`). */
function verifyWithAlgorithm(
  algorithm: string,
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  return algorithm === "ed25519" && verifyEd25519(message, signature, publicKey);
}

/** Two application references name the same application. */
export function sameApplication(a: ApplicationRef, b: ApplicationRef): boolean {
  return (
    a.subjectUserId === b.subjectUserId &&
    a.subjectDomain === b.subjectDomain &&
    a.applicationId === b.applicationId
  );
}

/** Two grantee references name the same grantee. */
export function sameGrantee(a: GranteeRef, b: GranteeRef): boolean {
  if (a.application && a.localRpDescriptorFingerprint === undefined &&
      b.application && b.localRpDescriptorFingerprint === undefined) {
    return sameApplication(a.application, b.application);
  }
  if (!a.application && a.localRpDescriptorFingerprint !== undefined &&
      !b.application && b.localRpDescriptorFingerprint !== undefined) {
    return a.localRpDescriptorFingerprint === b.localRpDescriptorFingerprint;
  }
  return false;
}

/** A GranteeRef must carry exactly one non-empty form. */
export function checkGrantee(grantee: GranteeRef): void {
  const app = grantee.application;
  const fp = grantee.localRpDescriptorFingerprint;
  if (app && fp === undefined) {
    if (!app.subjectUserId || !app.subjectDomain || !app.applicationId) {
      throw new ActAsError("malformed-grantee");
    }
    return;
  }
  if (!app && fp !== undefined && fp.length > 0) return;
  throw new ActAsError("malformed-grantee");
}

// ---------------------------------------------------------------------------
// Key validity
// ---------------------------------------------------------------------------

/** `ApplicationKeyRef::is_valid_signing_key`: a signing key, not revoked, not expired at `now`. */
function isValidSigningKey(key: ApplicationKeyRef, nowMs: number): boolean {
  if (key.keyUsage !== KEY_USAGE_SIGN) return false;
  if (key.revokedAt !== undefined) {
    const revoked = parseRfc3339(key.revokedAt);
    if (revoked === undefined || revoked <= nowMs) return false;
  }
  const expires = parseRfc3339(key.expiresAt);
  return expires !== undefined && expires > nowMs;
}

/** `ApplicationKeyRef::was_valid_at`: could this key authorize something at `at`? */
function keyWasValidAt(key: ApplicationKeyRef, atMs: number): boolean {
  const created = parseRfc3339(key.createdAt);
  if (created !== undefined && created > atMs) return false;
  const expires = parseRfc3339(key.expiresAt);
  if (expires === undefined || expires <= atMs) return false;
  if (key.revokedAt !== undefined) {
    const revoked = parseRfc3339(key.revokedAt);
    if (revoked === undefined || revoked <= atMs) return false;
  }
  return true;
}

/** `assertions::check_signing_key_valid`: a signing key, never revoked, not past expiry. */
function domainSigningKeyValid(key: DomainPublicKey, nowMs: number): boolean {
  if (key.keyUsage !== KEY_USAGE_SIGN) return false;
  if (key.revokedAt !== undefined) return false;
  const expires = parseRfc3339(key.expiresAt);
  return expires !== undefined && nowMs <= expires;
}

function verifyDomainSignature(
  message: Uint8Array,
  signatures: readonly ClaimSignature[],
  domainKeys: readonly DomainPublicKey[],
  domain: string,
  nowMs: number,
): void {
  for (const sig of signatures) {
    if (sig.domain !== domain) continue;
    const key = domainKeys.find((k) => k.keyId === sig.signedByKeyId);
    if (!key) continue;
    if (!domainSigningKeyValid(key, nowMs)) continue;
    if (verifyWithAlgorithm(key.algorithm, message, sig.signature, key.publicKey)) return;
  }
  throw new ActAsError("untrusted-signer");
}

/**
 * Every attestation-verified key of a set, INCLUDING keys that expired or were
 * revoked since, each with its `revokedAt` (the reference server's
 * `attested_key_refs`). The verifier's validity rule decides which key can
 * vouch for a signature.
 *
 * Use it for `verifyScopeSet` and `AudienceContext.ownScopeSetKeys`: a scope
 * set is checked against the keys that were valid when it was issued, so a
 * list of usable keys only refuses sets that were signed before a rotation.
 */
export function attestedKeyRefs(set: VerifiedApplicationKeySet): ApplicationKeyRef[] {
  return set.keys.map(({ attestation: a, status }) => ({
    keyId: a.keyId,
    keyUsage: a.keyUsage,
    algorithm: a.algorithm,
    publicKey: a.publicKey,
    fingerprint: a.fingerprint,
    createdAt: a.keyCreatedAt,
    expiresAt: a.keyExpiresAt,
    revokedAt: status.kind === "revoked" ? status.revokedAt : undefined,
  }));
}

/**
 * The usable keys of a verified application-key set, in the form the act-as
 * verifiers take (the reference server's `usable_key_refs`). Use it on the
 * result of `resolveApplicationKeys` for the grantee instance that signed a
 * request or a presentation. Do NOT use it for a scope set: use
 * `attestedKeyRefs`.
 */
export function usableKeyRefs(set: VerifiedApplicationKeySet): ApplicationKeyRef[] {
  return set.keys
    .filter((k) => k.status.kind === "usable")
    .map(({ attestation: a }) => ({
      keyId: a.keyId,
      keyUsage: a.keyUsage,
      algorithm: a.algorithm,
      publicKey: a.publicKey,
      fingerprint: a.fingerprint,
      createdAt: a.keyCreatedAt,
      expiresAt: a.keyExpiresAt,
    }));
}

// ---------------------------------------------------------------------------
// Signers
// ---------------------------------------------------------------------------

/** An application's own Ed25519 signing key (an attested key of one instance). */
export interface ApplicationKeySigner {
  keyId: string;
  /** Raw 32-byte Ed25519 seed. */
  privateKey: Uint8Array;
}

/** A grantee's signing material, as the grantee holds it. */
export type GranteeSigner =
  | {
      kind: "application";
      /** The enrolled instance whose attested key signs. */
      instanceId: string;
      signer: ApplicationKeySigner;
    }
  | {
      kind: "localRp";
      descriptor: SignedLocalRpDescriptor;
      /** SHA-256 hex of the descriptor signing key. */
      fingerprint: string;
      /** Raw 32-byte Ed25519 seed of the descriptor signing key. */
      signingPrivateKey: Uint8Array;
    };

/** Sign `message` with a grantee key and wrap the signature in a proof. */
export function granteeProve(signer: GranteeSigner, message: Uint8Array): GranteeProof {
  if (signer.kind === "application") {
    return {
      applicationInstanceId: signer.instanceId,
      localRpDescriptor: undefined,
      signature: {
        signedByKeyId: signer.signer.keyId,
        signature: signEd25519(message, signer.signer.privateKey),
      },
    };
  }
  return {
    applicationInstanceId: undefined,
    localRpDescriptor: signer.descriptor,
    signature: {
      signedByKeyId: signer.fingerprint,
      signature: signEd25519(message, signer.signingPrivateKey),
    },
  };
}

// ---------------------------------------------------------------------------
// Local-RP descriptors and grantee proofs
// ---------------------------------------------------------------------------

/**
 * Verify a local RP's self-signed descriptor (port of
 * `local_rp::verify_local_rp_descriptor`): both keys are 32 bytes, the
 * fingerprint is SHA-256 hex of the signing key, the signing key signed
 * `CBOR([LOCAL_RP_DESCRIPTOR_TAG, descriptor_bytes])`, and `now` is inside
 * the validity window, with `skewSeconds` on each side.
 */
export function verifyLocalRpDescriptor(
  signed: SignedLocalRpDescriptor,
  now: Date,
  skewSeconds: number,
): LocalRpDescriptor {
  const descriptor = decodeWith(fromLocalRpDescriptorCbor, signed.descriptor, "local-RP descriptor");
  if (descriptor.signingPublicKey.length !== 32 || descriptor.encryptionPublicKey.length !== 32) {
    throw new ActAsError("untrusted-signer", "local-RP descriptor key has the wrong length");
  }
  if (descriptor.fingerprint !== fingerprint(descriptor.signingPublicKey)) {
    throw new ActAsError("untrusted-signer", "local-RP descriptor fingerprint mismatch");
  }
  if (!verifyEd25519(
    actAsSignatureInput(LOCAL_RP_DESCRIPTOR_TAG, signed.descriptor),
    signed.signature,
    descriptor.signingPublicKey,
  )) {
    throw new ActAsError("untrusted-signer", "local-RP descriptor signature did not verify");
  }
  const issued = parseTime(descriptor.createdAt);
  const expires = parseTime(descriptor.expiresAt);
  const skew = skewSeconds * 1000;
  if (now.getTime() + skew < issued || now.getTime() - skew > expires) {
    throw new ActAsError("untrusted-signer", "local-RP descriptor is outside its validity window");
  }
  return descriptor;
}

/** Who signed a proof, once the proof is verified. */
export interface VerifiedGranteeSigner {
  /** The application instance, for an application grantee. */
  instanceId?: string;
  /** The key id or descriptor fingerprint that signed. */
  keyId: string;
}

/**
 * Verify that a grantee key signed `message`.
 *
 * For an application grantee, `instanceKeys` are the attested keys of the
 * instance that the proof names (`proof.applicationInstanceId`). The caller
 * MUST have verified those attestations against the grantee's home domain,
 * for the grantee's `ApplicationRef`. The signing key must be a signing key
 * that is valid at `now`.
 *
 * For a local-RP grantee, `instanceKeys` is ignored. The descriptor in the
 * proof must verify, its fingerprint must equal the grantee's, and its
 * signing key must have signed.
 */
export function verifyGranteeProof(
  proof: GranteeProof,
  message: Uint8Array,
  grantee: GranteeRef,
  instanceKeys: readonly ApplicationKeyRef[],
  now: Date,
  skewSeconds: number,
): VerifiedGranteeSigner {
  checkGrantee(grantee);
  const appProof = proof.applicationInstanceId !== undefined && proof.localRpDescriptor === undefined;
  const localProof = proof.applicationInstanceId === undefined && proof.localRpDescriptor !== undefined;

  if (grantee.application && appProof) {
    const key = instanceKeys.find((k) => k.keyId === proof.signature.signedByKeyId);
    if (!key || !isValidSigningKey(key, now.getTime())) throw new ActAsError("untrusted-signer");
    if (!verifyWithAlgorithm(key.algorithm, message, proof.signature.signature, key.publicKey)) {
      throw new ActAsError("bad-signature");
    }
    return { instanceId: proof.applicationInstanceId, keyId: key.keyId };
  }

  if (grantee.localRpDescriptorFingerprint !== undefined && localProof) {
    let descriptor: LocalRpDescriptor;
    try {
      descriptor = verifyLocalRpDescriptor(proof.localRpDescriptor!, now, skewSeconds);
    } catch {
      throw new ActAsError("untrusted-signer");
    }
    if (
      descriptor.fingerprint !== grantee.localRpDescriptorFingerprint ||
      proof.signature.signedByKeyId !== descriptor.fingerprint
    ) {
      throw new ActAsError("mismatch", "local_rp_descriptor_fingerprint");
    }
    if (!verifyEd25519(message, proof.signature.signature, descriptor.signingPublicKey)) {
      throw new ActAsError("bad-signature");
    }
    return { instanceId: undefined, keyId: descriptor.fingerprint };
  }

  throw new ActAsError("proof-does-not-match-grantee");
}

// ---------------------------------------------------------------------------
// Revoked-key policy
// ---------------------------------------------------------------------------

/**
 * How a verifier treats a signature whose key was revoked after it signed.
 * Revocation invalidates one key, never the others. Each party chooses:
 *
 * - `"acceptBeforeRevocation"` (the default, invariant I-7): a signature made
 *   before the key's revocation time stays valid.
 * - `"refuseRevoked"`: any signature by a key that is now revoked is refused.
 */
export type RevokedKeyPolicy = "acceptBeforeRevocation" | "refuseRevoked";

/** The default revoked-key policy. */
export const DEFAULT_REVOKED_KEY_POLICY: RevokedKeyPolicy = "acceptBeforeRevocation";

/**
 * The clock skew allowed between a signer and the home domain that recorded
 * its key's creation time. Mirrors `liblinkkeys::act_as::KEY_CLOCK_SKEW_SECONDS`.
 */
export const ACT_AS_KEY_CLOCK_SKEW_SECONDS = 300;

/** The key could vouch at `signedAtMs`, allowing the skew for a key recorded as created slightly later. */
function validAtWithSkew(key: ApplicationKeyRef, signedAtMs: number): boolean {
  if (keyWasValidAt(key, signedAtMs)) return true;
  const created = parseRfc3339(key.createdAt);
  return created !== undefined
    && created > signedAtMs
    && created <= signedAtMs + ACT_AS_KEY_CLOCK_SKEW_SECONDS * 1000
    && keyWasValidAt(key, created);
}

/** Why `key` cannot vouch for something signed at `signedAtMs`, or undefined. */
function keyRefusal(key: ApplicationKeyRef, signedAtMs: number, policy: RevokedKeyPolicy): string | undefined {
  if (key.keyUsage !== KEY_USAGE_SIGN) return "not a signing key";
  if (policy === "refuseRevoked" && key.revokedAt !== undefined) {
    return `revoked at ${key.revokedAt}; this verifier refuses revoked keys`;
  }
  if (!validAtWithSkew(key, signedAtMs)) {
    return key.revokedAt !== undefined
      ? `revoked at ${key.revokedAt}, before it signed`
      : "not inside its validity window when it signed";
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Scope sets
// ---------------------------------------------------------------------------

/** Check a scope set's shape: bounded, non-empty, no repeated scope, RFC3339 times. */
export function checkScopeSetShape(set: ActAsScopeSet): void {
  checkGrantee(set.grantee);
  if (set.entries.length === 0) throw new ActAsError("bad-scope-set", "no entries");
  if (set.entries.length > ACT_AS_MAX_SCOPE_ENTRIES) {
    throw new ActAsError("bad-scope-set", `more than ${ACT_AS_MAX_SCOPE_ENTRIES} entries`);
  }
  const seen = new Set<string>();
  for (const entry of set.entries) {
    const length = utf8Length(entry.scope);
    if (length === 0 || length > ACT_AS_MAX_SCOPE_BYTES) {
      throw new ActAsError("bad-scope-set", "scope length out of range");
    }
    if (entry.description !== undefined && utf8Length(entry.description) > ACT_AS_MAX_DESCRIPTION_BYTES) {
      throw new ActAsError("bad-scope-set", "description too long");
    }
    if (seen.has(entry.scope)) throw new ActAsError("bad-scope-set", "a scope repeats");
    seen.add(entry.scope);
  }
  if (set.audienceHandleClaim !== undefined) checkHandleClaimSubject(set.audienceHandleClaim, set.audience);
  parseTime(set.issuedAt);
  parseTime(set.expiresAt);
}

/**
 * The audience signs the scope set it offers one grantee, with every current
 * signing key of the instance. A verifier needs one signature from a valid
 * key, so one expired or revoked key does not break the set. `signers` must
 * be non-empty, with no key id listed twice.
 */
export function signScopeSet(
  set: ActAsScopeSet,
  signerInstanceId: string,
  signers: readonly ApplicationKeySigner[],
): SignedActAsScopeSet {
  checkScopeSetShape(set);
  if (signers.length === 0) throw new ActAsError("no-valid-signature", "no signing key given");
  if (new Set(signers.map((s) => s.keyId)).size !== signers.length) {
    throw new ActAsError("no-valid-signature", "a key is listed twice");
  }
  const scopeSet = toActAsScopeSetCbor(set);
  const message = actAsSignatureInput(ACT_AS_SCOPE_SET_TAG, scopeSet);
  const signatures: ApplicationKeySignature[] = signers.map((signer) => ({
    signedByKeyId: signer.keyId,
    signature: signEd25519(message, signer.privateKey),
  }));
  return { scopeSet, signerInstanceId, signatures };
}

/**
 * Verify a scope set's signatures and shape.
 *
 * `audienceKeys` are the attested keys of the instance that
 * `signed.signerInstanceId` names, INCLUDING keys that expired or were
 * revoked since, each with its `revokedAt` (use `attestedKeyRefs`, not
 * `usableKeyRefs`). The caller MUST have verified them for
 * `expectedAudience`. One signature by a key that was valid at the set's
 * `issued_at`, and that `policy` accepts, is enough. A later key rotation
 * does not invalidate a set that a user already approved.
 *
 * When no signature is acceptable, this throws `no-valid-signature`. The
 * message names each signing key and why it was refused.
 *
 * This does not check the set's expiry. Only approval does that, with
 * `checkScopeSetCurrent`.
 */
export function verifyScopeSet(
  signed: SignedActAsScopeSet,
  expectedAudience: ApplicationRef,
  audienceKeys: readonly ApplicationKeyRef[],
  policy: RevokedKeyPolicy = DEFAULT_REVOKED_KEY_POLICY,
): ActAsScopeSet {
  const set = decodeWith(fromActAsScopeSetCbor, signed.scopeSet, "scope set");
  if (!sameApplication(set.audience, expectedAudience)) throw new ActAsError("mismatch", "scope_set.audience");
  checkScopeSetShape(set);
  if (signed.signatures.length === 0) throw new ActAsError("no-valid-signature", "the scope set is unsigned");
  const issuedAt = parseTime(set.issuedAt);
  const message = actAsSignatureInput(ACT_AS_SCOPE_SET_TAG, signed.scopeSet);
  const refusals: string[] = [];
  for (const sig of signed.signatures) {
    const key = audienceKeys.find((k) => k.keyId === sig.signedByKeyId);
    if (!key) {
      refusals.push(`${sig.signedByKeyId}: not a key of the audience`);
      continue;
    }
    const reason = keyRefusal(key, issuedAt, policy);
    if (reason !== undefined) {
      refusals.push(`${key.keyId}: ${reason}`);
      continue;
    }
    if (verifyWithAlgorithm(key.algorithm, message, sig.signature, key.publicKey)) return set;
    refusals.push(`${key.keyId}: signature did not verify`);
  }
  throw new ActAsError("no-valid-signature", refusals.join("; "));
}

// ---------------------------------------------------------------------------
// Handle claims
// ---------------------------------------------------------------------------

/** The claim type a handle claim carries. */
export const ACT_AS_HANDLE_CLAIM_TYPE = "handle";

/** A handle claim must be a `handle` claim about the party's own account. */
function checkHandleClaimSubject(claim: Claim, party: ApplicationRef): void {
  if (claim.claimType !== ACT_AS_HANDLE_CLAIM_TYPE) {
    throw new ActAsError(
      "bad-handle-claim",
      `claim type is ${JSON.stringify(claim.claimType)}, not ${JSON.stringify(ACT_AS_HANDLE_CLAIM_TYPE)}`,
    );
  }
  if (claim.userId !== party.subjectUserId) {
    throw new ActAsError("bad-handle-claim", "the claim is about another account");
  }
}

/**
 * Verify a handle claim about `party`'s enrolling account and return the
 * handle. Only signatures by the party's own `subjectDomain` count: a handle
 * is that domain's statement. Signatures by other domains are ignored.
 * `domainKeys` are that domain's signing keys. The claim must also not be
 * revoked or expired at `now`.
 *
 * A claim that does not verify is not shown. It does not block consent.
 */
export function verifyHandleClaim(
  claim: Claim,
  party: ApplicationRef,
  domainKeys: readonly DomainPublicKey[],
  now: Date = new Date(),
): string {
  checkHandleClaimSubject(claim, party);
  const own: Claim = { ...claim, signatures: claim.signatures.filter((s) => s.domain === party.subjectDomain) };
  try {
    verifyClaim(own, party.subjectDomain, [{ domain: party.subjectDomain, keys: domainKeys }], now);
  } catch (err) {
    throw new ActAsError("bad-handle-claim", (err as Error).message);
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(claim.claimValue);
  } catch {
    throw new ActAsError("bad-handle-claim", "the handle is not UTF-8");
  }
}

/** At approval only: the scope set has not expired. */
export function checkScopeSetCurrent(set: ActAsScopeSet, now: Date, skewSeconds: number): void {
  try {
    checkWindow(set.issuedAt, set.expiresAt, now.getTime(), skewSeconds);
  } catch {
    throw new ActAsError("scope-set-expired");
  }
}

/** The approved scope is a non-empty subset of the set, with no repeats. */
export function checkApprovedScope(set: ActAsScopeSet, approved: readonly string[]): void {
  if (approved.length === 0) throw new ActAsError("bad-approved-scope", "no scope approved");
  const offered = new Set(set.entries.map((e) => e.scope));
  const seen = new Set<string>();
  for (const scope of approved) {
    if (!offered.has(scope)) throw new ActAsError("bad-approved-scope", "a scope is not in the scope set");
    if (seen.has(scope)) throw new ActAsError("bad-approved-scope", "a scope repeats");
    seen.add(scope);
  }
}

// ---------------------------------------------------------------------------
// Grant requests
// ---------------------------------------------------------------------------

/** A grant request's handle claim must name the grantee's own account. A
 * local-RP grantee has no account, so it cannot carry one. */
function checkGranteeHandleClaim(request: ActAsGrantRequest): void {
  if (request.granteeHandleClaim === undefined) return;
  if (!request.grantee.application) {
    throw new ActAsError("bad-handle-claim", "a local-RP grantee has no account to name");
  }
  checkHandleClaimSubject(request.granteeHandleClaim, request.grantee.application);
}

/**
 * The grantee signs a grant request. To show your handle on the consent
 * screen, set `granteeHandleClaim` to a signed `handle` claim about the
 * account that enrolled your application, signed by that account's domain.
 * A local-RP grantee cannot carry a handle claim.
 */
export function signGrantRequest(request: ActAsGrantRequest, signer: GranteeSigner): SignedActAsGrantRequest {
  checkGrantee(request.grantee);
  checkGranteeHandleClaim(request);
  const bytes = toActAsGrantRequestCbor(request);
  return { request: bytes, proof: granteeProve(signer, actAsSignatureInput(ACT_AS_GRANT_REQUEST_TAG, bytes)) };
}

/** Decode a grant request without verifying it. Never trust the result before `verifyGrantRequest`. */
export function decodeGrantRequest(signed: SignedActAsGrantRequest): ActAsGrantRequest {
  return decodeWith(fromActAsGrantRequestCbor, signed.request, "grant request");
}

/**
 * Verify a grant request's signature, window, and shape. This is the home
 * domain's check; a grantee can use it to self-test. The caller still owns
 * the scope-set signature, the scope set's expiry, and nonce single-use.
 */
export function verifyGrantRequest(
  signed: SignedActAsGrantRequest,
  granteeInstanceKeys: readonly ApplicationKeyRef[],
  now: Date,
  skewSeconds: number,
): ActAsGrantRequest {
  const request = decodeGrantRequest(signed);
  checkGrantee(request.grantee);
  checkWindow(request.requestedAt, request.expiresAt, now.getTime(), skewSeconds);
  if (request.requestedLifetimeSeconds !== undefined && request.requestedLifetimeSeconds <= 0) {
    throw new ActAsError("bad-terms", "requested lifetime must be positive");
  }
  if (request.requestedRenewalWindowSeconds !== undefined && request.requestedRenewalWindowSeconds < 0) {
    throw new ActAsError("bad-terms", "requested renewal window must not be negative");
  }
  checkGranteeHandleClaim(request);
  if (request.nonce.length === 0 || request.callbackUrl.length === 0) {
    throw new ActAsError("decode", "nonce and callback_url are required");
  }
  verifyGranteeProof(
    signed.proof,
    actAsSignatureInput(ACT_AS_GRANT_REQUEST_TAG, signed.request),
    request.grantee,
    granteeInstanceKeys,
    now,
    skewSeconds,
  );
  return request;
}

// ---------------------------------------------------------------------------
// Terms
// ---------------------------------------------------------------------------

/** The home domain's bounds for one grant. */
export interface DomainTermBounds {
  defaultLifetimeSeconds: number;
  maxLifetimeSeconds: number;
  maxRenewalWindowSeconds: number;
}

/** The reference server's default bounds. */
export const DEFAULT_DOMAIN_TERM_BOUNDS: Readonly<DomainTermBounds> = Object.freeze({
  defaultLifetimeSeconds: ACT_AS_DEFAULT_LIFETIME_SECONDS,
  maxLifetimeSeconds: ACT_AS_DEFAULT_MAX_LIFETIME_SECONDS,
  maxRenewalWindowSeconds: ACT_AS_DEFAULT_MAX_RENEWAL_WINDOW_SECONDS,
});

/** What the consent screen offers: starting values and the most the user can choose. */
export interface OfferedTerms {
  defaultLifetimeSeconds: number;
  maxLifetimeSeconds: number;
  defaultRenewalWindowSeconds: number;
  maxRenewalWindowSeconds: number;
}

/**
 * The consent screen's starting values and limits. The grantee's request is
 * a ceiling, never a floor. An absent requested lifetime sets no ceiling, and
 * the screen starts at the domain default. An absent renewal window means 0.
 */
export function offeredTerms(
  requestedLifetimeSeconds: number | undefined,
  requestedRenewalWindowSeconds: number | undefined,
  bounds: DomainTermBounds = DEFAULT_DOMAIN_TERM_BOUNDS,
): OfferedTerms {
  const maxLifetime = Math.max(
    requestedLifetimeSeconds === undefined
      ? bounds.maxLifetimeSeconds
      : Math.min(requestedLifetimeSeconds, bounds.maxLifetimeSeconds),
    1,
  );
  const defaultLifetime = Math.max(
    Math.min(requestedLifetimeSeconds ?? bounds.defaultLifetimeSeconds, maxLifetime),
    1,
  );
  const maxWindow = Math.max(Math.min(requestedRenewalWindowSeconds ?? 0, bounds.maxRenewalWindowSeconds), 0);
  return {
    defaultLifetimeSeconds: defaultLifetime,
    maxLifetimeSeconds: maxLifetime,
    defaultRenewalWindowSeconds: maxWindow,
    maxRenewalWindowSeconds: maxWindow,
  };
}

/**
 * The issued lifetime and renewal window: the user's choice, never above the
 * offered maximum. A choice above the maximum is an error, not a silent cap.
 */
export function issuedTerms(
  offered: OfferedTerms,
  chosenLifetimeSeconds: number,
  chosenRenewalWindowSeconds: number,
): { lifetimeSeconds: number; renewalWindowSeconds: number } {
  if (chosenLifetimeSeconds <= 0 || chosenLifetimeSeconds > offered.maxLifetimeSeconds) {
    throw new ActAsError("bad-terms", "lifetime is outside the offered range");
  }
  if (chosenRenewalWindowSeconds < 0 || chosenRenewalWindowSeconds > offered.maxRenewalWindowSeconds) {
    throw new ActAsError("bad-terms", "renewal window is outside the offered range");
  }
  return { lifetimeSeconds: chosenLifetimeSeconds, renewalWindowSeconds: chosenRenewalWindowSeconds };
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

/** Decode a grant without verifying it. */
export function decodeGrant(signed: SignedActAsGrant): ActAsGrant {
  return decodeWith(fromActAsGrantCbor, signed.grant, "grant");
}

/**
 * Verify a grant's home-domain signature and internal consistency.
 * `domainKeys` are the keys of the grant's `subject_domain`. This does not
 * check expiry, revocation, the audience, or the scope set. `verifyCredential`
 * does all of those. A grant with a device binding is refused: device keys
 * are Reserved, so no verifier can check one yet.
 */
export function verifyGrantSignature(
  signed: SignedActAsGrant,
  domainKeys: readonly DomainPublicKey[],
  now: Date = new Date(),
): ActAsGrant {
  const grant = decodeGrant(signed);
  checkGrantee(grant.grantee);
  if (grant.deviceFingerprint !== undefined) throw new ActAsError("device-binding-unsupported");
  verifyDomainSignature(
    actAsSignatureInput(ACT_AS_GRANT_TAG, signed.grant),
    signed.signatures,
    domainKeys,
    grant.subjectDomain,
    now.getTime(),
  );
  return grant;
}

// ---------------------------------------------------------------------------
// Refresh and renewal
// ---------------------------------------------------------------------------

/** What a refresh returns: the stored grant, or a renewed grant with these times. */
export type RefreshDecision =
  | { kind: "stored" }
  | { kind: "renew"; issuedAt: string; expiresAt: string };

/**
 * Decide whether a refresh renews the grant (the home domain's rule). A
 * grantee uses it to predict what a refresh returns and when to call.
 *
 * An expired grant cannot be renewed (`grant-expired`). While more than one
 * half of the life remains, the stored grant is returned. A renewal happens
 * only before `renewable_until`, and only when it extends the expiry. A
 * renewed grant expires at `min(now + lifetime, renewable_until)`.
 */
export function refreshDecision(
  grant: Pick<ActAsGrant, "issuedAt" | "expiresAt" | "renewableUntil">,
  lifetimeSeconds: number,
  now: Date,
): RefreshDecision {
  const issued = parseTime(grant.issuedAt);
  const expires = parseTime(grant.expiresAt);
  const renewableUntil = parseTime(grant.renewableUntil);
  const nowMs = now.getTime();
  if (nowMs >= expires) throw new ActAsError("grant-expired");
  if (expires <= issued) return { kind: "stored" };
  const half = issued + Math.trunc((expires - issued) / 2);
  if (nowMs < half || nowMs >= renewableUntil) return { kind: "stored" };
  const newExpires = Math.min(nowMs + lifetimeSeconds * 1000, renewableUntil);
  if (newExpires <= expires) return { kind: "stored" };
  return { kind: "renew", issuedAt: formatActAsTime(nowMs), expiresAt: formatActAsTime(newExpires) };
}

/**
 * The earliest time a refresh can renew the grant: the half-life point. A
 * grantee SHOULD refresh after this time and before `expires_at`.
 */
export function refreshDueAt(grant: Pick<ActAsGrant, "issuedAt" | "expiresAt">): Date {
  const issued = parseTime(grant.issuedAt);
  const expires = parseTime(grant.expiresAt);
  return new Date(issued + Math.trunc(Math.max(expires - issued, 0) / 2));
}

/** The grantee signs a refresh request. */
export function signRefreshRequest(request: ActAsRefreshRequest, signer: GranteeSigner): SignedActAsRefreshRequest {
  checkGrantee(request.grantee);
  const bytes = toActAsRefreshRequestCbor(request);
  return { request: bytes, proof: granteeProve(signer, actAsSignatureInput(ACT_AS_REFRESH_REQUEST_TAG, bytes)) };
}

/** Decode a refresh request without verifying it. */
export function decodeRefreshRequest(signed: SignedActAsRefreshRequest): ActAsRefreshRequest {
  return decodeWith(fromActAsRefreshRequestCbor, signed.request, "refresh request");
}

/** Verify a refresh request against the stored grant's grantee (the home domain's check). */
export function verifyRefreshRequest(
  signed: SignedActAsRefreshRequest,
  grantGrantee: GranteeRef,
  granteeInstanceKeys: readonly ApplicationKeyRef[],
  now: Date,
  skewSeconds: number,
): ActAsRefreshRequest {
  const request = decodeRefreshRequest(signed);
  if (!sameGrantee(request.grantee, grantGrantee)) throw new ActAsError("mismatch", "grantee");
  checkWindow(request.requestedAt, request.expiresAt, now.getTime(), skewSeconds);
  verifyGranteeProof(
    signed.proof,
    actAsSignatureInput(ACT_AS_REFRESH_REQUEST_TAG, signed.request),
    grantGrantee,
    granteeInstanceKeys,
    now,
    skewSeconds,
  );
  return request;
}

// ---------------------------------------------------------------------------
// Presentations and audience verification
// ---------------------------------------------------------------------------

/**
 * The grantee builds the credential for one call to the audience.
 * `presentedAt` is written as whole-second RFC3339 UTC. `nonce` must be
 * unique per presentation; the audience uses it for replay protection.
 */
export function present(
  grant: SignedActAsGrant,
  audience: ApplicationRef,
  requestDigest: Uint8Array,
  presentedAt: Date,
  nonce: Uint8Array,
  signer: GranteeSigner,
): ActAsCredential {
  const presentation = toActAsPresentationCbor({
    grantHash: grantHash(grant.grant),
    audience,
    requestDigest,
    presentedAt: formatActAsTime(presentedAt),
    nonce,
  });
  return {
    grant,
    presentation: {
      presentation,
      proof: granteeProve(signer, actAsSignatureInput(ACT_AS_PRESENTATION_TAG, presentation)),
    },
  };
}

/** Decode a credential received from a grantee, with a size bound. */
export function decodeActAsCredential(
  encoded: Uint8Array,
  maxBytes: number = ACT_AS_MAX_CREDENTIAL_BYTES,
): ActAsCredential {
  if (encoded.length > maxBytes) throw new ActAsError("decode", "credential is too large");
  return decodeWith(fromActAsCredentialCbor, encoded, "credential");
}

/**
 * What the audience supplies to verify a credential. Every key list is
 * already verified by the caller: domain keys from the issuer's anchor, and
 * application keys from verified attestations.
 */
export interface AudienceContext {
  /** The verifier's own application. Never read from the request. */
  ownApplication: ApplicationRef;
  /** The verifier's own attested keys, for the instance that signed the
   * scope set, INCLUDING keys that expired or were revoked since (use
   * `attestedKeyRefs`, not `usableKeyRefs`). Find the instance with
   * `credentialScopeSetSigner`. */
  ownScopeSetKeys: readonly ApplicationKeyRef[];
  /** Signing keys of the grant's `subject_domain`. */
  issuerDomainKeys: readonly DomainPublicKey[];
  /** Attested keys of the grantee instance that signed the presentation.
   * Find the instance with `credentialSignerInstance`. Ignored for a
   * local-RP grantee. */
  granteeInstanceKeys: readonly ApplicationKeyRef[];
  /** The digest of this request, as the audience's protocol defines it. */
  expectedRequestDigest: Uint8Array;
  /** Grant ids the verifier holds a valid revocation for. */
  revokedGrantIds: readonly string[];
  /** Largest accepted age of a presentation, in seconds. */
  maxPresentationAgeSeconds: number;
  now: Date;
  skewSeconds: number;
  /** How to treat scope-set signatures by keys revoked since. Default:
   * `"acceptBeforeRevocation"`. */
  revokedKeyPolicy?: RevokedKeyPolicy;
}

/** A credential the audience accepted. */
export interface VerifiedActAs {
  grantId: string;
  /** `user_id@subject_domain`. */
  userId: string;
  subjectDomain: string;
  grantee: GranteeRef;
  signer: VerifiedGranteeSigner;
  /** The only scope the audience's policy may act on. */
  approvedScope: string[];
  expiresAt: string;
  /** The presentation nonce. The audience owns replay protection. */
  nonce: Uint8Array;
}

/** The grantee instance whose key signed the presentation, or undefined for a local-RP grantee. */
export function credentialSignerInstance(credential: ActAsCredential): string | undefined {
  return credential.presentation.proof.applicationInstanceId;
}

/** The audience instance whose key signed the embedded scope set. */
export function credentialScopeSetSigner(credential: ActAsCredential): string {
  return decodeGrant(credential.grant).scopeSet.signerInstanceId;
}

/**
 * The audience's verification checklist, in this order. Every step must pass:
 *
 * 1. The grant's home-domain signature verifies.
 * 2. The grant's audience is the verifier.
 * 3. The grant is inside its validity window.
 * 4. The presentation was signed by a key of the grantee.
 * 5. The presentation binds this grant, this audience, and this request,
 *    and is fresh.
 * 6. The embedded scope set was signed by the verifier, names the same
 *    grantee, and contains every approved scope. Its expiry is NOT checked.
 * 7. The verifier holds no revocation for the grant.
 *
 * Throws `ActAsError` on the first failed step. The caller still owns replay
 * protection: record `nonce` until the accepted presentation age passes.
 */
export function verifyCredential(credential: ActAsCredential, ctx: AudienceContext): VerifiedActAs {
  const nowMs = ctx.now.getTime();
  const skew = ctx.skewSeconds * 1000;
  // 1
  const grant = verifyGrantSignature(credential.grant, ctx.issuerDomainKeys, ctx.now);
  // 2
  if (!sameApplication(grant.audience, ctx.ownApplication)) throw new ActAsError("mismatch", "audience");
  // 3
  const issued = parseTime(grant.issuedAt);
  const expires = parseTime(grant.expiresAt);
  if (nowMs + skew < issued) throw new ActAsError("request-expired");
  if (nowMs - skew >= expires) throw new ActAsError("grant-expired");
  // 4
  const signed = credential.presentation;
  const signer = verifyGranteeProof(
    signed.proof,
    actAsSignatureInput(ACT_AS_PRESENTATION_TAG, signed.presentation),
    grant.grantee,
    ctx.granteeInstanceKeys,
    ctx.now,
    ctx.skewSeconds,
  );
  // 5
  const presentation = decodeWith(fromActAsPresentationCbor, signed.presentation, "presentation");
  if (!equalBytes(presentation.grantHash, grantHash(credential.grant.grant))) {
    throw new ActAsError("mismatch", "grant_hash");
  }
  if (!sameApplication(presentation.audience, ctx.ownApplication)) {
    throw new ActAsError("mismatch", "presentation.audience");
  }
  if (!equalBytes(presentation.requestDigest, ctx.expectedRequestDigest)) {
    throw new ActAsError("mismatch", "request_digest");
  }
  const presentedAt = parseTime(presentation.presentedAt);
  if (presentedAt > nowMs + skew || presentedAt + ctx.maxPresentationAgeSeconds * 1000 + skew < nowMs) {
    throw new ActAsError("request-expired");
  }
  // 6
  const set = verifyScopeSet(
    grant.scopeSet,
    ctx.ownApplication,
    ctx.ownScopeSetKeys,
    ctx.revokedKeyPolicy ?? DEFAULT_REVOKED_KEY_POLICY,
  );
  if (!sameGrantee(set.grantee, grant.grantee)) throw new ActAsError("mismatch", "scope_set.grantee");
  checkApprovedScope(set, grant.approvedScope);
  // 7
  if (ctx.revokedGrantIds.includes(grant.grantId)) throw new ActAsError("grant-revoked");
  return {
    grantId: grant.grantId,
    userId: `${grant.userId}@${grant.subjectDomain}`,
    subjectDomain: grant.subjectDomain,
    grantee: grant.grantee,
    signer,
    approvedScope: grant.approvedScope,
    expiresAt: grant.expiresAt,
    nonce: presentation.nonce,
  };
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

/** Verify a grant revocation against the issuing domain's keys. */
export function verifyGrantRevocation(
  signed: SignedActAsGrantRevocation,
  domainKeys: readonly DomainPublicKey[],
  expectedDomain: string,
  now: Date = new Date(),
): ActAsGrantRevocation {
  const revocation = decodeWith(fromActAsGrantRevocationCbor, signed.revocation, "grant revocation");
  if (revocation.subjectDomain !== expectedDomain) throw new ActAsError("mismatch", "subject_domain");
  parseTime(revocation.revokedAt);
  verifyDomainSignature(
    actAsSignatureInput(ACT_AS_GRANT_REVOCATION_TAG, signed.revocation),
    signed.signatures,
    domainKeys,
    expectedDomain,
    now.getTime(),
  );
  return revocation;
}

/** The grant ids that a set of revocations validly revokes. Records that fail verification are ignored. */
export function revokedGrantIds(
  revocations: readonly SignedActAsGrantRevocation[],
  domainKeys: readonly DomainPublicKey[],
  expectedDomain: string,
  now: Date = new Date(),
): string[] {
  const out: string[] = [];
  for (const r of revocations) {
    try {
      out.push(verifyGrantRevocation(r, domainKeys, expectedDomain, now).grantId);
    } catch {
      // A record that does not verify revokes nothing.
    }
  }
  return out;
}
