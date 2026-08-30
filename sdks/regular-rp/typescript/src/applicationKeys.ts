// Application-key attestation and revocation verification — the TypeScript
// port of the subset of `crates/liblinkkeys/src/application_keys.rs` this SDK
// needs to VALIDATE (not enroll, renew, or sign) application public keys.
//
// `docs/application-keys.md` is the normative description of the protocol;
// read it first. This file implements only the READ side: verifying a home
// domain's attestation of one application public key, verifying a
// sibling-signed revocation, and classifying a key's current usability —
// exactly what `applicationKeyCache.ts`'s `resolveApplicationKeys` needs to
// validate the signed records an RP hands back, again, before use (design
// doc, "RP-facing operations": "The RP validates the material before it
// stores or returns it. The application SDK validates the signed records
// again before it uses an application key.").
//
// Deliberately NOT ported here: key addition, attestation renewal, and the
// X25519 sealed-challenge proof of possession. Those are ENROLLMENT
// operations — an application instance adding/renewing/proving its OWN
// keys with its OWN home domain — which is a different concern from this
// SDK's job of resolving and trusting a PEER's already-attested keys. See
// this package's README for the scope note.

import { decode } from "../generated/codec.gen.ts";
import { fromApplicationKeyAttestationCborValue } from "../generated/codec.gen.ts";
import { encodeCborTuple, text, bytes as bytesElem } from "./cborTuple.ts";
import { fingerprint, verifyEd25519 } from "./crypto.ts";
import type {
  ApplicationKeyAttestation,
  ApplicationKeyRevocation,
  DomainPublicKey,
  SignedApplicationKeyAttestation,
} from "../generated/types.gen.ts";

// ---------------------------------------------------------------------------
// Domain-separation tags and protocol constants (docs/application-keys.md,
// "Domain-separation tags" / configuration table).
// ---------------------------------------------------------------------------

export const ATTESTATION_TAG = "linkkeys-application-key-attestation-v1alpha";
export const REVOCATION_TAG = "linkkeys-application-key-revocation-v1alpha";

/** Distinct valid sibling signing keys required to revoke a key. */
export const REVOCATION_QUORUM = 2;

/** Key use: an Ed25519 signing key. */
export const KEY_USAGE_SIGN = "sign";
/** Key use: an X25519 key-agreement key. */
export const KEY_USAGE_AGREE = "agree";

const ALG_ED25519 = "ed25519";
const ALG_X25519 = "x25519";

/**
 * Bytes a home-domain signature over an attestation covers:
 * `CBOR([ATTESTATION_TAG, attestation_bytes])` — the same two-element
 * envelope every signed structure in this protocol uses (see
 * `application_keys.rs`'s `envelope_signature_input`), except
 * `ApplicationKeyRevocation` (see `revocationPayload` below).
 */
export function attestationSignatureInput(attestationBytes: Uint8Array): Uint8Array {
  return encodeCborTuple([text(ATTESTATION_TAG), bytesElem(attestationBytes)]);
}

/**
 * Bytes a sibling signature over a revocation covers. Unlike the
 * attestation, a revocation is verified from its FIELDS rather than from
 * stored bytes — the tag-first tuple pattern
 * (`CBOR([REVOCATION_TAG, subject_user_id, subject_domain, application_id,
 * instance_id, target_key_id, target_fingerprint, revoked_at])`, an
 * eight-element array), so a revocation can never move between subjects,
 * applications, or instances.
 */
export function revocationPayload(
  subjectUserId: string,
  subjectDomain: string,
  applicationId: string,
  instanceId: string,
  targetKeyId: string,
  targetFingerprint: string,
  revokedAt: string,
): Uint8Array {
  return encodeCborTuple([
    text(REVOCATION_TAG),
    text(subjectUserId),
    text(subjectDomain),
    text(applicationId),
    text(instanceId),
    text(targetKeyId),
    text(targetFingerprint),
    text(revokedAt),
  ]);
}

function revocationPayloadOf(rev: ApplicationKeyRevocation): Uint8Array {
  return revocationPayload(
    rev.subjectUserId,
    rev.subjectDomain,
    rev.applicationId,
    rev.instanceId,
    rev.targetKeyId,
    rev.targetFingerprint,
    rev.revokedAt,
  );
}

/** The algorithm a key use requires. Ed25519 keys sign; X25519 keys agree. */
function expectedAlgorithm(keyUsage: string): string | undefined {
  if (keyUsage === KEY_USAGE_SIGN) return ALG_ED25519;
  if (keyUsage === KEY_USAGE_AGREE) return ALG_X25519;
  return undefined;
}

/**
 * A key's stated use, algorithm, public key length, and fingerprint must be
 * internally consistent before anything trusts them (mirrors
 * `application_keys::check_key_shape`).
 */
export function checkKeyShape(
  keyUsage: string,
  algorithm: string,
  publicKey: Uint8Array,
  fingerprintHex: string,
): boolean {
  const expected = expectedAlgorithm(keyUsage);
  if (expected === undefined || algorithm !== expected) return false;
  if (publicKey.length !== 32) return false;
  return fingerprint(publicKey) === fingerprintHex;
}

function signingKeyValidity(key: DomainPublicKey, now: Date): "valid" | "revoked" | "expired" {
  if (key.revokedAt !== undefined) return "revoked";
  const expires = Date.parse(key.expiresAt);
  if (Number.isNaN(expires)) return "expired";
  return now.getTime() > expires ? "expired" : "valid";
}

/**
 * Verify a home-domain attestation and return what it says, or `undefined`
 * if no currently-valid signing key of `expectedDomain` produced a valid
 * signature over the exact stored bytes (mirrors
 * `application_keys::verify_attestation_signature`).
 *
 * This is a domain assertion, not a peer quorum: the domain's own key set is
 * already pinned via the RP (or DNS, for a DNS-less caller), so one valid
 * signature is the proof. Whether the attestation is CURRENT (not expired)
 * is a separate question — see `classifyKey`.
 */
export function verifyAttestationSignature(
  signed: SignedApplicationKeyAttestation,
  domainKeys: readonly DomainPublicKey[],
  expectedDomain: string,
  now: Date = new Date(),
): ApplicationKeyAttestation | undefined {
  let attestation: ApplicationKeyAttestation;
  try {
    attestation = fromApplicationKeyAttestationCborValue(decode(signed.attestation));
  } catch {
    return undefined;
  }
  if (attestation.subjectDomain !== expectedDomain) return undefined;
  if (!checkKeyShape(attestation.keyUsage, attestation.algorithm, attestation.publicKey, attestation.fingerprint)) {
    return undefined;
  }

  const message = attestationSignatureInput(signed.attestation);
  for (const sig of signed.signatures) {
    if (sig.domain !== expectedDomain) continue;
    const key = domainKeys.find((k) => k.keyId === sig.signedByKeyId);
    if (!key) continue;
    if (key.keyUsage !== KEY_USAGE_SIGN) continue;
    if (signingKeyValidity(key, now) !== "valid") continue;
    if (verifyEd25519(message, sig.signature, key.publicKey)) {
      return attestation;
    }
  }
  return undefined;
}

/** One application public key as the verifying side knows it, built from an
 * attested record (mirrors `application_keys::ApplicationKeyRef`, the
 * subset this module needs — always built from an ALREADY-attested key, so
 * `revokedAt` starts unset here; revocation is layered on separately by
 * `verifyApplicationKeySet`). */
export interface ApplicationKeyRef {
  keyId: string;
  keyUsage: string;
  algorithm: string;
  publicKey: Uint8Array;
  fingerprint: string;
  createdAt: string;
  expiresAt: string;
}

function wasValidAt(key: ApplicationKeyRef, at: Date): boolean {
  const created = Date.parse(key.createdAt);
  const expires = Date.parse(key.expiresAt);
  if (Number.isFinite(created) && created > at.getTime()) return false;
  if (!Number.isFinite(expires) || expires <= at.getTime()) return false;
  return true;
}

function attestedKeyRef(a: ApplicationKeyAttestation): ApplicationKeyRef {
  return {
    keyId: a.keyId,
    keyUsage: a.keyUsage,
    algorithm: a.algorithm,
    publicKey: a.publicKey,
    fingerprint: a.fingerprint,
    createdAt: a.keyCreatedAt,
    expiresAt: a.keyExpiresAt,
  };
}

/**
 * Count DISTINCT valid application signing keys (excluding the revocation's
 * own target) that signed `rev`'s canonical payload, judged by whether each
 * signer `wasValidAt` the revocation's effective time — a revocation must
 * stay verifiable after its signers themselves later expire or rotate out
 * (mirrors `application_keys::count_distinct_signers` as
 * `verify_revocation` uses it).
 */
export function countApplicationKeyRevocationSigners(
  rev: ApplicationKeyRevocation,
  keys: readonly ApplicationKeyRef[],
): number {
  const effective = new Date(Date.parse(rev.revokedAt));
  const message = revocationPayloadOf(rev);
  const accepted = new Set<string>();
  for (const sig of rev.signatures) {
    if (sig.signedByKeyId === rev.targetKeyId) continue;
    if (accepted.has(sig.signedByKeyId)) continue;
    const key = keys.find((k) => k.keyId === sig.signedByKeyId);
    if (!key) continue;
    if (key.keyUsage !== KEY_USAGE_SIGN) continue;
    if (!wasValidAt(key, effective)) continue;
    if (verifyEd25519(message, sig.signature, key.publicKey)) {
      accepted.add(sig.signedByKeyId);
    }
  }
  return accepted.size;
}

/** Verify a revocation against the instance's attested sibling keys. Requires
 * `REVOCATION_QUORUM` distinct signers; the target never counts. */
export function verifyApplicationKeyRevocation(
  rev: ApplicationKeyRevocation,
  keys: readonly ApplicationKeyRef[],
): boolean {
  const target = keys.find((k) => k.keyId === rev.targetKeyId);
  if (!target || target.fingerprint !== rev.targetFingerprint) return false;
  return countApplicationKeyRevocationSigners(rev, keys) >= REVOCATION_QUORUM;
}

// ---------------------------------------------------------------------------
// Classification and the whole-set verifier
// ---------------------------------------------------------------------------

export type KeyStatus =
  | { kind: "usable" }
  | { kind: "attestation_expired" }
  | { kind: "key_expired" }
  | { kind: "revoked"; revokedAt: string };

export interface VerifiedApplicationKey {
  attestation: ApplicationKeyAttestation;
  status: KeyStatus;
}

export interface RejectedRecord {
  what: string;
  reason: string;
}

export interface VerifiedApplicationKeySet {
  keys: VerifiedApplicationKey[];
  revokedKeyIds: Set<string>;
  rejected: RejectedRecord[];
}

/** Decide the status of one verified attestation at `now` (mirrors
 * `application_keys::classify_key`). */
export function classifyKey(
  attestation: ApplicationKeyAttestation,
  revokedAt: string | undefined,
  now: Date,
  skewSeconds: number,
): KeyStatus {
  const skewMs = skewSeconds * 1000;
  if (revokedAt !== undefined) {
    const effective = Date.parse(revokedAt);
    if (Number.isFinite(effective) && effective <= now.getTime() + skewMs) {
      return { kind: "revoked", revokedAt };
    }
  }
  const keyExpires = Date.parse(attestation.keyExpiresAt);
  if (!Number.isFinite(keyExpires) || keyExpires + skewMs <= now.getTime()) {
    return { kind: "key_expired" };
  }
  const attestationExpires = Date.parse(attestation.attestationExpiresAt);
  if (!Number.isFinite(attestationExpires) || attestationExpires + skewMs <= now.getTime()) {
    return { kind: "attestation_expired" };
  }
  return { kind: "usable" };
}

/** True when `attestation` names exactly this instance. */
function identityMatches(
  a: ApplicationKeyAttestation,
  instance: {
    subjectUserId: string;
    subjectDomain: string;
    applicationId: string;
    instanceId: string;
  },
): boolean {
  return (
    a.subjectUserId === instance.subjectUserId &&
    a.subjectDomain === instance.subjectDomain &&
    a.applicationId === instance.applicationId &&
    a.instanceId === instance.instanceId
  );
}

/**
 * Verify a whole application-key response the way this SDK must before
 * trusting it (mirrors `application_keys::verify_application_key_set`):
 *
 * 1. Verify every attestation against the home domain's pinned key set.
 * 2. Verify every revocation against those attested SIBLING keys.
 * 3. Classify each key against the accepted revocations and `now`.
 *
 * A bad record is rejected individually (recorded in `rejected`, with a
 * reason) rather than failing the whole set — a caller that needs
 * completeness checks `rejected.length === 0`.
 */
export function verifyApplicationKeySet(
  signedAttestations: readonly SignedApplicationKeyAttestation[],
  revocations: readonly ApplicationKeyRevocation[],
  domainKeys: readonly DomainPublicKey[],
  instance: {
    subjectUserId: string;
    subjectDomain: string;
    applicationId: string;
    instanceId: string;
  },
  now: Date,
  skewSeconds: number,
): VerifiedApplicationKeySet {
  const rejected: RejectedRecord[] = [];
  const attested: ApplicationKeyAttestation[] = [];
  const seenKeyIds = new Set<string>();

  for (const signed of signedAttestations) {
    const attestation = verifyAttestationSignature(signed, domainKeys, instance.subjectDomain, now);
    if (!attestation) {
      rejected.push({ what: "attestation", reason: "no valid home-domain signature" });
      continue;
    }
    if (!identityMatches(attestation, instance)) {
      rejected.push({
        what: `attestation ${attestation.keyId}`,
        reason: "bound to a different subject, domain, application, or instance",
      });
      continue;
    }
    if (seenKeyIds.has(attestation.keyId)) {
      rejected.push({ what: `attestation ${attestation.keyId}`, reason: "duplicate key id" });
      continue;
    }
    seenKeyIds.add(attestation.keyId);
    attested.push(attestation);
  }

  const keyRefs = attested.map(attestedKeyRef);
  const revoked = new Map<string, string>();
  for (const rev of revocations) {
    if (
      rev.subjectUserId !== instance.subjectUserId ||
      rev.subjectDomain !== instance.subjectDomain ||
      rev.applicationId !== instance.applicationId ||
      rev.instanceId !== instance.instanceId
    ) {
      rejected.push({ what: `revocation of ${rev.targetKeyId}`, reason: "bound to a different instance" });
      continue;
    }
    if (!verifyApplicationKeyRevocation(rev, keyRefs)) {
      rejected.push({ what: `revocation of ${rev.targetKeyId}`, reason: "insufficient valid sibling signatures" });
      continue;
    }
    const existing = revoked.get(rev.targetKeyId);
    if (existing === undefined || rev.revokedAt < existing) {
      revoked.set(rev.targetKeyId, rev.revokedAt);
    }
  }

  const keys: VerifiedApplicationKey[] = [];
  const revokedKeyIds = new Set<string>();
  for (const a of attested) {
    const status = classifyKey(a, revoked.get(a.keyId), now, skewSeconds);
    if (status.kind === "revoked") revokedKeyIds.add(a.keyId);
    keys.push({ attestation: a, status });
  }

  return { keys, revokedKeyIds, rejected };
}

/** Every currently usable key of one use. All such keys are equal — there is
 * no preferred key, and array order carries no meaning. */
export function usableKeys(
  set: VerifiedApplicationKeySet,
  keyUsage: string,
): ApplicationKeyAttestation[] {
  return set.keys
    .filter((k) => k.status.kind === "usable" && k.attestation.keyUsage === keyUsage)
    .map((k) => k.attestation);
}

/** Look up one key by id and confirm it is acceptable for a specific
 * operation — fails closed on an unknown, expired, unattested, mismatched,
 * or revoked key. */
export function keyForUse(
  set: VerifiedApplicationKeySet,
  keyId: string,
  keyUsage: string,
  algorithm: string,
): ApplicationKeyAttestation | undefined {
  if (set.revokedKeyIds.has(keyId)) return undefined;
  const found = set.keys.find((k) => k.attestation.keyId === keyId);
  if (!found || found.status.kind !== "usable") return undefined;
  if (found.attestation.keyUsage !== keyUsage || found.attestation.algorithm !== algorithm) return undefined;
  return found.attestation;
}
