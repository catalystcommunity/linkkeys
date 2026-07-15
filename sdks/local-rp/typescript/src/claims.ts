// Claim signing/verification, mirroring `crates/liblinkkeys/src/claims.rs`'s
// subset this SDK needs: verifying claims returned by ticket redemption
// against per-signer-domain public keys. `sign_claim` is included too (small,
// and useful for tests/fakes that need to mint a realistic `Claim`).

import { encodeCborTuple, text, bytes as tupleBytes, textOrNull } from "./cborTuple.ts";
import { signEd25519, verifyEd25519 } from "./crypto.ts";
import type { Claim, ClaimSignature, DomainPublicKey } from "./generated/types.gen.ts";

export type ClaimErrorCode =
  | "signature-invalid"
  | "key-not-found"
  | "key-revoked"
  | "key-expired"
  | "revoked"
  | "expired"
  | "bad-expiry"
  | "unsigned"
  | "domain-keys-unavailable"
  | "domain-unverified";

export class ClaimError extends Error {
  readonly code: ClaimErrorCode;
  readonly detail?: string;
  constructor(code: ClaimErrorCode, detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = "ClaimError";
    this.code = code;
    this.detail = detail;
  }
}

const CLAIM_PAYLOAD_TAG = "linkkeys-claim-v2";

/**
 * Canonical bytes a single signature covers for a claim. The subject is the
 * full identity `user_id@subject_domain` (never a bare user_id), and
 * `signing_domain` is bound per-signature, so a signature from one domain
 * can't be relabeled as another's, and a claim about one subject domain
 * can't be replayed against a different one. `claimValue` is a raw byte
 * string (bstr) in the payload, never text — see `claims.json`'s
 * `claim_non_utf8_binary_value` conformance case. Exported so conformance
 * tests can byte-compare against `claims.json`'s `signed_payload_cbor_hex`.
 */
export function claimSignPayload(
  claimId: string,
  claimType: string,
  claimValue: Uint8Array,
  userId: string,
  subjectDomain: string,
  signingDomain: string,
  expiresAt: string | undefined,
  attestedAt: string,
): Uint8Array {
  const subject = `${userId}@${subjectDomain}`;
  return encodeCborTuple([
    text(CLAIM_PAYLOAD_TAG),
    text(claimId),
    text(claimType),
    tupleBytes(claimValue),
    text(subject),
    text(signingDomain),
    textOrNull(expiresAt),
    text(attestedAt),
  ]);
}

export interface ClaimSpec {
  claimId: string;
  claimType: string;
  claimValue: Uint8Array;
  userId: string;
  subjectDomain: string;
  expiresAt?: string;
  attestedAt: string;
}

export interface ClaimSigner {
  domain: string;
  keyId: string;
  privateKeySeed: Uint8Array;
}

/** Sign a claim with one or more keys, producing a `Claim` carrying one `ClaimSignature` per signer. */
export function signClaim(spec: ClaimSpec, signers: readonly ClaimSigner[]): Claim {
  const signatures: ClaimSignature[] = signers.map((signer) => {
    const payload = claimSignPayload(
      spec.claimId,
      spec.claimType,
      spec.claimValue,
      spec.userId,
      spec.subjectDomain,
      signer.domain,
      spec.expiresAt,
      spec.attestedAt,
    );
    return {
      domain: signer.domain,
      signedByKeyId: signer.keyId,
      signature: signEd25519(payload, signer.privateKeySeed),
    };
  });

  return {
    claimId: spec.claimId,
    userId: spec.userId,
    claimType: spec.claimType,
    claimValue: spec.claimValue,
    signatures,
    attestedAt: spec.attestedAt,
    createdAt: new Date().toISOString(),
    expiresAt: spec.expiresAt,
    revokedAt: undefined,
  };
}

/** A domain and the set of its currently-known public keys, as supplied to `verifyClaim`. */
export interface DomainKeySet {
  domain: string;
  keys: readonly DomainPublicKey[];
}

function signingKeyValidity(key: DomainPublicKey, now: Date): "valid" | "revoked" | "expired" {
  if (key.revokedAt !== undefined) return "revoked";
  const expires = new Date(key.expiresAt);
  if (Number.isNaN(expires.getTime())) return "expired";
  return now.getTime() > expires.getTime() ? "expired" : "valid";
}

function verifyOneSignature(
  sig: ClaimSignature,
  payload: Uint8Array,
  keys: readonly DomainPublicKey[],
  now: Date,
): void {
  const key = keys.find((k) => k.keyId === sig.signedByKeyId);
  if (!key) {
    throw new ClaimError("key-not-found", sig.signedByKeyId);
  }
  // A claim signature must come from a signing key, never an encryption key
  // sharing the same id.
  if (key.keyUsage !== "sign") {
    throw new ClaimError("signature-invalid");
  }
  const validity = signingKeyValidity(key, now);
  if (validity === "revoked") throw new ClaimError("key-revoked", key.keyId);
  if (validity === "expired") throw new ClaimError("key-expired", key.keyId);

  if (key.algorithm !== "ed25519") {
    throw new ClaimError("signature-invalid", `unsupported algorithm: ${key.algorithm}`);
  }
  if (!verifyEd25519(payload, sig.signature, key.publicKey)) {
    throw new ClaimError("signature-invalid");
  }
}

/**
 * The cryptographic per-domain quorum: EVERY distinct domain that signed
 * must contribute at least one signature from a currently-valid key of that
 * domain, over `payloadFor(signingDomain)`.
 */
function verifySignatureQuorum(
  signatures: readonly ClaimSignature[],
  domainKeys: readonly DomainKeySet[],
  payloadFor: (signingDomain: string) => Uint8Array,
  now: Date,
): void {
  if (signatures.length === 0) {
    throw new ClaimError("unsigned");
  }

  const domains = [...new Set(signatures.map((s) => s.domain))].sort();

  for (const signingDomain of domains) {
    const set = domainKeys.find((s) => s.domain === signingDomain);
    if (!set) {
      throw new ClaimError("domain-keys-unavailable", signingDomain);
    }
    const payload = payloadFor(signingDomain);

    let lastError: ClaimError = new ClaimError("domain-unverified", signingDomain);
    let satisfied = false;
    for (const sig of signatures.filter((s) => s.domain === signingDomain)) {
      try {
        verifyOneSignature(sig, payload, set.keys, now);
        satisfied = true;
        break;
      } catch (e) {
        if (e instanceof ClaimError) lastError = e;
        else throw e;
      }
    }
    if (!satisfied) throw lastError;
  }
}

/** Verify only the cryptographic per-domain quorum (not revocation/expiry — see `verifyClaim`). */
export function verifyClaimSignatures(
  claim: Claim,
  subjectDomain: string,
  domainKeys: readonly DomainKeySet[],
  now: Date = new Date(),
): void {
  verifySignatureQuorum(
    claim.signatures,
    domainKeys,
    (signingDomain) =>
      claimSignPayload(
        claim.claimId,
        claim.claimType,
        claim.claimValue,
        claim.userId,
        subjectDomain,
        signingDomain,
        claim.expiresAt,
        claim.attestedAt,
      ),
    now,
  );
}

/** Full claim verification: the cryptographic quorum plus the claim's own revocation and expiry. */
export function verifyClaim(
  claim: Claim,
  subjectDomain: string,
  domainKeys: readonly DomainKeySet[],
  now: Date = new Date(),
): void {
  verifyClaimSignatures(claim, subjectDomain, domainKeys, now);

  if (claim.revokedAt !== undefined) {
    throw new ClaimError("revoked");
  }
  if (claim.expiresAt !== undefined) {
    const expires = new Date(claim.expiresAt);
    if (Number.isNaN(expires.getTime())) {
      throw new ClaimError("bad-expiry");
    }
    if (now.getTime() > expires.getTime()) {
      throw new ClaimError("expired");
    }
  }
}
