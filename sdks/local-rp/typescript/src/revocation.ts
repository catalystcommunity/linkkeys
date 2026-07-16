// Sibling-signed key revocation certificate verification, mirroring
// `crates/liblinkkeys/src/revocation.rs`'s subset this SDK needs:
// `fetchDomainKeys` (src/rpc.ts) uses this to drop keys a quorum-verified
// revocation certificate targets.

import { encodeCborTuple, text } from "./cborTuple.ts";
import { verifyEd25519 } from "./crypto.ts";
import type { DomainPublicKey, RevocationCertificate } from "./generated/types.gen.ts";

/** Minimum number of distinct sibling signatures required to revoke a key. */
export const REVOCATION_QUORUM = 2;

/** Domain-separation tag / version for the signed revocation payload. */
export const REVOCATION_TAG = "linkkeys-key-revocation-v1alpha";

/**
 * Canonical bytes one sibling signature covers:
 * `CBOR([tag, target_key_id, target_fingerprint, revoked_at,
 * signing_domain])` — a FIVE-element CBOR array with the domain-separation
 * tag first (the older house tuple pattern; NOT the local-RP envelopes'
 * two-element `CBOR([context, payload])` framing). The signing domain is
 * bound per-signature so a signature can never be replayed for another
 * domain. Exported so conformance tests can byte-compare against
 * `revocations.json`'s `signed_payload_cbor_hex`.
 */
export function revocationPayload(
  targetKeyId: string,
  targetFingerprint: string,
  revokedAt: string,
  signingDomain: string,
): Uint8Array {
  return encodeCborTuple([
    text(REVOCATION_TAG),
    text(targetKeyId),
    text(targetFingerprint),
    text(revokedAt),
    text(signingDomain),
  ]);
}

function signingKeyValidity(key: DomainPublicKey, now: Date): "valid" | "revoked" | "expired" {
  if (key.revokedAt !== undefined) return "revoked";
  const expires = new Date(key.expiresAt);
  if (Number.isNaN(expires.getTime())) return "expired";
  return now.getTime() > expires.getTime() ? "expired" : "valid";
}

/**
 * Count the DISTINCT signer key ids on `cert` that survive every filtering
 * rule (the conformance vectors' `expected_counted_signers`):
 *
 * 1. Skip any signature whose `signedByKeyId` equals the certificate's
 *    `targetKeyId` (a key never authorizes its own revocation), any whose
 *    wire `domain` field differs from the domain being verified, and any
 *    whose signer key is absent from the fetched key list or is not a
 *    currently-valid signing key (wrong `keyUsage`, expired, or itself
 *    revoked).
 * 2. For the rest, recompute the payload using the signature's **wire**
 *    `domain` field (the `domain` parameter only filters — this is what
 *    stops a signature minted for another domain from being re-labeled) and
 *    verify the Ed25519 signature with the signer's public key.
 * 3. Distinctness is by signer key id.
 */
export function countRevocationCertificateSigners(
  cert: RevocationCertificate,
  domainKeys: readonly DomainPublicKey[],
  domain: string,
  now: Date = new Date(),
): number {
  const validSigners = new Set<string>();

  for (const sig of cert.signatures) {
    // A key can never authorize its own revocation.
    if (sig.signedByKeyId === cert.targetKeyId) continue;
    if (sig.domain !== domain) continue;

    const key = domainKeys.find((k) => k.keyId === sig.signedByKeyId);
    if (!key) continue;
    if (key.keyUsage !== "sign") continue;
    if (signingKeyValidity(key, now) !== "valid") continue;
    if (key.algorithm !== "ed25519") continue;

    // Recompute from the signature's WIRE domain field (which the filter
    // above has already required to equal `domain`).
    const payload = revocationPayload(
      cert.targetKeyId,
      cert.targetFingerprint,
      cert.revokedAt,
      sig.domain,
    );
    if (verifyEd25519(payload, sig.signature, key.publicKey)) {
      validSigners.add(sig.signedByKeyId);
    }
  }

  return validSigners.size;
}

/**
 * Verify a revocation certificate against a domain's public key set.
 * Requires at least `REVOCATION_QUORUM` DISTINCT signing keys of `domain`,
 * each currently valid and NOT the target key, to have signed the canonical
 * payload. Returns `true` when the quorum is met.
 */
export function verifyRevocationCertificate(
  cert: RevocationCertificate,
  domainKeys: readonly DomainPublicKey[],
  domain: string,
  now: Date = new Date(),
): boolean {
  return countRevocationCertificateSigners(cert, domainKeys, domain, now) >= REVOCATION_QUORUM;
}
