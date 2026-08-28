import assert from "node:assert/strict";
import test from "node:test";

import { ClaimError, signClaim, verifyClaim } from "../src/claims.ts";
import { derivePublicKeyFromEd25519PrivateKey, fingerprint } from "../src/crypto.ts";

const NOW = new Date("2026-08-27T12:00:00Z");
const SEED = new Uint8Array(32).fill(7);

test("claim verification binds the issuer and full subject identity", () => {
  const claim = signClaim({
    claimId: "claim-1",
    claimType: "over_18",
    claimValue: new TextEncoder().encode("true"),
    userId: "user-1",
    subjectDomain: "id.example",
    attestedAt: NOW.toISOString(),
    expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
  }, [{ domain: "issuer.example", keyId: "key-1", privateKeySeed: SEED }]);
  const publicKey = derivePublicKeyFromEd25519PrivateKey(SEED);
  const keys = [{
    domain: "issuer.example",
    keys: [{
      keyId: "key-1",
      publicKey,
      fingerprint: fingerprint(publicKey),
      algorithm: "ed25519",
      keyUsage: "sign",
      createdAt: new Date(NOW.getTime() - 60_000).toISOString(),
      expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
    }],
  }];

  assert.doesNotThrow(() => verifyClaim(claim, "id.example", keys, NOW));
  assert.throws(
    () => verifyClaim(claim, "other.example", keys, NOW),
    (error: unknown) => error instanceof ClaimError && error.code === "signature-invalid",
  );
});

test("claim verification rejects unsigned claims", () => {
  const claim = signClaim({
    claimId: "claim-1",
    claimType: "over_18",
    claimValue: new Uint8Array([1]),
    userId: "user-1",
    subjectDomain: "id.example",
    attestedAt: NOW.toISOString(),
  }, []);
  assert.throws(
    () => verifyClaim(claim, "id.example", [], NOW),
    (error: unknown) => error instanceof ClaimError && error.code === "unsigned",
  );
});

test("claim verification accepts an attestation made before key revocation", () => {
  const claim = signClaim({
    claimId: "claim-before-revocation",
    claimType: "member",
    claimValue: new TextEncoder().encode("true"),
    userId: "user-1",
    subjectDomain: "id.example",
    attestedAt: NOW.toISOString(),
  }, [{ domain: "issuer.example", keyId: "key-1", privateKeySeed: SEED }]);
  const publicKey = derivePublicKeyFromEd25519PrivateKey(SEED);
  const key = {
    keyId: "key-1",
    publicKey,
    fingerprint: fingerprint(publicKey),
    algorithm: "ed25519",
    keyUsage: "sign",
    createdAt: new Date(NOW.getTime() - 60_000).toISOString(),
    expiresAt: new Date(NOW.getTime() + 120_000).toISOString(),
    revokedAt: new Date(NOW.getTime() + 60_000).toISOString(),
  };
  assert.doesNotThrow(() => verifyClaim(claim, "id.example", [{ domain: "issuer.example", keys: [key] }], new Date(NOW.getTime() + 90_000)));
});
