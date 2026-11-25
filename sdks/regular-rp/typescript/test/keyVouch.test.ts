import assert from "node:assert/strict";
import test from "node:test";

import type { DomainPublicKey } from "../generated/types.gen.ts";
import { derivePublicKeyFromEd25519PrivateKey, fingerprint, signEd25519 } from "../src/crypto.ts";
import { keyVouchPayload, verifyKeyVouch } from "../src/dnsRecords.ts";

const NOW = new Date("2026-08-27T12:00:00Z");
const SIGN_SEED = new Uint8Array(32).fill(9);

function keys(encExpiresAt: Date): { signing: DomainPublicKey; enc: DomainPublicKey } {
  const signingPublic = derivePublicKeyFromEd25519PrivateKey(SIGN_SEED);
  const encPublic = new Uint8Array(32).fill(5);
  const signing: DomainPublicKey = {
    keyId: "sign-1",
    publicKey: signingPublic,
    fingerprint: fingerprint(signingPublic),
    algorithm: "ed25519",
    keyUsage: "sign",
    createdAt: new Date("2026-01-01T00:00:00Z"),
    expiresAt: new Date("2027-01-01T00:00:00Z"),
  };
  const wholeExpiry = new Date(Math.floor(encExpiresAt.getTime() / 1000) * 1000);
  const enc: DomainPublicKey = {
    keyId: "enc-1",
    publicKey: encPublic,
    fingerprint: fingerprint(encPublic),
    algorithm: "x25519",
    keyUsage: "encrypt",
    createdAt: new Date("2026-01-01T00:00:00Z"),
    expiresAt: encExpiresAt,
    signedByKeyId: "sign-1",
    keySignature: signEd25519(keyVouchPayload(fingerprint(encPublic), wholeExpiry), SIGN_SEED),
  };
  return { signing, enc };
}

test("key vouch signs the expiry as whole Unix seconds (a CBOR integer)", () => {
  const payload = keyVouchPayload("ab", new Date("2026-01-01T00:00:00Z"));
  // [tag, "ab", 1767225600]: the last element is 0x1a + four bytes.
  assert.equal(Buffer.from(payload.subarray(payload.length - 5)).toString("hex"), "1a6955b900");
  const { signing, enc } = keys(new Date("2026-12-01T00:00:00Z"));
  assert.equal(verifyKeyVouch(enc, signing, NOW), true);
});

test("key vouch with a fractional expiry does not verify", () => {
  const { signing, enc } = keys(new Date("2026-12-01T00:00:00.250Z"));
  assert.equal(verifyKeyVouch(enc, signing, NOW), false);
});
