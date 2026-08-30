// Exercises `resolveApplicationKeys` / `ApplicationKeyClientCache`
// (`src/applicationKeyCache.ts`) against a fake `Rp/resolve-application-keys`
// operation built from the real, checked-in attestation conformance vector —
// so a "resolved" result in these tests is a genuinely verified attestation,
// not a stub.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import type { ClaimSignature, DomainPublicKey, RpResolveApplicationKeysResponse } from "../generated/types.gen.ts";
import {
  ApplicationKeyClientCache,
  resolveApplicationKeys,
  type InstanceIdentity,
  type ResolveApplicationKeysOperation,
} from "../src/applicationKeyCache.ts";
import { usableKeys } from "../src/applicationKeys.ts";

const CONFORMANCE_DIR = resolve(process.cwd(), "../conformance");

function load(name: string): any {
  return JSON.parse(readFileSync(resolve(CONFORMANCE_DIR, name), "utf8"));
}

function hex(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "hex"));
}

function domainKeyFrom(v: any): DomainPublicKey {
  return {
    keyId: v.key_id,
    publicKey: hex(v.public_key_hex),
    fingerprint: v.fingerprint,
    algorithm: v.algorithm,
    keyUsage: v.key_usage,
    createdAt: v.created_at,
    expiresAt: v.expires_at,
    revokedAt: v.revoked_at ?? undefined,
  };
}

const vectors = load("application_key_attestation.json");
const positiveCase = vectors.cases[0];
// The fixture's attestation is only valid within a fixed 2026 window (see
// `sdks/regular-rp/conformance/README.md`: every timestamp in these vectors
// is a fixed constant, not wall-clock time). Evaluate "current usability"
// tests at that fixed instant rather than real wall-clock `now`, which will
// eventually run past `attestation_expires_at`.
const FIXED_NOW = new Date(vectors.attestation.attested_at);
const instance: InstanceIdentity = {
  subjectUserId: vectors.instance.subject_user_id,
  subjectDomain: vectors.instance.subject_domain,
  applicationId: vectors.instance.application_id,
  instanceId: vectors.instance.instance_id,
};

function cannedResponse(cacheStatus: string): RpResolveApplicationKeysResponse {
  const signatures: ClaimSignature[] = positiveCase.signed.signatures.map(
    (sig: any): ClaimSignature => ({
      domain: sig.domain,
      signedByKeyId: sig.signed_by_key_id,
      signature: hex(sig.signature_hex),
    }),
  );
  return {
    subjectUserId: instance.subjectUserId,
    subjectDomain: instance.subjectDomain,
    applicationId: instance.applicationId,
    instanceId: instance.instanceId,
    applicationKeys: [{ attestation: hex(positiveCase.signed.attestation_cbor_hex), signatures }],
    applicationKeyRevocations: [],
    homeDomainKeys: positiveCase.domain_keys.map(domainKeyFrom),
    homeDomainKeyRevocations: [],
    fetchedAt: new Date().toISOString(),
    revocationsCheckedAt: new Date().toISOString(),
    cacheStatus,
  };
}

class FakeRp implements ResolveApplicationKeysOperation {
  calls = 0;
  response: RpResolveApplicationKeysResponse | Error = cannedResponse("refreshed");

  async resolveApplicationKeys(): Promise<RpResolveApplicationKeysResponse> {
    this.calls++;
    if (this.response instanceof Error) throw this.response;
    return this.response;
  }
}

test("a cache miss calls the RP and reports the RP's cache_status", async () => {
  const rp = new FakeRp();
  rp.response = cannedResponse("refreshed");
  const cache = new ApplicationKeyClientCache();
  const result = await resolveApplicationKeys(rp, cache, instance, { now: () => FIXED_NOW });
  assert.equal(rp.calls, 1);
  assert.equal(result.freshness, "refreshed");
  assert.equal(usableKeys(result.keys, "sign").length, 1);
});

test("a call within the local cache window does not call the RP again", async () => {
  const rp = new FakeRp();
  rp.response = cannedResponse("fresh");
  const cache = new ApplicationKeyClientCache();
  await resolveApplicationKeys(rp, cache, instance, { now: () => FIXED_NOW });
  const second = await resolveApplicationKeys(rp, cache, instance, { now: () => FIXED_NOW });
  assert.equal(rp.calls, 1, "must not re-call the RP while within the local cache window");
  assert.equal(second.freshness, "fresh");
});

test("an RP failure with no prior cache entry propagates", async () => {
  const rp = new FakeRp();
  rp.response = new Error("RP unreachable");
  const cache = new ApplicationKeyClientCache();
  await assert.rejects(() => resolveApplicationKeys(rp, cache, instance));
});

test("an RP failure with a prior cache entry falls back to a stale result", async () => {
  const rp = new FakeRp();
  rp.response = cannedResponse("fresh");
  const cache = new ApplicationKeyClientCache();
  await resolveApplicationKeys(rp, cache, instance, { localCacheAgeMs: 0, now: () => FIXED_NOW });

  rp.response = new Error("RP unreachable");
  // A later `now` than the first call: with `localCacheAgeMs: 0`, an EQUAL
  // timestamp would (correctly) still count as "within the window" and skip
  // the RP entirely, so a real elapsed gap is needed to force this call past
  // the local cache and into the RP (failing) path.
  const oneMsLater = () => new Date(FIXED_NOW.getTime() + 1);
  const result = await resolveApplicationKeys(rp, cache, instance, { localCacheAgeMs: 0, now: oneMsLater });
  assert.equal(result.freshness, "stale", "a failed refresh with a cached fallback must report stale, never fresh");
  assert.equal(usableKeys(result.keys, "sign").length, 1, "the last verified keys are still returned, just marked stale");
});

test("the RP's own stale status is never upgraded to fresh", async () => {
  const rp = new FakeRp();
  rp.response = cannedResponse("stale");
  const cache = new ApplicationKeyClientCache();
  const result = await resolveApplicationKeys(rp, cache, instance, { now: () => FIXED_NOW });
  assert.equal(result.freshness, "stale");
});

test("re-verification catches an attestation that expired since it was cached", async () => {
  const rp = new FakeRp();
  rp.response = cannedResponse("refreshed");
  const cache = new ApplicationKeyClientCache();

  const attestedAt = new Date(vectors.attestation.attested_at);
  // A local cache age generous enough to comfortably outlast the 5-year jump
  // below — this test is specifically about re-verifying a STILL-CACHED
  // entry against a new `now`, not about the local cache expiring.
  const localCacheAgeMs = 200 * 365 * 24 * 60 * 60 * 1000;
  const stillCurrent = await resolveApplicationKeys(rp, cache, instance, {
    localCacheAgeMs,
    now: () => attestedAt,
  });
  assert.equal(usableKeys(stillCurrent.keys, "sign").length, 1);

  // Same cached entry, but evaluated at a time far past the attestation's
  // own expiry — must be re-classified as unusable WITHOUT a second RP call.
  const farFuture = new Date(vectors.attestation.attestation_expires_at);
  farFuture.setUTCFullYear(farFuture.getUTCFullYear() + 5);
  const laterResult = await resolveApplicationKeys(rp, cache, instance, {
    localCacheAgeMs,
    now: () => farFuture,
  });
  assert.equal(rp.calls, 1, "re-classification must not require a network call");
  assert.equal(usableKeys(laterResult.keys, "sign").length, 0, "an expired attestation must never be usable");
});

test("ApplicationKeyClientCache evicts the least-recently-used entry past its bound", () => {
  const cache = new ApplicationKeyClientCache(2);
  const entry = (n: number) => ({
    request: cannedResponse("fresh"),
    domainKeys: [],
    fetchedAt: Date.now(),
  });
  const id = (n: number): InstanceIdentity => ({
    subjectUserId: `user-${n}`,
    subjectDomain: "example.com",
    applicationId: "tinku",
    instanceId: "instance-1",
  });
  cache.put(id(1), entry(1));
  cache.put(id(2), entry(2));
  assert.ok(cache.get(id(1)) !== undefined);
  cache.put(id(3), entry(3));
  assert.ok(cache.get(id(1)) !== undefined, "recently touched, must survive");
  assert.ok(cache.get(id(2)) === undefined, "least-recently-used, must be evicted");
  assert.ok(cache.get(id(3)) !== undefined, "just inserted, must survive");
  assert.equal(cache.size, 2);
});
