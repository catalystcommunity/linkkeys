// Unit tests for the act-as API: the full grantee/audience flow with keys
// from the conformance files, the RP helpers with a fake transport, and the
// browser URL with a fake DNS resolver. No live network.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import {
  fromRpActAsRefreshRequestCbor,
  fromRpResolveActAsRevocationsRequestCbor,
  fromRpResolveDomainKeysRequestCbor,
  fromSignedActAsGrantRequestCbor,
  fromSignedActAsGrantRevocationCbor,
  toActAsGrantCbor,
  toActAsGrantRequestCbor,
  toActAsGrantRevocationCbor,
  toGetActAsGrantRevocationsResponseCbor,
  toRefreshActAsGrantResponseCbor,
  toRpResolveDomainKeysResponseCbor,
} from "../generated/codec.gen.ts";
import type {
  ActAsGrant,
  ActAsGrantRequest,
  ActAsScopeSet,
  ApplicationKeyAttestation,
  Claim,
  ApplicationRef,
  DomainPublicKey,
  GranteeRef,
  SignedActAsGrant,
  SignedActAsGrantRevocation,
} from "../generated/types.gen.ts";
import {
  ACT_AS_GRANT_REQUEST_TAG,
  ACT_AS_GRANT_REVOCATION_TAG,
  ACT_AS_GRANT_TAG,
  ActAsError,
  actAsSignatureInput,
  attestedKeyRefs,
  checkScopeSetCurrent,
  credentialScopeSetSigner,
  credentialSignerInstance,
  formatActAsTime,
  granteeProve,
  parseRfc3339,
  present,
  refreshDueAt,
  revokedGrantIds,
  signGrantRequest,
  signRefreshRequest,
  signScopeSet,
  verifyCredential,
  verifyGrantRequest,
  verifyGrantSignature,
  verifyGranteeProof,
  verifyHandleClaim,
  verifyScopeSet,
  usableKeyRefs,
  type AudienceContext,
  type GranteeSigner,
} from "../src/actAs.ts";
import { ACT_AS_ROUTE, ActAsRpClient, actAsRequestUrl, type RpCallTransport } from "../src/actAsClient.ts";
import type { ApplicationKeyRef } from "../src/applicationKeys.ts";
import { signClaim } from "../src/claims.ts";
import { derivePublicKeyFromEd25519PrivateKey, fingerprint, signEd25519 } from "../src/crypto.ts";
import type { DnsResolver } from "../src/dns.ts";
import type { RpcCallOptions } from "../src/rpc.ts";

const V = JSON.parse(readFileSync(resolve(process.cwd(), "../conformance/act_as_signatures.json"), "utf8"));
const NOW = new Date("2026-10-06T12:00:00Z");
const SKEW = 60;
const HOME: string = V.home_domain;

function hex(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "hex"));
}

function appRef(v: any): ApplicationRef {
  return { subjectUserId: v.subject_user_id, subjectDomain: v.subject_domain, applicationId: v.application_id };
}

function keyRefs(v: any[]): ApplicationKeyRef[] {
  return v.map((k) => ({
    keyId: k.key_id,
    keyUsage: k.key_usage,
    algorithm: k.algorithm,
    publicKey: hex(k.public_key_hex),
    fingerprint: k.fingerprint,
    createdAt: k.created_at,
    expiresAt: k.expires_at,
  }));
}

const HOME_KEYS: DomainPublicKey[] = V.home_domain_keys.map((k: any) => ({
  keyId: k.key_id,
  publicKey: hex(k.public_key_hex),
  fingerprint: k.fingerprint,
  algorithm: k.algorithm,
  keyUsage: k.key_usage,
  createdAt: k.created_at,
  expiresAt: k.expires_at,
}));
const HOME_PRIVATE = hex(V.keys.home.private_key_hex);
const AUDIENCE = appRef(V.audience);
const AUDIENCE_KEYS = keyRefs(V.audience_keys);
const GRANTEE_KEYS = keyRefs(V.grantee_instance_keys);
const GRANTEE: GranteeRef = {
  application: { subjectUserId: "018f3333-0000-7000-8000-0000000000c1", subjectDomain: "grantee.conformance.example", applicationId: "grantee-app" },
};
const GRANTEE_SIGNER: GranteeSigner = {
  kind: "application",
  instanceId: "grantee-instance-1",
  signer: { keyId: V.keys.grantee.key_id, privateKey: hex(V.keys.grantee.private_key_hex) },
};
const DIGEST = new TextEncoder().encode("request-digest");

function homeSign(grant: ActAsGrant): SignedActAsGrant {
  const bytes = toActAsGrantCbor(grant);
  return {
    grant: bytes,
    signatures: [{ domain: HOME, signedByKeyId: V.keys.home.key_id, signature: signEd25519(actAsSignatureInput(ACT_AS_GRANT_TAG, bytes), HOME_PRIVATE) }],
  };
}

function homeRevoke(grantId: string): SignedActAsGrantRevocation {
  const bytes = toActAsGrantRevocationCbor({ grantId, userId: "user-a", subjectDomain: HOME, revokedAt: "2026-10-06T12:30:00Z" });
  return {
    revocation: bytes,
    signatures: [{ domain: HOME, signedByKeyId: V.keys.home.key_id, signature: signEd25519(actAsSignatureInput(ACT_AS_GRANT_REVOCATION_TAG, bytes), HOME_PRIVATE) }],
  };
}

const AUDIENCE_SIGNER = { keyId: V.keys.audience.key_id, privateKey: hex(V.keys.audience.private_key_hex) };

/** A second audience key, made here: the vectors hold only one private key. */
const SECOND_SEED = new Uint8Array(32).fill(7);
const SECOND_SIGNER = { keyId: "audience-key-test-2", privateKey: SECOND_SEED };
const SECOND_KEY: ApplicationKeyRef = {
  keyId: SECOND_SIGNER.keyId,
  keyUsage: "sign",
  algorithm: "ed25519",
  publicKey: derivePublicKeyFromEd25519PrivateKey(SECOND_SEED),
  fingerprint: fingerprint(derivePublicKeyFromEd25519PrivateKey(SECOND_SEED)),
  createdAt: "2026-01-01T00:00:00Z",
  expiresAt: "2027-01-01T00:00:00Z",
};
const FIRST_KEY = AUDIENCE_KEYS.find((k) => k.keyId === AUDIENCE_SIGNER.keyId)!;

function scopeSetBody(overrides: Partial<ActAsScopeSet> = {}): ActAsScopeSet {
  return {
    audience: AUDIENCE,
    grantee: GRANTEE,
    entries: [{ scope: "read", description: "Read" }, { scope: "write" }],
    language: "en-US",
    issuedAt: "2026-10-06T11:55:00Z",
    expiresAt: "2026-10-06T12:10:00Z",
    ...overrides,
  };
}

function flow(overrides: Partial<ActAsGrant> = {}) {
  const scopeSet = signScopeSet(scopeSetBody(), "audience-instance-1", [AUDIENCE_SIGNER]);
  const grant = homeSign({
    grantId: "grant-9",
    userId: "user-a",
    subjectDomain: HOME,
    grantee: GRANTEE,
    audience: AUDIENCE,
    scopeSet,
    approvedScope: ["read"],
    issuedAt: "2026-10-06T12:00:00Z",
    expiresAt: "2026-10-06T13:00:00Z",
    seriesIssuedAt: "2026-10-06T12:00:00Z",
    renewableUntil: "2026-10-06T13:00:00Z",
    ...overrides,
  });
  return { scopeSet, grant };
}

function context(overrides: Partial<AudienceContext> = {}): AudienceContext {
  return {
    ownApplication: AUDIENCE,
    ownScopeSetKeys: AUDIENCE_KEYS,
    issuerDomainKeys: HOME_KEYS,
    granteeInstanceKeys: GRANTEE_KEYS,
    expectedRequestDigest: DIGEST,
    revokedGrantIds: [],
    maxPresentationAgeSeconds: 300,
    now: new Date("2026-10-06T12:30:00Z"),
    skewSeconds: SKEW,
    ...overrides,
  };
}

function code(fn: () => unknown): string | undefined {
  try {
    fn();
    return undefined;
  } catch (err) {
    assert.ok(err instanceof ActAsError, String(err));
    return err.code;
  }
}

// ---------------------------------------------------------------------------
// Pure protocol
// ---------------------------------------------------------------------------

test("full flow: scope set, grant request, presentation, audience verification", () => {
  const { scopeSet, grant } = flow();
  assert.deepEqual(verifyScopeSet(scopeSet, AUDIENCE, AUDIENCE_KEYS).entries.map((e) => e.scope), ["read", "write"]);

  const signedRequest = signGrantRequest(
    {
      grantee: GRANTEE,
      scopeSet,
      requestedLifetimeSeconds: 1800,
      callbackUrl: "https://grantee.example/act-as/callback",
      nonce: "n-1",
      requestedAt: "2026-10-06T11:59:00Z",
      expiresAt: "2026-10-06T12:04:00Z",
    },
    GRANTEE_SIGNER,
  );
  assert.equal(verifyGrantRequest(signedRequest, GRANTEE_KEYS, NOW, SKEW).nonce, "n-1");

  const credential = present(grant, AUDIENCE, DIGEST, new Date("2026-10-06T12:29:59.900Z"), hex("01020304"), GRANTEE_SIGNER);
  assert.equal(credentialSignerInstance(credential), "grantee-instance-1");
  assert.equal(credentialScopeSetSigner(credential), "audience-instance-1");
  const verified = verifyCredential(credential, context());
  assert.equal(verified.userId, `user-a@${HOME}`);
  assert.deepEqual(verified.approvedScope, ["read"]);
  assert.equal(verified.signer.keyId, V.keys.grantee.key_id);

  // The scope set expired at 12:10. Approval refuses it; the audience does not check it.
  const set = verifyScopeSet(scopeSet, AUDIENCE, AUDIENCE_KEYS);
  assert.equal(code(() => checkScopeSetCurrent(set, new Date("2026-10-06T12:30:00Z"), SKEW)), "scope-set-expired");
});

test("audience checklist refuses revoked, expired, and wrong-digest credentials", () => {
  const { grant } = flow();
  const credential = present(grant, AUDIENCE, DIGEST, new Date("2026-10-06T12:30:00Z"), hex("05"), GRANTEE_SIGNER);
  assert.equal(code(() => verifyCredential(credential, context({ revokedGrantIds: ["grant-9"] }))), "grant-revoked");
  assert.equal(code(() => verifyCredential(credential, context({ expectedRequestDigest: hex("00") }))), "mismatch");
  assert.equal(code(() => verifyCredential(credential, context({ now: new Date("2026-10-06T13:01:00Z") }))), "grant-expired");
  // Step 1 runs before step 2: a forged grant fails on the signature, not the audience.
  assert.equal(
    code(() => verifyCredential(credential, context({ issuerDomainKeys: [], ownApplication: { ...AUDIENCE, applicationId: "x" } }))),
    "untrusted-signer",
  );
});

test("a device-bound grant is refused until device keys exist", () => {
  const { grant } = flow({ deviceFingerprint: "ab".repeat(32) });
  assert.equal(code(() => verifyGrantSignature(grant, HOME_KEYS, NOW)), "device-binding-unsupported");
});

test("a proof whose form does not match the grantee is refused", () => {
  const proof = {
    applicationInstanceId: undefined,
    localRpDescriptor: { descriptor: new Uint8Array(), signature: new Uint8Array() },
    signature: { signedByKeyId: "fp", signature: new Uint8Array(64) },
  };
  assert.equal(code(() => verifyGranteeProof(proof, new Uint8Array(), GRANTEE, GRANTEE_KEYS, NOW, SKEW)), "proof-does-not-match-grantee");
  assert.equal(
    code(() => verifyGranteeProof(proof, new Uint8Array(), { ...GRANTEE, localRpDescriptorFingerprint: "fp" }, GRANTEE_KEYS, NOW, SKEW)),
    "malformed-grantee",
  );
});

test("a revoked grantee key cannot sign a presentation", () => {
  const { grant } = flow();
  const credential = present(grant, AUDIENCE, DIGEST, new Date("2026-10-06T12:30:00Z"), hex("06"), GRANTEE_SIGNER);
  const revokedKeys = GRANTEE_KEYS.map((k) => ({ ...k, revokedAt: "2026-10-06T12:15:00Z" }));
  assert.equal(code(() => verifyCredential(credential, context({ granteeInstanceKeys: revokedKeys }))), "untrusted-signer");
});

test("timestamps: whole-second UTC with Z, strict RFC3339 parsing", () => {
  assert.equal(formatActAsTime(new Date("2026-10-06T12:00:00.999Z")), "2026-10-06T12:00:00Z");
  assert.equal(parseRfc3339("2026-10-06T14:00:00+02:00"), Date.parse("2026-10-06T12:00:00Z"));
  assert.equal(parseRfc3339("2026-10-06T12:00:00.5Z"), Date.parse("2026-10-06T12:00:00.500Z"));
  assert.equal(parseRfc3339("2028-02-29T00:00:00Z"), Date.parse("2028-02-29T00:00:00Z"));
  assert.equal(new Date(parseRfc3339("0050-01-01T00:00:00Z")!).getUTCFullYear(), 50);
  for (const bad of ["2026-02-29T00:00:00Z", "2026-10-06", "2026-02-30T00:00:00Z", "2026-10-06T12:00:00", "Tue, 06 Oct 2026 12:00:00 GMT"]) {
    assert.equal(parseRfc3339(bad), undefined, bad);
  }
  assert.deepEqual(
    refreshDueAt({ issuedAt: "2026-10-06T12:00:00Z", expiresAt: "2026-10-06T13:00:00Z" }),
    new Date("2026-10-06T12:30:00Z"),
  );
});

test("revokedGrantIds keeps only revocations that the home domain signed", () => {
  const forged = fromSignedActAsGrantRevocationCbor(hex(V.revocation.negative_cases[0].signed_cbor_hex));
  assert.deepEqual(revokedGrantIds([homeRevoke("g-1"), forged], HOME_KEYS, HOME, NOW), ["g-1"]);
  assert.deepEqual(revokedGrantIds([homeRevoke("g-1")], HOME_KEYS, "other.example", NOW), []);
});

// ---------------------------------------------------------------------------
// RP helpers with a fake transport
// ---------------------------------------------------------------------------

type Handler = (req: Uint8Array) => Uint8Array;

class FakeTransport implements RpCallTransport {
  readonly calls: string[] = [];
  constructor(private readonly handlers: Record<string, Handler>) {}

  async callWithOptions(service: string, op: string, req: Uint8Array, _options?: RpcCallOptions): Promise<Uint8Array> {
    this.calls.push(`${service}/${op}`);
    const handler = this.handlers[`${service}/${op}`];
    if (!handler) throw new Error(`unexpected call ${service}/${op}`);
    return handler(req);
  }
}

function domainKeysResponse(domain = HOME): Handler {
  return (req) => {
    assert.equal(fromRpResolveDomainKeysRequestCbor(req).domain, HOME);
    return toRpResolveDomainKeysResponseCbor({
      domain,
      keys: HOME_KEYS,
      revocations: [],
      fetchedAt: "2026-10-06T12:00:00Z",
      revocationsCheckedAt: "2026-10-06T12:00:00Z",
      cacheStatus: "fresh",
    });
  };
}

test("refreshGrant forwards the signed request through Rp/act-as-refresh-grant", async () => {
  const { grant } = flow();
  const signed = signRefreshRequest(
    { grantId: "grant-9", grantee: GRANTEE, requestedAt: "2026-10-06T12:40:00Z", expiresAt: "2026-10-06T12:45:00Z", nonce: "r-1" },
    GRANTEE_SIGNER,
  );
  const transport = new FakeTransport({
    "Rp/act-as-refresh-grant": (req) => {
      const decoded = fromRpActAsRefreshRequestCbor(req);
      assert.equal(decoded.subjectDomain, HOME);
      assert.deepEqual(decoded.request.request, signed.request);
      return toRefreshActAsGrantResponseCbor({ grant, signed: true });
    },
  });
  const response = await new ActAsRpClient(transport).refreshGrant(HOME, signed);
  assert.equal(response.signed, true);
  assert.deepEqual(response.grant.grant, grant.grant);
  assert.deepEqual(transport.calls, ["Rp/act-as-refresh-grant"]);
  await assert.rejects(new ActAsRpClient(transport).refreshGrant("not a domain", signed), TypeError);
});

test("refreshGrant refuses a grant for another grant id, grantee, or domain", async () => {
  const { grant } = flow();
  const refresh = (grantId: string) =>
    signRefreshRequest(
      { grantId, grantee: GRANTEE, requestedAt: "2026-10-06T12:40:00Z", expiresAt: "2026-10-06T12:45:00Z", nonce: "r-2" },
      GRANTEE_SIGNER,
    );
  const client = new ActAsRpClient(
    new FakeTransport({ "Rp/act-as-refresh-grant": () => toRefreshActAsGrantResponseCbor({ grant, signed: false }) }),
  );
  const isMismatch = (field: string) => (err: unknown) =>
    err instanceof ActAsError && err.code === "mismatch" && err.message.includes(field);
  await assert.rejects(client.refreshGrant(HOME, refresh("grant-other")), isMismatch("grant_id"));
  await assert.rejects(client.refreshGrant("other.example", refresh("grant-9")), isMismatch("subject_domain"));
  // An ASCII case difference in the domain is the same domain.
  assert.equal((await client.refreshGrant(HOME.toUpperCase(), refresh("grant-9"))).signed, false);
});

test("resolveGrantRevocations returns only verified revocations for requested grants", async () => {
  const forged = fromSignedActAsGrantRevocationCbor(hex(V.revocation.negative_cases[0].signed_cbor_hex));
  const transport = new FakeTransport({
    "Rp/resolve-act-as-revocations": (req) => {
      const decoded = fromRpResolveActAsRevocationsRequestCbor(req);
      assert.equal(decoded.subjectDomain, HOME);
      assert.deepEqual(decoded.grantIds, ["grant-1", "grant-2"]);
      return toGetActAsGrantRevocationsResponseCbor({
        revocations: [homeRevoke("grant-1"), homeRevoke("not-asked"), forged],
      });
    },
    "Rp/resolve-domain-keys": domainKeysResponse(),
  });
  const result = await new ActAsRpClient(transport).resolveGrantRevocations(HOME, ["grant-1", "grant-2", "grant-1"], { now: NOW });
  assert.deepEqual(result.revokedGrantIds, ["grant-1"]);
  assert.equal(result.revocations[0]!.revokedAt, "2026-10-06T12:30:00Z");
  assert.equal(result.rejectedCount, 2);
  assert.equal(result.domainKeysCacheStatus, "fresh");
});

test("resolveGrantRevocations refuses bad input and keys for another domain", async () => {
  const client = new ActAsRpClient(new FakeTransport({
    "Rp/resolve-act-as-revocations": () => toGetActAsGrantRevocationsResponseCbor({ revocations: [] }),
    "Rp/resolve-domain-keys": domainKeysResponse("other.example"),
  }));
  await assert.rejects(client.resolveGrantRevocations(HOME, []), TypeError);
  await assert.rejects(client.resolveGrantRevocations(HOME, [""]), TypeError);
  await assert.rejects(client.resolveGrantRevocations(HOME, Array.from({ length: 101 }, (_, i) => `g-${i}`)), TypeError);
  await assert.rejects(client.resolveGrantRevocations(HOME, ["g-1"]), (err: unknown) => err instanceof ActAsError && err.code === "mismatch");
});

// ---------------------------------------------------------------------------
// Browser URL with a fake DNS resolver
// ---------------------------------------------------------------------------

test("actAsRequestUrl uses the discovered browser base and keeps its path prefix", async () => {
  const signed = fromSignedActAsGrantRequestCbor(hex(V.grant_request.signed_cbor_hex));
  const dns: DnsResolver = {
    async txtLookup(name: string): Promise<string[]> {
      assert.equal(name, `_linkkeys_apis.${HOME}`);
      return ["v=lk1 tcp=id.example:4987 https=login.id.example/linkkeys"];
    },
  };
  const url = new URL(await actAsRequestUrl(dns, HOME, signed));
  assert.equal(url.origin, "https://login.id.example");
  assert.equal(url.pathname, `/linkkeys${ACT_AS_ROUTE}`);
  const param = url.searchParams.get("signed_request")!;
  assert.doesNotMatch(param, /[=+/]/);
  const decoded = fromSignedActAsGrantRequestCbor(new Uint8Array(Buffer.from(param, "base64url")));
  assert.deepEqual(decoded.request, signed.request);
});

test("actAsRequestUrl falls back to the subject domain when DNS fails", async () => {
  const signed = fromSignedActAsGrantRequestCbor(hex(V.grant_request.signed_cbor_hex));
  const dns: DnsResolver = { txtLookup: async () => { throw new Error("NXDOMAIN"); } };
  const url = new URL(await actAsRequestUrl(dns, HOME, signed));
  assert.equal(url.origin, `https://${HOME}`);
  assert.equal(url.pathname, ACT_AS_ROUTE);
  await assert.rejects(actAsRequestUrl(dns, "evil.example/path?x=", signed), TypeError);
});


test("usableKeyRefs keeps only usable keys", () => {
  const attestation = (keyId: string): ApplicationKeyAttestation => ({
    subjectUserId: "u", subjectDomain: "d.example", applicationId: "a", instanceId: "i",
    keyId, keyUsage: "sign", algorithm: "ed25519", publicKey: new Uint8Array(32), fingerprint: "f",
    keyCreatedAt: "2026-01-01T00:00:00Z", keyExpiresAt: "2027-01-01T00:00:00Z",
    attestedAt: "2026-01-01T00:00:00Z", attestationExpiresAt: "2026-12-01T00:00:00Z",
  });
  const refs = usableKeyRefs({
    keys: [
      { attestation: attestation("k-1"), status: { kind: "usable" } },
      { attestation: attestation("k-2"), status: { kind: "revoked", revokedAt: "2026-06-01T00:00:00Z" } },
    ],
    revokedKeyIds: new Set(["k-2"]),
    rejected: [],
  });
  assert.deepEqual(refs.map((k) => k.keyId), ["k-1"]);
  assert.equal(refs[0]!.createdAt, "2026-01-01T00:00:00Z");
});


// ---------------------------------------------------------------------------
// Multi-signed scope sets and the revoked-key policy
// ---------------------------------------------------------------------------

function errorOf(fn: () => unknown): ActAsError {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof ActAsError, String(err));
    return err;
  }
  assert.fail("expected an ActAsError");
}

test("signScopeSet signs with every key and refuses an empty or repeated key list", () => {
  const signed = signScopeSet(scopeSetBody(), "audience-instance-1", [AUDIENCE_SIGNER, SECOND_SIGNER]);
  assert.deepEqual(signed.signatures.map((s) => s.signedByKeyId), [AUDIENCE_SIGNER.keyId, SECOND_SIGNER.keyId]);
  assert.equal(code(() => signScopeSet(scopeSetBody(), "i", [])), "no-valid-signature");
  assert.equal(code(() => signScopeSet(scopeSetBody(), "i", [AUDIENCE_SIGNER, AUDIENCE_SIGNER])), "no-valid-signature");
});

test("one acceptable signature is enough; one expired or unknown key does not break the set", () => {
  const signed = signScopeSet(scopeSetBody(), "audience-instance-1", [AUDIENCE_SIGNER, SECOND_SIGNER]);
  const expiredFirst = { ...FIRST_KEY, expiresAt: "2026-01-02T00:00:00Z" };
  assert.equal(verifyScopeSet(signed, AUDIENCE, [expiredFirst, SECOND_KEY]).entries.length, 2);
  assert.equal(verifyScopeSet(signed, AUDIENCE, [SECOND_KEY]).entries.length, 2);
});

test("no acceptable signature: the error names every key and why it was refused", () => {
  const signed = signScopeSet(scopeSetBody(), "audience-instance-1", [AUDIENCE_SIGNER, SECOND_SIGNER]);
  const expiredFirst = { ...FIRST_KEY, expiresAt: "2026-01-02T00:00:00Z" };
  const revokedSecond = { ...SECOND_KEY, revokedAt: "2026-10-06T11:00:00Z" };
  let err = errorOf(() => verifyScopeSet(signed, AUDIENCE, [expiredFirst, revokedSecond]));
  assert.equal(err.code, "no-valid-signature");
  assert.match(err.message, new RegExp(`${FIRST_KEY.keyId}: not inside its validity window when it signed`));
  assert.match(err.message, new RegExp(`${SECOND_KEY.keyId}: revoked at 2026-10-06T11:00:00Z, before it signed`));

  err = errorOf(() => verifyScopeSet(signed, AUDIENCE, []));
  assert.match(err.message, new RegExp(`${FIRST_KEY.keyId}: not a key of the audience`));
  assert.match(err.message, new RegExp(`${SECOND_KEY.keyId}: not a key of the audience`));

  // The second key's public key under the first key's id: the signature does not verify.
  const swapped = { ...SECOND_KEY, keyId: FIRST_KEY.keyId };
  err = errorOf(() => verifyScopeSet(signed, AUDIENCE, [swapped]));
  assert.match(err.message, new RegExp(`${FIRST_KEY.keyId}: signature did not verify`));

  assert.equal(code(() => verifyScopeSet({ ...signed, signatures: [] }, AUDIENCE, AUDIENCE_KEYS)), "no-valid-signature");
});

test("revoked-key policy: accept before revocation by default, refuse on request", () => {
  const signed = signScopeSet(scopeSetBody(), "audience-instance-1", [AUDIENCE_SIGNER]);
  const revokedLater = { ...FIRST_KEY, revokedAt: "2026-10-06T12:30:00Z" };
  assert.equal(verifyScopeSet(signed, AUDIENCE, [revokedLater]).entries.length, 2);
  assert.equal(verifyScopeSet(signed, AUDIENCE, [revokedLater], "acceptBeforeRevocation").entries.length, 2);
  const err = errorOf(() => verifyScopeSet(signed, AUDIENCE, [revokedLater], "refuseRevoked"));
  assert.equal(err.code, "no-valid-signature");
  assert.match(err.message, /revoked at 2026-10-06T12:30:00Z; this verifier refuses revoked keys/);

  // The audience checklist passes its policy through.
  const { grant } = flow();
  const credential = present(grant, AUDIENCE, DIGEST, new Date("2026-10-06T12:30:00Z"), hex("07"), GRANTEE_SIGNER);
  assert.equal(verifyCredential(credential, context({ ownScopeSetKeys: [revokedLater] })).grantId, "grant-9");
  assert.equal(
    code(() => verifyCredential(credential, context({ ownScopeSetKeys: [revokedLater], revokedKeyPolicy: "refuseRevoked" }))),
    "no-valid-signature",
  );
});

// ---------------------------------------------------------------------------
// Handle claims
// ---------------------------------------------------------------------------

const PARTY_DOMAIN = AUDIENCE.subjectDomain;
const PARTY_SEED = new Uint8Array(32).fill(9);
const OTHER_SEED = new Uint8Array(32).fill(11);

function domainKey(keyId: string, seed: Uint8Array): DomainPublicKey {
  const publicKey = derivePublicKeyFromEd25519PrivateKey(seed);
  return {
    keyId,
    publicKey,
    fingerprint: fingerprint(publicKey),
    algorithm: "ed25519",
    keyUsage: "sign",
    createdAt: "2026-01-01T00:00:00Z",
    expiresAt: "2027-01-01T00:00:00Z",
  };
}
const PARTY_KEYS = [domainKey("party-key-1", PARTY_SEED)];

function handleClaim(overrides: { userId?: string; claimType?: string; expiresAt?: string; signers?: { domain: string; seed: Uint8Array; keyId: string }[] } = {}): Claim {
  const signers = overrides.signers ?? [{ domain: PARTY_DOMAIN, seed: PARTY_SEED, keyId: "party-key-1" }];
  return signClaim(
    {
      claimId: "claim-h1",
      claimType: overrides.claimType ?? "handle",
      claimValue: new TextEncoder().encode("audience-team"),
      userId: overrides.userId ?? AUDIENCE.subjectUserId,
      subjectDomain: PARTY_DOMAIN,
      expiresAt: overrides.expiresAt,
      attestedAt: "2026-10-01T00:00:00Z",
    },
    signers.map((s) => ({ domain: s.domain, keyId: s.keyId, privateKeySeed: s.seed })),
  );
}

test("verifyHandleClaim counts only the party's own domain and checks expiry", () => {
  assert.equal(verifyHandleClaim(handleClaim(), AUDIENCE, PARTY_KEYS, NOW), "audience-team");
  // A third-domain signature next to a good one is ignored.
  const mixed = handleClaim({
    signers: [
      { domain: PARTY_DOMAIN, seed: PARTY_SEED, keyId: "party-key-1" },
      { domain: "third.example", seed: OTHER_SEED, keyId: "third-1" },
    ],
  });
  assert.equal(verifyHandleClaim(mixed, AUDIENCE, PARTY_KEYS, NOW), "audience-team");
  // A third-domain signature alone does not count.
  const third = handleClaim({ signers: [{ domain: "third.example", seed: OTHER_SEED, keyId: "third-1" }] });
  assert.equal(code(() => verifyHandleClaim(third, AUDIENCE, PARTY_KEYS, NOW)), "bad-handle-claim");
  assert.equal(code(() => verifyHandleClaim(handleClaim({ userId: "someone-else" }), AUDIENCE, PARTY_KEYS, NOW)), "bad-handle-claim");
  assert.equal(code(() => verifyHandleClaim(handleClaim({ claimType: "email" }), AUDIENCE, PARTY_KEYS, NOW)), "bad-handle-claim");
  const expired = handleClaim({ expiresAt: "2026-10-05T00:00:00Z" });
  assert.equal(code(() => verifyHandleClaim(expired, AUDIENCE, PARTY_KEYS, NOW)), "bad-handle-claim");
  const revoked = { ...handleClaim(), revokedAt: "2026-10-05T00:00:00Z" };
  assert.equal(code(() => verifyHandleClaim(revoked, AUDIENCE, PARTY_KEYS, NOW)), "bad-handle-claim");
  const revokedKey = [{ ...PARTY_KEYS[0]!, revokedAt: "2026-09-01T00:00:00Z" }];
  assert.equal(code(() => verifyHandleClaim(handleClaim(), AUDIENCE, revokedKey, NOW)), "bad-handle-claim");
});

test("a scope set's audience handle claim must name the audience's account", () => {
  const signed = signScopeSet(scopeSetBody({ audienceHandleClaim: handleClaim() }), "audience-instance-1", [AUDIENCE_SIGNER]);
  const set = verifyScopeSet(signed, AUDIENCE, AUDIENCE_KEYS);
  assert.equal(verifyHandleClaim(set.audienceHandleClaim!, set.audience, PARTY_KEYS, NOW), "audience-team");
  assert.equal(
    code(() => signScopeSet(scopeSetBody({ audienceHandleClaim: handleClaim({ userId: "someone-else" }) }), "i", [AUDIENCE_SIGNER])),
    "bad-handle-claim",
  );
});

test("a grant request's handle claim must name the grantee's account; a local RP cannot carry one", () => {
  const { scopeSet } = flow();
  const base: ActAsGrantRequest = {
    grantee: GRANTEE,
    scopeSet,
    callbackUrl: "https://grantee.example/act-as/callback",
    nonce: "n-2",
    requestedAt: "2026-10-06T11:59:00Z",
    expiresAt: "2026-10-06T12:04:00Z",
  };
  const granteeClaim = { ...handleClaim(), userId: GRANTEE.application!.subjectUserId };
  const signed = signGrantRequest({ ...base, granteeHandleClaim: granteeClaim }, GRANTEE_SIGNER);
  assert.equal(verifyGrantRequest(signed, GRANTEE_KEYS, NOW, SKEW).granteeHandleClaim?.claimId, "claim-h1");

  const wrong = { ...base, granteeHandleClaim: handleClaim() };
  assert.equal(code(() => signGrantRequest(wrong, GRANTEE_SIGNER)), "bad-handle-claim");
  const local = { ...base, grantee: { localRpDescriptorFingerprint: "fp" }, granteeHandleClaim: granteeClaim };
  assert.equal(code(() => signGrantRequest(local, GRANTEE_SIGNER)), "bad-handle-claim");

  // The home domain's check refuses the same request when a grantee signs it without the SDK guard.
  const bytes = toActAsGrantRequestCbor(wrong);
  const forged = { request: bytes, proof: granteeProve(GRANTEE_SIGNER, actAsSignatureInput(ACT_AS_GRANT_REQUEST_TAG, bytes)) };
  assert.equal(code(() => verifyGrantRequest(forged, GRANTEE_KEYS, NOW, SKEW)), "bad-handle-claim");
});

test("attestedKeyRefs keeps every attested key, with revokedAt for a revoked key", () => {
  const attestation = (keyId: string): ApplicationKeyAttestation => ({
    subjectUserId: "u", subjectDomain: "d.example", applicationId: "a", instanceId: "i",
    keyId, keyUsage: "sign", algorithm: "ed25519", publicKey: new Uint8Array(32), fingerprint: "f",
    keyCreatedAt: "2026-01-01T00:00:00Z", keyExpiresAt: "2027-01-01T00:00:00Z",
    attestedAt: "2026-01-01T00:00:00Z", attestationExpiresAt: "2026-12-01T00:00:00Z",
  });
  const refs = attestedKeyRefs({
    keys: [
      { attestation: attestation("k-1"), status: { kind: "usable" } },
      { attestation: attestation("k-2"), status: { kind: "revoked", revokedAt: "2026-06-01T00:00:00Z" } },
      { attestation: attestation("k-3"), status: { kind: "key_expired" } },
      { attestation: attestation("k-4"), status: { kind: "attestation_expired" } },
    ],
    revokedKeyIds: new Set(["k-2"]),
    rejected: [],
  });
  assert.deepEqual(refs.map((k) => [k.keyId, k.revokedAt]), [
    ["k-1", undefined],
    ["k-2", "2026-06-01T00:00:00Z"],
    ["k-3", undefined],
    ["k-4", undefined],
  ]);
});
