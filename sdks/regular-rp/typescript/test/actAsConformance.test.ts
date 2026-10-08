// Consumer of the act-as vectors in `sdks/regular-rp/conformance/`. Replays
// every positive AND negative case in act_as_signatures.json,
// act_as_credential.json, act_as_terms.json, and act_as_grantee_signing.json
// against `src/actAs.ts`, and builds every input from the JSON alone.
//
// `crates/liblinkkeys/tests/act_as_conformance.rs` is consumer zero for the
// same files; this test reads them the same way.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import {
  fromActAsCredentialCbor,
  fromClaimCbor,
  fromSignedActAsGrantCbor,
  fromSignedActAsGrantRequestCbor,
  fromSignedActAsGrantRevocationCbor,
  fromSignedActAsRefreshRequestCbor,
  fromSignedActAsScopeSetCbor,
  fromSignedLocalRpDescriptorCbor,
  toActAsCredentialCbor,
  toSignedActAsGrantRequestCbor,
  toSignedActAsRefreshRequestCbor,
} from "../generated/codec.gen.ts";
import type { ApplicationRef, DomainPublicKey, GranteeRef } from "../generated/types.gen.ts";
import {
  ACT_AS_GRANT_REQUEST_TAG,
  ACT_AS_GRANT_REVOCATION_TAG,
  ACT_AS_GRANT_TAG,
  ACT_AS_PRESENTATION_TAG,
  ACT_AS_REFRESH_REQUEST_TAG,
  ACT_AS_SCOPE_SET_TAG,
  actAsSignatureInput,
  grantHash,
  issuedTerms,
  offeredTerms,
  present,
  refreshDecision,
  signGrantRequest,
  signRefreshRequest,
  verifyCredential,
  verifyGrantRequest,
  verifyGrantRevocation,
  verifyGrantSignature,
  verifyHandleClaim,
  verifyRefreshRequest,
  verifyScopeSet,
  type GranteeSigner,
  type RevokedKeyPolicy,
} from "../src/actAs.ts";
import { encodeSignedGrantRequestParam } from "../src/actAsClient.ts";
import type { ApplicationKeyRef } from "../src/applicationKeys.ts";

const CONFORMANCE_DIR = resolve(process.cwd(), "../conformance");

function load(name: string): any {
  return JSON.parse(readFileSync(resolve(CONFORMANCE_DIR, name), "utf8"));
}

function hex(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "hex"));
}

function toHex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

function appRef(v: any): ApplicationRef {
  return { subjectUserId: v.subject_user_id, subjectDomain: v.subject_domain, applicationId: v.application_id };
}

function granteeRef(v: any): GranteeRef {
  return {
    application: v.application ? appRef(v.application) : undefined,
    localRpDescriptorFingerprint: v.local_rp_descriptor_fingerprint ?? undefined,
  };
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
    revokedAt: k.revoked_at ?? undefined,
  }));
}

function domainKeys(v: any[]): DomainPublicKey[] {
  return v.map((k) => ({
    keyId: k.key_id,
    publicKey: hex(k.public_key_hex),
    fingerprint: k.fingerprint,
    algorithm: k.algorithm,
    keyUsage: k.key_usage,
    createdAt: k.created_at,
    expiresAt: k.expires_at,
    revokedAt: undefined,
    signedByKeyId: undefined,
    keySignature: undefined,
  }));
}

function policy(v: unknown): RevokedKeyPolicy {
  if (v === undefined || v === null || v === "accept_before_revocation") return "acceptBeforeRevocation";
  if (v === "refuse_revoked") return "refuseRevoked";
  throw new Error(`unknown revoked_key_policy ${String(v)}`);
}

function allCases(section: any): any[] {
  return [...section.cases, ...section.negative_cases];
}

function ok(fn: () => unknown): boolean {
  try {
    fn();
    return true;
  } catch {
    return false;
  }
}

test("act-as tags match the conformance table", () => {
  const tags = load("act_as_signatures.json").tags;
  assert.equal(ACT_AS_SCOPE_SET_TAG, tags.scope_set);
  assert.equal(ACT_AS_GRANT_TAG, tags.grant);
  assert.equal(ACT_AS_GRANT_REQUEST_TAG, tags.grant_request);
  assert.equal(ACT_AS_REFRESH_REQUEST_TAG, tags.refresh_request);
  assert.equal(ACT_AS_PRESENTATION_TAG, tags.presentation);
  assert.equal(ACT_AS_GRANT_REVOCATION_TAG, tags.grant_revocation);
});

test("act_as_signatures.json: every case matches expected_valid", () => {
  const v = load("act_as_signatures.json");
  const now = new Date(v.now);
  const skew: number = v.skew_seconds;
  const audienceKeys = keyRefs(v.audience_keys);
  const granteeKeys = keyRefs(v.grantee_instance_keys);
  const homeKeys = domainKeys(v.home_domain_keys);
  const home: string = v.home_domain;
  let count = 0;

  const scopeCases = [...allCases(v.scope_set), ...v.scope_set.policy_cases];
  assert.ok(v.scope_set.policy_cases.length >= 2, "policy_cases present");
  for (const c of scopeCases) {
    const signed = fromSignedActAsScopeSetCbor(hex(c.signed_cbor_hex));
    const audience = appRef(c.expected_audience ?? v.audience);
    const keys = Array.isArray(c.audience_keys) ? keyRefs(c.audience_keys) : audienceKeys;
    assert.equal(
      ok(() => verifyScopeSet(signed, audience, keys, policy(c.revoked_key_policy))),
      c.expected_valid,
      `scope_set ${c.name}`,
    );
    count++;
  }
  const scopeSigned = fromSignedActAsScopeSetCbor(hex(v.scope_set.signed_cbor_hex));
  assert.ok(scopeSigned.signatures.length >= 2, "the positive scope set carries every audience key's signature");

  const hc = v.handle_claims;
  const party = appRef(hc.party);
  const partyKeys = domainKeys(hc.party_domain_keys);
  const handleCases = allCases(hc);
  assert.ok(handleCases.length >= 5, "handle_claims cases present");
  for (const c of handleCases) {
    const claim = fromClaimCbor(hex(c.claim_cbor_hex));
    let valid = true;
    try {
      const handle = verifyHandleClaim(claim, party, partyKeys, now);
      if (c.expected_handle) assert.equal(handle, c.expected_handle, `handle_claims ${c.name}`);
    } catch (err) {
      if (err instanceof assert.AssertionError) throw err;
      valid = false;
    }
    assert.equal(valid, c.expected_valid, `handle_claims ${c.name}`);
    count++;
  }
  assert.equal(toHex(scopeSigned.scopeSet), v.scope_set.scope_set_cbor_hex);
  assert.equal(toHex(actAsSignatureInput(ACT_AS_SCOPE_SET_TAG, scopeSigned.scopeSet)), v.scope_set.signature_input_cbor_hex);

  for (const c of allCases(v.grant_request)) {
    const signed = fromSignedActAsGrantRequestCbor(hex(c.signed_cbor_hex));
    const at = c.now ? new Date(c.now) : now;
    assert.equal(ok(() => verifyGrantRequest(signed, granteeKeys, at, skew)), c.expected_valid, `grant_request ${c.name}`);
    count++;
  }
  const requestSigned = fromSignedActAsGrantRequestCbor(hex(v.grant_request.signed_cbor_hex));
  assert.equal(toHex(requestSigned.request), v.grant_request.request_cbor_hex);
  assert.equal(
    toHex(actAsSignatureInput(ACT_AS_GRANT_REQUEST_TAG, requestSigned.request)),
    v.grant_request.signature_input_cbor_hex,
  );

  const refreshNow = new Date(v.refresh_request.now);
  const grantGrantee = granteeRef(v.refresh_request.grant_grantee);
  for (const c of allCases(v.refresh_request)) {
    const signed = fromSignedActAsRefreshRequestCbor(hex(c.signed_cbor_hex));
    assert.equal(
      ok(() => verifyRefreshRequest(signed, grantGrantee, granteeKeys, refreshNow, skew)),
      c.expected_valid,
      `refresh_request ${c.name}`,
    );
    count++;
  }

  const grant = fromSignedActAsGrantCbor(hex(v.grant.signed_cbor_hex));
  assert.equal(toHex(grant.grant), v.grant.grant_cbor_hex);
  assert.equal(toHex(grantHash(grant.grant)), v.grant.grant_hash_hex);
  assert.equal(toHex(actAsSignatureInput(ACT_AS_GRANT_TAG, grant.grant)), v.grant.signature_input_cbor_hex);
  verifyGrantSignature(grant, homeKeys, now);

  for (const c of allCases(v.revocation)) {
    const signed = fromSignedActAsGrantRevocationCbor(hex(c.signed_cbor_hex));
    let valid = true;
    try {
      const r = verifyGrantRevocation(signed, homeKeys, home, now);
      if (c.expected_grant_id) assert.equal(r.grantId, c.expected_grant_id);
    } catch {
      valid = false;
    }
    assert.equal(valid, c.expected_valid, `revocation ${c.name}`);
    count++;
  }
  assert.ok(count >= 21, `replayed ${count} signature cases`);
});

test("act_as_credential.json: every case matches expected_valid", () => {
  const v = load("act_as_credential.json");
  const base = v.context;
  const cases = allCases(v);
  assert.ok(cases.length >= 14);
  for (const c of cases) {
    const field = (name: string): any => (name in c ? c[name] : base[name]);
    const credential = fromActAsCredentialCbor(hex(c.credential_cbor_hex));
    let result;
    let valid = true;
    try {
      result = verifyCredential(credential, {
        ownApplication: appRef(field("own_application")),
        ownScopeSetKeys: keyRefs(field("own_scope_set_keys")),
        issuerDomainKeys: domainKeys(field("issuer_domain_keys")),
        granteeInstanceKeys: keyRefs(field("grantee_instance_keys")),
        expectedRequestDigest: hex(field("expected_request_digest_hex")),
        revokedGrantIds: field("revoked_grant_ids"),
        maxPresentationAgeSeconds: field("max_presentation_age_seconds"),
        now: new Date(field("now")),
        skewSeconds: field("skew_seconds"),
        revokedKeyPolicy: policy(field("revoked_key_policy")),
      });
    } catch {
      valid = false;
    }
    assert.equal(valid, c.expected_valid, `credential ${c.name}`);
    if (result && c.expected) {
      assert.equal(result.grantId, c.expected.grant_id, c.name);
      assert.equal(result.userId, c.expected.user_id, c.name);
      assert.deepEqual(result.approvedScope, c.expected.approved_scope, c.name);
      assert.equal(result.signer.instanceId ?? null, c.expected.signer_instance_id, c.name);
      assert.equal(toHex(result.nonce), c.expected.nonce_hex, c.name);
    }
  }
});

test("act_as_terms.json: offered terms, issued terms, and refresh decisions", () => {
  const v = load("act_as_terms.json");
  const b = v.domain_bounds;
  const bounds = {
    defaultLifetimeSeconds: b.default_lifetime_seconds,
    maxLifetimeSeconds: b.max_lifetime_seconds,
    maxRenewalWindowSeconds: b.max_renewal_window_seconds,
  };
  for (const c of v.offered_terms) {
    const o = offeredTerms(
      c.requested_lifetime_seconds ?? undefined,
      c.requested_renewal_window_seconds ?? undefined,
      bounds,
    );
    assert.deepEqual(o, {
      defaultLifetimeSeconds: c.expected.default_lifetime_seconds,
      maxLifetimeSeconds: c.expected.max_lifetime_seconds,
      defaultRenewalWindowSeconds: c.expected.default_renewal_window_seconds,
      maxRenewalWindowSeconds: c.expected.max_renewal_window_seconds,
    });
  }

  const offer = v.issued_terms.offer;
  const offered = offeredTerms(
    offer.requested_lifetime_seconds ?? undefined,
    offer.requested_renewal_window_seconds ?? undefined,
    bounds,
  );
  for (const c of v.issued_terms.cases) {
    assert.equal(
      ok(() => issuedTerms(offered, c.chosen_lifetime_seconds, c.chosen_renewal_window_seconds)),
      c.expected_valid,
      JSON.stringify(c),
    );
  }

  for (const c of v.refresh) {
    const grant = {
      issuedAt: c.grant.issued_at,
      expiresAt: c.grant.expires_at,
      renewableUntil: c.grant.renewable_until,
    };
    const e = c.expected;
    if (e.decision === "expired") {
      assert.throws(() => refreshDecision(grant, c.lifetime_seconds, new Date(c.now)), c.name);
      continue;
    }
    const d = refreshDecision(grant, c.lifetime_seconds, new Date(c.now));
    if (e.decision === "stored") {
      assert.deepEqual(d, { kind: "stored" }, c.name);
    } else {
      assert.deepEqual(d, { kind: "renew", issuedAt: e.issued_at, expiresAt: e.expires_at }, c.name);
    }
  }
});

test("act_as_grantee_signing.json: grantee bytes are identical for both grantee forms", () => {
  const v = load("act_as_grantee_signing.json");
  const appKey = v.application_grantee.key;
  const local = v.local_rp_grantee;
  const localDescriptor = fromSignedLocalRpDescriptorCbor(hex(local.signed_descriptor_cbor_hex));
  const names: string[] = [];

  for (const c of v.cases) {
    const grantee = granteeRef(c.grantee);
    const signer: GranteeSigner = grantee.application
      ? {
          kind: "application",
          instanceId: v.application_grantee.instance_id,
          signer: { keyId: appKey.key_id, privateKey: hex(appKey.private_key_hex) },
        }
      : {
          kind: "localRp",
          descriptor: localDescriptor,
          fingerprint: local.fingerprint,
          signingPrivateKey: hex(local.signing_private_key_hex),
        };

    const gi = c.grant_request.inputs;
    const signedRequest = signGrantRequest(
      {
        grantee,
        scopeSet: fromSignedActAsScopeSetCbor(hex(gi.scope_set_signed_cbor_hex)),
        requestedLifetimeSeconds: gi.requested_lifetime_seconds ?? undefined,
        requestedRenewalWindowSeconds: gi.requested_renewal_window_seconds ?? undefined,
        callbackUrl: gi.callback_url,
        nonce: gi.nonce,
        requestedAt: gi.requested_at,
        expiresAt: gi.expires_at,
      },
      signer,
    );
    assert.equal(toHex(signedRequest.request), c.grant_request.request_cbor_hex, `${c.name}: request bytes`);
    assert.equal(
      toHex(actAsSignatureInput(ACT_AS_GRANT_REQUEST_TAG, signedRequest.request)),
      c.grant_request.signature_input_cbor_hex,
      `${c.name}: signature input`,
    );
    assert.equal(toHex(toSignedActAsGrantRequestCbor(signedRequest)), c.grant_request.signed_cbor_hex, `${c.name}: signed request`);
    assert.equal(encodeSignedGrantRequestParam(signedRequest), c.grant_request.url_param, `${c.name}: url_param`);

    const ri = c.refresh_request.inputs;
    const signedRefresh = signRefreshRequest(
      {
        grantId: ri.grant_id,
        grantee,
        requestedAt: ri.requested_at,
        expiresAt: ri.expires_at,
        nonce: ri.nonce,
      },
      signer,
    );
    assert.equal(toHex(signedRefresh.request), c.refresh_request.request_cbor_hex, `${c.name}: refresh bytes`);
    assert.equal(toHex(toSignedActAsRefreshRequestCbor(signedRefresh)), c.refresh_request.signed_cbor_hex, `${c.name}: signed refresh`);

    const pi = c.presentation.inputs;
    const grant = fromSignedActAsGrantCbor(hex(pi.grant_signed_cbor_hex));
    const credential = present(
      grant,
      appRef(pi.audience),
      hex(pi.request_digest_hex),
      new Date(pi.presented_at),
      hex(pi.nonce_hex),
      signer,
    );
    assert.equal(toHex(grantHash(grant.grant)), c.presentation.grant_hash_hex, `${c.name}: grant hash`);
    assert.equal(toHex(credential.presentation.presentation), c.presentation.presentation_cbor_hex, `${c.name}: presentation`);
    assert.equal(toHex(toActAsCredentialCbor(credential)), c.presentation.credential_cbor_hex, `${c.name}: credential`);
    names.push(c.name);
  }
  assert.deepEqual(names.sort(), ["application_grantee", "local_rp_grantee"]);
});
