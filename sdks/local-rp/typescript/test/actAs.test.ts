// Act-as grantee tests: the `local_rp_grantee` case of
// `sdks/regular-rp/conformance/act_as_grantee_signing.json` byte for byte,
// begin act-as browser discovery with fake DNS, and the callback nonce
// check. The refresh call is tested against the fake IDP in flow.test.ts.
// No test here touches the network.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  ACT_AS_GRANT_REQUEST_TAG,
  actAsGrantHash,
  beginActAs,
  completeActAsCallback,
  formatActAsTime,
  presentActAs,
  signActAsGrantRequest,
  signActAsRefreshRequest,
  signedActAsGrantRequestToUrlParam,
  type ActAsSigningMaterial,
} from "../src/actAs.ts";
import { verifyEd25519 } from "../src/crypto.ts";
import type { DnsResolver } from "../src/dns.ts";
import * as generated from "../src/generated/codec.gen.ts";
import { InvalidInputError } from "../src/identity.ts";
import { envelopeSignatureInput, LocalRpError } from "../src/localRp.ts";

const VECTOR_PATH = fileURLToPath(
  new URL("../../../regular-rp/conformance/act_as_grantee_signing.json", import.meta.url),
);
const vectors = JSON.parse(readFileSync(VECTOR_PATH, "utf8"));
const localCase = vectors.cases.find((c: any) => c.name === "local_rp_grantee");

function hex(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "hex"));
}
function toHex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

const keyMaterial: ActAsSigningMaterial = {
  descriptor: generated.fromSignedLocalRpDescriptorCbor(hex(vectors.local_rp_grantee.signed_descriptor_cbor_hex)),
  fingerprint: vectors.local_rp_grantee.fingerprint,
  signingPrivateKey: hex(vectors.local_rp_grantee.signing_private_key_hex),
};

function descriptorPublicKey(): Uint8Array {
  return generated.fromLocalRpDescriptorCbor(keyMaterial.descriptor.descriptor).signingPublicKey;
}

test("vector: descriptor round-trips through the codec", () => {
  assert.ok(localCase, "local_rp_grantee case missing");
  assert.equal(
    toHex(generated.toSignedLocalRpDescriptorCbor(keyMaterial.descriptor)),
    vectors.local_rp_grantee.signed_descriptor_cbor_hex,
  );
  assert.equal(localCase.grantee.local_rp_descriptor_fingerprint, keyMaterial.fingerprint);
});

test("vector: grant request bytes, signed bytes, and url param", () => {
  const inputs = localCase.grant_request.inputs;
  const signed = signActAsGrantRequest(
    {
      grantee: { localRpDescriptorFingerprint: keyMaterial.fingerprint },
      scopeSet: generated.fromSignedActAsScopeSetCbor(hex(inputs.scope_set_signed_cbor_hex)),
      requestedLifetimeSeconds: inputs.requested_lifetime_seconds ?? undefined,
      requestedRenewalWindowSeconds: inputs.requested_renewal_window_seconds ?? undefined,
      callbackUrl: inputs.callback_url,
      nonce: inputs.nonce,
      requestedAt: inputs.requested_at,
      expiresAt: inputs.expires_at,
    },
    keyMaterial,
  );
  assert.equal(toHex(signed.request), localCase.grant_request.request_cbor_hex);
  assert.equal(
    toHex(envelopeSignatureInput(ACT_AS_GRANT_REQUEST_TAG, signed.request)),
    localCase.grant_request.signature_input_cbor_hex,
  );
  assert.equal(toHex(generated.toSignedActAsGrantRequestCbor(signed)), localCase.grant_request.signed_cbor_hex);
  assert.equal(signedActAsGrantRequestToUrlParam(signed), localCase.grant_request.url_param);
});

test("vector: refresh request signed bytes", () => {
  const inputs = localCase.refresh_request.inputs;
  const signed = signActAsRefreshRequest(
    {
      grantId: inputs.grant_id,
      grantee: { localRpDescriptorFingerprint: keyMaterial.fingerprint },
      requestedAt: inputs.requested_at,
      expiresAt: inputs.expires_at,
      nonce: inputs.nonce,
    },
    keyMaterial,
  );
  assert.equal(toHex(signed.request), localCase.refresh_request.request_cbor_hex);
  assert.equal(toHex(generated.toSignedActAsRefreshRequestCbor(signed)), localCase.refresh_request.signed_cbor_hex);
});

test("vector: presentation and credential bytes", () => {
  const inputs = localCase.presentation.inputs;
  const grant = generated.fromSignedActAsGrantCbor(hex(inputs.grant_signed_cbor_hex));
  assert.equal(toHex(actAsGrantHash(grant.grant)), localCase.presentation.grant_hash_hex);
  const { credential, credentialCbor } = presentActAs({
    grant,
    audience: {
      subjectUserId: inputs.audience.subject_user_id,
      subjectDomain: inputs.audience.subject_domain,
      applicationId: inputs.audience.application_id,
    },
    requestDigest: hex(inputs.request_digest_hex),
    now: new Date(inputs.presented_at),
    nonce: hex(inputs.nonce_hex),
    keyMaterial,
  });
  assert.equal(toHex(credential.presentation.presentation), localCase.presentation.presentation_cbor_hex);
  assert.equal(toHex(credentialCbor), localCase.presentation.credential_cbor_hex);
});

test("formatActAsTime drops fractional seconds and ends in Z", () => {
  assert.equal(formatActAsTime(new Date("2026-10-06T12:05:00.987Z")), "2026-10-06T12:05:00Z");
});

// ---------------------------------------------------------------------
// beginActAs
// ---------------------------------------------------------------------

const IDENTITY_DOMAIN = "ident.example.test";
const CALLBACK = "http://app.lan:8080/act-as/callback";
const scopeSetBytes = hex(localCase.grant_request.inputs.scope_set_signed_cbor_hex);

function resolver(records: Record<string, string[]>): DnsResolver {
  return {
    txtLookup: async (name) => {
      const txts = records[name];
      if (!txts) throw new Error(`no fake record for ${name}`);
      return txts;
    },
  };
}

async function begin(dns: DnsResolver, extra: Partial<Parameters<typeof beginActAs>[0]> = {}) {
  return beginActAs({
    keyMaterial,
    userDomain: `alice@${IDENTITY_DOMAIN}`,
    scopeSet: scopeSetBytes,
    requestedLifetimeSeconds: 1800,
    callbackUrl: CALLBACK,
    now: new Date(localCase.grant_request.inputs.requested_at),
    dns,
    ...extra,
  });
}

test("beginActAs uses the discovered https host and signs a verifiable request", async () => {
  const { redirect, pending } = await begin(
    resolver({ [`_linkkeys_apis.${IDENTITY_DOMAIN}`]: ["v=lk1 https=login.example.test/linkkeys"] }),
  );
  const url = new URL(redirect.redirectUrl);
  assert.equal(url.origin + url.pathname, "https://login.example.test/linkkeys/auth/act-as");
  assert.deepEqual([...url.searchParams.keys()], ["signed_request"]);
  assert.equal(pending.userDomain, IDENTITY_DOMAIN);
  assert.equal(pending.callbackUrl, CALLBACK);
  assert.match(pending.nonce, /^[A-Za-z0-9_-]{43}$/);

  const signedBytes = new Uint8Array(Buffer.from(url.searchParams.get("signed_request")!, "base64url"));
  const signed = generated.fromSignedActAsGrantRequestCbor(signedBytes);
  const request = generated.fromActAsGrantRequestCbor(signed.request);
  assert.equal(request.nonce, pending.nonce);
  assert.equal(request.grantee.localRpDescriptorFingerprint, keyMaterial.fingerprint);
  assert.equal(request.grantee.application, undefined);
  assert.equal(request.requestedAt, localCase.grant_request.inputs.requested_at);
  assert.equal(request.expiresAt, localCase.grant_request.inputs.expires_at);
  assert.equal(request.requestedLifetimeSeconds, 1800);
  assert.equal(request.requestedRenewalWindowSeconds, undefined);
  assert.equal(request.callbackUrl, CALLBACK);
  assert.equal(toHex(generated.toSignedActAsScopeSetCbor(request.scopeSet)), toHex(scopeSetBytes));
  assert.equal(signed.proof.signature.signedByKeyId, keyMaterial.fingerprint);
  assert.equal(
    toHex(generated.toSignedLocalRpDescriptorCbor(signed.proof.localRpDescriptor!)),
    vectors.local_rp_grantee.signed_descriptor_cbor_hex,
  );
  assert.ok(
    verifyEd25519(
      envelopeSignatureInput(ACT_AS_GRANT_REQUEST_TAG, signed.request),
      signed.proof.signature.signature,
      descriptorPublicKey(),
    ),
  );
});

test("beginActAs falls back to the identity domain when discovery fails", async () => {
  const { redirect } = await begin(resolver({}));
  assert.ok(redirect.redirectUrl.startsWith(`https://${IDENTITY_DOMAIN}/auth/act-as?signed_request=`), redirect.redirectUrl);
});

test("beginActAs makes a fresh nonce per call", async () => {
  const a = await begin(resolver({}));
  const b = await begin(resolver({}));
  assert.notEqual(a.pending.nonce, b.pending.nonce);
});

test("beginActAs rejects bad input", async () => {
  const dns = resolver({});
  await assert.rejects(begin(dns, { requestWindowSeconds: 901 }));
  await assert.rejects(begin(dns, { requestWindowSeconds: 0 }));
  await assert.rejects(begin(dns, { callbackUrl: "javascript:alert(1)" }));
  await assert.rejects(begin(dns, { userDomain: "not a domain" }));
  await assert.rejects(begin(dns, { requestedRenewalWindowSeconds: -1 }));
  await assert.rejects(begin(dns, { scopeSet: new Uint8Array([0xff]) }), LocalRpError);
});

// ---------------------------------------------------------------------
// completeActAsCallback
// ---------------------------------------------------------------------

test("callback returns the grant id when the nonce matches", async () => {
  const { pending } = await begin(resolver({}));
  const arrived = `${CALLBACK}?act_as_grant_id=grant-42&nonce=${pending.nonce}`;
  assert.equal(completeActAsCallback(pending, arrived), "grant-42");
  assert.equal(completeActAsCallback(pending, new URL(arrived).search), "grant-42");
  assert.equal(completeActAsCallback(pending, new URL(arrived).searchParams), "grant-42");
});

test("callback rejects a nonce mismatch and missing parameters", async () => {
  const { pending } = await begin(resolver({}));
  const wrong = pending.nonce.slice(0, -1) + (pending.nonce.endsWith("A") ? "B" : "A");
  assert.throws(
    () => completeActAsCallback(pending, `${CALLBACK}?act_as_grant_id=grant-42&nonce=${wrong}`),
    (e: unknown) => e instanceof LocalRpError && e.code === "nonce-mismatch",
  );
  assert.throws(
    () => completeActAsCallback(pending, `${CALLBACK}?act_as_grant_id=grant-42&nonce=short`),
    (e: unknown) => e instanceof LocalRpError && e.code === "nonce-mismatch",
  );
  assert.throws(
    () => completeActAsCallback(pending, `${CALLBACK}?nonce=${pending.nonce}`),
    (e: unknown) => e instanceof LocalRpError && e.code === "missing-parameter",
  );
  assert.throws(
    () => completeActAsCallback(pending, `${CALLBACK}?act_as_grant_id=grant-42`),
    (e: unknown) => e instanceof LocalRpError && e.code === "missing-parameter",
  );
  // A repeated parameter is refused, even when one value is correct.
  assert.throws(
    () => completeActAsCallback(pending, `${CALLBACK}?act_as_grant_id=evil&act_as_grant_id=grant-42&nonce=${pending.nonce}`),
    InvalidInputError,
  );
  assert.throws(
    () => completeActAsCallback(pending, `${CALLBACK}?act_as_grant_id=grant-42&nonce=${pending.nonce}&nonce=other`),
    InvalidInputError,
  );
});
