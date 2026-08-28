import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import * as generated from "../generated/codec.gen.ts";
import type { DomainPublicKey } from "../generated/types.gen.ts";
import { verifyClaim, type ClaimErrorCode, ClaimError, type DomainKeySet } from "../src/claims.ts";
import { parseLinkkeysApisTxt, parseLinkkeysTxt, DnsParseError } from "../src/dnsRecords.ts";
import {
  countRevocationCertificateSigners,
  revocationPayload,
  REVOCATION_QUORUM,
  REVOCATION_TAG,
  verifyRevocationCertificate,
} from "../src/revocation.ts";
import { RpcPush, RpcRequest, RpcResponse } from "../src/vendor/csilgen-transport/index.ts";

const LINKKEYS_VECTORS = resolve(process.cwd(), "../../local-rp/conformance");
const RPC_VECTORS = resolve(process.cwd(), "test/fixtures/csil-rpc.json");

function loadLinkKeys(name: string): any {
  return JSON.parse(readFileSync(resolve(LINKKEYS_VECTORS, name), "utf8"));
}

function hex(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "hex"));
}

function fixtureKey(key: any): DomainPublicKey {
  return {
    keyId: key.key_id,
    publicKey: hex(key.public_key_hex),
    fingerprint: key.fingerprint_hex,
    algorithm: key.algorithm,
    keyUsage: key.key_usage,
    createdAt: key.created_at,
    expiresAt: key.expires_at,
    revokedAt: key.revoked_at ?? undefined,
  };
}

test("official DNS vectors", () => {
  const vectors = loadLinkKeys("dns.json");
  for (const c of vectors.linkkeys_txt.valid_cases) {
    assert.deepEqual(parseLinkkeysTxt(c.txt).fingerprints, c.expected_fingerprints);
  }
  for (const c of vectors.linkkeys_txt.invalid_cases) {
    assert.throws(() => parseLinkkeysTxt(c.txt), DnsParseError);
  }
  for (const c of vectors.linkkeys_apis_txt.valid_cases) {
    const parsed = parseLinkkeysApisTxt(c.txt);
    assert.equal(parsed.tcp, c.expected_tcp ?? undefined);
    assert.equal(parsed.httpsBase, c.expected_https_base ?? undefined);
  }
  for (const c of vectors.linkkeys_apis_txt.invalid_cases) {
    assert.throws(() => parseLinkkeysApisTxt(c.txt), DnsParseError);
  }
});

test("official revocation vectors", () => {
  const vectors = loadLinkKeys("revocations.json");
  const keys = vectors.domain_keys.map(fixtureKey);
  assert.equal(vectors.tag, REVOCATION_TAG);
  assert.equal(vectors.quorum, REVOCATION_QUORUM);

  for (const c of vectors.certificate_cases) {
    const cert = generated.fromRevocationCertificateCbor(hex(c.certificate_cbor_hex));
    assert.equal(
      countRevocationCertificateSigners(cert, keys, c.verify_domain),
      c.expected_counted_signers,
      c.name,
    );
    assert.equal(verifyRevocationCertificate(cert, keys, c.verify_domain), c.expected_valid, c.name);
  }

  const valid = vectors.certificate_cases.find((c: any) => c.name === "valid_quorum_two_siblings");
  assert.ok(valid);
  for (const signature of valid.certificate.signatures) {
    assert.deepEqual(
      Buffer.from(revocationPayload(
        valid.certificate.target_key_id,
        valid.certificate.target_fingerprint,
        valid.certificate.revoked_at,
        signature.domain,
      )),
      Buffer.from(hex(signature.signed_payload_cbor_hex)),
    );
  }
});

test("official claim vectors", () => {
  const vectors = loadLinkKeys("claims.json");
  const now = new Date("2026-06-15T00:00:00Z");
  const defaultKeys: DomainKeySet[] = [{
    domain: vectors.subject_domain,
    keys: vectors.domain_keys.map(fixtureKey),
  }];

  for (const c of vectors.cases) {
    const bytes = hex(c.claim_cbor_hex);
    const claim = generated.fromClaimCbor(bytes);
    assert.deepEqual(Buffer.from(generated.toClaimCbor(claim)), Buffer.from(bytes), c.name);
    assert.doesNotThrow(() => verifyClaim(claim, c.subject_domain, defaultKeys, now), c.name);
  }

  const errorCodes: Record<string, ClaimErrorCode> = {
    signature_invalid: "signature-invalid",
    key_not_found: "key-not-found",
  };
  for (const c of vectors.negative_cases) {
    const claim = generated.fromClaimCbor(hex(c.claim_cbor_hex));
    const keys: DomainKeySet[] = [{
      domain: vectors.subject_domain,
      keys: (c.domain_keys ?? vectors.domain_keys).map(fixtureKey),
    }];
    assert.throws(
      () => verifyClaim(claim, c.subject_domain, keys, now),
      (error: unknown) => error instanceof ClaimError && error.code === errorCodes[c.expected_error],
      c.name,
    );
  }
  for (const c of vectors.decode_negative_cases) {
    assert.throws(() => generated.fromClaimCbor(hex(c.claim_cbor_hex)), c.name);
  }
});

test("official CSIL-RPC vectors", () => {
  const vectors = JSON.parse(readFileSync(RPC_VECTORS, "utf8")).vectors;
  for (const vector of vectors) {
    const input = vector.input;
    const payload = hex(input.payload_hex);
    let value: RpcRequest | RpcResponse | RpcPush;
    if (input.kind === "request") {
      value = new RpcRequest(input.service, input.op, payload);
      value.id = input.id ?? undefined;
      value.auth = input.auth ?? undefined;
      assert.deepEqual(RpcRequest.decode(value.encode()), value, vector.name);
    } else if (input.kind === "response") {
      value = new RpcResponse(input.status, payload);
      value.id = input.id ?? undefined;
      value.variant = input.variant ?? undefined;
      value.error = input.error ?? undefined;
      assert.deepEqual(RpcResponse.decode(value.encode()), value, vector.name);
    } else {
      value = new RpcPush(input.service, input.event, payload);
      assert.deepEqual(RpcPush.decode(value.encode()), value, vector.name);
    }
    assert.equal(Buffer.from(value.encode()).toString("hex"), vector.hex, vector.name);
  }
});
