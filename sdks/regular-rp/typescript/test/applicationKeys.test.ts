// Consumer of `sdks/regular-rp/conformance/`: replays the checked-in JSON
// vectors for application keys (signing-things-request.md, "Required tests
// and acceptance checks" -> "Cryptographic tests") against this SDK's own
// `src/applicationKeys.ts`, every positive AND negative case.
//
// Only `application_key_attestation.json` and `application_key_revocation.json`
// are replayed here: this SDK implements the READ side of the protocol
// (verifying a peer's already-attested keys), not application-key
// enrollment (adding a key, renewing an attestation, or the X25519 sealed-
// challenge proof of possession) — see `src/applicationKeys.ts`'s module
// docs for the scope note. `application_key_addition.json`,
// `application_key_renewal.json`, and `application_key_sealed_challenge.json`
// cover functionality this package does not implement and are intentionally
// not replayed here.
//
// `crates/liblinkkeys/tests/application_key_conformance.rs` is consumer
// zero for every file in that directory, including the ones this test does
// not cover.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import type {
  ApplicationKeyRevocation,
  ApplicationKeySignature,
  ClaimSignature,
  DomainPublicKey,
  SignedApplicationKeyAttestation,
} from "../generated/types.gen.ts";
import {
  attestationSignatureInput,
  ATTESTATION_TAG,
  type ApplicationKeyRef,
  REVOCATION_QUORUM,
  REVOCATION_TAG,
  revocationPayload,
  verifyApplicationKeyRevocation,
  verifyAttestationSignature,
} from "../src/applicationKeys.ts";

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

function attestationSignedFrom(v: any): SignedApplicationKeyAttestation {
  const signatures: ClaimSignature[] = v.signatures.map(
    (sig: any): ClaimSignature => ({
      domain: sig.domain,
      signedByKeyId: sig.signed_by_key_id,
      signature: hex(sig.signature_hex),
    }),
  );
  return { attestation: hex(v.attestation_cbor_hex), signatures };
}

function applicationKeyRefFrom(v: any): ApplicationKeyRef {
  return {
    keyId: v.key_id,
    keyUsage: v.key_usage,
    algorithm: v.algorithm,
    publicKey: hex(v.public_key_hex),
    fingerprint: v.fingerprint,
    createdAt: v.created_at,
    expiresAt: v.expires_at,
  };
}

function revocationFrom(v: any): ApplicationKeyRevocation {
  const signatures: ApplicationKeySignature[] = v.signatures.map(
    (sig: any): ApplicationKeySignature => ({
      signedByKeyId: sig.signed_by_key_id,
      signature: hex(sig.signature_hex),
    }),
  );
  return {
    subjectUserId: v.subject_user_id,
    subjectDomain: v.subject_domain,
    applicationId: v.application_id,
    instanceId: v.instance_id,
    targetKeyId: v.target_key_id,
    targetFingerprint: v.target_fingerprint,
    revokedAt: v.revoked_at,
    signatures,
  };
}

test("application-key attestation: signature input matches the tag+bytes envelope", () => {
  const d = load("application_key_attestation.json");
  const attestationBytes = hex(d.attestation_cbor_hex);
  assert.deepEqual(attestationSignatureInput(attestationBytes), hex(d.signature_input_cbor_hex));
  assert.equal(d.tag, ATTESTATION_TAG);
});

test("application-key attestation: positive cases verify", () => {
  const d = load("application_key_attestation.json");
  assert.ok(d.cases.length > 0);
  for (const c of d.cases) {
    assert.equal(c.expected_valid, true, `cases[] must all be positive: ${c.name}`);
    const signed = attestationSignedFrom(c.signed);
    const domainKeys = c.domain_keys.map(domainKeyFrom);
    const result = verifyAttestationSignature(signed, domainKeys, c.expected_domain);
    assert.ok(result !== undefined, `attestation verify mismatch for ${c.name}`);
  }
});

test("application-key attestation: negative cases fail", () => {
  const d = load("application_key_attestation.json");
  assert.equal(d.negative_cases.length, 3);
  for (const c of d.negative_cases) {
    assert.equal(c.expected_valid, false, `negative_cases[] must all be negative: ${c.name}`);
    const signed = attestationSignedFrom(c.signed);
    const domainKeys = c.domain_keys.map(domainKeyFrom);
    const result = verifyAttestationSignature(signed, domainKeys, c.expected_domain);
    assert.ok(result === undefined, `attestation verify mismatch for ${c.name}`);
  }
});

test("application-key revocation: payload matches the tag-first tuple", () => {
  const d = load("application_key_revocation.json");
  const instance = d.instance;
  const expected = hex(d.revocation_payload_cbor_hex);
  assert.deepEqual(
    revocationPayload(
      instance.subject_user_id,
      instance.subject_domain,
      instance.application_id,
      instance.instance_id,
      d.target_key_id,
      d.target_fingerprint,
      d.revoked_at,
    ),
    expected,
  );
  assert.equal(d.tag, REVOCATION_TAG);
  assert.equal(d.quorum, REVOCATION_QUORUM);
});

test("application-key revocation: positive cases verify", () => {
  const d = load("application_key_revocation.json");
  const keys = d.keys.map(applicationKeyRefFrom);
  assert.ok(d.cases.length > 0);
  for (const c of d.cases) {
    assert.equal(c.expected_valid, true, `cases[] must all be positive: ${c.name}`);
    const rev = revocationFrom(c.revocation);
    assert.equal(verifyApplicationKeyRevocation(rev, keys), true, `revocation verify mismatch for ${c.name}`);
  }
});

test("application-key revocation: negative cases fail", () => {
  const d = load("application_key_revocation.json");
  const keys = d.keys.map(applicationKeyRefFrom);
  assert.equal(d.negative_cases.length, 3);
  for (const c of d.negative_cases) {
    assert.equal(c.expected_valid, false, `negative_cases[] must all be negative: ${c.name}`);
    const rev = revocationFrom(c.revocation);
    assert.equal(verifyApplicationKeyRevocation(rev, keys), false, `revocation verify mismatch for ${c.name}`);
  }
});
