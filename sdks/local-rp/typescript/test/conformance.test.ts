// Conformance-vector tests: consumes every file under
// `sdks/local-rp/conformance/` (see that directory's README for the
// schema) — the same fixed, checked-in vectors every other SDK (and the
// Rust "consumer zero") consumes. Positive AND negative cases in every
// file.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

import * as crypto from "../src/crypto.ts";
import { fingerprintFromString, fingerprintToString, generateLocalRpIdentity } from "../src/identity.ts";
import { checkExpirations } from "../src/index.ts";
import * as localRp from "../src/localRp.ts";
import * as dnsRecords from "../src/dnsRecords.ts";
import * as revocation from "../src/revocation.ts";
import * as claims from "../src/claims.ts";
import * as generated from "../src/generated/codec.gen.ts";
import * as encoding from "../src/encoding.ts";
import type { AeadSuite } from "../src/crypto.ts";
import type {
  DomainPublicKey,
  LocalRpEncryptedCallback,
  SignedLocalRpCallbackPayload,
} from "../src/generated/types.gen.ts";
import type { DomainKeySet } from "../src/claims.ts";

const CONFORMANCE_DIR = fileURLToPath(new URL("../../conformance/", import.meta.url));

function load(name: string): any {
  return JSON.parse(readFileSync(`${CONFORMANCE_DIR}${name}`, "utf8"));
}

function hex(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "hex"));
}

function caseLabel(c: any): string {
  return c.name ?? c.structure ?? "<unnamed case>";
}

// ---------------------------------------------------------------------
// keys.json
// ---------------------------------------------------------------------

test("keys: fingerprints round-trip through the SDK's fingerprint helpers", () => {
  const d = load("keys.json");
  for (const [path, privField] of [
    [d.local_rp.signing, "seed_hex"],
    [d.domain_signing_key, "seed_hex"],
  ] as const) {
    const seed = hex(path[privField]);
    const publicKey = hex(path.public_key_hex);
    const expectedFp: string = path.fingerprint_hex;
    void seed; // the seed itself isn't needed for a fingerprint check; kept for symmetry with the Rust test.

    const computed = crypto.fingerprint(publicKey);
    assert.equal(computed, expectedFp);

    const s = fingerprintToString(computed);
    assert.equal(fingerprintFromString(s), expectedFp);
  }

  assert.throws(() => fingerprintFromString("deadbeef"));
});

// ---------------------------------------------------------------------
// envelopes.json
// ---------------------------------------------------------------------

function checkEnvelopeCase(c: any): void {
  const context: string = c.context;
  const payload = hex(c.payload_cbor_hex);
  const expectedSigInput = hex(c.signature_input_cbor_hex);
  const signature = hex(c.signature_hex);
  const verifyKey = hex(c.verify_key_hex);
  const expectedValid: boolean = c.expected_valid;

  const computedSigInput = localRp.envelopeSignatureInput(context, payload);
  assert.deepEqual(
    Buffer.from(computedSigInput),
    Buffer.from(expectedSigInput),
    `signature_input_cbor_hex mismatch for ${caseLabel(c)}`,
  );

  const result = crypto.verifyEd25519(computedSigInput, signature, verifyKey);
  assert.equal(result, expectedValid, `verify result mismatch for ${caseLabel(c)}`);
}

test("envelopes: positive cases verify", () => {
  const d = load("envelopes.json");
  assert.equal(d.cases.length, 4);
  for (const c of d.cases) {
    assert.equal(c.expected_valid, true);
    checkEnvelopeCase(c);
  }
});

test("envelopes: negative cases fail", () => {
  const d = load("envelopes.json");
  assert.equal(d.negative_cases.length, 20);
  for (const c of d.negative_cases) {
    assert.equal(c.expected_valid, false);
    checkEnvelopeCase(c);
  }
});

// ---------------------------------------------------------------------
// callback_box.json
// ---------------------------------------------------------------------

test("callback_box: positive cases open via the SDK's sealed-box implementation", () => {
  const d = load("callback_box.json");
  assert.equal(d.positive_cases.length, 2);

  for (const c of d.positive_cases) {
    const encrypted: LocalRpEncryptedCallback = {
      header: hex(c.header_cbor_hex),
      ciphertext: hex(c.ciphertext_hex),
    };
    const decryptKey = hex(c.decrypt_private_key_hex);
    const allowed = c.allowed_suites as string[];

    const { header, signedPayload } = localRp.openLocalRpCallback(encrypted, decryptKey, allowed as AeadSuite[]);

    assert.equal(header.suite, c.suite);
    assert.equal(header.fingerprint, c.fingerprint);
    assert.deepEqual(Buffer.from(header.nonce), Buffer.from(hex(c.nonce_hex)));
    assert.deepEqual(Buffer.from(header.state), Buffer.from(hex(c.state_hex)));
    assert.equal(header.issuedAt, c.issued_at);
    assert.equal(header.expiresAt, c.expires_at);

    const plaintext = generated.toSignedLocalRpCallbackPayloadCbor(signedPayload);
    assert.deepEqual(Buffer.from(plaintext), Buffer.from(hex(c.plaintext_cbor_hex)));
  }
});

test("callback_box: negative cases fail", () => {
  const d = load("callback_box.json");
  assert.equal(d.negative_cases.length, 13);

  for (const c of d.negative_cases) {
    const encrypted: LocalRpEncryptedCallback = {
      header: hex(c.header_cbor_hex),
      ciphertext: hex(c.ciphertext_hex),
    };
    const decryptKey = hex(c.decrypt_private_key_hex);
    const allowed = c.allowed_suites as string[];

    assert.throws(
      () => localRp.openLocalRpCallback(encrypted, decryptKey, allowed as AeadSuite[]),
      `negative case ${caseLabel(c)} unexpectedly opened`,
    );
  }
});

// ---------------------------------------------------------------------
// url_params.json
// ---------------------------------------------------------------------

test("url_params: cases round-trip both directions", () => {
  const d = load("url_params.json");
  for (const c of d.cases) {
    const cbor = hex(c.cbor_hex);
    const b64: string = c.base64url_unpadded;

    assert.equal(Buffer.from(cbor).toString("base64url"), b64);
    assert.deepEqual(Buffer.from(cbor), Buffer.from(b64, "base64url"));

    if (c.name === "signed_local_rp_login_request") {
      const typed = generated.fromSignedLocalRpLoginRequestCbor(cbor);
      assert.equal(encoding.signedLocalRpLoginRequestToUrlParam(typed), b64);
      const roundTripped = encoding.signedLocalRpLoginRequestFromUrlParam(b64);
      assert.deepEqual(Buffer.from(roundTripped.request), Buffer.from(typed.request));
      assert.deepEqual(Buffer.from(roundTripped.signature), Buffer.from(typed.signature));
    } else if (c.name === "local_rp_encrypted_callback") {
      const typed = generated.fromLocalRpEncryptedCallbackCbor(cbor);
      assert.equal(encoding.localRpEncryptedCallbackToUrlParam(typed), b64);
      const roundTripped = encoding.localRpEncryptedCallbackFromUrlParam(b64);
      assert.deepEqual(Buffer.from(roundTripped.header), Buffer.from(typed.header));
      assert.deepEqual(Buffer.from(roundTripped.ciphertext), Buffer.from(typed.ciphertext));
    } else {
      assert.fail(`unrecognized url_params.json case name: ${c.name}`);
    }
  }
});

test("url_params: negative cases rejected", () => {
  const d = load("url_params.json");
  assert.equal(d.negative_cases.length, 2);
  for (const c of d.negative_cases) {
    const input: string = c.input;
    assert.throws(() => encoding.localRpEncryptedCallbackFromUrlParam(input));
  }
});

// ---------------------------------------------------------------------
// dns.json
// ---------------------------------------------------------------------

function dnsErrorCode(e: unknown): string | undefined {
  if (e instanceof dnsRecords.DnsParseError) {
    return e.code.replace(/-/g, "_");
  }
  return undefined;
}

test("dns: linkkeys_txt cases", () => {
  const d = load("dns.json");

  for (const c of d.linkkeys_txt.valid_cases) {
    const record = dnsRecords.parseLinkkeysTxt(c.txt);
    assert.deepEqual(record.fingerprints, c.expected_fingerprints, `txt=${c.txt}`);
  }

  for (const c of d.linkkeys_txt.invalid_cases) {
    assert.throws(
      () => dnsRecords.parseLinkkeysTxt(c.txt),
      (e: unknown) => dnsErrorCode(e) === c.expected_error,
    );
  }

  assert.equal(d.linkkeys_txt.no_record_case.documentation_only, true);
});

test("dns: linkkeys_apis_txt cases", () => {
  const d = load("dns.json");

  for (const c of d.linkkeys_apis_txt.valid_cases) {
    const apis = dnsRecords.parseLinkkeysApisTxt(c.txt);
    assert.equal(apis.tcp, c.expected_tcp ?? undefined, `txt=${c.txt}`);
    assert.equal(apis.httpsBase, c.expected_https_base ?? undefined, `txt=${c.txt}`);
  }

  for (const c of d.linkkeys_apis_txt.invalid_cases) {
    assert.throws(
      () => dnsRecords.parseLinkkeysApisTxt(c.txt),
      (e: unknown) => dnsErrorCode(e) === c.expected_error,
    );
  }

  assert.equal(d.default_tcp_port, dnsRecords.DEFAULT_TCP_PORT);
});

// ---------------------------------------------------------------------
// tickets.json
// ---------------------------------------------------------------------

test("tickets: hash pairs match the fingerprint routine", () => {
  const d = load("tickets.json");
  assert.ok(d.cases.length > 0);
  for (const c of d.cases) {
    const ticket = hex(c.ticket_hex);
    assert.equal(ticket.length, 32);
    assert.equal(crypto.fingerprint(ticket), c.sha256_hex);
  }
});

// ---------------------------------------------------------------------
// expirations.json
// ---------------------------------------------------------------------

test("expirations: check_expirations thresholds via the SDK wrapper", () => {
  const d = load("expirations.json");
  const expiresAt: string = d.check_expirations.expires_at;
  const cases = d.check_expirations.cases;
  assert.equal(cases.length, 11);

  const createdAt = new Date(new Date(expiresAt).getTime() - 3650 * 24 * 60 * 60 * 1000);
  const identity = generateLocalRpIdentity({
    appName: "Conformance Test App",
    lifetimeMs: new Date(expiresAt).getTime() - createdAt.getTime(),
    now: createdAt,
  });

  for (const c of cases) {
    const now = new Date(c.now);
    const status = checkExpirations(identity, now);
    assert.equal(status.level, c.expected_level, `now=${now.toISOString()}`);
  }
});

test("expirations: check_timestamps skew boundaries are exact", () => {
  const d = load("expirations.json");
  const issuedAt: string = d.check_timestamps.issued_at;
  const expiresAt: string = d.check_timestamps.expires_at;
  const skew: number = d.check_timestamps.skew_seconds;
  const cases = d.check_timestamps.cases;
  assert.equal(cases.length, 4);

  for (const c of cases) {
    const now = new Date(c.now);
    const expectedValid: boolean = c.expected_valid;
    let ok = true;
    try {
      localRp.checkTimestamps(issuedAt, expiresAt, now, skew);
    } catch {
      ok = false;
    }
    assert.equal(ok, expectedValid, `now=${now.toISOString()}`);
  }
});

// ---------------------------------------------------------------------
// revocations.json
// ---------------------------------------------------------------------

/** Map a revocations.json `domain_keys[]` fixture entry onto the DomainPublicKey wire shape. */
function revocationFixtureKey(k: any): DomainPublicKey {
  return {
    keyId: k.key_id,
    publicKey: hex(k.public_key_hex),
    fingerprint: k.fingerprint_hex,
    algorithm: k.algorithm,
    keyUsage: k.key_usage,
    createdAt: k.created_at,
    expiresAt: k.expires_at,
    revokedAt: k.revoked_at ?? undefined,
    signedByKeyId: undefined,
    keySignature: undefined,
  };
}

test("revocations: constants and per-signature payload construction match", () => {
  const d = load("revocations.json");
  assert.equal(d.tag, revocation.REVOCATION_TAG);
  assert.equal(d.quorum, revocation.REVOCATION_QUORUM);

  // Byte-compare the recomputed payload against the vectors'
  // signed_payload_cbor_hex for the fully-valid case (whose signatures were
  // computed over exactly the bytes a verifier must recompute — the
  // five-element CBOR tuple, NOT the two-element envelope framing).
  const valid = d.certificate_cases.find((c: any) => c.name === "valid_quorum_two_siblings");
  assert.ok(valid, "valid_quorum_two_siblings case must exist");
  for (const sig of valid.certificate.signatures) {
    const recomputed = revocation.revocationPayload(
      valid.certificate.target_key_id,
      valid.certificate.target_fingerprint,
      valid.certificate.revoked_at,
      sig.domain,
    );
    assert.deepEqual(
      Buffer.from(recomputed),
      Buffer.from(hex(sig.signed_payload_cbor_hex)),
      `payload bytes for signer ${sig.signed_by_key_id}`,
    );
  }
});

test("revocations: all certificate cases verify with exact counted signers", () => {
  const d = load("revocations.json");
  const domainKeys: DomainPublicKey[] = d.domain_keys.map(revocationFixtureKey);
  assert.equal(d.certificate_cases.length, 9);

  for (const c of d.certificate_cases) {
    // Decode the certificate from its CSIL CBOR wire encoding (the same
    // bytes fetchDomainKeys receives from get-revocations) and cross-check
    // it against the expanded fixture fields.
    const cert = generated.fromRevocationCertificateCbor(hex(c.certificate_cbor_hex));
    assert.equal(cert.targetKeyId, c.certificate.target_key_id, caseLabel(c));
    assert.equal(cert.targetFingerprint, c.certificate.target_fingerprint, caseLabel(c));
    assert.equal(cert.revokedAt, c.certificate.revoked_at, caseLabel(c));
    assert.equal(cert.signatures.length, c.certificate.signatures.length, caseLabel(c));

    const counted = revocation.countRevocationCertificateSigners(
      cert,
      domainKeys,
      c.verify_domain,
    );
    assert.equal(
      counted,
      c.expected_counted_signers,
      `counted signers mismatch for ${caseLabel(c)}`,
    );

    const valid = revocation.verifyRevocationCertificate(cert, domainKeys, c.verify_domain);
    assert.equal(valid, c.expected_valid, `verify outcome mismatch for ${caseLabel(c)}`);
  }
});

test("revocations: application case — a valid certificate kills the target key's envelope", () => {
  const d = load("revocations.json");
  const domainKeys: DomainPublicKey[] = d.domain_keys.map(revocationFixtureKey);
  const app = d.application_case;

  const signed: SignedLocalRpCallbackPayload = {
    payload: hex(app.envelope.payload_cbor_hex),
    signingKeyId: app.envelope.signing_key_id,
    signature: hex(app.envelope.signature_hex),
  };
  const now = new Date(app.verify_now);
  const skew: number = app.clock_skew_seconds;

  // Before applying the certificate: the fetched key entry for the target
  // key carries no revoked_at, so the envelope verifies.
  assert.equal(app.expected_valid_before_revocation, true);
  const payload = localRp.verifyLocalRpCallbackPayload(signed, domainKeys, now, skew);
  assert.equal(payload.userDomain, d.domain);

  // Verify the referenced certificate, then APPLY it exactly the way
  // src/rpc.ts's fetchDomainKeys does (drop the targeted key from the
  // trusted set). The same envelope must now fail even though the fetched
  // key entry itself looked valid — an SDK that verifies certificates but
  // forgets to apply them fails here.
  const validCase = d.certificate_cases.find((c: any) => c.name === "valid_quorum_two_siblings");
  const cert = generated.fromRevocationCertificateCbor(hex(validCase.certificate_cbor_hex));
  assert.equal(revocation.verifyRevocationCertificate(cert, domainKeys, d.domain), true);

  const afterApply = domainKeys.filter((k) => k.keyId !== cert.targetKeyId);

  assert.equal(app.expected_valid_after_revocation, false);
  assert.throws(
    () => localRp.verifyLocalRpCallbackPayload(signed, afterApply, now, skew),
    localRp.LocalRpError,
  );
});

// ---------------------------------------------------------------------
// claims.json
// ---------------------------------------------------------------------

/** Map a claims.json `domain_keys[]` fixture entry onto the DomainPublicKey wire shape. */
function claimFixtureKey(k: any): DomainPublicKey {
  return {
    keyId: k.key_id,
    publicKey: hex(k.public_key_hex),
    fingerprint: k.fingerprint_hex,
    algorithm: k.algorithm,
    keyUsage: k.key_usage,
    createdAt: k.created_at,
    expiresAt: k.expires_at,
    revokedAt: k.revoked_at ?? undefined,
    signedByKeyId: undefined,
    keySignature: undefined,
  };
}

// A fixed instant inside every fixture's validity window: well after
// created_at (2026-01-01), well before both far-future expires_at values
// (2126-01-01) and any signing-key expiry, and irrelevant to the one claim
// whose expires_at is absent.
const CLAIMS_NOW = new Date("2026-06-15T00:00:00Z");

function claimsDefaultDomainKeys(d: any): DomainKeySet[] {
  return [{ domain: d.subject_domain, keys: d.domain_keys.map(claimFixtureKey) }];
}

test("claims: positive cases round-trip byte-exactly and verify via the SDK's own claim-verification path", () => {
  const d = load("claims.json");
  assert.equal(d.cases.length, 3);
  const defaultDomainKeys = claimsDefaultDomainKeys(d);

  for (const c of d.cases) {
    assert.equal(c.expected_valid, true, caseLabel(c));

    // Wire round-trip: decode claim_cbor_hex through the generated codec,
    // then re-encode, and require byte-identical output. This is the check
    // that would fail immediately if claim_value were wired as a CBOR text
    // string (tstr) instead of bytes (bstr) — a tstr encoder round-trips
    // fine on its own but produces different bytes than the fixture.
    const claimBytes = hex(c.claim_cbor_hex);
    const decoded = generated.fromClaimCbor(claimBytes);
    const reencoded = generated.toClaimCbor(decoded);
    assert.deepEqual(Buffer.from(reencoded), Buffer.from(claimBytes), `wire round-trip for ${caseLabel(c)}`);

    // claim_value must decode as raw bytes (Uint8Array), matching
    // claim_value_hex exactly — including the non-UTF-8 case, which a tstr
    // codec could not even represent.
    assert.ok(decoded.claimValue instanceof Uint8Array, `claimValue must be bytes for ${caseLabel(c)}`);
    assert.deepEqual(Buffer.from(decoded.claimValue), Buffer.from(hex(c.claim.claim_value_hex)), caseLabel(c));

    assert.equal(decoded.claimId, c.claim.claim_id, caseLabel(c));
    assert.equal(decoded.userId, c.claim.user_id, caseLabel(c));
    assert.equal(decoded.claimType, c.claim.claim_type, caseLabel(c));
    assert.equal(decoded.attestedAt, c.claim.attested_at, caseLabel(c));
    assert.equal(decoded.createdAt, c.claim.created_at, caseLabel(c));
    assert.equal(decoded.expiresAt, c.claim.expires_at ?? undefined, caseLabel(c));
    assert.equal(decoded.revokedAt, c.claim.revoked_at ?? undefined, caseLabel(c));
    assert.equal(decoded.signatures.length, c.claim.signatures.length, caseLabel(c));

    // Per-signature payload construction: byte-exact against the fixture's
    // signed_payload_cbor_hex (the 8-element tag-first array, subject as one
    // '@'-joined string, expires_at as CBOR null when absent), and the
    // fixture's signature bytes verify over exactly those bytes.
    for (const sigFixture of c.claim.signatures) {
      const recomputed = claims.claimSignPayload(
        decoded.claimId,
        decoded.claimType,
        decoded.claimValue,
        decoded.userId,
        c.subject_domain,
        sigFixture.domain,
        decoded.expiresAt,
        decoded.attestedAt,
      );
      assert.deepEqual(
        Buffer.from(recomputed),
        Buffer.from(hex(sigFixture.signed_payload_cbor_hex)),
        `signed payload bytes for ${caseLabel(c)} / ${sigFixture.signed_by_key_id}`,
      );

      const sig = decoded.signatures.find(
        (s) => s.signedByKeyId === sigFixture.signed_by_key_id && s.domain === sigFixture.domain,
      );
      assert.ok(sig, `decoded claim missing signature from ${sigFixture.signed_by_key_id}`);
      assert.deepEqual(Buffer.from(sig!.signature), Buffer.from(hex(sigFixture.signature_hex)));

      const key = d.domain_keys.find((k: any) => k.key_id === sigFixture.signed_by_key_id);
      assert.ok(
        crypto.verifyEd25519(recomputed, hex(sigFixture.signature_hex), hex(key.public_key_hex)),
        `fixture signature does not verify over the recomputed payload for ${caseLabel(c)}`,
      );
    }

    // Full verification path — this is exactly what completeLocalLogin
    // (src/complete.ts) calls on every claim it receives from ticket
    // redemption.
    assert.doesNotThrow(
      () => claims.verifyClaim(decoded, c.subject_domain, defaultDomainKeys, CLAIMS_NOW),
      `verifyClaim unexpectedly threw for ${caseLabel(c)}`,
    );
  }
});

test("claims: negative cases fail verification with the expected error kind", () => {
  const d = load("claims.json");
  assert.equal(d.negative_cases.length, 4);

  const errorKindByFixtureName: Record<string, claims.ClaimErrorCode> = {
    signature_invalid: "signature-invalid",
    key_not_found: "key-not-found",
  };

  for (const c of d.negative_cases) {
    const decoded = generated.fromClaimCbor(hex(c.claim_cbor_hex));
    const domainKeys: DomainKeySet[] = c.domain_keys
      ? [{ domain: d.subject_domain, keys: c.domain_keys.map(claimFixtureKey) }]
      : claimsDefaultDomainKeys(d);
    const expectedCode = errorKindByFixtureName[c.expected_error];
    assert.ok(expectedCode, `unmapped expected_error: ${c.expected_error}`);

    assert.throws(
      () => claims.verifyClaim(decoded, c.subject_domain, domainKeys, CLAIMS_NOW),
      (e: unknown) => {
        assert.ok(e instanceof claims.ClaimError, `${caseLabel(c)}: not a ClaimError (${e})`);
        assert.equal((e as claims.ClaimError).code, expectedCode, caseLabel(c));
        return true;
      },
      `negative case ${caseLabel(c)} unexpectedly verified`,
    );
  }
});

test("claims: decode-negative cases fail to decode (claim_value must be bstr, never tstr)", () => {
  const d = load("claims.json");
  assert.equal(d.decode_negative_cases.length, 1);

  for (const c of d.decode_negative_cases) {
    assert.equal(c.expected_decode_ok, false);
    assert.throws(
      () => generated.fromClaimCbor(hex(c.claim_cbor_hex)),
      `decode-negative case ${caseLabel(c)} unexpectedly decoded`,
    );
  }
});

test("claims: LocalRpTicketRedemptionResponse round-trips byte-exactly and every embedded claim verifies", () => {
  const d = load("claims.json");
  const r = d.ticket_redemption_response;
  const responseBytes = hex(r.response_cbor_hex);

  const decoded = generated.fromLocalRpTicketRedemptionResponseCbor(responseBytes);
  const reencoded = generated.toLocalRpTicketRedemptionResponseCbor(decoded);
  assert.deepEqual(Buffer.from(reencoded), Buffer.from(responseBytes));

  assert.equal(decoded.userId, r.user_id);
  assert.equal(decoded.userDomain, r.user_domain);
  assert.equal(decoded.ticketExpiresAt, r.ticket_expires_at);
  assert.equal(decoded.claims.length, 3);

  // claims_ref: the three positive cases, in order.
  for (let i = 0; i < d.cases.length; i++) {
    assert.deepEqual(
      Buffer.from(decoded.claims[i].claimValue),
      Buffer.from(hex(d.cases[i].claim.claim_value_hex)),
      `claims[${i}] value mismatch`,
    );
    assert.equal(decoded.claims[i].claimId, d.cases[i].claim.claim_id);
  }

  // "Decoding without verifying fails the point" — verify each embedded
  // claim's signatures through the same path completeLocalLogin uses.
  const domainKeys = claimsDefaultDomainKeys(d);
  for (const claim of decoded.claims) {
    assert.doesNotThrow(() => claims.verifyClaim(claim, decoded.userDomain, domainKeys, CLAIMS_NOW));
  }
});
