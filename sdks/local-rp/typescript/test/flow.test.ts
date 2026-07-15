// Flow tests: `completeLocalLogin`'s full verification chain, end to end,
// against a real (but locally spun up, fake-identity) LinkKeys IDP —
// DNS-pinned TLS, CSIL-RPC framing, and all. Only two things are faked: the
// DNS TXT answers (`FakeDnsResolver`, so no real network/DNS is touched) and
// the IDP's identity itself (a throwaway domain signing key, not a real
// LinkKeys deployment). A small custom `Transport` is used instead of
// `NodeTransport` to demonstrate the seam is genuinely injectable — the TLS
// handshake, certificate pinning, and RPC wire format underneath it are all
// this SDK's real production code paths (`src/rpc.ts`).
//
// Uses the same fixed, publicly-known test key seeds as
// `sdks/local-rp/conformance/keys.json` (`local_rp.signing` = 0x01 repeated,
// `local_rp.encryption` = 0x02 repeated, `domain_signing_key` = 0x03
// repeated), verified byte-for-byte interoperable with the Rust reference's
// ed25519-dalek/x25519-dalek derivation before this file was written.
//
// The fake IDP's TLS certificate is minted with the system `openssl` CLI
// (there is no certificate-issuing API in Node's stdlib) from the fixed
// domain signing seed, so its SPKI fingerprint is exactly what the test's
// fake DNS answer pins to.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";
import tls from "node:tls";
import test from "node:test";

import { beginLocalLogin } from "../src/begin.ts";
import { signClaim, ClaimError, type ClaimSigner } from "../src/claims.ts";
import {
  derivePublicKeyFromEd25519PrivateKey,
  derivePublicKeyFromX25519PrivateKey,
  fingerprint,
  signEd25519,
} from "../src/crypto.ts";
import type { DnsResolver } from "../src/dns.ts";
import { localRpEncryptedCallbackToUrlParam } from "../src/encoding.ts";
import * as generated from "../src/generated/codec.gen.ts";
import type {
  Claim,
  DomainPublicKey,
  LocalRpCallbackPayload,
  LocalRpTicketRedemptionResponse,
  RevocationCertificate,
} from "../src/generated/types.gen.ts";
import type { LocalRpKeyMaterial } from "../src/identity.ts";
import {
  LocalRpError,
  buildLocalRpCallbackPayload,
  buildLocalRpDescriptor,
  sealLocalRpCallback,
  signLocalRpCallbackPayload,
  signLocalRpDescriptor,
} from "../src/localRp.ts";
import { completeLocalLogin, type VerifiedLocalLogin } from "../src/complete.ts";
import { RpcServerError } from "../src/rpc.ts";
import { revocationPayload } from "../src/revocation.ts";
import type { Transport } from "../src/transport.ts";
import { RpcRequest, RpcResponse, Status } from "../src/vendor/csilgen-transport/index.ts";

// Same fixed seeds as sdks/local-rp/conformance/keys.json.
const LOCAL_RP_SIGNING_SEED = new Uint8Array(32).fill(1);
const LOCAL_RP_ENCRYPTION_PRIVATE = new Uint8Array(32).fill(2);
const DOMAIN_SIGNING_SEED = new Uint8Array(32).fill(3);
const DOMAIN_KEY_ID = "test-domain-key-1";
const USER_DOMAIN = "example.test";
const CALLBACK_URL = "http://localhost/callback";

// ---------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------

/** A `Transport` the test provides itself, proving the seam is genuinely injectable. Still dials a real loopback socket — only the DNS answer steering it there is faked. */
class TestTransport implements Transport {
  dial(hostPort: string): Promise<net.Socket> {
    const idx = hostPort.lastIndexOf(":");
    const host = hostPort.slice(0, idx);
    const port = Number.parseInt(hostPort.slice(idx + 1), 10);
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host, port });
      socket.once("connect", () => resolve(socket));
      socket.once("error", reject);
    });
  }
}

/** Canned DNS answers for exactly one domain. */
class FakeDnsResolver implements DnsResolver {
  private readonly linkkeysTxt: string;
  private readonly apisTxt: string;

  constructor(linkkeysTxt: string, apisTxt: string) {
    this.linkkeysTxt = linkkeysTxt;
    this.apisTxt = apisTxt;
  }

  async txtLookup(name: string): Promise<string[]> {
    if (name === `_linkkeys.${USER_DOMAIN}`) return [this.linkkeysTxt];
    if (name === `_linkkeys_apis.${USER_DOMAIN}`) return [this.apisTxt];
    throw new Error(`no fake record for ${name}`);
  }
}

// ---------------------------------------------------------------------
// Fake IDP TLS certificate (minted via system `openssl`, from a fixed seed)
// ---------------------------------------------------------------------

const ED25519_PKCS8_PREFIX_HEX = "302e020100300506032b657004220420";

function ed25519SeedToPkcs8Pem(seed: Uint8Array): string {
  const der = Buffer.concat([Buffer.from(ED25519_PKCS8_PREFIX_HEX, "hex"), Buffer.from(seed)]);
  const b64 = der.toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----\n`;
}

/** Self-sign a certificate for `domain` from `seed` via the system `openssl` CLI (Node's stdlib has no certificate-issuing API). Returns PEM key + cert. */
function generateDomainTlsCertPem(domain: string, seed: Uint8Array): { keyPem: string; certPem: string } {
  const dir = mkdtempSync(join(tmpdir(), "linkkeys-local-rp-flow-test-"));
  const keyPath = join(dir, "key.pem");
  const certPath = join(dir, "cert.pem");
  const keyPem = ed25519SeedToPkcs8Pem(seed);
  writeFileSync(keyPath, keyPem);
  execFileSync("openssl", [
    "req",
    "-new",
    "-x509",
    "-key",
    keyPath,
    "-days",
    "3",
    "-subj",
    `/CN=${domain}`,
    "-out",
    certPath,
  ]);
  return { keyPem, certPem: readFileSync(certPath, "utf8") };
}

// ---------------------------------------------------------------------
// Fake IDP: a real TCP+TLS(fp-pinned)+CSIL-RPC server, one request per connection
// ---------------------------------------------------------------------

type Dispatch = (service: string, op: string, payload: Uint8Array) => RpcResponse;

/** Spawns a fake IDP TLS server bound to a fresh loopback port, presenting a certificate derived from `domainSeed`, answering each connection's one request via `dispatch`. Returns the bound address string and a `close()`. */
function spawnFakeIdp(domainSeed: Uint8Array, dispatch: Dispatch): Promise<{ addr: string; close: () => void }> {
  const { keyPem, certPem } = generateDomainTlsCertPem(USER_DOMAIN, domainSeed);
  const server = tls.createServer({ key: keyPem, cert: certPem }, (socket) => {
    let buf = Buffer.alloc(0);
    socket.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 4) return;
      const len = buf.readUInt32BE(0);
      if (buf.length < 4 + len) return;
      const body = buf.subarray(4, 4 + len);
      buf = buf.subarray(4 + len);

      let resp: RpcResponse;
      try {
        const req = RpcRequest.decode(new Uint8Array(body));
        resp = dispatch(req.service, req.op, req.payload);
      } catch (e) {
        resp = RpcResponse.transportError(Status.MalformedEnvelope, String(e));
      }
      const encoded = resp.encode();
      const lenBuf = Buffer.alloc(4);
      lenBuf.writeUInt32BE(encoded.length, 0);
      socket.write(Buffer.concat([lenBuf, Buffer.from(encoded)]));
    });
    // A deliberately-bad-pin test's client aborts the TLS handshake before
    // ever reaching this handler; the server side may still see a reset.
    socket.on("error", () => undefined);
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({ addr: `127.0.0.1:${port}`, close: () => server.close() });
    });
  });
}

// ---------------------------------------------------------------------
// Scenario construction
// ---------------------------------------------------------------------

function fixedKeyMaterial(now: Date): LocalRpKeyMaterial {
  const signingPublicKey = derivePublicKeyFromEd25519PrivateKey(LOCAL_RP_SIGNING_SEED);
  const encryptionPublicKey = derivePublicKeyFromX25519PrivateKey(LOCAL_RP_ENCRYPTION_PRIVATE);

  const createdAt = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
  const expiresAt = new Date(now.getTime() + 3650 * 24 * 60 * 60 * 1000).toISOString();
  const descriptor = buildLocalRpDescriptor(
    "Flow Test App",
    undefined,
    signingPublicKey,
    encryptionPublicKey,
    ["aes-256-gcm", "chacha20-poly1305"],
    createdAt,
    expiresAt,
  );
  const fp = descriptor.fingerprint;
  const signedDescriptor = signLocalRpDescriptor(descriptor, LOCAL_RP_SIGNING_SEED);

  return {
    signingPrivateKey: LOCAL_RP_SIGNING_SEED,
    signingPublicKey,
    encryptionPrivateKey: LOCAL_RP_ENCRYPTION_PRIVATE,
    encryptionPublicKey,
    descriptor: signedDescriptor,
    fingerprint: fp,
  };
}

function domainPublicKey(
  now: Date,
  seed: Uint8Array = DOMAIN_SIGNING_SEED,
  keyId: string = DOMAIN_KEY_ID,
): DomainPublicKey {
  const pk = derivePublicKeyFromEd25519PrivateKey(seed);
  return {
    keyId,
    publicKey: pk,
    fingerprint: fingerprint(pk),
    algorithm: "ed25519",
    keyUsage: "sign",
    signedByKeyId: undefined,
    keySignature: undefined,
    createdAt: new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString(),
    expiresAt: new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    revokedAt: undefined,
  };
}

/** Every knob a failure-case test can turn, applied in this order: build the correct payload/domain key/claim/redemption response, then apply these mutators, then sign + seal + serve. */
interface Scenario {
  mutatePayload?: (p: LocalRpCallbackPayload) => void;
  mutateDomainKey?: (k: DomainPublicKey) => void;
  mutateClaim?: (c: Claim) => void;
  /** Mutates the (otherwise-honest) `LocalRp/redeem-claim-ticket` response before it's served — the hostile-IDP seam for FIX A's identity-binding checks. */
  mutateRedemption?: (r: LocalRpTicketRedemptionResponse) => void;
  dnsFingerprintOverride?: string;
  /** Overrides `beginLocalLogin`'s `requiredClaims`. Defaults to `DEFAULT_REQUIRED_CLAIMS` (`["handle"]`), matching the one claim this scenario signs. */
  requiredClaims?: readonly string[];
  /** Sibling domain signing keys served alongside the primary one (and DNS-pinned alongside it) — for revocation-quorum tests. */
  extraDomainKeys?: DomainPublicKey[];
  /**
   * What the fake IDP's `DomainKeys/get-revocations` responds with:
   * `"empty"` (default, successful empty list), `"error"` (RPC-level
   * error status — FIX B must fail closed, not swallow it), `"malformed"`
   * (an Ok status carrying undecodable bytes — simulates a dropped/garbled
   * response), or an explicit list of certificates to return.
   */
  revocations?: "empty" | "error" | "malformed" | RevocationCertificate[];
}

async function runScenario(scenario: Scenario): Promise<VerifiedLocalLogin> {
  const now = new Date();
  const keyMaterial = fixedKeyMaterial(now);

  const { pending } = beginLocalLogin({
    keyMaterial,
    callbackUrl: CALLBACK_URL,
    userDomain: USER_DOMAIN,
    requiredClaims: scenario.requiredClaims,
    now,
  });

  const domainKey = domainPublicKey(now);
  scenario.mutateDomainKey?.(domainKey);
  const allDomainKeys = [domainKey, ...(scenario.extraDomainKeys ?? [])];

  const claimTicket = new Uint8Array(32).fill(7);
  const payload = buildLocalRpCallbackPayload(
    "user-1",
    USER_DOMAIN,
    claimTicket,
    keyMaterial.fingerprint,
    CALLBACK_URL,
    Buffer.from(pending.nonceHex, "hex"),
    Buffer.from(pending.stateHex, "hex"),
    now.toISOString(),
    new Date(now.getTime() + 5 * 60 * 1000).toISOString(),
  );
  scenario.mutatePayload?.(payload);

  const signedPayload = signLocalRpCallbackPayload(payload, DOMAIN_KEY_ID, DOMAIN_SIGNING_SEED);

  const encrypted = sealLocalRpCallback(
    signedPayload,
    "aes-256-gcm",
    keyMaterial.encryptionPublicKey,
    payload.audienceFingerprint,
    payload.nonce,
    payload.state,
    payload.issuedAt,
    payload.expiresAt,
  );
  const encryptedToken = localRpEncryptedCallbackToUrlParam(encrypted);
  const arrivedUrl = `${CALLBACK_URL}?encrypted_token=${encryptedToken}`;

  const claimSigner: ClaimSigner = {
    domain: USER_DOMAIN,
    keyId: DOMAIN_KEY_ID,
    privateKeySeed: DOMAIN_SIGNING_SEED,
  };
  const claim = signClaim(
    {
      claimId: "claim-1",
      claimType: "handle",
      claimValue: new TextEncoder().encode("flowtestuser"),
      userId: "user-1",
      subjectDomain: USER_DOMAIN,
      attestedAt: now.toISOString(),
    },
    [claimSigner],
  );
  scenario.mutateClaim?.(claim);

  const ticketExpiresAt = new Date(now.getTime() + 60 * 60 * 1000).toISOString();
  const redemptionResponse: LocalRpTicketRedemptionResponse = {
    userId: "user-1",
    userDomain: USER_DOMAIN,
    claims: [claim],
    ticketExpiresAt,
  };
  scenario.mutateRedemption?.(redemptionResponse);

  const dispatch: Dispatch = (service, op) => {
    if (service === "DomainKeys" && op === "get-domain-keys") {
      const resp = {
        domain: USER_DOMAIN,
        keys: allDomainKeys,
        recentRevocationsAvailable: undefined,
      };
      return RpcResponse.ok("GetDomainKeysResponse", generated.toGetDomainKeysResponseCbor(resp));
    }
    if (service === "DomainKeys" && op === "get-revocations") {
      if (scenario.revocations === "error") {
        return RpcResponse.transportError(Status.Unavailable, "revocations backend unavailable");
      }
      if (scenario.revocations === "malformed") {
        // Not valid CBOR for `GetRevocationsResponse` — simulates a
        // dropped/garbled response the client must fail closed on rather
        // than silently treat as "no revocations".
        return RpcResponse.ok("GetRevocationsResponse", new Uint8Array([0xff, 0x00, 0x01]));
      }
      const revocations = Array.isArray(scenario.revocations) ? scenario.revocations : [];
      return RpcResponse.ok(
        "GetRevocationsResponse",
        generated.toGetRevocationsResponseCbor({ revocations }),
      );
    }
    if (service === "LocalRp" && op === "redeem-claim-ticket") {
      return RpcResponse.ok(
        "LocalRpTicketRedemptionResponse",
        generated.toLocalRpTicketRedemptionResponseCbor(redemptionResponse),
      );
    }
    return RpcResponse.transportError(
      Status.UnknownServiceOrOp,
      `fake IDP has no handler for ${service}/${op}`,
    );
  };

  const { addr, close } = await spawnFakeIdp(DOMAIN_SIGNING_SEED, dispatch);
  try {
    const realFingerprints = allDomainKeys.map((k) => fingerprint(k.publicKey));
    const pinnedFingerprints = scenario.dnsFingerprintOverride ? [scenario.dnsFingerprintOverride] : realFingerprints;
    const dns = new FakeDnsResolver(
      `v=lk1 ${pinnedFingerprints.map((f) => `fp=${f}`).join(" ")}`,
      `v=lk1 tcp=${addr}`,
    );
    const transport = new TestTransport();

    return await completeLocalLogin({
      keyMaterial,
      pending,
      encryptedToken,
      arrivedUrl,
      now,
      transport,
      dns,
    });
  } finally {
    close();
  }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

test("happy path returns verified login", async () => {
  const verified = await runScenario({});
  assert.equal(verified.userId, "user-1");
  assert.equal(verified.userDomain, USER_DOMAIN);
  assert.equal(verified.claims.length, 1);
  assert.equal(verified.claims[0]?.claimType, "handle");
  assert.equal(verified.localRpFingerprint.length, 64);
  assert.equal(verified.domainPublicKeys.length, 1);
});

test("wrong audience fingerprint is rejected", async () => {
  await assert.rejects(
    runScenario({ mutatePayload: (p) => (p.audienceFingerprint = "b".repeat(64)) }),
    LocalRpError,
  );
});

test("wrong issuer domain is rejected", async () => {
  await assert.rejects(
    runScenario({ mutatePayload: (p) => (p.userDomain = "attacker.test") }),
    LocalRpError,
  );
});

test("nonce mismatch is rejected", async () => {
  await assert.rejects(
    runScenario({ mutatePayload: (p) => (p.nonce = new Uint8Array(32).fill(0xee)) }),
    LocalRpError,
  );
});

test("expired callback payload is rejected", async () => {
  await assert.rejects(
    runScenario({
      mutatePayload: (p) => {
        const n = new Date();
        p.issuedAt = new Date(n.getTime() - 2 * 60 * 60 * 1000).toISOString();
        p.expiresAt = new Date(n.getTime() - 60 * 60 * 1000).toISOString();
      },
    }),
    LocalRpError,
  );
});

test("DNS fingerprint pin mismatch is rejected", async () => {
  // Fails during the TLS handshake pin check (the fake IDP's real cert
  // fingerprint no longer matches the pinned set) — either way it must
  // never reach a verified result.
  await assert.rejects(runScenario({ dnsFingerprintOverride: "c".repeat(64) }));
});

test("revoked signing key is rejected", async () => {
  await assert.rejects(
    runScenario({ mutateDomainKey: (k) => (k.revokedAt = new Date().toISOString()) }),
    LocalRpError,
  );
});

test("tampered claim signature is rejected", async () => {
  await assert.rejects(
    runScenario({
      mutateClaim: (c) => {
        const sig = c.signatures[0];
        if (sig && sig.signature.length > 0) {
          const tampered = Uint8Array.from(sig.signature);
          tampered[0] = (tampered[0] ?? 0) ^ 0xff;
          sig.signature = tampered;
        }
      },
    }),
    ClaimError,
  );
});

// ---------------------------------------------------------------------
// Security-review fixes: 5 hostile-IDP tests proving fatal, fail-closed
// rejection. The fake IDP in every one of these is otherwise honest (real
// domain signature, real TLS pin) — only the specific field under test is
// tampered, so a passing assertion here proves THAT check is what stopped
// the login, not some unrelated failure earlier in the chain.
// ---------------------------------------------------------------------

test("PendingLogin.requiredClaims round-trips through JSON", () => {
  const keyMaterial = fixedKeyMaterial(new Date());
  const { pending } = beginLocalLogin({
    keyMaterial,
    callbackUrl: CALLBACK_URL,
    userDomain: USER_DOMAIN,
    requiredClaims: ["handle", "email"],
    now: new Date(),
  });
  assert.deepEqual(pending.requiredClaims, ["handle", "email"]);
  const roundTripped = JSON.parse(JSON.stringify(pending));
  assert.deepEqual(roundTripped, pending);
});

test("[hostile IDP 1] ticket-redemption identity mismatch vs the signed callback payload is rejected", async () => {
  await assert.rejects(
    runScenario({ mutateRedemption: (r) => (r.userId = "attacker-user") }),
    (err: unknown) => err instanceof LocalRpError && err.code === "redemption-identity-mismatch",
  );
  await assert.rejects(
    runScenario({ mutateRedemption: (r) => (r.userDomain = "attacker.test") }),
    (err: unknown) => err instanceof LocalRpError && err.code === "redemption-identity-mismatch",
  );
});

test("[hostile IDP 2] claim user_id mismatch vs the verified callback subject is rejected", async () => {
  await assert.rejects(
    runScenario({ mutateClaim: (c) => (c.userId = "attacker-user") }),
    (err: unknown) => err instanceof LocalRpError && err.code === "claim-identity-mismatch",
  );
});

test("[hostile IDP 3] required claims not satisfied by the verified claim set is rejected", async () => {
  // Empty: the ticket redemption drops every claim, including the required one.
  await assert.rejects(
    runScenario({ mutateRedemption: (r) => (r.claims = []) }),
    (err: unknown) => err instanceof LocalRpError && err.code === "required-claim-missing",
  );
  // Insufficient: a required claim type this login demanded was never returned at all.
  await assert.rejects(
    runScenario({ requiredClaims: ["handle", "email"] }),
    (err: unknown) => err instanceof LocalRpError && err.code === "required-claim-missing",
  );
});

test("[hostile IDP 4] get-revocations failures fail closed and are never swallowed", async () => {
  // An RPC-level error status must propagate as a fatal failure, not be
  // treated as "no revocations known yet".
  await assert.rejects(runScenario({ revocations: "error" }), RpcServerError);
  // A response that can't even be decoded (dropped/garbled) must fail the
  // same way, never be treated as an empty/successful list.
  await assert.rejects(runScenario({ revocations: "malformed" }));
});

test("[hostile IDP 5] a quorum-verified revocation certificate for the callback's signing key is honored (fail closed)", async () => {
  const now = new Date();
  const siblingSeedA = new Uint8Array(32).fill(4);
  const siblingSeedB = new Uint8Array(32).fill(5);
  const siblingA = domainPublicKey(now, siblingSeedA, "test-domain-key-2");
  const siblingB = domainPublicKey(now, siblingSeedB, "test-domain-key-3");

  const targetFingerprint = fingerprint(derivePublicKeyFromEd25519PrivateKey(DOMAIN_SIGNING_SEED));
  const revokedAt = now.toISOString();
  const cert: RevocationCertificate = {
    targetKeyId: DOMAIN_KEY_ID,
    targetFingerprint,
    revokedAt,
    signatures: [
      { keyId: siblingA.keyId, seed: siblingSeedA },
      { keyId: siblingB.keyId, seed: siblingSeedB },
    ].map(({ keyId, seed }) => ({
      domain: USER_DOMAIN,
      signedByKeyId: keyId,
      signature: signEd25519(
        revocationPayload(DOMAIN_KEY_ID, targetFingerprint, revokedAt, USER_DOMAIN),
        seed,
      ),
    })),
  };

  // A quorum-verified (2 distinct sibling signers) revocation certificate
  // for the signing key the callback envelope was actually signed with
  // must be honored: that key drops out of the trusted set, so the
  // envelope signature can no longer be verified against it at all — the
  // login must fail closed, never silently proceed on a revoked key.
  await assert.rejects(
    runScenario({ extraDomainKeys: [siblingA, siblingB], revocations: [cert] }),
    LocalRpError,
  );
});
