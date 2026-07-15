// `completeLocalLogin` (design doc: "SDK API Shape", "Flow" steps 12-13).
// Mirrors `sdks/local-rp/rust/src/complete.rs`.
//
// This is the SDK's full verification chain, run in the exact order the
// pure `localRp.ts`/`claims.ts` helpers require:
//
// 1. decode the callback ciphertext from its URL-param encoding
// 2. open it (decrypt) — only with a suite this identity's own descriptor
//    advertises
// 3. fetch the pending domain's public keys + revocations, DNS-`fp=`-pinned,
//    over TCP CSIL-RPC
// 4. verify the domain-signed envelope (key lookup, revocation/expiry,
//    signature, payload timestamp bounds) — only now is anything inside the
//    payload trusted
// 5. cross-check the cleartext header's routing fields against the
//    now-verified payload
// 6. audience / issuer / callback-URL / nonce-state checks
// 7. redeem the claim ticket over TCP CSIL-RPC (signed with the local RP's
//    own key — the possession proof)
// 8. verify every returned claim's signatures against ITS signer domain's
//    keys (fetched the same pinned way), which also checks the claim's own
//    revocation/expiry

import type { PendingLogin } from "./begin.ts";
import { verifyClaim, type DomainKeySet } from "./claims.ts";
import { parseAeadSuite } from "./crypto.ts";
import type { DnsResolver } from "./dns.ts";
import { defaultDnsResolver, defaultTransport } from "./defaults.ts";
import { localRpEncryptedCallbackFromUrlParam } from "./encoding.ts";
import * as generated from "./generated/codec.gen.ts";
import type { Claim, DomainPublicKey } from "./generated/types.gen.ts";
import type { LocalRpKeyMaterial } from "./identity.ts";
import {
  DEFAULT_CLOCK_SKEW_SECONDS,
  LocalRpError,
  buildLocalRpTicketRedemptionRequest,
  checkCallbackHeaderMatchesPayload,
  checkTimestamps,
  openLocalRpCallback,
  signLocalRpTicketRedemptionRequest,
  verifyAudience,
  verifyCallbackUrl,
  verifyIssuer,
  verifyLocalRpCallbackPayload,
  verifyNonceState,
} from "./localRp.ts";
import { fetchDomainKeys, redeemClaimTicket } from "./rpc.ts";
import type { Transport } from "./transport.ts";

/**
 * Bound on the number of distinct claim-signer domains `completeLocalLogin`
 * will fetch keys for per completion. The redemption response's claim
 * signatures name their signing domains as plain, not-yet-verified strings
 * — a malicious/compromised home IDP could otherwise list an unbounded
 * number of distinct "signer domains" purely to make this SDK perform many
 * outbound DNS/TCP calls to attacker-chosen targets before any signature is
 * actually checked (an SSRF/DoS amplification vector against the app's own
 * process). A legitimate claim set names very few (typically one: the home
 * domain).
 */
const MAX_CLAIM_SIGNER_DOMAINS = 8;

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

/** Input to `completeLocalLogin`. Every field is load-bearing. */
export interface CompleteLocalLoginConfig {
  /** The same identity `beginLocalLogin` used. */
  keyMaterial: LocalRpKeyMaterial;
  /** The pending-login state `beginLocalLogin` returned, exactly as the app persisted it. Treat as single-use. */
  pending: PendingLogin;
  /** The `encrypted_token` query-parameter value (base64url CBOR `LocalRpEncryptedCallback`). */
  encryptedToken: string;
  /** The URL the callback actually arrived at (including the `encrypted_token` query parameter, which this SDK strips before comparing). */
  arrivedUrl: string;
  now: Date;
  /** Clock-skew tolerance for timestamp checks, in seconds. Defaults to `DEFAULT_CLOCK_SKEW_SECONDS` (300). */
  clockSkewSeconds?: number;
  /** The TCP dial seam. Defaults to `defaultTransport()`. */
  transport?: Transport;
  /** The DNS TXT lookup seam. Defaults to `defaultDnsResolver()`. */
  dns?: DnsResolver;
}

/** What `completeLocalLogin` returns to app code. */
export interface VerifiedLocalLogin {
  userId: string;
  userDomain: string;
  /** Verified claim values, current as of ticket redemption. */
  claims: Claim[];
  /** The user's home domain's public keys used to verify the callback envelope. */
  domainPublicKeys: DomainPublicKey[];
  localRpFingerprint: string;
  issuedAt: Date;
  expiresAt: Date;
  /** The ticket's own expiry — valid for a bounded window, multi-use within it. */
  ticketExpiresAt: Date;
}

function parseRfc3339(field: string, s: string): Date {
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) {
    throw new Error(`${field}: invalid RFC3339 timestamp: ${s}`);
  }
  return d;
}

/**
 * Undo the exact `?`/`&` + `encrypted_token=` suffix construction the IDP
 * uses to deliver the callback, so the recovered value can be compared
 * against the signed payload's `callback_url`. If the arrived URL doesn't
 * end with that exact suffix, returns it unchanged — the subsequent
 * `verifyCallbackUrl` equality check then correctly fails closed rather than
 * this function guessing.
 */
function stripEncryptedTokenParam(arrivedUrl: string): string {
  for (const sep of ["?", "&"]) {
    const marker = `${sep}encrypted_token=`;
    const idx = arrivedUrl.lastIndexOf(marker);
    if (idx >= 0) {
      return arrivedUrl.slice(0, idx);
    }
  }
  return arrivedUrl;
}

/** `complete_local_login(config) -> VerifiedLocalLogin` (design doc, "SDK API Shape"). See the module docs for the exact verification order. */
export async function completeLocalLogin(config: CompleteLocalLoginConfig): Promise<VerifiedLocalLogin> {
  const skew = config.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
  const transport = config.transport ?? defaultTransport();
  const dns = config.dns ?? defaultDnsResolver();

  // 1. Decode the callback's URL-param encoding.
  const encrypted = localRpEncryptedCallbackFromUrlParam(config.encryptedToken);

  // 2. Open it, restricted to suites THIS identity's own descriptor
  // advertises (Wire Precision: "The SDK must decrypt only with a suite
  // listed in its own descriptor").
  const ownDescriptor = generated.fromLocalRpDescriptorCbor(config.keyMaterial.descriptor.descriptor);
  const allowedSuites = ownDescriptor.supportedSuites
    .map((s) => parseAeadSuite(s))
    .filter((s): s is NonNullable<typeof s> => s !== undefined);
  const { header, signedPayload } = openLocalRpCallback(
    encrypted,
    config.keyMaterial.encryptionPrivateKey,
    allowedSuites,
  );

  // 3. Fetch the PENDING state's domain's keys + revocations, DNS-pinned,
  // over TCP CSIL-RPC.
  const userDomainKeys = await fetchDomainKeys(transport, dns, config.pending.userDomain);

  // 4. Verify the domain-signed envelope against those keys. Nothing inside
  // `payload` is trusted before this succeeds.
  const payload = verifyLocalRpCallbackPayload(signedPayload, userDomainKeys, config.now, skew);

  // 5. Cross-check the cleartext header's routing twins against the
  // now-verified payload.
  checkCallbackHeaderMatchesPayload(header, payload);

  // 6a. Audience: the callback names THIS local RP.
  verifyAudience(payload.audienceFingerprint, config.keyMaterial.fingerprint);

  // 6b. Issuer binding: the payload's user_domain must be the domain the
  // login was BEGUN with, not merely whichever domain's keys happened to
  // verify.
  verifyIssuer(payload.userDomain, config.pending.userDomain);

  // 6c. Callback URL binding against the URL the callback actually arrived
  // at (not merely the URL originally requested).
  const arrivedBaseUrl = stripEncryptedTokenParam(config.arrivedUrl);
  verifyCallbackUrl(payload.callbackUrl, arrivedBaseUrl);

  // 6d. Nonce/state equality against the pending state. Single-use replay
  // protection at the app boundary is the app's job.
  verifyNonceState(
    hexToBytes(config.pending.nonceHex),
    hexToBytes(config.pending.stateHex),
    payload.nonce,
    payload.state,
  );

  // 7. Redeem the claim ticket over TCP CSIL-RPC, signed with the local RP's
  // own key (the possession proof a stolen ticket can't satisfy).
  const redemptionRequest = buildLocalRpTicketRedemptionRequest(
    payload.claimTicket,
    config.keyMaterial.fingerprint,
    config.now.toISOString(),
  );
  const signedRedemption = signLocalRpTicketRedemptionRequest(
    redemptionRequest,
    config.keyMaterial.signingPrivateKey,
  );
  const redemption = await redeemClaimTicket(
    transport,
    dns,
    config.pending.userDomain,
    signedRedemption,
  );

  // 7a. Identity binding: the ticket-redemption response itself carries no
  // signature over its own `userId`/`userDomain` — it is trusted only
  // because it arrived over the pinned-TLS RPC channel to the domain the
  // login was begun with. That is NOT the same guarantee as the
  // domain-signed callback payload's identity, so a compromised/malicious
  // IDP must not be able to redeem a ticket for a DIFFERENT subject than the
  // one it told the browser (via the signed callback) it was returning.
  // Mismatch is fatal — this never resolves a successful login on a
  // mismatch.
  if (redemption.userId !== payload.userId || redemption.userDomain !== payload.userDomain) {
    throw new LocalRpError(
      "redemption-identity-mismatch",
      "ticket redemption response identity does not match the signed callback payload",
    );
  }

  // 8. Verify every returned claim's signatures against ITS signer domain's
  // keys, fetched the same pinned way (a claim may be attested by a domain
  // other than the user's home domain). Reuse the home domain's
  // already-fetched keys; fetch any additional signer domains on demand,
  // capped (see MAX_CLAIM_SIGNER_DOMAINS docs above).
  const domainKeySets: DomainKeySet[] = [{ domain: payload.userDomain, keys: userDomainKeys }];
  for (const claim of redemption.claims) {
    for (const sig of claim.signatures) {
      if (!domainKeySets.some((s) => s.domain === sig.domain)) {
        if (domainKeySets.length >= MAX_CLAIM_SIGNER_DOMAINS) {
          throw new Error(
            `claim set names more than ${MAX_CLAIM_SIGNER_DOMAINS} distinct signer domains; refusing to fetch further keys`,
          );
        }
        const keys = await fetchDomainKeys(transport, dns, sig.domain);
        domainKeySets.push({ domain: sig.domain, keys });
      }
    }
  }

  // 8a. Every claim must be about the VERIFIED subject (the signed
  // payload's userId), independent of the redemption response's own
  // (already checked, but defense-in-depth) echo — a claim naming a
  // different user_id must never be accepted into the verified result.
  // Then verify its cryptographic quorum + own revocation/expiry, against
  // the VERIFIED payload.userDomain as subject domain (never
  // redemption.userDomain — the payload is the trusted source once it has
  // passed signature verification above).
  const verifiedClaimTypes = new Set<string>();
  for (const claim of redemption.claims) {
    if (claim.userId !== payload.userId) {
      throw new LocalRpError(
        "claim-identity-mismatch",
        `claim ${claim.claimId} user_id does not match the verified callback subject`,
      );
    }
    verifyClaim(claim, payload.userDomain, domainKeySets, config.now);
    verifiedClaimTypes.add(claim.claimType);
  }

  // 8b. Enforce the required-claims list THIS login actually requested
  // (from `pending`, not anything IDP-supplied): every required claim type
  // must be present among the claims that just passed verification above.
  // Missing/insufficient — including an empty claim set — is fatal.
  for (const requiredType of config.pending.requiredClaims) {
    if (!verifiedClaimTypes.has(requiredType)) {
      throw new LocalRpError(
        "required-claim-missing",
        `required claim type not present among verified claims: ${requiredType}`,
      );
    }
  }

  return {
    // Sourced from the SIGNED callback payload, not the unauthenticated
    // ticket-redemption response (which is only usable here because it was
    // just checked to agree with the payload above).
    userId: payload.userId,
    userDomain: payload.userDomain,
    claims: redemption.claims,
    domainPublicKeys: userDomainKeys,
    localRpFingerprint: config.keyMaterial.fingerprint,
    issuedAt: parseRfc3339("callback issuedAt", payload.issuedAt),
    expiresAt: parseRfc3339("callback expiresAt", payload.expiresAt),
    ticketExpiresAt: parseRfc3339("ticketExpiresAt", redemption.ticketExpiresAt),
  };
}
