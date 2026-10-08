// Act-as grants, grantee side only (docs/spec/reserved/act-as-grants.md).
// Mirrors `crates/liblinkkeys/src/act_as.rs` (`GranteeSigner::LocalRp`,
// `sign_grant_request`, `sign_refresh_request`, `present`).
//
// A local RP can be the GRANTEE of an act-as grant: a user lets this app act
// as the user at an enrolled application (the audience). A local RP can
// never be an audience, because a peer cannot resolve its keys through DNS.
// The home domain accepts a local-RP grantee only after it approved that
// local RP.
//
// Every signature covers `CBOR([tag, payload_bytes])` and is made with the
// descriptor signing key. The proof carries the signed descriptor, and its
// `signed_by_key_id` is the descriptor fingerprint.

import { BROWSER_ROUTE_ACT_AS, resolveBrowserEndpoint } from "./browser.ts";
import { parseIdentityInput, validateCallbackScheme } from "./begin.ts";
import { constantTimeEqual, randomBytes, signEd25519 } from "./crypto.ts";
import { defaultDnsResolver, defaultTransport } from "./defaults.ts";
import type { DnsResolver } from "./dns.ts";
import * as generated from "./generated/codec.gen.ts";
import type {
  ActAsCredential,
  ActAsGrantRequest,
  ActAsPresentation,
  ActAsRefreshRequest,
  ApplicationRef,
  GranteeProof,
  GranteeRef,
  SignedActAsGrant,
  SignedActAsGrantRequest,
  SignedActAsRefreshRequest,
  SignedActAsScopeSet,
} from "./generated/types.gen.ts";
import { InvalidInputError, type LocalRpKeyMaterial } from "./identity.ts";
import { LocalRpError, envelopeSignatureInput } from "./localRp.ts";
import { refreshActAsGrant as rpcRefreshActAsGrant } from "./rpc.ts";
import type { Transport } from "./transport.ts";
import * as nodeCrypto from "node:crypto";

export const ACT_AS_GRANT_REQUEST_TAG = "linkkeys-act-as-grant-request-v1alpha";
export const ACT_AS_REFRESH_REQUEST_TAG = "linkkeys-act-as-refresh-request-v1alpha";
export const ACT_AS_PRESENTATION_TAG = "linkkeys-act-as-presentation-v1alpha";

/** Default request window for a grant request, in seconds. */
export const DEFAULT_ACT_AS_REQUEST_WINDOW_SECONDS = 300;
/** Largest request window the reference home domain accepts, in seconds. */
export const MAX_ACT_AS_REQUEST_WINDOW_SECONDS = 900;
/** Request window of a refresh request, in seconds. */
export const ACT_AS_REFRESH_WINDOW_SECONDS = 300;

/** The part of the key material that a grantee signature needs. */
export type ActAsSigningMaterial = Pick<LocalRpKeyMaterial, "descriptor" | "fingerprint" | "signingPrivateKey">;

/** Whole-second RFC3339 in UTC, ending in `Z` (`act_as::format_time`). */
export function formatActAsTime(t: Date): string {
  const ms = t.getTime();
  if (Number.isNaN(ms)) throw new InvalidInputError("invalid time");
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** SHA-256 of `SignedActAsGrant.grant`. A presentation binds this value. */
export function actAsGrantHash(grantBytes: Uint8Array): Uint8Array {
  return new Uint8Array(nodeCrypto.createHash("sha256").update(grantBytes).digest());
}

/** The local-RP form of `GranteeRef`. */
export function localRpGrantee(keyMaterial: ActAsSigningMaterial): GranteeRef {
  return { localRpDescriptorFingerprint: keyMaterial.fingerprint };
}

function prove(keyMaterial: ActAsSigningMaterial, tag: string, payload: Uint8Array): GranteeProof {
  return {
    localRpDescriptor: keyMaterial.descriptor,
    signature: {
      signedByKeyId: keyMaterial.fingerprint,
      signature: signEd25519(envelopeSignatureInput(tag, payload), keyMaterial.signingPrivateKey),
    },
  };
}

function freshNonce(): string {
  return Buffer.from(randomBytes(32)).toString("base64url");
}

/** Sign an `ActAsGrantRequest` with the descriptor signing key. Pure. */
export function signActAsGrantRequest(
  request: ActAsGrantRequest,
  keyMaterial: ActAsSigningMaterial,
): SignedActAsGrantRequest {
  const bytes = generated.toActAsGrantRequestCbor(request);
  return { request: bytes, proof: prove(keyMaterial, ACT_AS_GRANT_REQUEST_TAG, bytes) };
}

/** Sign an `ActAsRefreshRequest` with the descriptor signing key. Pure. */
export function signActAsRefreshRequest(
  request: ActAsRefreshRequest,
  keyMaterial: ActAsSigningMaterial,
): SignedActAsRefreshRequest {
  const bytes = generated.toActAsRefreshRequestCbor(request);
  return { request: bytes, proof: prove(keyMaterial, ACT_AS_REFRESH_REQUEST_TAG, bytes) };
}

/** `base64url-no-pad(CBOR(SignedActAsGrantRequest))`, the `signed_request` query value. */
export function signedActAsGrantRequestToUrlParam(signed: SignedActAsGrantRequest): string {
  return Buffer.from(generated.toSignedActAsGrantRequestCbor(signed)).toString("base64url");
}

function checkOptionalSeconds(name: string, value: number | undefined, min: number): void {
  if (value === undefined) return;
  if (!Number.isSafeInteger(value) || value < min) {
    throw new InvalidInputError(`${name} must be a whole number >= ${min}`);
  }
}

// ---------------------------------------------------------------------
// Begin
// ---------------------------------------------------------------------

export interface BeginActAsConfig {
  keyMaterial: ActAsSigningMaterial;
  /** The user's LinkKeys login or domain. Only the domain is used. */
  userDomain: string;
  /** The audience's `SignedActAsScopeSet`, as CBOR bytes, exactly as the audience sent it. */
  scopeSet: Uint8Array;
  requestedLifetimeSeconds?: number;
  requestedRenewalWindowSeconds?: number;
  /** Where the home domain sends the browser back. Must be `http://` or `https://`. */
  callbackUrl: string;
  now: Date;
  /** DNS seam for browser endpoint discovery. Defaults to `defaultDnsResolver()`. */
  dns?: DnsResolver;
  /** Request window in seconds. Default 300, maximum 900. */
  requestWindowSeconds?: number;
}

/** State to keep between `beginActAs` and `completeActAsCallback`. Plain JSON data. Single-use. */
export interface PendingActAs {
  nonce: string;
  userDomain: string;
  callbackUrl: string;
}

/**
 * Sign an `ActAsGrantRequest` and return the URL that sends the browser to
 * the user's home domain (`/auth/act-as`), plus the pending state. Browser
 * endpoint discovery and fallback are the same as `beginLocalLogin`.
 */
export async function beginActAs(config: BeginActAsConfig): Promise<{
  redirect: { redirectUrl: string };
  pending: PendingActAs;
}> {
  validateCallbackScheme(config.callbackUrl);
  const identity = parseIdentityInput(config.userDomain);
  checkOptionalSeconds("requestedLifetimeSeconds", config.requestedLifetimeSeconds, 1);
  checkOptionalSeconds("requestedRenewalWindowSeconds", config.requestedRenewalWindowSeconds, 0);
  const window = config.requestWindowSeconds ?? DEFAULT_ACT_AS_REQUEST_WINDOW_SECONDS;
  if (!Number.isSafeInteger(window) || window < 1 || window > MAX_ACT_AS_REQUEST_WINDOW_SECONDS) {
    throw new InvalidInputError(`requestWindowSeconds must be 1..${MAX_ACT_AS_REQUEST_WINDOW_SECONDS}`);
  }

  let scopeSet: SignedActAsScopeSet;
  try {
    scopeSet = generated.fromSignedActAsScopeSetCbor(config.scopeSet);
  } catch (e) {
    throw new LocalRpError("decode", `scope set: ${e}`, { cause: e });
  }

  const nonce = freshNonce();
  const request: ActAsGrantRequest = {
    grantee: localRpGrantee(config.keyMaterial),
    scopeSet,
    requestedLifetimeSeconds: config.requestedLifetimeSeconds,
    requestedRenewalWindowSeconds: config.requestedRenewalWindowSeconds,
    callbackUrl: config.callbackUrl,
    nonce,
    requestedAt: formatActAsTime(config.now),
    expiresAt: formatActAsTime(new Date(config.now.getTime() + window * 1000)),
  };
  const signed = signActAsGrantRequest(request, config.keyMaterial);
  const dns = config.dns ?? defaultDnsResolver();
  const redirectUrl = await resolveBrowserEndpoint(
    dns,
    identity.domain,
    BROWSER_ROUTE_ACT_AS,
    signedActAsGrantRequestToUrlParam(signed),
  );
  return {
    redirect: { redirectUrl },
    pending: { nonce, userDomain: identity.domain, callbackUrl: config.callbackUrl },
  };
}

// ---------------------------------------------------------------------
// Callback
// ---------------------------------------------------------------------

/**
 * Read `act_as_grant_id` and `nonce` from the callback. `arrived` is the full
 * callback URL, its query string, or parsed query parameters. The nonce must
 * equal the pending nonce (constant-time compare). Returns the grant id.
 */
export function completeActAsCallback(pending: PendingActAs, arrived: string | URLSearchParams): string {
  let params: URLSearchParams;
  if (typeof arrived !== "string") {
    params = arrived;
  } else if (arrived.includes("://")) {
    params = new URL(arrived).searchParams;
  } else {
    params = new URLSearchParams(arrived.startsWith("?") ? arrived.slice(1) : arrived);
  }
  // A repeated parameter is ambiguous: refuse it rather than pick one.
  if (params.getAll("act_as_grant_id").length > 1 || params.getAll("nonce").length > 1) {
    throw new InvalidInputError("callback repeats an act-as parameter");
  }
  const grantId = params.get("act_as_grant_id");
  const nonce = params.get("nonce");
  if (grantId === null || grantId === "" || nonce === null) {
    throw new LocalRpError("missing-parameter", "callback needs act_as_grant_id and nonce");
  }
  const encoder = new TextEncoder();
  if (!constantTimeEqual(encoder.encode(pending.nonce), encoder.encode(nonce))) {
    throw new LocalRpError("nonce-mismatch");
  }
  return grantId;
}

// ---------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------

export interface RefreshActAsConfig {
  keyMaterial: ActAsSigningMaterial;
  /** The user's home domain (`PendingActAs.userDomain`). */
  userDomain: string;
  grantId: string;
  now: Date;
  /** TCP dial seam. Defaults to `defaultTransport()`. */
  transport?: Transport;
  /** DNS seam. Defaults to `defaultDnsResolver()`. */
  dns?: DnsResolver;
}

/**
 * Fetch the grant, or a renewed grant, with `ActAs/refresh-grant` on the
 * user's home domain. `signed` is true when the home domain made a new
 * signature for this call.
 */
export async function refreshActAsGrant(
  config: RefreshActAsConfig,
): Promise<{ grant: SignedActAsGrant; signed: boolean }> {
  if (config.grantId === "") throw new InvalidInputError("grantId must not be empty");
  const request: ActAsRefreshRequest = {
    grantId: config.grantId,
    grantee: localRpGrantee(config.keyMaterial),
    requestedAt: formatActAsTime(config.now),
    expiresAt: formatActAsTime(new Date(config.now.getTime() + ACT_AS_REFRESH_WINDOW_SECONDS * 1000)),
    nonce: freshNonce(),
  };
  const signed = signActAsRefreshRequest(request, config.keyMaterial);
  const response = await rpcRefreshActAsGrant(
    config.transport ?? defaultTransport(),
    config.dns ?? defaultDnsResolver(),
    config.userDomain,
    signed,
  );
  // The audience checks the grant signature. This only checks that the home
  // domain returned the grant this call asked for, so a confused or hostile
  // server cannot hand this grantee another grant.
  const grant = generated.fromActAsGrantCbor(response.grant.grant);
  if (grant.grantId !== config.grantId) {
    throw new LocalRpError("grant-mismatch", "refresh-grant returned another grant id");
  }
  if (grant.grantee.application !== undefined || grant.grantee.localRpDescriptorFingerprint !== config.keyMaterial.fingerprint) {
    throw new LocalRpError("grant-mismatch", "refresh-grant returned a grant for another grantee");
  }
  if (asciiLower(grant.subjectDomain) !== asciiLower(config.userDomain)) {
    throw new LocalRpError("grant-mismatch", "refresh-grant returned a grant from another subject domain");
  }
  return { grant: response.grant, signed: response.signed };
}

/** ASCII-only lower case, for domain comparison. */
function asciiLower(value: string): string {
  return value.replace(/[A-Z]/g, (c) => c.toLowerCase());
}

// ---------------------------------------------------------------------
// Presentation
// ---------------------------------------------------------------------

export interface PresentActAsConfig {
  grant: SignedActAsGrant;
  /** The audience's `ApplicationRef`. */
  audience: ApplicationRef;
  /** Digest of this call, as the audience's protocol defines it. */
  requestDigest: Uint8Array;
  now: Date;
  /** A fresh nonce for this call. The audience owns replay protection. */
  nonce: Uint8Array;
  keyMaterial: ActAsSigningMaterial;
}

/** Build and sign the `ActAsCredential` for one call to the audience. Pure. */
export function presentActAs(config: PresentActAsConfig): { credential: ActAsCredential; credentialCbor: Uint8Array } {
  const presentation: ActAsPresentation = {
    grantHash: actAsGrantHash(config.grant.grant),
    audience: config.audience,
    requestDigest: config.requestDigest,
    presentedAt: formatActAsTime(config.now),
    nonce: config.nonce,
  };
  const bytes = generated.toActAsPresentationCbor(presentation);
  const credential: ActAsCredential = {
    grant: config.grant,
    presentation: { presentation: bytes, proof: prove(config.keyMaterial, ACT_AS_PRESENTATION_TAG, bytes) },
  };
  return { credential, credentialCbor: generated.toActAsCredentialCbor(credential) };
}
