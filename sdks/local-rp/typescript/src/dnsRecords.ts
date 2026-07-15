// Pure DNS TXT record parsing and key-trust logic, mirroring
// `crates/liblinkkeys/src/dns.rs`'s subset this SDK needs. This module does
// no lookups itself — see `src/dns.ts` for the resolver seam that fetches
// the raw TXT strings this module parses.

import { fingerprint, verifyEd25519 } from "./crypto.ts";
import { encodeCborTuple, text } from "./cborTuple.ts";
import type { DomainPublicKey } from "./generated/types.gen.ts";

/** Default TCP port for the LinkKeys protocol service. */
export const DEFAULT_TCP_PORT = 4987;

/** Maximum length of a single DNS TXT character-string (RFC 1035). */
export const MAX_TXT_STRING_LEN = 255;

export interface LinkKeysRecord {
  fingerprints: string[];
}

export interface LinkKeysApis {
  /** `host:port` for the TCP service, with the default port filled in. */
  tcp?: string;
  /** Full `https://host[:port][/path]` base for the HTTPS API. */
  httpsBase?: string;
}

export type DnsParseErrorCode =
  | "no-linkkeys-record"
  | "missing-version"
  | "unsupported-version"
  | "missing-apis-endpoint"
  | "invalid-format";

export class DnsParseError extends Error {
  readonly code: DnsParseErrorCode;
  constructor(code: DnsParseErrorCode, message?: string) {
    super(message ?? code);
    this.name = "DnsParseError";
    this.code = code;
  }
}

export function linkkeysDnsName(domain: string): string {
  return `_linkkeys.${domain}`;
}

export function linkkeysApisDnsName(domain: string): string {
  return `_linkkeys_apis.${domain}`;
}

function requireLk1Version(parts: readonly string[]): void {
  const versionPart = parts.find((p) => p.startsWith("v="));
  if (!versionPart) {
    throw new DnsParseError("missing-version");
  }
  const version = versionPart.slice(2);
  if (version !== "lk1") {
    throw new DnsParseError("unsupported-version", version);
  }
}

/** Parse a single `_linkkeys` TXT record string. Errors if it isn't a LinkKeys v1 record. */
export function parseLinkkeysTxt(txt: string): LinkKeysRecord {
  const parts = txt.split(/\s+/).filter((p) => p.length > 0);
  requireLk1Version(parts);
  const fingerprints = parts.filter((p) => p.startsWith("fp=")).map((p) => p.slice(3));
  return { fingerprints };
}

function normalizeTcpEndpoint(value: string): string {
  if (value.length === 0 || value.includes(":")) {
    return value;
  }
  return `${value}:${DEFAULT_TCP_PORT}`;
}

/** Parse a single `_linkkeys_apis` TXT record string. Errors if it isn't a LinkKeys v1 record or carries no endpoint. */
export function parseLinkkeysApisTxt(txt: string): LinkKeysApis {
  const parts = txt.split(/\s+/).filter((p) => p.length > 0);
  requireLk1Version(parts);

  const tcpPart = parts.find((p) => p.startsWith("tcp="));
  const tcpRaw = tcpPart ? normalizeTcpEndpoint(tcpPart.slice(4)) : undefined;
  const tcp = tcpRaw && tcpRaw.length > 0 ? tcpRaw : undefined;

  const httpsPart = parts.find((p) => p.startsWith("https="));
  const httpsRaw = httpsPart ? httpsPart.slice(6) : undefined;
  const httpsBase = httpsRaw && httpsRaw.length > 0 ? `https://${httpsRaw}` : undefined;

  if (tcp === undefined && httpsBase === undefined) {
    throw new DnsParseError("missing-apis-endpoint");
  }

  return { tcp, httpsBase };
}

/** True if `fp` is a syntactically valid key fingerprint: 64 hex chars (a SHA-256 digest). Case-insensitive. */
export function isValidFingerprint(fp: string): boolean {
  return fp.length === 64 && /^[0-9a-fA-F]{64}$/.test(fp);
}

/**
 * Pin fetched keys to the DNS-published fingerprint set. Recomputes
 * `fingerprint(publicKey)` for each candidate (never trusting the wire
 * `fingerprint` field, which is attacker-controlled) and keeps only keys
 * whose recomputed fingerprint is a member of `pinned`.
 */
export function pinKeysToFingerprints(
  keys: readonly DomainPublicKey[],
  pinned: readonly string[],
): DomainPublicKey[] {
  const pinnedLower = new Set(
    pinned.filter((f) => isValidFingerprint(f)).map((f) => f.toLowerCase()),
  );
  return keys.filter((k) => pinnedLower.has(fingerprint(k.publicKey).toLowerCase()));
}

const KEY_VOUCH_TAG = "linkkeys-key-vouch-v1";

/** Canonical bytes a signing key signs to vouch for an encryption key. */
export function keyVouchPayload(encFingerprint: string, encExpiresAt: string): Uint8Array {
  return encodeCborTuple([text(KEY_VOUCH_TAG), text(encFingerprint), text(encExpiresAt)]);
}

function signingKeyValidity(key: DomainPublicKey, now: Date): "valid" | "revoked" | "expired" {
  if (key.revokedAt !== undefined) return "revoked";
  const expires = new Date(key.expiresAt);
  if (Number.isNaN(expires.getTime())) return "expired";
  return now.getTime() > expires.getTime() ? "expired" : "valid";
}

/** Verify that `signingKey` vouches for `encKey`. The wire `fingerprint` field is never trusted — it is recomputed. */
export function verifyKeyVouch(
  encKey: DomainPublicKey,
  signingKey: DomainPublicKey,
  now: Date = new Date(),
): boolean {
  if (encKey.signedByKeyId !== signingKey.keyId) return false;
  if (signingKeyValidity(signingKey, now) !== "valid") return false;
  if (signingKey.algorithm !== "ed25519") return false;
  const sig = encKey.keySignature;
  if (!sig) return false;
  const recomputedFp = fingerprint(encKey.publicKey);
  const payload = keyVouchPayload(recomputedFp, encKey.expiresAt);
  return verifyEd25519(payload, sig, signingKey.publicKey);
}

/**
 * Establish the trusted key set from a fetched key list and the DNS-pinned
 * fingerprint set: signing keys are pinned directly; encryption keys are
 * trusted only when a pinned signing key vouches for them. An empty result
 * means "no trustworthy keys" — callers MUST fail closed.
 */
export function trustKeys(
  keys: readonly DomainPublicKey[],
  pinned: readonly string[],
  now: Date = new Date(),
): DomainPublicKey[] {
  const signing = keys.filter((k) => k.keyUsage === "sign");
  const pinnedSigning = pinKeysToFingerprints(signing, pinned);

  const trusted = [...pinnedSigning];
  for (const k of keys.filter((k) => k.keyUsage === "encrypt")) {
    if (pinnedSigning.some((sk) => verifyKeyVouch(k, sk, now))) {
      trusted.push(k);
    }
  }
  return trusted;
}
