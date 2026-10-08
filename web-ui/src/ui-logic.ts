import type { BrowserAuthorizationInspectResponse, BrowserConsentClaim } from "./generated/types.gen";
import { CsilStatus, CsilTransportError } from "./transport";

export function authenticationFailed(error: unknown): boolean {
  return error instanceof CsilTransportError
    && (error.status === CsilStatus.unauthenticated || error.status === CsilStatus.forbidden);
}

export function serviceMessage(error: unknown, fallback: string): string {
  return error instanceof CsilTransportError && error.status === CsilStatus.forbidden
    ? "You do not have permission to do that."
    : fallback;
}

export function loginFailureMessage(error: unknown): string {
  if (error instanceof CsilTransportError && error.message.toLowerCase().includes("too many")) {
    return "Too many sign-in attempts. Wait and try again.";
  }
  return error instanceof CsilTransportError
    && (error.status === CsilStatus.unauthenticated || error.status === CsilStatus.forbidden)
    ? "The username or password is incorrect."
    : "Could not sign in. Check your connection and try again.";
}

export function authorizationLoginPath(username: string): string {
  const base = "/app/login?next=/app/consent";
  return username ? `${base}&username=${encodeURIComponent(username)}` : base;
}

export function authorizationHandoff(
  search: string,
  fragment: string,
  hasSession: boolean,
): { signedRequest: string; path: string } | undefined {
  const signedRequest = new URLSearchParams(fragment.replace(/^#/, "")).get("request");
  if (!signedRequest) return undefined;
  const username = new URLSearchParams(search).get("username") ?? "";
  return {
    signedRequest,
    path: hasSession ? "/app/consent" : authorizationLoginPath(username),
  };
}

export function withLoginContext(path: string, next: string, username: string): string {
  const parameters: string[] = [];
  if (next) parameters.push(`next=${encodeURIComponent(next)}`);
  if (username) parameters.push(`username=${encodeURIComponent(username)}`);
  return parameters.length ? `${path}?${parameters.join("&")}` : path;
}

export function currentPasswordMessage(error: unknown, fallback: string): string {
  if (rateLimited(error)) return "Too many password attempts. Wait and try again.";
  return error instanceof CsilTransportError && error.status === CsilStatus.forbidden
    ? "The current password is incorrect."
    : fallback;
}

export function inputType(datatype: string | undefined): "text" | "email" | "url" | "date" | "number" {
  if (datatype === "email") return "email";
  if (datatype === "url") return "url";
  if (datatype === "date") return "date";
  if (datatype === "int" || datatype === "integer" || datatype === "number") return "number";
  return "text";
}

export function hasBlockedRequiredClaim(claims: BrowserConsentClaim[]): boolean {
  return claims.some((claim) => claim.required
    && (claim.policy === "forced_deny" || (!claim.available && !claim.userSettable)));
}

export function standingAuthorization(context: BrowserAuthorizationInspectResponse): string[] | undefined {
  return context.alreadyConsented === true && context.authorizedClaims
    ? context.authorizedClaims
    : undefined;
}

export function verificationFailureMessage(error: unknown): string {
  if (rateLimited(error)) return "Too many attempts. Wait and try again.";
  return error instanceof CsilTransportError
    && (error.status === CsilStatus.malformedEnvelope || error.status === CsilStatus.forbidden)
    ? "This link is invalid, expired, or belongs to another account. Sign in to the account that requested it, or ask for a new message."
    : "LinkKeys could not check this link. Check your connection and try again.";
}

export function passwordManagerUsername(identifier: string, domain: string): string {
  const value = identifier.trim();
  const parts = value.split("@");
  if (parts.length === 1) return value;
  return parts.length === 2
    && parts[0] !== ""
    && parts[1].toLowerCase() === domain.toLowerCase()
    ? value
    : "";
}

export function transportFailed(error: unknown): boolean {
  if (rateLimited(error)) return true;
  return !(error instanceof CsilTransportError)
    || (error.status !== CsilStatus.malformedEnvelope && error.status !== CsilStatus.forbidden);
}

export function rateLimited(error: unknown): boolean {
  return error instanceof CsilTransportError
    && error.message.toLowerCase().includes("too many");
}

export function recoveryLinkExpired(error: unknown): boolean {
  if (!(error instanceof CsilTransportError) || error.status !== CsilStatus.malformedEnvelope) return false;
  const detail = error.message.toLowerCase();
  return detail.includes("recovery link") && (detail.includes("invalid") || detail.includes("expired"));
}

export function recoveryValidationFailureMessage(error: unknown): string {
  if (rateLimited(error)) return "Too many recovery attempts. Wait and try again.";
  return transportFailed(error)
    ? "LinkKeys could not check this recovery link. Check your connection and try again."
    : "This recovery link is invalid or expired.";
}

export function recoveryCompletionFailureMessage(error: unknown): string {
  return rateLimited(error)
    ? "Too many recovery attempts. Wait and try again."
    : serviceMessage(error, "Could not reset your password.");
}

export function authorizationRequestIsTerminal(error: unknown): boolean {
  if (!(error instanceof CsilTransportError) || error.status !== CsilStatus.malformedEnvelope) return false;
  const detail = error.message.toLowerCase();
  return detail.includes("login request")
    || detail.includes("callback url")
    || detail.includes("authentication assurance request");
}

export function passwordLengthError(value: string, minCharacters: number, maxBytes: number): string {
  if ([...value].length < minCharacters) return `Use at least ${minCharacters} characters.`;
  if (new TextEncoder().encode(value).length > maxBytes) return "The password is too long.";
  return "";
}

export function claimValueTooLong(value: string, maxBytes: number): boolean {
  return new TextEncoder().encode(value).length > maxBytes;
}

export function cleanupOnce(): (cleanup: void | (() => void)) => void {
  let cleaned = false;
  return (cleanup) => {
    if (cleaned || !cleanup) return;
    cleaned = true;
    cleanup();
  };
}

// ---------------------------------------------------------------------------
// Act-as grants
// ---------------------------------------------------------------------------

export const actAsRequestKey = "linkkeys-act-as-request";

/** Takes the signed request from the `/app/act-as#request=` hand-off. */
export function actAsHandoff(fragment: string, hasSession: boolean): { signedRequest: string; path: string } | undefined {
  const signedRequest = new URLSearchParams(fragment.replace(/^#/, "")).get("request");
  if (!signedRequest) return undefined;
  return { signedRequest, path: hasSession ? "/app/act-as/consent" : "/app/login?next=/app/act-as/consent" };
}

/** A whole-unit, human description of a number of seconds. */
export function describeDuration(seconds: number): string {
  if (seconds <= 0) return "none";
  const units: [number, string][] = [[86_400, "day"], [3_600, "hour"], [60, "minute"], [1, "second"]];
  for (const [size, name] of units) {
    if (seconds % size === 0) {
      const count = seconds / size;
      return `${count} ${name}${count === 1 ? "" : "s"}`;
    }
  }
  return `${seconds} seconds`;
}

/** Choices for a duration field: common steps up to the maximum, plus the
 * default and the maximum themselves. Never above the maximum. */
export function durationChoices(defaultSeconds: number, maxSeconds: number, allowZero: boolean): number[] {
  const steps = [300, 900, 1_800, 3_600, 4 * 3_600, 8 * 3_600, 86_400, 7 * 86_400, 30 * 86_400];
  const values = new Set<number>(steps.filter((s) => s <= maxSeconds));
  if (allowZero) values.add(0);
  if (defaultSeconds >= 0 && defaultSeconds <= maxSeconds) values.add(defaultSeconds);
  if (maxSeconds > 0) values.add(maxSeconds);
  return [...values].filter((v) => allowZero || v > 0).sort((a, b) => a - b);
}

/** One line that names an application reference for a person. */
export function applicationLabel(reference: { applicationId: string; subjectDomain: string } | undefined, fallback = "an application"): string {
  return reference ? `${reference.applicationId} (${reference.subjectDomain})` : fallback;
}

/** The state of a grant in the user's list. The home domain cannot renew a
 * grant after its current expiry, so a renewal window that is still open
 * does not keep an expired grant active. */
export function actAsGrantState(grant: { expiresAt: string; revokedAt?: string }, now: Date): "revoked" | "expired" | "active" {
  if (grant.revokedAt) return "revoked";
  return Date.parse(grant.expiresAt) <= now.getTime() ? "expired" : "active";
}

/** The short name a person reads first for one consent-screen party. */
export function partyTitle(party: { domain?: string; localRpName?: string }): string {
  return party.domain ?? party.localRpName ?? "An application";
}

/** Plain sentences for a party's trust signals, strongest first. */
export function partyTrustNotes(party: { ownDomain: boolean; userHasHistory: boolean; domainKeyPinned: boolean; operatorTrusted: boolean; domain?: string }): string[] {
  const notes: string[] = [];
  if (party.ownDomain) notes.push("This is this site's own domain.");
  if (party.userHasHistory) notes.push("You have used this before.");
  if (party.domain && party.domainKeyPinned && !party.ownDomain) notes.push("This site has seen this domain before.");
  if (party.operatorTrusted) notes.push(party.domain ? "This site's operator trusts this domain." : "This site's operator approved this application.");
  if (notes.length === 0) notes.push("New to you and to this site. Check the name carefully.");
  return notes;
}
