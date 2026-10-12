import type { BrowserAuthorizationInspectResponse, BrowserConsentClaim } from "./generated/types.gen";
import { CsilStatus, CsilTransportError } from "./transport";
import { has, plural, t } from "./i18n";

export function authenticationFailed(error: unknown): boolean {
  return error instanceof CsilTransportError
    && (error.status === CsilStatus.unauthenticated || error.status === CsilStatus.forbidden);
}

export function serviceMessage(error: unknown, fallback: string): string {
  return error instanceof CsilTransportError && error.status === CsilStatus.forbidden
    ? t("app.error.no_permission")
    : fallback;
}

export function loginFailureMessage(error: unknown): string {
  if (error instanceof CsilTransportError && error.message.toLowerCase().includes("too many")) {
    return t("app.login.too_many");
  }
  return error instanceof CsilTransportError
    && (error.status === CsilStatus.unauthenticated || error.status === CsilStatus.forbidden)
    ? t("app.login.incorrect")
    : t("app.login.connection_failed");
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
  if (rateLimited(error)) return t("app.password.too_many");
  return error instanceof CsilTransportError && error.status === CsilStatus.forbidden
    ? t("app.password.current_incorrect")
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
  if (rateLimited(error)) return t("app.verify_contact.too_many");
  return error instanceof CsilTransportError
    && (error.status === CsilStatus.malformedEnvelope || error.status === CsilStatus.forbidden)
    ? t("app.verify_contact.link_invalid")
    : t("app.verify_contact.connection_failed");
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
  if (rateLimited(error)) return t("app.recovery.too_many");
  return transportFailed(error)
    ? t("app.recovery.connection_failed")
    : t("app.recovery.link_invalid");
}

export function recoveryCompletionFailureMessage(error: unknown): string {
  return rateLimited(error)
    ? t("app.recovery.too_many")
    : serviceMessage(error, t("app.recovery.reset_failed"));
}

export function authorizationRequestIsTerminal(error: unknown): boolean {
  if (!(error instanceof CsilTransportError) || error.status !== CsilStatus.malformedEnvelope) return false;
  const detail = error.message.toLowerCase();
  return detail.includes("login request")
    || detail.includes("callback url")
    || detail.includes("authentication assurance request");
}

export function passwordLengthError(value: string, minCharacters: number, maxBytes: number): string {
  if ([...value].length < minCharacters) return plural("app.password.min_length", minCharacters);
  if (new TextEncoder().encode(value).length > maxBytes) return t("app.password.too_long");
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
  if (seconds <= 0) return t("app.duration.none");
  const units: [number, string][] = [[86_400, "day"], [3_600, "hour"], [60, "minute"], [1, "second"]];
  for (const [size, name] of units) {
    if (seconds % size === 0) return plural(`app.duration.${name}`, seconds / size);
  }
  return plural("app.duration.second", seconds);
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
export function applicationLabel(reference: { applicationId: string; subjectDomain: string } | undefined, fallback = t("app.application.fallback")): string {
  return reference ? t("app.application.label", { application: reference.applicationId, domain: reference.subjectDomain }) : fallback;
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
  return party.domain ?? party.localRpName ?? t("app.party.unknown");
}

/** Plain sentences for a party's trust signals, strongest first. */
export function partyTrustNotes(party: { ownDomain: boolean; userHasHistory: boolean; domainKeyPinned: boolean; operatorTrusted: boolean; domain?: string }): string[] {
  const notes: string[] = [];
  if (party.ownDomain) notes.push(t("app.party.trust.own_domain"));
  if (party.userHasHistory) notes.push(t("app.party.trust.history"));
  if (party.domain && party.domainKeyPinned && !party.ownDomain) notes.push(t("app.party.trust.pinned"));
  if (party.operatorTrusted) notes.push(party.domain ? t("app.party.trust.operator_domain") : t("app.party.trust.operator_application"));
  if (notes.length === 0) notes.push(t("app.party.trust.new"));
  return notes;
}

/** The headline name of a party: the application and its domain, always in the
 * same shape, so two applications on one domain read differently. */
export function partyHeadline(party: { domain?: string; applicationId?: string; localRpName?: string }): string {
  if (party.applicationId && party.domain) return t("app.party.headline", { application: party.applicationId, domain: party.domain });
  return party.localRpName ?? party.domain ?? t("app.party.unknown");
}

/** The site address a user types, reduced to a bare domain. Accepts a pasted
 * web address ("https://Example.com/path") and returns "" when the text is not
 * a usable domain name. */
export function siteDomain(text: string): string {
  const host = text.trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, "").split(/[/?#]/, 1)[0].replace(/\.$/, "");
  const label = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  const labels = host.split(".");
  return host.length <= 253 && labels.length > 1 && labels.every((part) => label.test(part)) ? host : "";
}

/** The details a user asks another site to confirm, from a comma- or
 * line-separated list. Empty entries and repeats are removed. */
export function confirmationDetails(text: string): string[] {
  return [...new Set(text.split(/[,\n]/).map((part) => part.trim()).filter(Boolean))];
}

/** Base64url without padding: the text form other sites accept for a
 * confirmation request. */
export function base64UrlUnpadded(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** What a consent screen sends: forced claims plus the person's selected
 * ones, and inline values for authorized claims the person has no value for.
 * `oversized` is the first inline value longer than its claim type allows. */
export function consentDecision(claims: BrowserConsentClaim[], selected: Record<string, boolean>, values: Record<string, string>): { authorizedClaims: string[]; claimTypesToSet: string[]; claimValuesToSet: string[]; oversized?: BrowserConsentClaim } {
  const authorizedClaims = claims.filter((claim) => claim.policy === "forced_allow" || (claim.policy === "user" && selected[claim.claimType])).map((claim) => claim.claimType);
  const entries = claims.filter((claim) => authorizedClaims.includes(claim.claimType) && !claim.available && values[claim.claimType]?.trim());
  return {
    authorizedClaims,
    claimTypesToSet: entries.map((claim) => claim.claimType),
    claimValuesToSet: entries.map((claim) => values[claim.claimType].trim()),
    oversized: entries.find((claim) => claimValueTooLong(values[claim.claimType].trim(), claim.maxBytes)),
  };
}

/** The person-facing text for a refusal reason code (`/app/error?reason=`
 * and the message of a refused local-app sign-in call). */
export function reasonText(code: string): string {
  const key = `app.error.reason.${code}`;
  return /^[a-z_]+$/.test(code) && has(key) ? t(key) : t("app.error.reason.unknown");
}

/** The text for a failed local-app sign-in call: its reason code when the
 * server sent one, otherwise a connection message. */
export function localRpFailureMessage(error: unknown): string {
  return error instanceof CsilTransportError && /^[a-z_]+$/.test(error.message)
    ? reasonText(error.message)
    : t("app.error.reason.connection");
}
