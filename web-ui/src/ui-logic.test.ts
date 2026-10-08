import { describe, expect, it } from "vitest";
import type { BrowserAuthorizationInspectResponse, BrowserConsentClaim } from "./generated/types.gen";
import { CsilStatus, CsilTransportError } from "./transport";
import {
  authenticationFailed,
  authorizationHandoff,
  authorizationLoginPath,
  authorizationRequestIsTerminal,
  claimValueTooLong,
  cleanupOnce,
  currentPasswordMessage,
  hasBlockedRequiredClaim,
  inputType,
  loginFailureMessage,
  passwordLengthError,
  passwordManagerUsername,
  recoveryCompletionFailureMessage,
  recoveryLinkExpired,
  recoveryValidationFailureMessage,
  standingAuthorization,
  transportFailed,
  verificationFailureMessage,
  withLoginContext,
} from "./ui-logic";

const claim = (values: Partial<BrowserConsentClaim>): BrowserConsentClaim => ({
  claimType: "display_name",
  label: "Display name",
  datatype: "text",
  maxBytes: 254,
  requiresApproval: false,
  required: false,
  available: true,
  defaultGranted: false,
  policy: "user",
  userSettable: true,
  ...values,
});

describe("browser UI decisions", () => {
  it("treats only authentication statuses as a lost session", () => {
    expect(authenticationFailed(new CsilTransportError(CsilStatus.unauthenticated, ""))).toBe(true);
    expect(authenticationFailed(new CsilTransportError(CsilStatus.forbidden, ""))).toBe(true);
    expect(authenticationFailed(new CsilTransportError(CsilStatus.malformedEnvelope, ""))).toBe(false);
  });

  it("blocks consent when a required detail cannot be supplied", () => {
    expect(hasBlockedRequiredClaim([claim({ required: true, available: false, userSettable: false })])).toBe(true);
    expect(hasBlockedRequiredClaim([claim({ required: true, policy: "forced_deny" })])).toBe(true);
    expect(hasBlockedRequiredClaim([claim({ required: true, available: false, userSettable: true })])).toBe(false);
  });

  it("uses a standing grant only after the first claim disclosure", () => {
    const firstDisclosure = {
      relyingParty: "app.example",
      claims: [claim({ defaultGranted: true, policy: "forced_allow" })],
    } as BrowserAuthorizationInspectResponse;
    expect(standingAuthorization(firstDisclosure)).toBeUndefined();

    expect(standingAuthorization({
      ...firstDisclosure,
      alreadyConsented: true,
      authorizedClaims: ["display_name"],
    })).toEqual(["display_name"]);
  });

  it("uses useful controls for common claim datatypes", () => {
    expect(inputType("email")).toBe("email");
    expect(inputType("url")).toBe("url");
    expect(inputType("date")).toBe("date");
    expect(inputType("integer")).toBe("number");
  });

  it("does not give an email recovery address to the password manager as a username", () => {
    expect(passwordManagerUsername("person@example.test", "id.example.test")).toBe("");
    expect(passwordManagerUsername("alice", "id.example.test")).toBe("alice");
    expect(passwordManagerUsername("alice@ID.EXAMPLE.TEST", "id.example.test"))
      .toBe("alice@ID.EXAMPLE.TEST");
  });

  it("distinguishes invalid links from connection failures", () => {
    expect(verificationFailureMessage(new CsilTransportError(CsilStatus.malformedEnvelope, ""))).toContain("invalid");
    expect(verificationFailureMessage(new TypeError("offline"))).toContain("connection");
  });

  it("uses a useful message when the current password is wrong", () => {
    expect(currentPasswordMessage(new CsilTransportError(CsilStatus.forbidden, ""), "fallback"))
      .toBe("The current password is incorrect.");
  });

  it("does not describe a wrong login as a permission problem", () => {
    expect(loginFailureMessage(new CsilTransportError(CsilStatus.forbidden, "")))
      .toBe("The username or password is incorrect.");
    expect(loginFailureMessage(new CsilTransportError(CsilStatus.forbidden, "Too many attempts")))
      .toContain("Wait");
  });

  it("preserves the username hint when authorization needs login", () => {
    expect(authorizationLoginPath("househansmann@catalystlinkkeys.com"))
      .toBe("/app/login?next=/app/consent&username=househansmann%40catalystlinkkeys.com");
    expect(authorizationLoginPath(""))
      .toBe("/app/login?next=/app/consent");
    expect(authorizationHandoff(
      "?username=househansmann%40catalystlinkkeys.com",
      "#request=signed%2Brequest",
      false,
    )).toEqual({
      signedRequest: "signed+request",
      path: "/app/login?next=/app/consent&username=househansmann%40catalystlinkkeys.com",
    });
  });

  it("preserves login context through password recovery", () => {
    expect(withLoginContext(
      "/app/password/request",
      "/app/consent",
      "househansmann@catalystlinkkeys.com",
    )).toBe(
      "/app/password/request?next=%2Fapp%2Fconsent&username=househansmann%40catalystlinkkeys.com",
    );
  });

  it("treats service outages as retryable link failures", () => {
    expect(transportFailed(new CsilTransportError(503, "Unavailable"))).toBe(true);
    expect(transportFailed(new CsilTransportError(CsilStatus.malformedEnvelope, "Invalid"))).toBe(false);
    expect(transportFailed(new CsilTransportError(CsilStatus.forbidden, "Too many attempts"))).toBe(true);
    expect(recoveryValidationFailureMessage(new CsilTransportError(CsilStatus.forbidden, "Too many attempts"))).toContain("Wait");
    expect(recoveryCompletionFailureMessage(new CsilTransportError(CsilStatus.forbidden, "Too many attempts"))).toContain("Wait");
    expect(currentPasswordMessage(new CsilTransportError(CsilStatus.malformedEnvelope, "Too many attempts"), "fallback")).toContain("Wait");
  });

  it("identifies terminal recovery and authorization requests", () => {
    expect(recoveryLinkExpired(new CsilTransportError(CsilStatus.malformedEnvelope, "The password recovery link is invalid or expired"))).toBe(true);
    expect(recoveryLinkExpired(new CsilTransportError(CsilStatus.malformedEnvelope, "Use a longer password"))).toBe(false);
    expect(authorizationRequestIsTerminal(new CsilTransportError(CsilStatus.malformedEnvelope, "The login request has expired"))).toBe(true);
    expect(authorizationRequestIsTerminal(new CsilTransportError(CsilStatus.malformedEnvelope, "A profile value is invalid"))).toBe(false);
  });

  it("uses characters for the password minimum and bytes for its safety limit", () => {
    expect(passwordLengthError("🔑🔑🔑", 3, 12)).toBe("");
    expect(passwordLengthError("🔑🔑🔑", 4, 12)).toContain("4 characters");
    expect(passwordLengthError("🔑🔑🔑", 3, 11)).toBe("The password is too long.");
  });

  it("checks the encoded size of claim values", () => {
    expect(claimValueTooLong("é", 1)).toBe(true);
    expect(claimValueTooLong("é", 2)).toBe(false);
  });

  it("runs extension cleanup only once", () => {
    let calls = 0;
    const cleanup = cleanupOnce();
    cleanup(() => { calls += 1; });
    cleanup(() => { calls += 1; });
    expect(calls).toBe(1);
  });
});

describe("act-as helpers", () => {
  it("takes the signed request from the hand-off fragment", async () => {
    const { actAsHandoff } = await import("./ui-logic");
    expect(actAsHandoff("#request=abc", true)).toEqual({ signedRequest: "abc", path: "/app/act-as/consent" });
    expect(actAsHandoff("#request=abc", false)?.path).toBe("/app/login?next=/app/act-as/consent");
    expect(actAsHandoff("", true)).toBeUndefined();
  });

  it("describes durations in whole units", async () => {
    const { describeDuration } = await import("./ui-logic");
    expect(describeDuration(0)).toBe("none");
    expect(describeDuration(3600)).toBe("1 hour");
    expect(describeDuration(7200)).toBe("2 hours");
    expect(describeDuration(90)).toBe("90 seconds");
    expect(describeDuration(2_592_000)).toBe("30 days");
  });

  it("never offers a duration above the maximum", async () => {
    const { durationChoices } = await import("./ui-logic");
    const choices = durationChoices(1800, 3600, false);
    expect(Math.max(...choices)).toBe(3600);
    expect(choices).toContain(1800);
    expect(choices).not.toContain(0);
    expect(durationChoices(0, 0, true)).toEqual([0]);
    expect(durationChoices(600, 600, false)).toEqual([300, 600]);
  });

  it("classifies grants for the account list", async () => {
    const { actAsGrantState } = await import("./ui-logic");
    const now = new Date("2026-10-06T12:00:00Z");
    expect(actAsGrantState({ expiresAt: "2026-10-06T13:00:00Z", renewableUntil: "2026-10-06T13:00:00Z" }, now)).toBe("active");
    expect(actAsGrantState({ expiresAt: "2026-10-06T11:00:00Z", renewableUntil: "2026-10-06T11:00:00Z" }, now)).toBe("expired");
    // An expired grant cannot be renewed, so an open renewal window does not keep it active.
    expect(actAsGrantState({ expiresAt: "2026-10-06T11:00:00Z", renewableUntil: "2026-10-07T11:00:00Z" }, now)).toBe("expired");
    expect(actAsGrantState({ expiresAt: "2026-10-06T13:00:00Z", renewableUntil: "2026-10-06T13:00:00Z", revokedAt: "2026-10-06T11:30:00Z" }, now)).toBe("revoked");
  });
});

describe("act-as parties", () => {
  it("names the domain first and warns about a new party", async () => {
    const { partyTitle, partyTrustNotes } = await import("./ui-logic");
    const base = { ownDomain: false, userHasHistory: false, domainKeyPinned: false, operatorTrusted: false };
    expect(partyTitle({ domain: "drive.example", localRpName: "x" })).toBe("drive.example");
    expect(partyTitle({ localRpName: "Desk App" })).toBe("Desk App");
    expect(partyTrustNotes({ ...base, domain: "drive.example" })).toEqual(["New to you and to this site. Check the name carefully."]);
    expect(partyTrustNotes({ ...base, domain: "drive.example", userHasHistory: true, domainKeyPinned: true })).toEqual(["You have used this before.", "This site has seen this domain before."]);
    expect(partyTrustNotes({ ...base, operatorTrusted: true })).toEqual(["This site's operator approved this application."]);
  });
});
