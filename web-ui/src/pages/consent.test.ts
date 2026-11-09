// @vitest-environment happy-dom
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { defineControls } from "@catalystcommunity/controls";
import type { BrowserActAsInspectResponse, BrowserConsentClaim, GetUiConfigurationResponse } from "../generated/types.gen";
import type { PageProps } from "../shared";
import { t } from "../i18n";
import { actAsConsentPage, authorizeGatewayPage, consentPage } from "./consent";

const api = vi.hoisted(() => ({
  browserAuthorization: { inspect: vi.fn(), complete: vi.fn(), inspectActAs: vi.fn(), completeActAs: vi.fn() },
}));
vi.mock("../transport", async (original) => ({ ...(await original<typeof import("../transport")>()), api }));

const configuration = { domain: "example.test", capabilities: [] } as unknown as GetUiConfigurationResponse;

function context(): PageProps {
  return { navigate: vi.fn(), configuration, refreshSession: vi.fn(async () => {}) };
}

async function settle(): Promise<void> {
  for (let i = 0; i < 5; i += 1) await new Promise((resolve) => setTimeout(resolve, 0));
}

function mount(page: Element): Element {
  document.body.replaceChildren(page);
  return page;
}

function claim(overrides: Partial<BrowserConsentClaim>): BrowserConsentClaim {
  return { claimType: "email", label: "Email", datatype: "string", required: false, available: true, defaultGranted: false, policy: "user", userSettable: false, maxBytes: 100, requiresApproval: false, ...overrides };
}

/** Select a check box as a person does: the click goes to its input. */
function toggle(box: ZestCheckBox): void {
  box.querySelector("input")!.click();
}

let assign: ReturnType<typeof vi.fn>;

beforeAll(() => defineControls());

beforeEach(() => {
  vi.clearAllMocks();
  sessionStorage.clear();
  window.history.replaceState({}, "", "/app/consent");
  assign = vi.fn();
  vi.spyOn(window.location, "assign").mockImplementation(assign);
});

afterEach(() => vi.restoreAllMocks());

describe("consent page", () => {
  const claims = [
    claim({ claimType: "name", label: "Name", policy: "forced_allow" }),
    claim({ claimType: "phone", label: "Phone", available: false, userSettable: true }),
    claim({ claimType: "adult", label: "Adult", datatype: "bool", available: false, userSettable: true, defaultGranted: true }),
    claim({ claimType: "secret", label: "Secret", policy: "forced_deny" }),
  ];

  it("follows the claim policies and releases the chosen claims", async () => {
    sessionStorage.setItem("linkkeys-authorization-request", "signed");
    api.browserAuthorization.inspect.mockResolvedValue({ relyingParty: "app.test", claims });
    api.browserAuthorization.complete.mockResolvedValue({ redirectUrl: "https://app.test/done" });
    const page = mount(consentPage(context()));
    await settle();
    expect(api.browserAuthorization.inspect).toHaveBeenCalledWith({ signedRequest: "signed" });
    const rows = [...page.querySelectorAll<HTMLElement>(".consent-claim")];
    const box = (row: HTMLElement) => row.querySelector<ZestCheckBox>("check-box")!;
    expect(rows).toHaveLength(4);
    expect(box(rows[0]).checked).toBe(true);
    expect(box(rows[0]).disabled).toBe(true);
    expect(box(rows[1]).disabled).toBe(false);
    expect(box(rows[3]).disabled).toBe(true);
    // A value field shows only for a released claim that the user can set.
    expect(rows[1].querySelector("text-field")).toBeNull();
    const adult = rows[2].querySelector<ZestComboBox>("combo-box")!;
    expect(adult.options).toHaveLength(3);

    const otherRow = rows[2].firstElementChild;
    toggle(box(rows[1]));
    expect(box(rows[1]).checked).toBe(true);
    const phone = rows[1].querySelector<ZestTextField>("text-field")!;
    expect(phone).not.toBeNull();
    expect(rows[2].firstElementChild).toBe(otherRow);
    phone.value = "555-0100";
    phone.dispatchEvent(new Event("input", { bubbles: true }));

    page.querySelector("form")!.dispatchEvent(new Event("submit", { cancelable: true }));
    await settle();
    expect(api.browserAuthorization.complete).toHaveBeenCalledWith({ signedRequest: "signed", authorizedClaims: ["name", "phone", "adult"], claimTypesToSet: ["phone"], claimValuesToSet: ["555-0100"] });
    expect(assign).toHaveBeenCalledWith("https://app.test/done");
    expect(sessionStorage.getItem("linkkeys-authorization-request")).toBeNull();
  });

  it("disables the row controls and shows the error from a failed completion", async () => {
    sessionStorage.setItem("linkkeys-authorization-request", "signed");
    api.browserAuthorization.inspect.mockResolvedValue({ relyingParty: "app.test", claims });
    let fail!: (error: Error) => void;
    api.browserAuthorization.complete.mockReturnValue(new Promise((_, reject) => { fail = reject; }));
    const page = mount(consentPage(context()));
    await settle();
    const form = page.querySelector("form")!;
    form.dispatchEvent(new Event("submit", { cancelable: true }));
    const phoneBox = page.querySelectorAll<ZestCheckBox>("check-box")[1];
    expect(form.getAttribute("aria-busy")).toBe("true");
    expect(phoneBox.disabled).toBe(true);
    fail(new Error("Server said no"));
    await settle();
    expect(form.querySelector('[role="alert"]')!.textContent).toBe(t("app.consent.complete_failed"));
    expect(phoneBox.disabled).toBe(false);
    expect(assign).not.toHaveBeenCalled();
  });

  it("shows the access policy block", async () => {
    sessionStorage.setItem("linkkeys-authorization-request", "signed");
    api.browserAuthorization.inspect.mockResolvedValue({ relyingParty: "app.test", claims: [], accessDenied: { domain: "app.test", messages: ["Ask IT."] } });
    const page = mount(consentPage(context()));
    await settle();
    expect(page.querySelector("h1")!.textContent).toBe(t("app.access_blocked.title"));
    expect(page.textContent).toContain("Ask IT.");
    expect(sessionStorage.getItem("linkkeys-authorization-request")).toBeNull();
  });

  it("stops with an alert without a request", async () => {
    const page = mount(consentPage(context()));
    await settle();
    expect(page.querySelector('[role="alert"]')!.textContent).toBe(t("app.consent.missing"));
    expect(api.browserAuthorization.inspect).not.toHaveBeenCalled();
  });
});

describe("authorize gateway", () => {
  it("explains a link with no request", async () => {
    window.history.replaceState({}, "", "/app/authorize");
    const page = mount(authorizeGatewayPage(context()));
    await settle();
    expect(page.querySelector("h1")!.textContent).toBe(t("app.authorize.invalid_title"));
  });
});

describe("act-as consent page", () => {
  const party = { ownDomain: false, userHasHistory: false, domainKeyPinned: false, operatorTrusted: false, domain: "agent.test" };
  const inspect = {
    granteeParty: party,
    audienceParty: { ...party, domain: "api.test" },
    entries: [{ scope: "read", description: "Read data", removedByPolicy: false }, { scope: "write", removedByPolicy: true }],
    defaultLifetimeSeconds: 3600,
    maxLifetimeSeconds: 86400,
    defaultRenewalWindowSeconds: 0,
    maxRenewalWindowSeconds: 0,
  } as unknown as BrowserActAsInspectResponse;

  it("needs one scope and sends the approved scope", async () => {
    sessionStorage.setItem("linkkeys-act-as-request", "act");
    api.browserAuthorization.inspectActAs.mockResolvedValue(inspect);
    api.browserAuthorization.completeActAs.mockResolvedValue({ redirectUrl: "https://agent.test/ok" });
    const page = mount(actAsConsentPage(context()));
    await settle();
    const [read, write] = page.querySelectorAll<ZestCheckBox>("check-box");
    const allow = page.querySelector<ZestPushButton>('push-button[type="submit"]')!;
    expect(write.disabled).toBe(true);
    expect(allow.disabled).toBe(false);
    toggle(read);
    expect(allow.disabled).toBe(true);
    toggle(read);
    expect(allow.disabled).toBe(false);
    expect(page.querySelectorAll("combo-box")).toHaveLength(1);
    page.querySelector("form")!.dispatchEvent(new Event("submit", { cancelable: true }));
    await settle();
    expect(api.browserAuthorization.completeActAs).toHaveBeenCalledWith({ signedRequest: "act", approvedScope: ["read"], lifetimeSeconds: 3600, renewalWindowSeconds: 0 });
    expect(assign).toHaveBeenCalledWith("https://agent.test/ok");
  });
});
