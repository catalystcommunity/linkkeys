// @vitest-environment happy-dom
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { defineControls } from "@catalystcommunity/controls";
import type { PageProps } from "../shared";

const account = vi.hoisted(() => ({
  getMyInfo: vi.fn(),
  listVerifiedContactMethods: vi.fn(),
  listSettablePolicies: vi.fn(),
  getMyClaimSettings: vi.fn(),
  listActAsGrants: vi.fn(),
  setMyClaim: vi.fn(),
  removeMyClaim: vi.fn(),
  requestContactVerification: vi.fn(),
  revokeVerifiedContactMethod: vi.fn(),
  changePassword: vi.fn(),
  setMyClaimSharing: vi.fn(),
  setMyClaimKeepVerified: vi.fn(),
  createProfile: vi.fn(),
  revokeActAsGrant: vi.fn(),
  requestVerification: vi.fn(),
}));

vi.mock("../transport", async (original) => ({ ...(await original<typeof import("../transport")>()), api: { account } }));

const { accountPage } = await import("./account");
const { CsilStatus, CsilTransportError } = await import("../transport");

const policies = [
  { claimType: "nickname", label: "Nickname", datatype: "string", maxBytes: 32, signingRule: "self_signed", description: "What friends call you" },
  { claimType: "adult", label: "Adult", datatype: "bool", maxBytes: 5, signingRule: "unsigned" },
  { claimType: "age", label: "Age", datatype: "int", maxBytes: 3, signingRule: "unsigned" },
  { claimType: "born", label: "Born", datatype: "date", maxBytes: 10, signingRule: "unsigned" },
  { claimType: "passport", label: "Passport", datatype: "string", maxBytes: 32, signingRule: "verified" },
];

function context(overrides: Partial<PageProps> = {}): PageProps {
  return {
    navigate: vi.fn(),
    refreshSession: vi.fn(async () => undefined),
    configuration: { domain: "example.test", capabilities: ["password_login", "verify_contact"], passwordPolicy: { minLength: 8, maxLength: 64 } },
    session: { user: { id: "u1", username: "alice", displayName: "Alice", passwordLocked: false } },
    ...overrides,
  } as unknown as PageProps;
}

async function settle(): Promise<void> {
  for (let i = 0; i < 10; i++) await new Promise((resolve) => setTimeout(resolve, 0));
}

async function mount(props = context()): Promise<HTMLElement> {
  const page = accountPage(props) as HTMLElement;
  document.body.append(page);
  await settle();
  return page;
}

function submit(element: HTMLFormElement): void {
  element.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
}

function field(page: HTMLElement, name: string): ZestTextField {
  return page.querySelector<ZestTextField>(`text-field[name="${name}"]`)!;
}

beforeAll(() => defineControls());

beforeEach(() => {
  for (const mock of Object.values(account)) mock.mockReset();
  account.getMyInfo.mockResolvedValue({ claims: [{ claimId: "c1", claimType: "nickname", claimValue: new TextEncoder().encode("Al"), signatures: [] }] });
  account.listVerifiedContactMethods.mockResolvedValue({ contactMethods: [{ id: "m1", destination: "a@example.test" }] });
  account.listSettablePolicies.mockResolvedValue({ policies });
  account.getMyClaimSettings.mockResolvedValue({ settings: [{ claimType: "nickname", sharedWithEveryApp: true, keepVerified: false }], profiles: [], maxProfiles: 1 });
  account.listActAsGrants.mockResolvedValue({ grants: [] });
});

afterEach(() => {
  document.body.replaceChildren();
  vi.restoreAllMocks();
});

describe("account page", () => {
  it("shows the details, contacts, choices, and password form", async () => {
    const page = await mount();
    expect(page.querySelector("h1")!.textContent).toBe("Alice");
    expect(page.querySelector("tbody")!.textContent).toContain("Al");
    expect(page.querySelector(".row")!.textContent).toContain("a@example.test");
    expect(page.querySelectorAll("fieldset.consent-claim")).toHaveLength(4);
    const share = page.querySelector<ZestCheckBox>("fieldset.consent-claim check-box")!;
    expect(share.checked).toBe(true);
    expect(page.querySelector("#change-password-form")).not.toBeNull();
    expect(field(page, "new-password").getAttribute("aria-describedby")).toBe("change-password-rule");
    expect(page.querySelectorAll('text-field[autocomplete="username"][readonly]')).toHaveLength(2);
  });

  it("hides the profile list for one profile and shows it for more", async () => {
    let page = await mount();
    expect(page.querySelector('text-field[name="profile-label"]')).toBeNull();
    page.remove();
    account.getMyClaimSettings.mockResolvedValue({ settings: [], profiles: [{ id: "p1", domain: "example.test", label: "Work" }], maxProfiles: 3 });
    page = await mount();
    expect(page.querySelector('text-field[name="profile-label"]')).not.toBeNull();
    expect(page.textContent).toContain("p1@example.test");
  });

  it("hides the sharing choices when no policy is settable", async () => {
    account.listSettablePolicies.mockResolvedValue({ policies: [] });
    const page = await mount();
    expect(page.querySelector("fieldset.consent-claim")).toBeNull();
    expect(page.querySelector("form.inline-form combo-box")).toBeNull();
  });

  it("changes the value control with the detail type and clears the value", async () => {
    const page = await mount();
    const select = page.querySelector<ZestComboBox>("form.inline-form > div > combo-box")!;
    let value = page.querySelector<ZestTextField>("form.inline-form > text-field")!;
    expect(value.getAttribute("maxlength")).toBe("32");
    value.value = "typed";
    const form = select.closest("form")!;
    for (const [type, check] of [
      ["adult", () => { const boxes = form.querySelectorAll<ZestComboBox>("combo-box"); expect(boxes).toHaveLength(2); expect(boxes[1].required).toBe(true); expect(form.querySelector(":scope > text-field")).toBeNull(); }],
      ["age", () => { const age = form.querySelector<ZestTextField>(":scope > text-field")!; expect(age.getAttribute("inputmode")).toBe("numeric"); expect(age.type).toBe("text"); expect(age.value).toBe(""); }],
      ["born", () => expect(form.querySelector('date-time-picker[mode="date"]')).not.toBeNull()],
    ] as const) {
      select.value = type;
      select.dispatchEvent(new Event("change", { bubbles: true }));
      check();
    }
    select.value = "nickname";
    select.dispatchEvent(new Event("change", { bubbles: true }));
    value = form.querySelector<ZestTextField>(":scope > text-field")!;
    expect(value.value).toBe("");
    expect(page.textContent).toContain("What friends call you");
  });

  it("saves a detail and shows the status under the details", async () => {
    account.setMyClaim.mockResolvedValue({ outcome: "saved" });
    const page = await mount();
    const form = page.querySelector<HTMLFormElement>("form.inline-form")!;
    form.querySelector<ZestTextField>(":scope > text-field")!.value = "Ally";
    submit(form);
    await settle();
    expect(account.setMyClaim).toHaveBeenCalledWith({ claimType: "nickname", claimValue: "Ally" });
    const status = form.closest("section")!.querySelector('[role="status"]');
    expect(status?.textContent).toBeTruthy();
    expect(page.querySelector("#change-password-form")!.closest("section")!.querySelector('[role="alert"]')).toBeNull();
  });

  it("asks for the password before it removes a contact, under the contacts", async () => {
    const page = await mount();
    const remove = page.querySelector<HTMLElement>(".row push-button")!;
    remove.click();
    const contacts = remove.closest("section")!;
    expect(contacts.querySelector('[role="alert"]')).not.toBeNull();
    expect(account.revokeVerifiedContactMethod).not.toHaveBeenCalled();

    account.revokeVerifiedContactMethod.mockResolvedValue({});
    const confirm = vi.fn(() => true);
    Object.assign(window, { confirm });
    contacts.querySelector<ZestTextField>('text-field[name="current-password"]')!.value = "secret";
    remove.click();
    await settle();
    expect(confirm).toHaveBeenCalled();
    expect(account.revokeVerifiedContactMethod).toHaveBeenCalledWith({ contactMethodId: "m1", currentPassword: "secret" });
  });

  it("checks that the new passwords match before it calls the server", async () => {
    const page = await mount();
    const form = page.querySelector<HTMLFormElement>("#change-password-form")!;
    field(page, "new-password").value = "abcdefghij";
    form.querySelector<ZestTextField>('text-field[name="new-password-confirmation"]')!.value = "different";
    submit(form);
    expect(account.changePassword).not.toHaveBeenCalled();
    expect(form.closest("section")!.querySelector('[role="alert"]')).not.toBeNull();
  });

  it("changes the password, then goes to the login page", async () => {
    account.changePassword.mockResolvedValue({});
    const props = context();
    const page = await mount(props);
    const form = page.querySelector<HTMLFormElement>("#change-password-form")!;
    form.querySelector<ZestTextField>('text-field[name="current-password"]')!.value = "oldpassword";
    field(page, "new-password").value = "newpassword";
    form.querySelector<ZestTextField>('text-field[name="new-password-confirmation"]')!.value = "newpassword";
    submit(form);
    await settle();
    expect(account.changePassword).toHaveBeenCalledWith({ currentPassword: "oldpassword", newPassword: "newpassword" });
    expect(props.refreshSession).toHaveBeenCalled();
    expect(props.navigate).toHaveBeenCalledWith("/app/login");
  });

  it("shows a load failure with try again, and goes to login when signed out", async () => {
    account.getMyInfo.mockRejectedValueOnce(new Error("down"));
    let page = await mount();
    const alert = page.querySelector('[role="alert"]')!;
    expect(alert).not.toBeNull();
    page.querySelector<HTMLElement>("main section.card push-button")!.click();
    await settle();
    expect(page.querySelector("tbody")).not.toBeNull();
    expect(page.querySelector('main > [role="alert"]')).toBeNull();
    page.remove();

    account.getMyInfo.mockRejectedValueOnce(new CsilTransportError(CsilStatus.unauthenticated, "no"));
    const props = context();
    page = await mount(props);
    expect(props.navigate).toHaveBeenCalledWith("/app/login");
  });

  it("checks the confirmation site, then shows a code", async () => {
    account.requestVerification.mockRejectedValue(new Error("down"));
    const page = await mount();
    const form = page.querySelector<HTMLFormElement>("#confirmation-request-form")!;
    submit(form);
    expect(account.requestVerification).not.toHaveBeenCalled();
    expect(form.closest("section")!.querySelector('[role="alert"]')).not.toBeNull();
    field(page, "confirmation-site").value = "https://shop.example";
    field(page, "confirmation-details").value = "email";
    submit(form);
    await settle();
    expect(account.requestVerification).toHaveBeenCalledWith({ issuerDomain: "shop.example", requestedClaimTypes: ["email"] });
  });
});
