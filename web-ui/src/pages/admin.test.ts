// @vitest-environment happy-dom
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { defineControls } from "@catalystcommunity/controls";
import { defineElements } from "@catalystcommunity/base-components";
import { DateTimePicker } from "@catalystcommunity/date-time-picker";
import type { PageProps } from "../shared";
import { t } from "../i18n";

const admin = vi.hoisted(() => ({
  listUsers: vi.fn(),
  createUser: vi.fn(),
  deactivateUser: vi.fn(),
  activateUser: vi.fn(),
  resetPassword: vi.fn(),
  getUser: vi.fn(),
  getUserAuthenticationActivity: vi.fn(),
  getUserClaims: vi.fn(),
  listRelations: vi.fn(),
  listClaimTypes: vi.fn(),
  setClaim: vi.fn(),
  grantRelation: vi.fn(),
  listClaimTypeLabels: vi.fn(),
  listTrustedIssuers: vi.fn(),
  listReleaseRules: vi.fn(),
  setClaimType: vi.fn(),
  listAppAccessPolicies: vi.fn(),
  setAppAccessPolicy: vi.fn(),
  listPendingClaimApprovals: vi.fn(),
  approveClaim: vi.fn(),
  getSignInPolicy: vi.fn(),
  setSignInPolicy: vi.fn(),
}));
const browserIssuer = vi.hoisted(() => ({ inspectSigningRequest: vi.fn(), issueForSigningRequest: vi.fn() }));

vi.mock("../transport", async (original) => ({ ...(await original<typeof import("../transport")>()), api: { admin, browserIssuer } }));

const { adminAreaPage } = await import("./admin");
const { CsilStatus, CsilTransportError } = await import("../transport");

const alice = { id: "u1", username: "alice", displayName: "Alice", isActive: true, createdAt: "2026-01-01T00:00:00Z", updatedAt: "2026-01-01T00:00:00Z" };
const bob = { id: "u2", username: "bob", displayName: "Bob", isActive: true, createdAt: "2026-02-01T00:00:00Z", updatedAt: "2026-02-01T00:00:00Z", passwordLocked: false };
const carol = { id: "u3", username: "carol", displayName: "Carol", isActive: false, createdAt: "2026-03-01T00:00:00Z", updatedAt: "2026-03-01T00:00:00Z" };
const pronouns = { claimType: "pronouns", label: "Pronouns", description: "How to refer to you", valueType: "text", maxBytes: 64, setRule: "admin_only", signingRule: "verified", userSettable: true, defaultAutoSign: false, requiresApproval: true, suggested: false };

function context(path: string, overrides: Partial<PageProps> = {}): PageProps & { path: string } {
  return {
    path,
    navigate: vi.fn(),
    refreshSession: vi.fn(async () => undefined),
    configuration: { domain: "example.test", passwordPolicy: { minLength: 8, maxLength: 64 } },
    session: { user: { id: "u1", username: "alice", displayName: "Alice" } },
    ...overrides,
  } as unknown as PageProps & { path: string };
}

async function settle(): Promise<void> {
  for (let i = 0; i < 10; i++) await new Promise((resolve) => setTimeout(resolve, 0));
}

async function mount(path: string, overrides: Partial<PageProps> = {}): Promise<HTMLElement> {
  const page = adminAreaPage(context(path, overrides)) as HTMLElement;
  document.body.append(page);
  await settle();
  return page;
}

function submit(element: Element): void {
  element.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
}

function control<T extends Element>(root: Element, selector: string, label: string): T {
  const found = [...root.querySelectorAll<T>(selector)].find((element) => element.getAttribute("label") === label);
  if (!found) throw new Error(`No ${selector} labelled ${label}`);
  return found;
}

const field = (root: Element, label: string) => control<ZestTextField>(root, "text-field", label);
const combo = (root: Element, label: string) => control<ZestComboBox>(root, "combo-box", label);

function buttonNamed(root: Element, text: string): ZestPushButton {
  const found = [...root.querySelectorAll<ZestPushButton>("push-button")].find((element) => element.textContent?.trim() === text);
  if (!found) throw new Error(`No button ${text}`);
  return found;
}

function alertText(root: Element): string {
  return [...root.querySelectorAll('[role="alert"]')].map((element) => element.textContent).join(" ");
}

beforeAll(() => {
  defineControls();
  defineElements({ "date-time-picker": DateTimePicker });
});

beforeEach(() => {
  for (const mock of [...Object.values(admin), ...Object.values(browserIssuer)]) mock.mockReset();
  admin.listUsers.mockResolvedValue({ users: [alice, bob, carol] });
  admin.listClaimTypes.mockResolvedValue({ claimTypes: [pronouns] });
  admin.listClaimTypeLabels.mockResolvedValue({ labels: [] });
  admin.listTrustedIssuers.mockResolvedValue({ trustedIssuers: [] });
  admin.listReleaseRules.mockResolvedValue({ releaseRules: [] });
  admin.listAppAccessPolicies.mockResolvedValue({ policies: [] });
  admin.getUser.mockResolvedValue({ user: bob });
  admin.getUserAuthenticationActivity.mockResolvedValue({ activity: { successfulAuthenticationCount: 3, activeBrowserSessionCount: 1 } });
  admin.getUserClaims.mockResolvedValue({ claims: [] });
  admin.listRelations.mockResolvedValue({ relations: [] });
  vi.stubGlobal("confirm", vi.fn(() => true));
});

afterEach(() => {
  document.body.replaceChildren();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("admin routing", () => {
  it("shows not found with a way back for an unknown admin path", async () => {
    const page = await mount("/app/admin/nowhere");
    expect(page.querySelector("h1")?.textContent).toBe(t("app.not_found.title"));
    expect(page.querySelector("a")?.getAttribute("href")).toBe("/app/admin");
  });

  it("marks the current tab, also with a trailing slash on the path", async () => {
    const page = await mount("/app/admin/policy/");
    expect(page.querySelector('.admin-tabs a[aria-current="page"]')).toBeNull();
    const exact = await mount("/app/admin/policy");
    expect(exact.querySelector('.admin-tabs a[aria-current="page"]')?.getAttribute("href")).toBe("/app/admin/policy");
  });
});

describe("accounts", () => {
  it("lists accounts with the right action for each", async () => {
    const page = await mount("/app/admin");
    const rows = page.querySelectorAll("tbody tr");
    expect(rows).toHaveLength(3);
    expect(rows[0].textContent).toContain(t("app.admin.current_account"));
    expect(rows[1].querySelector("push-button")?.getAttribute("aria-label")).toBe(t("app.admin.disable_label", { username: "bob" }));
    const restore = rows[2].querySelector("form.stacked-action")!;
    expect([...restore.querySelectorAll("text-field")].map((element) => element.getAttribute("autocomplete"))).toEqual(["new-password", "new-password"]);
  });

  it("shows only the problem when the first load fails", async () => {
    admin.listUsers.mockRejectedValue(new CsilTransportError(CsilStatus.PermissionDenied, "no"));
    const page = await mount("/app/admin");
    expect(page.querySelector(".card")?.children).toHaveLength(1);
    expect(alertText(page)).not.toBe("");
  });

  it("refuses a confirmation that does not match", async () => {
    const page = await mount("/app/admin");
    field(page, t("app.admin.initial_password")).value = "long-password";
    field(page, t("app.admin.confirm_initial_password")).value = "other-password";
    submit(page.querySelector("form.account-form")!);
    await settle();
    expect(admin.createUser).not.toHaveBeenCalled();
    expect(alertText(page)).toBe(t("app.password.mismatch"));
  });

  it("creates an account, clears the form, and says so", async () => {
    admin.createUser.mockResolvedValue({});
    const page = await mount("/app/admin");
    field(page, t("app.admin.username")).value = "dave";
    field(page, t("app.admin.display_name")).value = "Dave";
    field(page, t("app.admin.initial_password")).value = "long-password";
    field(page, t("app.admin.confirm_initial_password")).value = "long-password";
    submit(page.querySelector("form.account-form")!);
    await settle();
    expect(admin.createUser).toHaveBeenCalledWith({ username: "dave", displayName: "Dave", password: "long-password" });
    expect(field(page, t("app.admin.username")).value).toBe("");
    expect(page.querySelector('[role="status"].notice')?.textContent).toBe(t("app.admin.created"));
  });
});

describe("one account", () => {
  it("keeps the hidden username on the password reset form", async () => {
    const page = await mount("/app/admin/users/u2");
    expect(page.querySelector("h1")?.textContent).toBe("Bob");
    const hidden = page.querySelector<ZestTextField>('text-field.visually-hidden[autocomplete="username"]');
    expect(hidden?.value).toBe("bob");
    expect(field(page, t("app.password.new")).getAttribute("autocomplete")).toBe("new-password");
  });

  it("adds a claim with the date as the start of that day in UTC", async () => {
    admin.setClaim.mockResolvedValue({});
    const page = await mount("/app/admin/users/u2");
    combo(page, t("app.account.field_detail")).value = "pronouns";
    field(page, t("app.account.field_value")).value = "they/them";
    page.querySelector<ZestDateTimePicker>("date-time-picker")!.value = "2027-05-01";
    submit(page.querySelectorAll("form.account-form")[1]);
    await settle();
    expect(admin.setClaim).toHaveBeenCalledWith({ userId: "u2", claimType: "pronouns", claimValue: "they/them", expiresAt: "2027-05-01T00:00:00Z" });
    expect(page.querySelector<ZestDateTimePicker>("date-time-picker")!.value).toBe("");
  });

  it("grants on a claim type with the claim types offered", async () => {
    admin.grantRelation.mockResolvedValue({});
    const page = await mount("/app/admin/users/u2");
    const objectId = combo(page, t("app.admin_user.object_id"));
    expect(objectId.value).toBe("example.test");
    const objectType = combo(page, t("app.admin_user.object_type"));
    objectType.value = "claim_type";
    objectType.dispatchEvent(new Event("change", { bubbles: true }));
    expect(objectId.value).toBe("");
    expect(objectId.options).toEqual([{ value: "pronouns", label: "Pronouns" }]);
    objectId.value = "pronouns";
    submit(objectId.closest("form")!);
    await settle();
    expect(admin.grantRelation).toHaveBeenCalledWith({ subjectType: "user", subjectId: "u2", relation: "manage_claims", objectType: "claim_type", objectId: "pronouns" });
  });
});

describe("policy", () => {
  it("fills every control from Edit, and Clear resets every control", async () => {
    const page = await mount("/app/admin/policy");
    const form = page.querySelector<HTMLFormElement>("#claim-type-form")!;
    const scroll = vi.spyOn(form, "scrollIntoView");
    buttonNamed(page, t("app.policy.edit")).click();
    expect(scroll).toHaveBeenCalled();
    expect(field(form, t("app.policy.field_type")).value).toBe("pronouns");
    expect(field(form, t("app.policy.field_max_bytes")).value).toBe("64");
    expect(combo(form, t("app.policy.col_set_rule")).value).toBe("admin_only");
    expect(combo(form, t("app.policy.col_signing")).value).toBe("verified");
    const flags = [...form.querySelectorAll<ZestCheckBox>("check-box")].map((box) => box.checked);
    expect(flags).toEqual([true, false, true, false]);
    buttonNamed(page, t("app.policy.clear")).click();
    expect(field(form, t("app.policy.field_type")).value).toBe("");
    expect(field(form, t("app.policy.field_max_bytes")).value).toBe("33792");
    expect(combo(form, t("app.policy.col_set_rule")).value).toBe("user_self");
    expect([...form.querySelectorAll<ZestCheckBox>("check-box")].some((box) => box.checked)).toBe(false);
  });

  it("refuses a max size that is not a positive whole number", async () => {
    const page = await mount("/app/admin/policy");
    const form = page.querySelector<HTMLFormElement>("#claim-type-form")!;
    field(form, t("app.policy.field_max_bytes")).value = "0x10";
    submit(form);
    await settle();
    expect(admin.setClaimType).not.toHaveBeenCalled();
    expect(alertText(page)).toBe(t("app.policy.max_bytes_invalid"));
  });

  it("saves an edited claim type with a number size", async () => {
    admin.setClaimType.mockResolvedValue({});
    const page = await mount("/app/admin/policy");
    buttonNamed(page, t("app.policy.edit")).click();
    submit(page.querySelector("#claim-type-form")!);
    await settle();
    expect(admin.setClaimType).toHaveBeenCalledWith({ ...pronouns, description: "How to refer to you" });
  });
});

describe("app access", () => {
  it("changes only the target fields for the kind and the operator", async () => {
    const page = await mount("/app/admin/access");
    const builder = page.querySelector("fieldset .inline-form")!;
    expect(builder.querySelector(`combo-box[label="${t("app.admin.col_username")}"]`)).not.toBeNull();
    const kind = combo(builder, t("app.access.target_kind"));
    kind.value = "claim";
    kind.dispatchEvent(new Event("change", { bubbles: true }));
    expect(builder.querySelector(`combo-box[label="${t("app.admin.col_username")}"]`)).toBeNull();
    const value = builder.querySelector<ZestTextField>("text-field")!;
    expect(value.label).toBe(t("app.access.field_age"));
    expect(value.getAttribute("inputmode")).toBe("numeric");
    const operator = combo(builder, t("app.access.field_condition"));
    operator.value = "present";
    operator.dispatchEvent(new Event("change", { bubbles: true }));
    expect(builder.querySelector("text-field")).toBeNull();
    expect(page.querySelector("fieldset small")?.textContent).toBe(t("app.access.claim_help"));
  });

  it("needs a number for an age, then saves the policy with its target", async () => {
    admin.setAppAccessPolicy.mockResolvedValue({});
    const page = await mount("/app/admin/access");
    const builder = page.querySelector("fieldset .inline-form")!;
    const kind = combo(builder, t("app.access.target_kind"));
    kind.value = "claim";
    kind.dispatchEvent(new Event("change", { bubbles: true }));
    combo(builder, t("app.access.field_claim_type")).value = "pronouns";
    builder.querySelector<ZestTextField>("text-field")!.value = "eighteen";
    buttonNamed(page, t("app.access.add_target")).click();
    expect(alertText(page)).toBe(t("app.access.value_required"));
    builder.querySelector<ZestTextField>("text-field")!.value = "18";
    buttonNamed(page, t("app.access.add_target")).click();
    expect(page.querySelectorAll("fieldset li")).toHaveLength(1);
    field(page, t("app.access.col_name")).value = " Adults ";
    page.querySelector<ZestTextArea>(`text-area[label="${t("app.access.col_patterns")}"]`)!.value = "*.example";
    submit(page.querySelector("#access-policy-form form")!);
    await settle();
    expect(admin.setAppAccessPolicy).toHaveBeenCalledWith({ id: undefined, name: "Adults", mode: "deny", patterns: ["*.example"], message: undefined, targets: [{ kind: "claim", claimType: "pronouns", claimOperator: "age_under", claimValue: "18" }] });
    expect(page.querySelector('[role="status"].notice')?.textContent).toBe(t("app.access.saved", { name: "Adults" }));
  });
});

describe("approvals", () => {
  it("approves a claim and turns off only its buttons while it runs", async () => {
    const approvals = [
      { id: "a1", userId: "u2", claimType: "pronouns", claimValue: new TextEncoder().encode("they"), createdAt: "2026-04-01T00:00:00Z" },
      { id: "a2", userId: "u3", claimType: "pronouns", claimValue: new TextEncoder().encode("she"), createdAt: "2026-04-01T00:00:00Z" },
    ];
    admin.listPendingClaimApprovals.mockResolvedValueOnce({ approvals }).mockResolvedValue({ approvals: [] });
    let finish = () => {};
    admin.approveClaim.mockReturnValue(new Promise<void>((resolve) => { finish = resolve; }));
    const page = await mount("/app/admin/approvals");
    const rows = page.querySelectorAll("tbody tr");
    rows[0].querySelector<ZestPushButton>("push-button")!.click();
    expect(rows[0].querySelector<ZestPushButton>("push-button")!.disabled).toBe(true);
    expect(rows[1].querySelector<ZestPushButton>("push-button")!.disabled).toBe(false);
    finish();
    await settle();
    expect(admin.approveClaim).toHaveBeenCalledWith({ approvalId: "a1" });
    expect(page.querySelector("p.muted")?.textContent).toBe(t("app.approvals.empty"));
  });
});

describe("issue", () => {
  it("checks a request, then signs only the filled values", async () => {
    browserIssuer.inspectSigningRequest.mockResolvedValue({ subjectUserId: "sam", subjectDomain: "other.test", requestedClaimTypes: ["pronouns", "email"], issuableClaimTypes: ["pronouns"], expiresAt: "2026-12-01T00:00:00Z" });
    browserIssuer.issueForSigningRequest.mockResolvedValue({ results: [{ claimType: "pronouns", outcome: "deposited" }] });
    const page = await mount("/app/admin/issue");
    page.querySelector<ZestTextArea>("text-area")!.value = " signed ";
    submit(page.querySelector("form")!);
    await settle();
    expect(browserIssuer.inspectSigningRequest).toHaveBeenCalledWith({ signedRequest: "signed" });
    expect(page.querySelector("code")?.textContent).toBe("sam@other.test");
    const sign = buttonNamed(page, t("app.issue.sign"));
    expect(sign.disabled).toBe(true);
    const value = page.querySelector<ZestTextField>("form text-field")!;
    value.value = "they";
    value.dispatchEvent(new Event("input", { bubbles: true }));
    expect(sign.disabled).toBe(false);
    submit(page.querySelector("form")!);
    await settle();
    expect(browserIssuer.issueForSigningRequest).toHaveBeenCalledWith({ signedRequest: "signed", claimTypes: ["pronouns"], claimValues: ["they"] });
    expect(page.querySelector(".consent-claim .notice.good")).not.toBeNull();
  });
});

describe("settings", () => {
  it("refuses hours out of range and saves hours in range", async () => {
    admin.getSignInPolicy.mockResolvedValue({ signInHours: 12, defaultSignInHours: 12, minSignInHours: 1, maxSignInHours: 720 });
    admin.setSignInPolicy.mockResolvedValue({ signInHours: 24, defaultSignInHours: 12, minSignInHours: 1, maxSignInHours: 720 });
    const page = await mount("/app/admin/settings");
    const hours = field(page, t("app.settings.hours"));
    expect(hours.value).toBe("12");
    expect(hours.getAttribute("inputmode")).toBe("numeric");
    hours.value = "1.5";
    submit(page.querySelector("form")!);
    await settle();
    expect(admin.setSignInPolicy).not.toHaveBeenCalled();
    expect(alertText(page)).toBe(t("app.settings.hours_invalid", { min: 1, max: 720 }));
    hours.value = "24";
    submit(page.querySelector("form")!);
    await settle();
    expect(admin.setSignInPolicy).toHaveBeenCalledWith({ signInHours: 24 });
    expect(page.querySelector('[role="status"].notice')?.textContent).toBe(t("app.settings.saved", { hours: 24 }));
  });
});
