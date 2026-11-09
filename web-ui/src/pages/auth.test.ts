// @vitest-environment happy-dom
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { defineControls } from "@catalystcommunity/controls";
import type { GetUiConfigurationResponse } from "../generated/types.gen";
import type { PageProps } from "../shared";
import { CsilStatus, CsilTransportError } from "../transport";
import { t } from "../i18n";
import { loginPage, resetPasswordPage, verifyContactPage } from "./auth";

const api = vi.hoisted(() => ({
  session: { loginPassword: vi.fn() },
  recovery: { validatePasswordRecovery: vi.fn(), completePasswordRecovery: vi.fn(), requestPasswordRecovery: vi.fn() },
  account: { confirmContactVerification: vi.fn() },
}));
vi.mock("../transport", async (original) => ({ ...(await original<typeof import("../transport")>()), api }));

const configuration = {
  domain: "example.test",
  capabilities: ["password_login", "reset_password"],
  passwordPolicy: { minLength: 8, maxLength: 1024 },
} as unknown as GetUiConfigurationResponse;

function context(overrides: Partial<PageProps> = {}): PageProps {
  return { navigate: vi.fn(), configuration, refreshSession: vi.fn(async () => {}), ...overrides };
}

async function settle(): Promise<void> {
  for (let i = 0; i < 5; i += 1) await new Promise((resolve) => setTimeout(resolve, 0));
}

function mount(page: Element): Element {
  document.body.replaceChildren(page);
  return page;
}

function submit(form: HTMLFormElement): void {
  form.dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));
}

beforeAll(() => defineControls());

beforeEach(() => {
  vi.clearAllMocks();
  sessionStorage.clear();
  window.history.replaceState({}, "", "/app/login");
});

describe("login page", () => {
  it("keeps the password manager attributes and signs in", async () => {
    window.history.replaceState({}, "", "/app/login?username=alice");
    api.session.loginPassword.mockResolvedValue({});
    const props = context();
    const page = mount(loginPage(props));
    const form = page.querySelector<HTMLFormElement>("form#login-form")!;
    expect(form.getAttribute("name")).toBe("login");
    const username = form.querySelector<ZestTextField>('text-field[autocomplete="username"]')!;
    const password = form.querySelector<ZestTextField>('text-field[type="password"]')!;
    expect(username.value).toBe("alice");
    expect(username.querySelector("input")!.getAttribute("autocomplete")).toBe("username");
    expect(password.querySelector("input")!.getAttribute("autocomplete")).toBe("current-password");
    expect(password.querySelector("input")!.type).toBe("password");
    // The username is already known, so the focus starts in the password.
    expect(document.activeElement).toBe(password.querySelector("input"));
    // The forgot link carries the typed username.
    const forgot = form.querySelector<HTMLAnchorElement>("small a")!;
    expect(forgot.getAttribute("href")).toBe("/app/password/request?username=alice");

    password.value = "secret-password";
    submit(form);
    await settle();
    expect(api.session.loginPassword).toHaveBeenCalledWith({ username: "alice", password: "secret-password" });
    expect(props.refreshSession).toHaveBeenCalled();
    expect(props.navigate).toHaveBeenCalledWith("/app/account");
    expect(password.value).toBe("");
  });

  it("shows an alert when the password is wrong", async () => {
    api.session.loginPassword.mockRejectedValue(new CsilTransportError(CsilStatus.unauthenticated, "unauthenticated"));
    const props = context();
    const page = mount(loginPage(props));
    const form = page.querySelector<HTMLFormElement>("form")!;
    expect(document.activeElement).toBe(form.querySelector('text-field[autocomplete="username"] input'));
    submit(form);
    expect(form.getAttribute("aria-busy")).toBe("true");
    expect(form.querySelector<ZestPushButton>('push-button[type="submit"]')!.disabled).toBe(true);
    await settle();
    expect(form.querySelector('[role="alert"]')!.textContent).toBe(t("app.login.incorrect"));
    expect(form.hasAttribute("aria-busy")).toBe(false);
    expect(props.navigate).not.toHaveBeenCalled();
  });

  it("explains when password sign-in is off", () => {
    const page = mount(loginPage(context({ configuration: { ...configuration, capabilities: [] } })));
    expect(page.querySelector("h1")!.textContent).toBe(t("app.login.unavailable_title"));
    expect(page.querySelector("form")).toBeNull();
  });
});

describe("reset password page", () => {
  it("checks the token from the fragment and stops a mismatch", async () => {
    window.history.replaceState({}, "", "/app/password/reset#token=abc");
    api.recovery.validatePasswordRecovery.mockResolvedValue({});
    const page = mount(resetPasswordPage(context()));
    await settle();
    expect(api.recovery.validatePasswordRecovery).toHaveBeenCalledWith({ token: "abc" });
    expect(window.location.hash).toBe("");
    const form = page.querySelector<HTMLFormElement>("form#reset-password-form")!;
    const [, password, confirmation] = form.querySelectorAll<ZestTextField>("text-field");
    password.value = "long-enough-1";
    confirmation.value = "long-enough-2";
    submit(form);
    await settle();
    expect(form.querySelector('[role="alert"]')!.textContent).toBe(t("app.password.mismatch"));
    expect(api.recovery.completePasswordRecovery).not.toHaveBeenCalled();
    confirmation.value = "long-enough-1";
    api.recovery.completePasswordRecovery.mockResolvedValue({});
    submit(form);
    await settle();
    expect(api.recovery.completePasswordRecovery).toHaveBeenCalledWith({ token: "abc", newPassword: "long-enough-1" });
    expect(page.querySelector(".card.good h2")!.textContent).toBe(t("app.recovery.done_title"));
  });
});

describe("verify contact page", () => {
  it("offers a retry after a connection failure", async () => {
    sessionStorage.setItem("linkkeys-contact-token", "tok");
    api.account.confirmContactVerification.mockRejectedValueOnce(new TypeError("offline")).mockResolvedValueOnce({});
    const page = mount(verifyContactPage(context()));
    await settle();
    const retry = page.querySelector<ZestPushButton>("push-button")!;
    expect(retry.hidden).toBe(false);
    expect(page.querySelector('[role="alert"]')).not.toBeNull();
    retry.click();
    await settle();
    expect(api.account.confirmContactVerification).toHaveBeenLastCalledWith({ token: "tok" });
    expect(page.querySelector(".card.good h2")!.textContent).toBe(t("app.verify_contact.done_title"));
    expect(sessionStorage.getItem("linkkeys-contact-token")).toBeNull();
  });
});
