// Pieces shared by the account, consent, and admin pages.
import { plural, t } from "./i18n";
import type { BrowserSessionInfo, Claim, GetUiConfigurationResponse } from "./generated/types.gen";
import { passwordLengthError } from "./ui-logic";
import { h, link } from "./dom";

/** What the app shell gives each page. */
export type PageProps = {
  navigate(path: string): void;
  configuration: GetUiConfigurationResponse;
  session?: BrowserSessionInfo;
  refreshSession(): Promise<void>;
  extensionFailures?: string[];
};

export function query(name: string): string { return new URLSearchParams(window.location.search).get(name) ?? ""; }

export function passwordRule(configuration: GetUiConfigurationResponse): string {
  return plural("app.password.min_length", configuration.passwordPolicy?.minLength ?? 8);
}

export function checkPassword(value: string, configuration: GetUiConfigurationResponse): string {
  return passwordLengthError(value, configuration.passwordPolicy?.minLength ?? 8, configuration.passwordPolicy?.maxLength ?? 1024);
}

export function claimText(claim: Claim): string {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(claim.claimValue); }
  catch { return t("app.account.binary_value"); }
}

/** A page that explains why it cannot continue, with an optional way out. */
export function unavailable(title: string, detail: string, destination?: string, action?: string): HTMLElement {
  return h("main", { class: "wrap narrow" }, h("section", { class: "card" }, h("h1", null, title), h("p", null, detail), destination && link(destination, action ?? t("app.common.return_to_account"))));
}

export function loading(): HTMLElement {
  return h("main", { class: "wrap narrow", "aria-busy": "true" }, h("section", { class: "card" }, h("h1", null, t("app.loading.title")), h("p", { role: "status" }, t("app.loading.body"))));
}
