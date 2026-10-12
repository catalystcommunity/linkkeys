// Pieces shared by the account, consent, and admin pages.
import { Show, type Component, type JSX } from "solid-js";
import { plural, t } from "./i18n";
import type { BrowserSessionInfo, Claim, GetUiConfigurationResponse } from "./generated/types.gen";
import { passwordLengthError } from "./ui-logic";

export type PageProps = { navigate(path: string): void; configuration: GetUiConfigurationResponse; session?: BrowserSessionInfo; refreshSession(): Promise<void>; extensionFailures?: string[] };

export function query(name: string): string { return new URLSearchParams(window.location.search).get(name) ?? ""; }

export function passwordRule(configuration: GetUiConfigurationResponse): string {
  return plural("app.password.min_length", configuration.passwordPolicy?.minLength ?? 8);
}

export function checkPassword(value: string, configuration: GetUiConfigurationResponse): string {
  return passwordLengthError(value, configuration.passwordPolicy?.minLength ?? 8, configuration.passwordPolicy?.maxLength ?? 1024);
}

export const Link: Component<{ href: string; current?: boolean; children: JSX.Element }> = (props) => (
  <a href={props.href} data-linkkeys-nav aria-current={props.current ? "page" : undefined}>{props.children}</a>
);

export function claimText(claim: Claim): string {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(claim.claimValue); }
  catch { return t("app.account.binary_value"); }
}

export const Unavailable: Component<{ title: string; detail: string; destination?: string; action?: string }> = (props) => <main class="wrap narrow"><section class="card"><h1>{props.title}</h1><p>{props.detail}</p><Show when={props.destination}><Link href={props.destination!}>{props.action ?? t("app.common.return_to_account")}</Link></Show></section></main>;
export const Loading: Component = () => <main class="wrap narrow" aria-busy="true"><section class="card"><h1>{t("app.loading.title")}</h1><p role="status">{t("app.loading.body")}</p></section></main>;
