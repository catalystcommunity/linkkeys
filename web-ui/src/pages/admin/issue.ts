// Issue claims for a signing request from another domain.
import { api } from "../../transport";
import { claimTypeLabel, t } from "../../i18n";
import { button, fill, form, formatted, h, textArea, textButton, textField, type Child } from "../../dom";
import type { InspectSigningRequestResponse, IssuedClaimResult } from "../../generated/types.gen";
import { authenticationFailed } from "../../ui-logic";
import { AdminPage, Slot, adminHeader } from "./common";

function issueResult(result: IssuedClaimResult, domain: string): HTMLElement {
  const name = claimTypeLabel(result.claimType);
  const reason = result.message ?? "";
  if (result.outcome === "deposited") return h("div", { class: "consent-claim" }, h("p", { class: "notice good" }, t("app.issue.deposited", { label: name, domain })));
  if (result.outcome === "skipped") return h("div", { class: "consent-claim" }, h("p", { class: "notice" }, t("app.issue.skipped", { label: name, reason })));
  if (result.outcome === "failed") return h("div", { class: "consent-claim" }, h("p", { class: "notice bad" }, t("app.issue.failed", { label: name, reason })));
  if (result.outcome !== "handoff") return h("div", { class: "consent-claim" });
  const copied = new Slot();
  const code = textArea("", { readonly: true, rows: 3, value: result.claimCode ?? "", "aria-label": t("app.issue.code_label", { label: name }), on: { focusin: () => code.select() } });
  const copy = async () => {
    try { await navigator.clipboard.writeText(result.claimCode ?? ""); copied.set(h("small", { role: "status" }, t("app.confirm.copied"))); }
    catch { copied.set(); }
  };
  return h("div", { class: "consent-claim" },
    h("p", { class: "notice" }, t("app.issue.handoff", { label: name, domain, reason })),
    code,
    h("div", { class: "button-row" }, button(t("app.confirm.copy"), { onClick: () => void copy() }), copied.anchor));
}

export class AdminIssuePage extends AdminPage {
  private request?: InspectSigningRequestResponse;
  private results: IssuedClaimResult[] = [];
  private working = false;
  private readonly content = new Slot();
  private readonly code = textArea(t("app.issue.code"), { rows: 5, required: true });
  private readonly checkButton = button(t("app.issue.check"), { type: "submit" });
  private readonly inspectForm = form({ "aria-busy": "false", onSubmit: () => void this.inspect() }, this.code, this.checkButton);
  private issueForm?: HTMLFormElement;
  private signButton?: ZestPushButton;
  private values = new Map<string, ZestTextField>();

  protected build(): Child {
    const header = adminHeader(this.context.path, t("app.issue.title"), t("app.issue.intro", { domain: this.context.configuration.domain }));
    return [...header.nodes, h("section", { class: "card" }, this.content.anchor, this.messages.element)];
  }

  protected async start(): Promise<void> {
    this.renderContent();
  }

  private chosen(): [string, string][] {
    return [...this.values].map(([type, field]): [string, string] => [type, field.value]).filter(([, value]) => value.trim());
  }

  private setWorking(working: boolean): void {
    this.working = working;
    this.inspectForm.setAttribute("aria-busy", String(working));
    this.checkButton.disabled = working;
    fill(this.checkButton, working ? t("app.issue.checking") : t("app.issue.check"));
    this.issueForm?.setAttribute("aria-busy", String(working));
    this.renderSignButton();
  }

  private renderSignButton(): void {
    if (!this.signButton) return;
    this.signButton.disabled = this.working || this.chosen().length === 0;
    fill(this.signButton, this.working ? t("app.issue.signing") : t("app.issue.sign"));
  }

  private renderContent(): void {
    const request = this.request;
    this.issueForm = undefined;
    this.signButton = undefined;
    this.values = new Map();
    if (!request) { this.content.set(this.inspectForm); return; }
    const intro = [
      h("p", null, formatted("app.issue.request_from", { subject: h("code", null, `${request.subjectUserId}@${request.subjectDomain}`) })),
      h("p", null, h("small", null, t("app.issue.request_until", { until: new Date(request.expiresAt).toLocaleString() }))),
    ];
    if (this.results.length) {
      this.content.set(...intro, ...this.results.map((result) => issueResult(result, request.subjectDomain)), button(t("app.issue.another"), { onClick: () => this.restart() }));
      return;
    }
    const fields = request.requestedClaimTypes.map((type) => {
      if (!request.issuableClaimTypes.includes(type)) return h("p", { class: "muted" }, t("app.issue.not_allowed", { label: claimTypeLabel(type) }));
      const field = textField("", { "aria-label": claimTypeLabel(type), on: { input: () => this.renderSignButton() } });
      this.values.set(type, field);
      return h("label", null, h("span", null, claimTypeLabel(type), " ", h("small", null, h("code", null, type))), field);
    });
    this.signButton = button(t("app.issue.sign"), { type: "submit" });
    this.issueForm = form({ "aria-busy": String(this.working), onSubmit: () => void this.issue() },
      h("p", null, t("app.issue.values_intro")),
      ...fields,
      h("div", { class: "button-row" }, this.signButton, textButton(t("app.common.cancel"), () => this.restart())));
    this.renderSignButton();
    this.content.set(...intro, this.issueForm);
  }

  private async inspect(): Promise<void> {
    this.request = undefined;
    this.results = [];
    this.messages.fail("");
    this.setWorking(true);
    try {
      const request = await api.browserIssuer.inspectSigningRequest({ signedRequest: this.code.value.trim() });
      if (!this.isActive()) return;
      this.request = request;
      this.renderContent();
    } catch (cause) {
      if (!this.isActive()) return;
      if (authenticationFailed(cause)) this.context.navigate("/app/login?next=/app/admin/issue");
      else this.messages.fail(cause instanceof Error && cause.message ? cause.message : t("app.issue.inspect_failed"));
    } finally {
      if (this.isActive()) this.setWorking(false);
    }
  }

  private async issue(): Promise<void> {
    const chosen = this.chosen();
    this.setWorking(true);
    this.messages.fail("");
    try {
      const response = await api.browserIssuer.issueForSigningRequest({ signedRequest: this.code.value.trim(), claimTypes: chosen.map(([type]) => type), claimValues: chosen.map(([, value]) => value.trim()) });
      if (!this.isActive()) return;
      this.results = response.results;
      this.renderContent();
    } catch (cause) {
      if (this.isActive()) this.messages.fail(cause instanceof Error && cause.message ? cause.message : t("app.issue.issue_failed"));
    } finally {
      if (this.isActive()) this.setWorking(false);
    }
  }

  private restart(): void {
    this.code.value = "";
    this.request = undefined;
    this.results = [];
    this.messages.fail("");
    this.renderContent();
  }
}
