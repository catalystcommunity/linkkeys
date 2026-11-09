// Domain policy: the claim type registry, translated names, trusted issuers,
// release rules, and the two policy previews.
import { api } from "../../transport";
import { t } from "../../i18n";
import { button, comboBox, fill, form, h, textButton, type Child } from "../../dom";
import type { ClaimTypeLabel, ClaimTypePolicy, PreviewIssuerPolicyResponse, PreviewReleasePolicyResponse, ReleaseRule, TrustedIssuer } from "../../generated/types.gen";
import { serviceMessage as message } from "../../ui-logic";
import { AdminPage, Slot, adminHeader, choices, claimTypeOptions, dispositionLabel, flagBox, list, numberText, plainField, setOptions, suggestField } from "./common";

const VALUE_TYPES = ["text", "url", "email", "bool", "int", "float", "decimal", "date", "timestamp", "opaque"];
const SET_RULES = ["user_self", "idp_on_request", "trusted_issuer_only", "admin_only", "deny"];
const SIGNING_RULES = ["self_signed", "verified", "attested", "unsigned"];
const DISPOSITIONS = ["forced_allow", "forced_deny"];

type ClaimTypeForm = { claimType: string; label: string; description: string; valueType: string; maxBytes: string; setRule: string; signingRule: string; userSettable: boolean; defaultAutoSign: boolean; requiresApproval: boolean; suggested: boolean };

const emptyClaimType = (): ClaimTypeForm => ({ claimType: "", label: "", description: "", valueType: "text", maxBytes: "33792", setRule: "user_self", signingRule: "self_signed", userSettable: false, defaultAutoSign: false, requiresApproval: false, suggested: false });

/** A table with a header row. */
function table(headings: string[], rows: HTMLTableRowElement[]): HTMLElement {
  return h("div", { class: "table-wrap" }, h("table", null,
    h("thead", null, h("tr", null, ...headings.map((text) => h("th", null, text)))),
    h("tbody", null, ...rows)));
}

function dash(values: string[]): string {
  return values.join(", ") || "—";
}

export class AdminPolicyPage extends AdminPage {
  private types: ClaimTypePolicy[] = [];
  private readonly typeRows = h("tbody");
  private readonly labelTable = new Slot();
  private readonly issuerTable = new Slot();
  private readonly ruleTable = new Slot();
  private readonly issuerResult = new Slot();
  private readonly releaseResult = new Slot();
  /** Each editable combo box that offers the claim types. */
  private readonly typeBoxes: ZestComboBox[] = [];

  // The claim type form.
  private readonly typeForm = {
    claimType: plainField(t("app.policy.field_type"), { required: true, placeholder: "pronouns" }),
    label: plainField(t("app.policy.field_name"), { required: true }),
    description: plainField(t("app.policy.field_description")),
    valueType: comboBox(t("app.policy.col_value_type"), choices(VALUE_TYPES), { value: "text" }),
    maxBytes: plainField(t("app.policy.field_max_bytes"), { inputmode: "numeric", required: true, value: "33792" }),
    setRule: comboBox(t("app.policy.col_set_rule"), choices(SET_RULES), { value: "user_self" }),
    signingRule: comboBox(t("app.policy.col_signing"), choices(SIGNING_RULES), { value: "self_signed" }),
    userSettable: flagBox(t("app.policy.flag_user_settable")),
    defaultAutoSign: flagBox(t("app.policy.flag_auto_sign")),
    requiresApproval: flagBox(t("app.policy.flag_approval")),
    suggested: flagBox(t("app.policy.flag_suggested")),
  };
  private typeFormElement!: HTMLFormElement;

  private readonly label = {
    claimType: this.typeBox(t("app.policy.col_type"), true),
    locale: plainField(t("app.policy.col_locale"), { placeholder: "es-ES", required: true }),
    label: plainField(t("app.policy.col_name"), { required: true }),
    description: plainField(t("app.policy.field_description")),
  };
  private readonly issuer = {
    claimType: this.typeBox(t("app.policy.col_type"), true),
    issuerDomain: plainField(t("app.policy.col_issuer"), { placeholder: "issuer.example", required: true }),
  };
  private readonly issuerTest = {
    subjectDomain: plainField(t("app.policy.field_subject_domain"), { placeholder: "example.com", required: true }),
    deniedDomains: plainField(t("app.policy.field_denied_domains"), { placeholder: t("app.policy.use_configured") }),
    deniedTlds: plainField(t("app.policy.field_denied_tlds"), { placeholder: t("app.policy.use_configured") }),
    issuerUserId: plainField(t("app.policy.field_issuer_user")),
    claimType: this.typeBox(t("app.policy.col_type"), false),
  };
  private readonly rule = {
    audience: plainField(t("app.policy.col_audience"), { value: "*", placeholder: "* or app.example", required: true }),
    claimType: this.typeBox(t("app.policy.col_type"), true),
    disposition: comboBox(t("app.policy.col_disposition"), choices(DISPOSITIONS, dispositionLabel), { value: "forced_allow" }),
  };
  private readonly release = {
    audience: plainField(t("app.policy.col_audience"), { placeholder: "app.example", required: true }),
    required: plainField(t("app.policy.field_required"), { placeholder: "display_name, email" }),
    optional: plainField(t("app.policy.field_optional"), { placeholder: "over_21" }),
    choices: plainField(t("app.policy.field_choices")),
    available: plainField(t("app.policy.field_available"), { placeholder: t("app.policy.all_requested") }),
    tempAudience: plainField(t("app.policy.field_temp_audience"), { placeholder: "* or app.example" }),
    tempClaimType: this.typeBox(t("app.policy.field_temp_type"), false),
    tempDisposition: comboBox(t("app.policy.field_temp_disposition"), choices(DISPOSITIONS, dispositionLabel), { value: "forced_allow" }),
  };

  private typeBox(label: string, required: boolean): ZestComboBox {
    const box = suggestField(label, [], { required });
    this.typeBoxes.push(box);
    return box;
  }

  private submit(text: string): ZestPushButton {
    return this.busy.control(button(text, { type: "submit" }));
  }

  protected build(): Child {
    const header = adminHeader(this.context.path, t("app.policy.title"), t("app.policy.intro"));
    const fields = this.typeForm;
    this.typeFormElement = this.busy.form(form({ id: "claim-type-form", class: "account-form", onSubmit: () => void this.saveType() },
      fields.claimType, fields.label, fields.description, fields.valueType, fields.maxBytes, fields.setRule, fields.signingRule,
      h("div", null, fields.userSettable, fields.defaultAutoSign, fields.requiresApproval, fields.suggested),
      h("div", { class: "button-row" }, this.submit(t("app.policy.type_save")), textButton(t("app.policy.clear"), () => this.fillTypeForm(emptyClaimType())))));
    const typeHeadings = [t("app.policy.col_type"), t("app.policy.col_name"), t("app.policy.col_value_type"), t("app.policy.col_set_rule"), t("app.policy.col_signing"), t("app.policy.col_flags")];
    const types = h("section", { class: "card" },
      h("h2", null, t("app.policy.types_title")), h("p", null, t("app.policy.types_intro")),
      h("div", { class: "table-wrap" }, h("table", null,
        h("thead", null, h("tr", null, ...[...typeHeadings, t("app.account.col_action")].map((text) => h("th", null, text)))),
        this.typeRows)),
      h("h3", null, t("app.policy.type_form_title")),
      this.typeFormElement);

    const labels = h("section", { class: "card" },
      h("h2", null, t("app.policy.labels_title")), h("p", null, t("app.policy.labels_intro")),
      this.labelTable.anchor,
      this.busy.form(form({ class: "account-form", onSubmit: () => this.saveLabel() },
        this.label.claimType, this.label.locale, this.label.label, this.label.description, this.submit(t("app.policy.label_save")))));

    const test = this.issuerTest;
    const issuers = h("section", { class: "card" },
      h("h2", null, t("app.policy.issuers_title")), h("p", null, t("app.policy.issuers_intro")),
      this.issuerTable.anchor,
      this.busy.form(form({ class: "account-form", onSubmit: () => this.addIssuer() },
        this.issuer.claimType, this.issuer.issuerDomain, this.submit(t("app.policy.issuer_add")))),
      h("h3", null, t("app.policy.issuer_preview_title")), h("p", null, t("app.policy.issuer_preview_intro")),
      form({ class: "account-form", onSubmit: () => void this.previewIssuer() },
        test.subjectDomain, test.deniedDomains, test.deniedTlds, test.issuerUserId, test.claimType, button(t("app.policy.preview"), { type: "submit" })),
      this.issuerResult.anchor);

    const release = this.release;
    const rules = h("section", { class: "card" },
      h("h2", null, t("app.policy.rules_title")), h("p", null, t("app.policy.rules_intro")),
      this.ruleTable.anchor,
      this.busy.form(form({ class: "account-form", onSubmit: () => this.saveRule() },
        this.rule.audience, this.rule.claimType, this.rule.disposition, this.submit(t("app.policy.rule_save")))),
      h("h3", null, t("app.policy.release_preview_title")), h("p", null, t("app.policy.release_preview_intro")),
      form({ class: "account-form", onSubmit: () => void this.previewRelease() },
        release.audience, release.required, release.optional, release.choices, release.available,
        release.tempAudience, release.tempClaimType, release.tempDisposition, button(t("app.policy.preview"), { type: "submit" })),
      this.releaseResult.anchor);

    return [...header.nodes, this.messages.element, types, labels, issuers, rules];
  }

  protected async start(): Promise<void> {
    await this.load(() => this.refresh(), () => t("app.policy.load_failed"));
  }

  protected async refresh(): Promise<void> {
    const [registry, names, trusted, released] = await Promise.all([api.admin.listClaimTypes({}), api.admin.listClaimTypeLabels({}), api.admin.listTrustedIssuers({}), api.admin.listReleaseRules({})]);
    if (!this.isActive()) return;
    this.types = registry.claimTypes;
    const options = claimTypeOptions(this.types);
    for (const box of this.typeBoxes) setOptions(box, options);
    this.renderTypes();
    this.renderLabels(names.labels);
    this.renderIssuers(trusted.trustedIssuers);
    this.renderRules(released.releaseRules);
  }

  private flags(type: ClaimTypePolicy): string {
    return [type.userSettable && t("app.policy.flag_user_settable"), type.defaultAutoSign && t("app.policy.flag_auto_sign"), type.requiresApproval && t("app.policy.flag_approval"), type.suggested && t("app.policy.flag_suggested")].filter(Boolean).join(", ");
  }

  private removeButton(control: <T extends { disabled: boolean }>(item: T) => T, name: string, work: () => Promise<unknown>): ZestPushButton {
    return control(textButton(t("app.common.remove"), () => this.confirmRemove(name, work)));
  }

  private renderTypes(): void {
    const control = this.busy.region("types");
    fill(this.typeRows, ...this.types.map((type) => h("tr", null,
      h("td", null, h("code", null, type.claimType)),
      h("td", null, type.label),
      h("td", null, type.valueType),
      h("td", null, type.setRule),
      h("td", null, type.signingRule),
      h("td", null, h("small", null, this.flags(type))),
      h("td", null, h("div", { class: "button-row" },
        textButton(t("app.policy.edit"), () => this.editType(type)),
        this.removeButton(control, type.claimType, () => api.admin.removeClaimType({ claimType: type.claimType })))))));
  }

  private renderLabels(labels: ClaimTypeLabel[]): void {
    const control = this.busy.region("labels");
    if (!labels.length) { this.labelTable.set(h("p", { class: "muted" }, t("app.policy.labels_empty"))); return; }
    const headings = [t("app.policy.col_type"), t("app.policy.col_locale"), t("app.policy.col_name"), t("app.policy.field_description"), t("app.account.col_action")];
    this.labelTable.set(table(headings, labels.map((entry) => h("tr", null,
      h("td", null, h("code", null, entry.claimType)),
      h("td", null, entry.locale),
      h("td", null, entry.label),
      h("td", null, entry.description ?? ""),
      h("td", null, this.removeButton(control, `${entry.claimType} (${entry.locale})`, () => api.admin.removeClaimTypeLabel({ claimType: entry.claimType, locale: entry.locale })))))));
  }

  private renderIssuers(issuers: TrustedIssuer[]): void {
    const control = this.busy.region("issuers");
    if (!issuers.length) { this.issuerTable.set(h("p", { class: "muted" }, t("app.policy.issuers_empty"))); return; }
    const headings = [t("app.policy.col_type"), t("app.policy.col_issuer"), t("app.account.col_action")];
    this.issuerTable.set(table(headings, issuers.map((entry) => h("tr", null,
      h("td", null, h("code", null, entry.claimType)),
      h("td", null, entry.issuerDomain),
      h("td", null, this.removeButton(control, `${entry.issuerDomain} → ${entry.claimType}`, () => api.admin.removeTrustedIssuer({ claimType: entry.claimType, issuerDomain: entry.issuerDomain })))))));
  }

  private renderRules(rules: ReleaseRule[]): void {
    const control = this.busy.region("rules");
    if (!rules.length) { this.ruleTable.set(h("p", { class: "muted" }, t("app.policy.rules_empty"))); return; }
    const headings = [t("app.policy.col_audience"), t("app.policy.col_type"), t("app.policy.col_disposition"), t("app.account.col_action")];
    this.ruleTable.set(table(headings, rules.map((entry) => h("tr", null,
      h("td", null, h("code", null, entry.audience)),
      h("td", null, h("code", null, entry.claimType)),
      h("td", null, dispositionLabel(entry.disposition)),
      h("td", null, this.removeButton(control, `${entry.audience} / ${entry.claimType}`, () => api.admin.removeReleaseRule({ audience: entry.audience, claimType: entry.claimType })))))));
  }

  private confirmRemove(name: string, work: () => Promise<unknown>): void {
    if (window.confirm(t("app.policy.remove_confirm", { name }))) void this.act(work, t("app.policy.removed"), t("app.policy.remove_failed"));
  }

  /** Set each control of the claim type form. */
  private fillTypeForm(value: ClaimTypeForm): void {
    const fields = this.typeForm;
    fields.claimType.value = value.claimType;
    fields.label.value = value.label;
    fields.description.value = value.description;
    fields.valueType.value = value.valueType;
    fields.maxBytes.value = value.maxBytes;
    fields.setRule.value = value.setRule;
    fields.signingRule.value = value.signingRule;
    fields.userSettable.checked = value.userSettable;
    fields.defaultAutoSign.checked = value.defaultAutoSign;
    fields.requiresApproval.checked = value.requiresApproval;
    fields.suggested.checked = value.suggested;
  }

  private editType(type: ClaimTypePolicy): void {
    this.fillTypeForm({ claimType: type.claimType, label: type.label, description: type.description, valueType: type.valueType, maxBytes: String(type.maxBytes), setRule: type.setRule, signingRule: type.signingRule, userSettable: type.userSettable, defaultAutoSign: type.defaultAutoSign, requiresApproval: type.requiresApproval, suggested: type.suggested });
    this.typeFormElement.scrollIntoView({ behavior: "smooth" });
  }

  private async saveType(): Promise<void> {
    const fields = this.typeForm;
    const maxBytesText = fields.maxBytes.value;
    const maxBytes = Number(maxBytesText);
    // The original `type=number` input refused text that is not a number.
    if (!numberText(maxBytesText) || !Number.isInteger(maxBytes) || maxBytes <= 0) return this.messages.fail(t("app.policy.max_bytes_invalid"));
    const request = {
      claimType: fields.claimType.value.trim(), label: fields.label.value.trim(), description: fields.description.value.trim() || undefined,
      valueType: fields.valueType.value, maxBytes, setRule: fields.setRule.value, signingRule: fields.signingRule.value,
      userSettable: fields.userSettable.checked, defaultAutoSign: fields.defaultAutoSign.checked, requiresApproval: fields.requiresApproval.checked, suggested: fields.suggested.checked,
    };
    if (await this.act(() => api.admin.setClaimType(request), t("app.policy.type_saved"), t("app.policy.type_save_failed"))) this.fillTypeForm(emptyClaimType());
  }

  private saveLabel(): void {
    const value = this.label;
    const request = { claimType: value.claimType.value, locale: value.locale.value.trim(), label: value.label.value.trim(), description: value.description.value.trim() || undefined };
    void this.act(() => api.admin.setClaimTypeLabel(request), t("app.policy.label_saved"), t("app.policy.label_save_failed"));
  }

  private addIssuer(): void {
    const request = { claimType: this.issuer.claimType.value, issuerDomain: this.issuer.issuerDomain.value.trim() };
    void this.act(() => api.admin.addTrustedIssuer(request), t("app.policy.issuer_added"), t("app.policy.issuer_add_failed"));
  }

  private saveRule(): void {
    const request = { audience: this.rule.audience.value.trim(), claimType: this.rule.claimType.value, disposition: this.rule.disposition.value };
    void this.act(() => api.admin.setReleaseRule(request), t("app.policy.rule_saved"), t("app.policy.rule_save_failed"));
  }

  private releaseRequest = 0;

  private async previewRelease(): Promise<void> {
    this.messages.fail("");
    const value = this.release;
    const tempClaimType = value.tempClaimType.value.trim();
    const request = ++this.releaseRequest;
    try {
      const result = await api.admin.previewReleasePolicy({
        audience: value.audience.value.trim(), requiredClaims: list(value.required.value), optionalClaims: list(value.optional.value),
        availableClaims: list(value.available.value), userChoices: list(value.choices.value),
        tempAudience: value.tempAudience.value.trim() || undefined, tempClaimType: tempClaimType || undefined, tempDisposition: tempClaimType ? value.tempDisposition.value : undefined,
      });
      if (this.isActive() && request === this.releaseRequest) this.releaseResult.set(this.releaseView(result));
    } catch (cause) {
      if (this.isActive() && request === this.releaseRequest) this.messages.fail(message(cause, t("app.policy.preview_failed")));
    }
  }

  private releaseView(result: PreviewReleasePolicyResponse): HTMLElement {
    const headings = [t("app.policy.col_type"), t("app.policy.col_requested"), t("app.policy.col_available"), t("app.policy.col_disposition"), t("app.policy.col_starts")];
    return h("div", { class: "notice" },
      h("p", null, t("app.policy.preview_shared", { claims: dash(result.authorizedClaims) })),
      h("p", null, h("small", null, t("app.policy.preview_rules", { allow: dash(result.forcedAllow), deny: dash(result.forcedDeny) }))),
      table(headings, result.rows.map((row) => h("tr", null,
        h("td", null, h("code", null, row.claimType)),
        h("td", null, row.required ? t("app.policy.required") : t("app.policy.optional")),
        h("td", null, row.available ? t("app.common.yes") : t("app.common.no")),
        h("td", null, dispositionLabel(row.policy), row.locked ? ` (${t("app.policy.locked")})` : ""),
        h("td", null, row.defaultGranted ? t("app.policy.checked") : t("app.policy.unchecked"))))));
  }

  private issuerRequest = 0;

  private async previewIssuer(): Promise<void> {
    this.messages.fail("");
    const value = this.issuerTest;
    const request = ++this.issuerRequest;
    try {
      const result = await api.admin.previewIssuerPolicy({
        subjectDomain: value.subjectDomain.value.trim(),
        deniedDomains: value.deniedDomains.value.trim() ? list(value.deniedDomains.value) : undefined,
        deniedTlds: value.deniedTlds.value.trim() ? list(value.deniedTlds.value) : undefined,
        issuerUserId: value.issuerUserId.value.trim() || undefined,
        claimType: value.claimType.value.trim() || undefined,
      });
      if (this.isActive() && request === this.issuerRequest) this.issuerResult.set(this.issuerView(result));
    } catch (cause) {
      if (this.isActive() && request === this.issuerRequest) this.messages.fail(message(cause, t("app.policy.preview_failed")));
    }
  }

  private issuerView(result: PreviewIssuerPolicyResponse): HTMLElement {
    return h("div", { class: "notice" },
      h("p", null, result.allowed ? t("app.policy.issuer_allowed") : t("app.policy.issuer_denied"), " ", h("small", null, `(${result.reason})`)),
      h("p", null, h("small", null, t("app.policy.denies_used", { domains: dash(result.deniedDomains), tlds: dash(result.deniedTlds) }))),
      result.userCanIssue !== undefined && h("p", null, result.userCanIssue ? t("app.policy.user_can_issue") : t("app.policy.user_cannot_issue")),
      h("p", null, h("small", null, t("app.policy.claim_ttl", { seconds: result.attestedClaimTtlSeconds }))));
  }
}
