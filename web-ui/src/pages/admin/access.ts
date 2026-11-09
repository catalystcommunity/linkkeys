// App access: policies that allow or deny sign-in to apps, by domain
// pattern and by who signs in, and a test of one account against them.
import { api } from "../../transport";
import { claimTypeLabel, t } from "../../i18n";
import { button, comboBox, fill, form, h, textArea, textButton, type Child } from "../../dom";
import type { AdminUser, AppAccessPolicy, AppAccessTarget, ClaimTypePolicy, PreviewAppAccessResponse } from "../../generated/types.gen";
import { patternList, serviceMessage as message } from "../../ui-logic";
import { AdminPage, Slot, adminHeader, choices, claimTypeOptions, numberText, plainField, setOptions, suggestField, userOptions } from "./common";

const ACCESS_MODES = ["deny", "allow"];
const TARGET_KINDS = ["everyone", "user", "group", "claim"];
const CLAIM_OPERATORS = ["present", "absent", "equals", "age_under", "age_at_least"];

function accessModeLabel(mode: string): string {
  return mode === "allow" ? t("app.access.mode_allow") : t("app.access.mode_deny");
}

function operatorLabel(operator: string): string {
  return t(`app.access.operator_${operator}`);
}

function takesValue(operator: string): boolean {
  return !["present", "absent"].includes(operator);
}

export class AdminAccessPage extends AdminPage {
  private users: AdminUser[] = [];
  private types: ClaimTypePolicy[] = [];
  private readonly policyTable = new Slot();
  private readonly testResult = new Slot();

  // The policy form. `editing` is the id of the stored policy that it edits.
  private editing?: string;
  private targets: AppAccessTarget[] = [];
  private readonly formHeading = h("h2");
  private readonly name = plainField(t("app.access.col_name"), { required: true, on: { input: () => this.renderFormHeading() } });
  private readonly mode = comboBox(t("app.access.col_mode"), choices(ACCESS_MODES, accessModeLabel), { value: "deny" });
  private readonly patterns = textArea(t("app.access.col_patterns"), { rows: 4, placeholder: "*.ru\nshop.example", helper: t("app.access.patterns_help"), required: true });
  private readonly message = textArea(t("app.access.field_message"), { rows: 2, maxlength: 1000, helper: t("app.access.message_help") });
  private readonly targetList = new Slot();

  // The target builder. Its fields show by kind and by operator.
  private readonly kind = comboBox(t("app.access.target_kind"), choices(TARGET_KINDS, (kind) => t(`app.access.kind_${kind}`)), { value: "user", on: { change: () => this.renderTargetFields() } });
  private readonly targetUser = suggestField(t("app.admin.col_username"));
  private readonly groupName = plainField(t("app.access.field_group"));
  private readonly claimType = suggestField(t("app.access.field_claim_type"));
  private readonly operator = comboBox(t("app.access.field_condition"), choices(CLAIM_OPERATORS, operatorLabel), { value: "age_under", on: { change: () => this.renderTargetFields() } });
  private readonly claimValue = plainField("");
  private readonly kindSlot = new Slot();
  private readonly valueSlot = new Slot();
  private readonly claimHelp = new Slot();

  // The test form.
  private readonly testUser = suggestField(t("app.admin.col_username"), [], { required: true });
  private readonly testDomain = plainField(t("app.access.field_domain"), { placeholder: t("app.access.local_app") });
  private formSection!: HTMLElement;
  private testRequest = 0;

  protected build(): Child {
    const header = adminHeader(this.context.path, t("app.access.title"), t("app.access.intro"));
    const list = h("section", { class: "card" }, h("h2", null, t("app.access.list_title")), h("p", null, t("app.access.rules")), this.policyTable.anchor);
    const builder = h("div", { class: "inline-form" },
      this.kind, this.kindSlot.anchor,
      button(t("app.access.add_target"), { onClick: () => this.addTarget() }));
    const policyForm = this.busy.form(form({ class: "account-form", onSubmit: () => void this.save() },
      this.name, this.mode, this.patterns, this.message,
      h("fieldset", null, h("legend", null, t("app.access.col_targets")), this.targetList.anchor, builder, this.claimHelp.anchor),
      h("div", { class: "button-row" },
        this.busy.control(button(t("app.access.save"), { type: "submit" })),
        textButton(t("app.policy.clear"), () => { this.fillForm(); this.resetTarget("user"); }))));
    this.formSection = h("section", { class: "card", id: "access-policy-form" }, this.formHeading, policyForm);
    const test = h("section", { class: "card" }, h("h2", null, t("app.access.test_title")), h("p", null, t("app.access.test_intro")),
      form({ class: "inline-form", onSubmit: () => void this.runTest() }, this.testUser, this.testDomain, button(t("app.policy.preview"), { type: "submit" })),
      this.testResult.anchor);
    return [...header.nodes, this.messages.element, list, this.formSection, test];
  }

  protected async start(): Promise<void> {
    this.renderFormHeading();
    this.renderTargets();
    this.renderTargetFields();
    this.renderPolicies([]);
    await this.load(async () => {
      const [stored, accounts, registry] = await Promise.all([api.admin.listAppAccessPolicies({}), api.admin.listUsers({ limit: 1000 }), api.admin.listClaimTypes({})]);
      if (!this.isActive()) return;
      this.users = accounts.users.filter((user) => !user.purgedAt);
      this.types = registry.claimTypes;
      for (const box of [this.targetUser, this.testUser]) setOptions(box, userOptions(this.users));
      setOptions(this.claimType, claimTypeOptions(this.types));
      this.renderPolicies(stored.policies);
      this.renderTargets();
    }, () => t("app.access.load_failed"));
  }

  protected async refresh(): Promise<void> {
    const policies = (await api.admin.listAppAccessPolicies({})).policies;
    if (this.isActive()) this.renderPolicies(policies);
  }

  private userById(id?: string): AdminUser | undefined {
    return this.users.find((user) => user.id === id);
  }

  private userByName(name: string): AdminUser | undefined {
    return this.users.find((user) => user.username === name.trim() || user.id === name.trim());
  }

  private targetText(entry: AppAccessTarget): string {
    switch (entry.kind) {
      case "everyone": return t("app.access.target_everyone");
      case "user": return t("app.access.target_user", { user: this.userById(entry.userId)?.username ?? entry.userId ?? "" });
      case "group": return t("app.access.target_group", { group: entry.groupName ?? "" });
      default: return t("app.access.target_claim", { label: claimTypeLabel(entry.claimType ?? ""), condition: operatorLabel(entry.claimOperator ?? ""), value: entry.claimValue ?? "" }).trim();
    }
  }

  private renderPolicies(policies: AppAccessPolicy[]): void {
    const control = this.busy.region("policies");
    if (!policies.length) { this.policyTable.set(h("p", { class: "muted" }, t("app.access.empty"))); return; }
    const headings = [t("app.access.col_name"), t("app.access.col_mode"), t("app.access.col_patterns"), t("app.access.col_targets"), t("app.access.col_message")];
    this.policyTable.set(h("div", { class: "table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, ...[...headings, t("app.account.col_action")].map((text) => h("th", null, text)))),
      h("tbody", null, ...policies.map((policy) => h("tr", null,
        h("td", null, policy.name),
        h("td", null, h("span", { class: "pill" }, accessModeLabel(policy.mode))),
        h("td", null, ...policy.patterns.map((pattern) => [h("code", null, pattern), " "])),
        h("td", null, policy.targets.length ? h("small", null, policy.targets.map((entry) => this.targetText(entry)).join("; ")) : h("small", { class: "muted" }, t("app.access.targets_none"))),
        h("td", null, h("small", null, policy.message ?? "")),
        h("td", null, h("div", { class: "button-row" },
          textButton(t("app.policy.edit"), () => this.editPolicy(policy)),
          control(textButton(t("app.common.remove"), () => void this.removePolicy(policy)))))))))));
  }

  private renderFormHeading(): void {
    fill(this.formHeading, this.editing ? t("app.access.form_edit_title", { name: this.name.value }) : t("app.access.form_title"));
  }

  private renderTargets(): void {
    if (!this.targets.length) { this.targetList.set(h("p", { class: "muted" }, t("app.access.targets_none"))); return; }
    this.targetList.set(h("ul", null, ...this.targets.map((entry, index) => h("li", null,
      this.targetText(entry), " ",
      textButton(t("app.common.remove"), () => { this.targets = this.targets.filter((_, position) => position !== index); this.renderTargets(); })))));
  }

  /** Show the builder fields for the kind and the operator. Only this part of the form changes. */
  private renderTargetFields(): void {
    const kind = this.kind.value;
    const operator = this.operator.value;
    const age = operator.startsWith("age_");
    this.claimValue.label = age ? t("app.access.field_age") : t("app.account.field_value");
    if (age) this.claimValue.setAttribute("inputmode", "numeric");
    else this.claimValue.removeAttribute("inputmode");
    const fields: Child[] = kind === "user" ? [this.targetUser] : kind === "group" ? [this.groupName] : kind === "claim" ? [this.claimType, this.operator, this.valueSlot.anchor] : [];
    // The value slot is inside the kind slot, so it empties first.
    if (kind !== "claim") this.valueSlot.set();
    if (!this.sameFields(fields)) this.kindSlot.set(...fields);
    if (kind === "claim") this.valueSlot.set(takesValue(operator) ? this.claimValue : null);
    this.claimHelp.set(kind === "claim" ? h("small", null, t("app.access.claim_help")) : null);
  }

  private shownFields: Child[] = [];

  /** True when the slot already shows these fields, so that the focus stays. */
  private sameFields(fields: Child[]): boolean {
    const same = fields.length === this.shownFields.length && fields.every((field, index) => field === this.shownFields[index]);
    this.shownFields = fields;
    return same;
  }

  private resetTarget(kind: string): void {
    this.kind.value = kind;
    this.targetUser.value = "";
    this.groupName.value = "";
    this.claimType.value = "";
    this.operator.value = "age_under";
    this.claimValue.value = "";
    this.renderTargetFields();
  }

  private addTarget(): void {
    this.messages.fail("");
    const kind = this.kind.value;
    let next: AppAccessTarget;
    if (kind === "user") {
      const user = this.userByName(this.targetUser.value);
      if (!user) return this.messages.fail(t("app.access.user_unknown", { user: this.targetUser.value.trim() }));
      next = { kind: "user", userId: user.id };
    } else if (kind === "group") {
      const groupName = this.groupName.value.trim();
      if (!groupName) return this.messages.fail(t("app.access.group_required"));
      next = { kind: "group", groupName };
    } else if (kind === "claim") {
      const claimType = this.claimType.value.trim();
      if (!claimType) return this.messages.fail(t("app.access.claim_required"));
      const operator = this.operator.value;
      const value = this.claimValue.value.trim();
      const withValue = takesValue(operator);
      // An age field was a `type=number` input: text that is not a number had no value.
      const valid = operator.startsWith("age_") ? numberText(value) : Boolean(value);
      if (withValue && !valid) return this.messages.fail(t("app.access.value_required"));
      next = { kind: "claim", claimType, claimOperator: operator, claimValue: withValue ? value : undefined };
    } else next = { kind: "everyone" };
    this.targets = [...this.targets, next];
    this.renderTargets();
    this.resetTarget(kind);
  }

  /** Set each control of the policy form, or clear the form. */
  private fillForm(policy?: AppAccessPolicy): void {
    this.editing = policy?.id;
    this.name.value = policy?.name ?? "";
    this.mode.value = policy?.mode ?? "deny";
    this.patterns.value = policy?.patterns.join("\n") ?? "";
    this.message.value = policy?.message ?? "";
    this.targets = policy ? [...policy.targets] : [];
    this.renderFormHeading();
    this.renderTargets();
  }

  private editPolicy(policy: AppAccessPolicy): void {
    this.fillForm(policy);
    this.formSection.scrollIntoView({ behavior: "smooth" });
  }

  private async save(): Promise<void> {
    const name = this.name.value.trim();
    const request = { id: this.editing, name, mode: this.mode.value, patterns: patternList(this.patterns.value), message: this.message.value.trim() || undefined, targets: this.targets };
    this.busy.set(true);
    this.messages.clear();
    try {
      await api.admin.setAppAccessPolicy(request);
      if (!this.isActive()) return;
      await this.refresh();
      if (!this.isActive()) return;
      this.fillForm();
      this.messages.status(t("app.access.saved", { name }));
    } catch (cause) {
      if (this.isActive()) this.messages.fail(message(cause, t("app.access.save_failed")));
    } finally {
      if (this.isActive()) this.busy.set(false);
    }
  }

  private async removePolicy(policy: AppAccessPolicy): Promise<void> {
    if (!window.confirm(t("app.policy.remove_confirm", { name: policy.name }))) return;
    this.busy.set(true);
    this.messages.clear();
    try {
      await api.admin.removeAppAccessPolicy({ id: policy.id });
      if (!this.isActive()) return;
      await this.refresh();
      if (!this.isActive()) return;
      if (this.editing === policy.id) this.fillForm();
      this.messages.status(t("app.policy.removed"));
    } catch (cause) {
      if (this.isActive()) this.messages.fail(message(cause, t("app.policy.remove_failed")));
    } finally {
      if (this.isActive()) this.busy.set(false);
    }
  }

  private async runTest(): Promise<void> {
    this.messages.fail("");
    this.testResult.set();
    const request = ++this.testRequest;
    const user = this.userByName(this.testUser.value);
    if (!user) return this.messages.fail(t("app.access.user_unknown", { user: this.testUser.value.trim() }));
    try {
      const result = await api.admin.previewAppAccess({ userId: user.id, domain: this.testDomain.value.trim() || undefined });
      if (this.isActive() && request === this.testRequest) this.testResult.set(this.testView(result));
    } catch (cause) {
      if (this.isActive() && request === this.testRequest) this.messages.fail(message(cause, t("app.policy.preview_failed")));
    }
  }

  private testView(result: PreviewAppAccessResponse): HTMLElement {
    return h("div", { class: result.allowed ? "notice good" : "notice bad" },
      h("p", null, result.allowed ? t("app.access.test_allowed") : t("app.access.test_blocked", { policies: result.blockingPolicies.join(", ") })),
      h("p", null, h("small", null, t("app.access.test_applied", { policies: result.appliedPolicies.join(", ") || "—" }))),
      ...result.messages.map((text) => h("p", null, h("small", null, text))));
  }
}
