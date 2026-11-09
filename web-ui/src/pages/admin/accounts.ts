// The account list, and the page for one account.
import { api } from "../../transport";
import { claimTypeLabel, t } from "../../i18n";
import { button, comboBox, fill, form, h, hiddenUsername, link, nodes, textButton, textField, type Child } from "../../dom";
import { checkPassword, claimText, passwordRule, type PageProps } from "../../shared";
import type { AdminUser, Claim, ClaimTypePolicy, Relation, UserAuthenticationActivity } from "../../generated/types.gen";
import { serviceMessage as message } from "../../ui-logic";
import { AdminPage, Slot, adminHeader, choices, claimTypeOptions, setOptions, suggestField, when } from "./common";

const RELATIONS = ["admin", "manage_users", "manage_claims", "api_access", "issue_claims", "ui_extension"];
const OBJECT_TYPES = ["domain", "claim_type"];

/** The form that gives a disabled account a new password and turns it on. */
function reactivateForm(props: { userId: string; username: string; configuration: PageProps["configuration"]; complete(): Promise<void>; fail(text: string): void }): HTMLFormElement {
  const password = textField("", { type: "password", autocomplete: "new-password", required: true, "aria-label": t("app.admin.new_password_for", { username: props.username }) });
  const confirmation = textField("", { type: "password", autocomplete: "new-password", required: true, "aria-label": t("app.admin.confirm_password_for", { username: props.username }) });
  const submit = button(t("app.admin.restore_submit"), { type: "submit" });
  const setBusy = (busy: boolean) => { element.setAttribute("aria-busy", String(busy)); submit.disabled = busy; };
  const element = form({ class: "stacked-action", onSubmit: async () => {
    if (password.value !== confirmation.value) return props.fail(t("app.password.mismatch_new"));
    const lengthError = checkPassword(password.value, props.configuration);
    if (lengthError) return props.fail(lengthError);
    setBusy(true);
    try {
      await api.admin.resetPassword({ userId: props.userId, newPassword: password.value });
      await api.admin.activateUser({ userId: props.userId });
      password.value = "";
      confirmation.value = "";
      await props.complete();
    } catch {
      props.fail(t("app.admin.restore_failed", { username: props.username }));
    } finally {
      setBusy(false);
    }
  } }, h("small", null, passwordRule(props.configuration)), password, confirmation, submit);
  return element;
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

const PAGE_SIZE = 50;

export class AdminAccountsPage extends AdminPage {
  private users: AdminUser[] = [];
  private hasMore = false;
  private failureShown = false;
  private readonly card = h("section", { class: "card" });
  private readonly rows = h("tbody");
  private readonly moreSlot = new Slot();
  private rowControl = this.busy.region("rows");
  private readonly username = textField(t("app.admin.username"), { autocomplete: "off", maxlength: 254, required: true });
  private readonly displayName = textField(t("app.admin.display_name"), { maxlength: 254, required: true });
  private readonly password = textField(t("app.admin.initial_password"), { type: "password", autocomplete: "new-password", "aria-describedby": "admin-password-rule", required: true });
  private readonly confirmation = textField(t("app.admin.confirm_initial_password"), { type: "password", autocomplete: "new-password", required: true });
  private readonly moreButton = this.busy.control(button(t("app.admin.load_more"), { onClick: () => void this.loadMore() }));
  private content: Node[] = [];

  protected build(): Child {
    const context = this.context;
    const failures = context.extensionFailures ?? [];
    const createForm = this.busy.form(form({ class: "account-form", onSubmit: () => void this.createUser() },
      h("p", { id: "admin-password-rule" }, passwordRule(context.configuration)),
      this.username, this.displayName, this.password, this.confirmation,
      this.busy.control(button(t("app.admin.create"), { type: "submit" }))));
    const headings = [t("app.admin.col_username"), t("app.admin.col_display_name"), t("app.admin.col_status"), t("app.admin.col_created"), t("app.admin.col_action")].map((text) => h("th", null, text));
    this.content = nodes([
      failures.length > 0 && h("p", { class: "operator-warning", role: "status" }, t("app.admin.extension_failures", { names: failures.join(", ") })),
      createForm,
      h("div", { class: "table-wrap" }, h("table", null, h("thead", null, h("tr", null, ...headings)), this.rows)),
      this.moreSlot.anchor,
      this.messages.element,
    ]);
    this.card.append(...this.content);
    return [...adminHeader(context.path, t("app.admin.title"), t("app.admin.intro", { domain: context.configuration.domain })).nodes, this.card];
  }

  protected async start(): Promise<void> {
    await this.load(() => this.refresh(), () => t("app.admin.no_access"));
  }

  protected showLoadError(text: string): void {
    this.messages.fail(text);
    this.renderCard();
  }

  protected async refresh(): Promise<void> {
    const result = (await api.admin.listUsers({ limit: PAGE_SIZE + 1 })).users;
    if (!this.isActive()) return;
    this.users = result.slice(0, PAGE_SIZE);
    this.hasMore = result.length > PAGE_SIZE;
    this.rowControl = this.busy.region("rows");
    fill(this.rows, ...this.users.map((user) => this.row(user)));
    this.renderCard();
    this.renderMore();
  }

  /** With a problem and no accounts, the card shows only the problem. */
  private renderCard(): void {
    const failure = Boolean(this.messages.error) && this.users.length === 0;
    if (failure === this.failureShown) return;
    this.failureShown = failure;
    if (failure) this.card.replaceChildren(h("p", { class: "notice bad", role: "alert" }, this.messages.error));
    else this.card.replaceChildren(...this.content);
  }

  private renderMore(): void {
    fill(this.moreButton, this.busy.active ? t("app.admin.loading") : t("app.admin.load_more"));
    if (this.hasMore && this.moreSlot.empty) this.moreSlot.set(this.moreButton);
    if (!this.hasMore) this.moreSlot.set();
  }

  private setBusy(busy: boolean): void {
    this.busy.set(busy);
    this.renderMore();
  }

  private row(user: AdminUser): HTMLTableRowElement {
    let action: Child;
    if (user.id === this.context.session?.user.id) action = h("span", { class: "muted" }, t("app.admin.current_account"));
    else if (user.isActive) action = this.rowControl(textButton(t("app.admin.disable"), () => void this.deactivate(user.id, user.username), { "aria-label": t("app.admin.disable_label", { username: user.username }) }));
    else action = reactivateForm({
      userId: user.id, username: user.username, configuration: this.context.configuration,
      fail: (text) => { this.messages.fail(text); this.renderCard(); },
      complete: async () => { await this.refresh(); if (this.isActive()) this.messages.status(t("app.admin.restored", { username: user.username })); },
    });
    return h("tr", null,
      h("td", null, link(`/app/admin/users/${encodeURIComponent(user.id)}`, h("code", null, user.username))),
      h("td", null, user.displayName),
      h("td", null, h("span", { class: "pill" }, user.isActive ? t("app.admin.status_active") : t("app.admin.status_disabled"))),
      h("td", null, new Date(user.createdAt).toLocaleDateString()),
      h("td", null, action));
  }

  private async loadMore(): Promise<void> {
    this.setBusy(true);
    this.messages.fail("");
    try {
      const result = (await api.admin.listUsers({ offset: this.users.length, limit: PAGE_SIZE + 1 })).users;
      if (!this.isActive()) return;
      const added = result.slice(0, PAGE_SIZE);
      this.users = [...this.users, ...added];
      this.hasMore = result.length > PAGE_SIZE;
      this.rows.append(...added.map((user) => this.row(user)));
    } catch (cause) {
      if (this.isActive()) this.messages.fail(message(cause, t("app.admin.load_more_failed")));
    } finally {
      if (this.isActive()) this.setBusy(false);
    }
  }

  private async createUser(): Promise<void> {
    this.messages.clear();
    if (this.password.value !== this.confirmation.value) return this.messages.fail(t("app.password.mismatch"));
    const lengthError = checkPassword(this.password.value, this.context.configuration);
    if (lengthError) return this.messages.fail(lengthError);
    this.setBusy(true);
    try {
      await api.admin.createUser({ username: this.username.value, displayName: this.displayName.value, password: this.password.value });
      if (!this.isActive()) return;
      for (const field of [this.username, this.displayName, this.password, this.confirmation]) field.value = "";
      await this.refresh();
      if (this.isActive()) this.messages.status(t("app.admin.created"));
    } catch (cause) {
      if (this.isActive()) this.messages.fail(message(cause, t("app.admin.create_failed")));
    } finally {
      if (this.isActive()) this.setBusy(false);
    }
  }

  private async deactivate(userId: string, username: string): Promise<void> {
    if (!window.confirm(t("app.admin.disable_confirm", { username }))) return;
    this.setBusy(true);
    this.messages.clear();
    try {
      await api.admin.deactivateUser({ userId });
      if (!this.isActive()) return;
      await this.refresh();
      if (this.isActive()) this.messages.status(t("app.admin.disabled", { username }));
    } catch (cause) {
      if (this.isActive()) this.messages.fail(message(cause, t("app.admin.disable_failed")));
    } finally {
      if (this.isActive()) this.setBusy(false);
    }
  }
}

// ---------------------------------------------------------------------------
// One account
// ---------------------------------------------------------------------------

export class AdminUserPage extends AdminPage {
  userId = "";
  private user?: AdminUser;
  private activity?: UserAuthenticationActivity;
  private claims: Claim[] = [];
  private relations: Relation[] = [];
  private claimTypes: ClaimTypePolicy[] = [];
  private heading!: HTMLHeadingElement;
  private readonly body = new Slot();
  private readonly placeholder = h("p", { role: "status" }, t("app.admin_user.loading"));
  private sectionsBuilt = false;

  // The parts that change after a load.
  private readonly facts = h("dl", { class: "facts" });
  private readonly statusSlot = new Slot();
  private statusActive?: boolean;
  private readonly passwordSlot = new Slot();
  private passwordShown = false;
  private readonly claimTable = new Slot();
  private readonly relationTable = new Slot();

  private readonly displayName = textField(t("app.admin.display_name"), { maxlength: 254, required: true });
  private readonly claimType = suggestField(t("app.account.field_detail"), [], { required: true });
  private readonly claimValue = textField(t("app.account.field_value"), { required: true });
  private readonly expires = h("date-time-picker", { mode: "date" });
  private readonly relation = comboBox(t("app.admin_user.col_relation"), choices(RELATIONS), { value: "manage_claims" });
  private readonly objectType = comboBox(t("app.admin_user.object_type"), choices(OBJECT_TYPES), { value: "domain", on: { change: () => this.objectTypeChanged() } });
  private readonly objectId = suggestField(t("app.admin_user.object_id"), [], { required: true });
  private lock?: ZestCheckBox;

  private get self(): boolean {
    return this.userId === this.context.session?.user.id;
  }

  protected build(): Child {
    const header = adminHeader(this.context.path, t("app.admin_user.title"));
    this.heading = header.heading;
    this.objectId.setAttribute("value", this.context.configuration.domain);
    return [...header.nodes, this.body.anchor];
  }

  protected async start(): Promise<void> {
    this.body.set(h("section", { class: "card" }, this.placeholder));
    await this.load(async () => {
      await this.refresh();
      const registry = await api.admin.listClaimTypes({});
      if (!this.isActive()) return;
      this.claimTypes = registry.claimTypes;
      setOptions(this.claimType, claimTypeOptions(this.claimTypes));
      this.objectTypeOptions();
    }, () => t("app.admin_user.load_failed"));
  }

  protected showLoadError(text: string): void {
    this.messages.fail(text);
    if (!this.user) {
      this.placeholder.setAttribute("role", "alert");
      fill(this.placeholder, text);
    }
  }

  protected async refresh(): Promise<void> {
    const userId = this.userId;
    const [found, seen, held, granted] = await Promise.all([
      api.admin.getUser({ userId }),
      api.admin.getUserAuthenticationActivity({ userId }),
      api.admin.getUserClaims({ userId }),
      api.admin.listRelations({ subjectType: "user", subjectId: userId }),
    ]);
    if (!this.isActive()) return;
    this.user = found.user;
    this.activity = seen.activity;
    this.claims = held.claims;
    this.relations = granted.relations.filter((entry) => !entry.removedAt);
    this.displayName.value = found.user.displayName;
    this.renderSections();
  }

  private renderSections(): void {
    const user = this.user!;
    if (!this.sectionsBuilt) this.buildSections();
    fill(this.heading, user.displayName);
    this.renderFacts(user);
    this.renderStatusAction(user);
    this.renderPassword(user);
    this.renderClaims();
    this.renderRelations();
  }

  private buildSections(): void {
    this.sectionsBuilt = true;
    const nameForm = this.busy.form(form({ class: "inline-form", onSubmit: () => void this.saveName() },
      this.displayName, this.busy.control(button(t("app.admin_user.save_name"), { type: "submit" }))));
    const summary = h("section", { class: "card" }, h("h2", null, t("app.admin_user.summary")), this.facts, nameForm, this.statusSlot.anchor, this.messages.element);
    const claimForm = this.busy.form(form({ class: "account-form", onSubmit: () => void this.addClaim() },
      this.claimType, this.claimValue,
      h("label", null, h("span", null, t("app.admin_user.expires_optional")), this.expires),
      this.busy.control(button(t("app.admin_user.add_claim"), { type: "submit" }))));
    const claims = h("section", { class: "card" }, h("h2", null, t("app.admin_user.claims_title")), this.claimTable.anchor, claimForm);
    const grantForm = this.busy.form(form({ class: "account-form", onSubmit: () => void this.grant() },
      this.relation, this.objectType, this.objectId,
      this.busy.control(button(t("app.admin_user.grant"), { type: "submit" }))));
    const relations = h("section", { class: "card" }, h("h2", null, t("app.admin_user.relations_title")), h("p", null, t("app.admin_user.relations_intro")), this.relationTable.anchor, grantForm);
    this.body.set(summary, this.passwordSlot.anchor, claims, relations);
  }

  private renderFacts(user: AdminUser): void {
    const activity = this.activity;
    const fact = (label: string, value: Child) => [h("dt", null, label), h("dd", null, value)];
    fill(this.facts,
      fact(t("app.admin.col_username"), h("code", null, user.username)),
      fact(t("app.party.field.account_id"), h("code", null, user.id)),
      fact(t("app.admin.col_status"), user.isActive ? t("app.admin.status_active") : t("app.admin.status_disabled")),
      fact(t("app.admin.col_created"), when(user.createdAt)),
      fact(t("app.admin_user.last_sign_in"), when(activity?.lastAuthenticatedAt)),
      fact(t("app.admin_user.last_seen"), when(activity?.lastSeenAt)),
      fact(t("app.admin_user.sign_in_count"), activity?.successfulAuthenticationCount ?? 0),
      fact(t("app.admin_user.active_sessions"), activity?.activeBrowserSessionCount ?? 0));
  }

  /** The disable button, or the restore form for a disabled account. It is
   * made again only when the account turns on or off. */
  private renderStatusAction(user: AdminUser): void {
    if (this.self || this.statusActive === user.isActive) return;
    this.statusActive = user.isActive;
    if (user.isActive) {
      this.statusSlot.set(h("div", { class: "button-row" }, this.busy.region("status")(textButton(t("app.admin.disable"), () => this.deactivate()))));
      return;
    }
    this.busy.region("status");
    this.statusSlot.set(reactivateForm({
      userId: this.userId, username: user.username, configuration: this.context.configuration,
      fail: (text) => this.messages.fail(text),
      complete: async () => { await this.refresh(); if (this.isActive()) this.messages.status(t("app.admin.restored", { username: user.username })); },
    }));
  }

  private renderPassword(user: AdminUser): void {
    const shown = user.isActive && !this.self;
    if (shown && !this.passwordShown) this.passwordSlot.set(this.passwordCard(user));
    if (!shown && this.passwordShown) { this.passwordSlot.set(); this.busy.region("password"); this.lock = undefined; }
    this.passwordShown = shown;
    if (this.lock) this.lock.checked = user.passwordLocked === true;
  }

  private passwordCard(user: AdminUser): HTMLElement {
    const control = this.busy.region("password");
    const password = textField(t("app.password.new"), { type: "password", autocomplete: "new-password", "aria-describedby": "admin-reset-rule", required: true });
    const confirmation = textField(t("app.password.confirm_new"), { type: "password", autocomplete: "new-password", required: true });
    const resetForm = control(form({ class: "account-form", onSubmit: () => void this.resetPassword(password, confirmation) },
      hiddenUsername(user.username), password, confirmation, control(button(t("app.admin_user.password_submit"), { type: "submit" }))));
    this.lock = control(h("check-box", { class: "checkbox-label", "aria-describedby": "admin-lock-help", on: { change: () => this.setLock(this.lock!.checked) } }, t("app.admin_user.lock_label")));
    return h("section", { class: "card" },
      h("h2", null, t("app.admin_user.password_title")),
      h("p", { id: "admin-reset-rule" }, `${passwordRule(this.context.configuration)} ${t("app.admin_user.password_intro")}`),
      resetForm,
      h("h3", null, t("app.admin_user.lock_title")),
      h("p", { id: "admin-lock-help" }, t("app.admin_user.lock_intro")),
      this.lock);
  }

  private renderClaims(): void {
    const control = this.busy.region("claims");
    if (!this.claims.length) { this.claimTable.set(h("p", { class: "muted" }, t("app.account.details_empty"))); return; }
    const headings = [t("app.account.col_detail"), t("app.account.col_value"), t("app.admin_user.col_confirmed"), t("app.admin_user.col_expires"), t("app.account.col_action")];
    this.claimTable.set(h("div", { class: "table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, ...headings.map((text) => h("th", null, text)))),
      h("tbody", null, ...this.claims.map((claim) => h("tr", null,
        h("td", null, claimTypeLabel(claim.claimType), " ", h("small", null, h("code", null, claim.claimType))),
        h("td", null, claimText(claim)),
        h("td", null, claim.signatures.length ? t("app.common.yes") : t("app.common.no")),
        h("td", null, when(claim.expiresAt)),
        h("td", null, control(textButton(t("app.common.remove"), () => this.removeClaim(claim))))))))));
  }

  private renderRelations(): void {
    const control = this.busy.region("relations");
    if (!this.relations.length) { this.relationTable.set(h("p", { class: "muted" }, t("app.admin_user.relations_empty"))); return; }
    const headings = [t("app.admin_user.col_relation"), t("app.admin_user.col_object"), t("app.admin_user.col_since"), t("app.account.col_action")];
    this.relationTable.set(h("div", { class: "table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, ...headings.map((text) => h("th", null, text)))),
      h("tbody", null, ...this.relations.map((entry) => h("tr", null,
        h("td", null, h("code", null, entry.relation)),
        h("td", null, entry.objectType, " ", h("code", null, entry.objectId)),
        h("td", null, when(entry.createdAt)),
        h("td", null, control(textButton(t("app.common.remove"), () => this.revoke(entry))))))))));
  }

  /** A claim type object takes a claim type from the list; a domain takes this domain. */
  private objectTypeChanged(): void {
    this.objectId.value = this.objectType.value === "domain" ? this.context.configuration.domain : "";
    this.objectTypeOptions();
  }

  private objectTypeOptions(): void {
    setOptions(this.objectId, this.objectType.value === "claim_type" ? claimTypeOptions(this.claimTypes) : []);
  }

  private saveName(): void {
    void this.act(() => api.admin.updateUser({ userId: this.userId, displayName: this.displayName.value.trim() }), t("app.admin_user.name_saved"), t("app.admin_user.name_failed"));
  }

  private async resetPassword(password: ZestTextField, confirmation: ZestTextField): Promise<void> {
    this.messages.clear();
    if (password.value !== confirmation.value) return this.messages.fail(t("app.password.mismatch_new"));
    const lengthError = checkPassword(password.value, this.context.configuration);
    if (lengthError) return this.messages.fail(lengthError);
    if (await this.act(() => api.admin.resetPassword({ userId: this.userId, newPassword: password.value }), t("app.admin_user.password_reset"), t("app.admin_user.password_reset_failed"))) {
      password.value = "";
      confirmation.value = "";
    }
  }

  private setLock(locked: boolean): void {
    void this.act(() => api.admin.setUserPasswordLock({ userId: this.userId, locked }), locked ? t("app.admin_user.lock_saved") : t("app.admin_user.unlock_saved"), t("app.admin_user.lock_failed"));
  }

  private deactivate(): void {
    const username = this.user?.username ?? "";
    if (window.confirm(t("app.admin.disable_confirm", { username }))) void this.act(() => api.admin.deactivateUser({ userId: this.userId }), t("app.admin.disabled", { username }), t("app.admin.disable_failed"));
  }

  private async addClaim(): Promise<void> {
    const expires = this.expires.value;
    const request = { userId: this.userId, claimType: this.claimType.value.trim(), claimValue: this.claimValue.value, expiresAt: expires ? `${expires}T00:00:00Z` : undefined };
    if (await this.act(() => api.admin.setClaim(request), t("app.admin_user.claim_added"), t("app.admin_user.claim_add_failed"))) {
      this.claimValue.value = "";
      this.expires.value = "";
    }
  }

  private removeClaim(claim: Claim): void {
    if (window.confirm(t("app.admin_user.claim_remove_confirm", { label: claimTypeLabel(claim.claimType) }))) void this.act(() => api.admin.removeClaim({ claimId: claim.claimId }), t("app.admin_user.claim_removed"), t("app.admin_user.claim_remove_failed"));
  }

  private grant(): void {
    const request = { subjectType: "user", subjectId: this.userId, relation: this.relation.value, objectType: this.objectType.value, objectId: this.objectId.value.trim() };
    void this.act(() => api.admin.grantRelation(request), t("app.admin_user.relation_granted"), t("app.admin_user.relation_grant_failed"));
  }

  private revoke(entry: Relation): void {
    if (window.confirm(t("app.admin_user.relation_remove_confirm", { relation: entry.relation, object: entry.objectId }))) void this.act(() => api.admin.removeRelation({ relationId: entry.id }), t("app.admin_user.relation_removed"), t("app.admin_user.relation_remove_failed"));
  }
}
