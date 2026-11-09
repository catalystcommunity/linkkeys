// The account page: the person's details, contact methods, sharing choices,
// profiles, act-as grants, confirmation codes, and password. Each section
// loads and saves on its own. The page builds its elements one time and then
// changes only the parts that change.
import { api } from "../transport";
import { claimTypeLabel, t } from "../i18n";
import { attribute, button, checkBox, comboBox, Feedback, fill, form, formatted, h, hiddenUsername, nodes, setBusy, setDisabled, textArea, textButton, textField, yesNoOptions, type Child } from "../dom";
import { createPage, Page } from "../page";
import { checkPassword, claimText, passwordRule, type PageProps } from "../shared";
import type { ActAsGrantSummary, Claim, MyClaimSetting, Profile, SettableClaimPolicy, VerifiedContactMethod } from "../generated/types.gen";
import { fromSigningRequestCbor, toSignedSigningRequestCbor } from "../generated/codec.gen";
import { actAsGrantState, applicationLabel, authenticationFailed, base64UrlUnpadded, claimValueTooLong, confirmationDetails, currentPasswordMessage, inputType, serviceMessage as message, siteDomain } from "../ui-logic";

export function accountPage(context: PageProps): Element {
  return createPage("linkkeys-account-page", AccountPage, context);
}

/** A place in the DOM for content that comes and goes, with no wrapper
 * element. A `.card` is a flex box, so `hidden` cannot hide a child; a slot
 * removes the nodes instead. The anchor must be in a parent before `set`. */
class Slot {
  readonly anchor = document.createComment("");
  private current: Node[] = [];

  set(...children: Child[]): void {
    for (const node of this.current) node.parentNode?.removeChild(node);
    this.current = nodes(children);
    this.anchor.after(...this.current);
  }
}

/** A status line and an alert line that show at the same time when both have
 * text, as in the original account page. */
function statusLine(slot: Slot, text: string | false): void {
  slot.set(text && h("p", { class: "notice good", role: "status" }, text));
}

function alertLine(slot: Slot, text: string | false): void {
  slot.set(text && h("p", { class: "notice bad", role: "alert" }, text));
}

/** Settable policies, without the ones that only a verifier can sign. */
function settablePolicies(policies: SettableClaimPolicy[]): SettableClaimPolicy[] {
  return policies.filter((policy) => policy.signingRule !== "verified");
}

/** One account section. It belongs to a page, and it stops changing the
 * page after the page goes away. */
abstract class Section {
  constructor(protected page: Page, protected context: PageProps) {}

  protected active(): boolean {
    return this.page.isActive();
  }

  /** Go to the login page when the session is gone. Returns true then. */
  protected signedOut(cause: unknown): boolean {
    if (!authenticationFailed(cause)) return false;
    this.context.navigate("/app/login");
    return true;
  }

  abstract nodes(): Node[];
  abstract load(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Act-as grants
// ---------------------------------------------------------------------------

class ActAsGrantList extends Section {
  private grants: ActAsGrantSummary[] = [];
  private busy = "";
  private loadCount = 0;
  private stopButtons = new Map<string, ZestPushButton>();
  private list = h("div");
  private feedback = new Feedback();
  private element = h("section", { class: "card" }, h("h2", null, t("app.act_as_list.title")), this.list, this.feedback.element);

  nodes(): Node[] {
    return [this.element];
  }

  async load(): Promise<void> {
    const count = ++this.loadCount;
    try {
      const { grants } = await api.account.listActAsGrants({});
      if (!this.active() || count !== this.loadCount) return;
      this.grants = grants;
      this.renderList();
    } catch (cause) {
      if (!this.active() || count !== this.loadCount) return;
      if (!this.signedOut(cause)) this.feedback.error(t("app.act_as_list.load_failed"));
    }
  }

  private async revoke(grantId: string): Promise<void> {
    this.setBusyGrant(grantId);
    this.feedback.clear();
    try {
      await api.account.revokeActAsGrant({ grantId });
      if (!this.active()) return;
      await this.load();
    } catch {
      if (this.active()) this.feedback.error(t("app.act_as_list.stop_failed"));
    } finally {
      if (this.active()) this.setBusyGrant("");
    }
  }

  private setBusyGrant(grantId: string): void {
    this.busy = grantId;
    for (const [id, stop] of this.stopButtons) {
      stop.disabled = id === grantId;
      fill(stop, id === grantId ? t("app.act_as_list.stopping") : t("app.act_as_list.stop"));
    }
  }

  private renderList(): void {
    const active = this.grants.filter((grant) => actAsGrantState(grant, new Date()) === "active");
    this.stopButtons.clear();
    if (!active.length) return fill(this.list, h("p", { class: "muted" }, t("app.act_as_list.empty")));
    fill(this.list, h("ul", null, active.map((grant) => this.item(grant))));
  }

  private item(grant: ActAsGrantSummary): HTMLLIElement {
    const grantee = h("strong", null, applicationLabel(grant.grantee.application, t("app.act_as_list.local_application")));
    const until = grant.renewableUntil !== grant.expiresAt
      ? t("app.act_as_list.until_renewable", { until: new Date(grant.expiresAt).toLocaleString(), renewable: new Date(grant.renewableUntil).toLocaleString() })
      : t("app.act_as_list.until", { until: new Date(grant.expiresAt).toLocaleString() });
    const stopping = this.busy === grant.grantId;
    const stop = textButton(stopping ? t("app.act_as_list.stopping") : t("app.act_as_list.stop"), () => void this.revoke(grant.grantId), { disabled: stopping });
    this.stopButtons.set(grant.grantId, stop);
    const text = formatted("app.act_as_list.item", { grantee, audience: applicationLabel(grant.audience), scopes: grant.approvedScope.join(", ") });
    return h("li", null, text, " ", h("small", null, until), " ", stop);
  }
}

// ---------------------------------------------------------------------------
// Sharing choices for each detail
// ---------------------------------------------------------------------------

interface ChoiceRow {
  fieldset: HTMLFieldSetElement;
  share: ZestCheckBox;
  keep?: ZestCheckBox;
}

class DetailChoices extends Section {
  private policies: SettableClaimPolicy[] = [];
  private settings: MyClaimSetting[] = [];
  private loadCount = 0;
  private shape = "";
  private rows = new Map<string, ChoiceRow>();
  private slot = new Slot();
  private list = h("div");
  private feedback = new Feedback();
  private element = h("section", { class: "card" }, h("h2", null, t("app.choices.title")), h("p", null, t("app.choices.intro")), this.list, this.feedback.element);

  nodes(): Node[] {
    return [this.slot.anchor];
  }

  async load(): Promise<void> {
    const count = ++this.loadCount;
    try {
      const [available, mine] = await Promise.all([api.account.listSettablePolicies({}), api.account.getMyClaimSettings({})]);
      if (!this.active() || count !== this.loadCount) return;
      this.policies = settablePolicies(available.policies);
      this.settings = mine.settings;
      this.render();
    } catch (cause) {
      if (!this.active() || count !== this.loadCount) return;
      if (!this.signedOut(cause)) this.feedback.error(t("app.choices.load_failed"));
    }
  }

  private setting(claimType: string): MyClaimSetting | undefined {
    return this.settings.find((entry) => entry.claimType === claimType);
  }

  /** Keep each row when the policies are the same, so that the focus stays
   * on the check box that the person just changed. */
  private render(): void {
    this.slot.set(this.policies.length > 0 && this.element);
    const shape = JSON.stringify(this.policies.map((policy) => [policy.claimType, policy.label, policy.signingRule]));
    if (shape !== this.shape) {
      this.shape = shape;
      this.rows.clear();
      fill(this.list, this.policies.map((policy) => this.row(policy)));
    }
    for (const [claimType, row] of this.rows) {
      const setting = this.setting(claimType);
      row.share.checked = setting?.sharedWithEveryApp ?? false;
      if (row.keep) row.keep.checked = setting?.keepVerified ?? false;
    }
  }

  private row(policy: SettableClaimPolicy): HTMLFieldSetElement {
    const claimType = policy.claimType;
    const share = checkBox(h("span", null, t("app.choices.share_every_app")), {
      on: { change: () => void this.change(claimType, () => api.account.setMyClaimSharing({ claimType, share: share.checked })) },
    });
    share.classList.add("checkbox-label");
    let keep: ZestCheckBox | undefined;
    if (policy.signingRule === "self_signed") {
      const keepBox = checkBox(h("span", null, t("app.choices.keep_verified", { domain: this.context.configuration.domain })), {
        on: { change: () => void this.change(claimType, () => api.account.setMyClaimKeepVerified({ claimType, keepVerified: keepBox.checked })) },
      });
      keepBox.classList.add("checkbox-label");
      keep = keepBox;
    }
    const fieldset = h("fieldset", { class: "consent-claim" }, h("legend", null, policy.label), share, keep);
    this.rows.set(claimType, { fieldset, share, keep });
    return fieldset;
  }

  private setBusyType(claimType: string): void {
    for (const [type, row] of this.rows) row.fieldset.disabled = type === claimType;
  }

  private async change(claimType: string, save: () => Promise<unknown>): Promise<void> {
    this.setBusyType(claimType);
    this.feedback.clear();
    try {
      await save();
      if (!this.active()) return;
      await this.load();
      if (!this.active()) return;
      this.feedback.status(t("app.choices.saved"));
    } catch (cause) {
      if (!this.active()) return;
      this.feedback.error(message(cause, t("app.choices.save_failed")));
      await this.load();
    } finally {
      if (this.active()) this.setBusyType("");
    }
  }
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

class ProfileList extends Section {
  private profiles: Profile[] = [];
  private maxProfiles = 1;
  private busy = false;
  private loadCount = 0;
  private slot = new Slot();
  private list = h("ul");
  private labelField = textField(t("app.profiles.label"), { name: "profile-label", maxlength: 64, autocomplete: "off" });
  private createButton = button(t("app.profiles.create"), { type: "submit" });
  private createForm = form({ class: "inline-form", onSubmit: () => void this.create() }, this.labelField, this.createButton);
  private limitLine = h("p", { class: "muted" });
  private formSlot = new Slot();
  private feedback = new Feedback();
  private element = h("section", { class: "card" }, h("h2", null, t("app.profiles.title")), h("p", null, t("app.profiles.intro")), this.list, this.formSlot.anchor, this.feedback.element);

  nodes(): Node[] {
    return [this.slot.anchor];
  }

  async load(): Promise<void> {
    const count = ++this.loadCount;
    try {
      const mine = await api.account.getMyClaimSettings({});
      if (!this.active() || count !== this.loadCount) return;
      this.profiles = mine.profiles;
      this.maxProfiles = mine.maxProfiles;
      this.render();
    } catch (cause) {
      if (!this.active() || count !== this.loadCount) return;
      if (!this.signedOut(cause)) this.feedback.error(t("app.profiles.load_failed"));
    }
  }

  private render(): void {
    this.slot.set(this.maxProfiles > 1 && this.element);
    fill(this.list, this.profiles.map((profile) => h("li", null, profile.label ?? t("app.profiles.unnamed"), " ", h("small", null, h("code", null, `${profile.id}@${profile.domain}`)))));
    fill(this.limitLine, t("app.profiles.limit_reached", { count: this.maxProfiles }));
    this.formSlot.set(this.profiles.length < this.maxProfiles ? this.createForm : this.limitLine);
  }

  private async create(): Promise<void> {
    if (this.busy) return;
    this.setBusyState(true);
    this.feedback.clear();
    try {
      await api.account.createProfile({ label: this.labelField.value.trim() || undefined });
      if (!this.active()) return;
      this.labelField.value = "";
      await this.load();
      if (!this.active()) return;
      this.feedback.status(t("app.profiles.created"));
    } catch (cause) {
      if (this.active()) this.feedback.error(message(cause, t("app.profiles.create_failed")));
    } finally {
      if (this.active()) this.setBusyState(false);
    }
  }

  private setBusyState(busy: boolean): void {
    this.busy = busy;
    setBusy(this.createForm, busy, [this.createButton]);
  }
}

// ---------------------------------------------------------------------------
// Confirmation codes for another site
// ---------------------------------------------------------------------------

class ConfirmationRequest extends Section {
  private busy = false;
  private code = "";
  private site = textField(t("app.confirm.site"), { name: "confirmation-site", placeholder: t("app.confirm.site_placeholder"), autocomplete: "off", inputmode: "url", required: true });
  private details = textField(t("app.confirm.details"), { name: "confirmation-details", autocomplete: "off", required: true, helper: t("app.confirm.details_hint") });
  private submit = button(t("app.confirm.submit"), { type: "submit" });
  private requestForm = form({ id: "confirmation-request-form", name: "confirmation-request", onSubmit: () => void this.create() }, this.site, this.details, this.submit);
  private result = new Slot();
  private feedback = new Feedback();
  private element = h("section", { class: "card" }, h("h2", null, t("app.confirm.title")), h("p", { id: "confirmation-help" }, t("app.confirm.intro")), this.requestForm, this.result.anchor, this.feedback.element);

  nodes(): Node[] {
    return [this.element];
  }

  async load(): Promise<void> {}

  private async create(): Promise<void> {
    if (this.busy) return;
    this.feedback.clear();
    this.showResult(undefined);
    const issuerDomain = siteDomain(this.site.value);
    const requestedClaimTypes = confirmationDetails(this.details.value);
    if (!issuerDomain) return this.feedback.error(t("app.confirm.site_invalid"));
    if (!requestedClaimTypes.length) return this.feedback.error(t("app.confirm.details_missing"));
    this.setBusyState(true);
    try {
      const { signedRequest } = await api.account.requestVerification({ issuerDomain, requestedClaimTypes });
      if (!this.active()) return;
      this.showResult({ site: issuerDomain, code: base64UrlUnpadded(toSignedSigningRequestCbor(signedRequest)), expiresAt: fromSigningRequestCbor(signedRequest.request).expiresAt });
    } catch (cause) {
      if (!this.active()) return;
      if (!this.signedOut(cause)) this.feedback.error(message(cause, t("app.confirm.failed")));
    } finally {
      if (this.active()) this.setBusyState(false);
    }
  }

  private showResult(made: { site: string; code: string; expiresAt: string } | undefined): void {
    this.code = made?.code ?? "";
    if (!made) return this.result.set();
    const text = formatted("app.confirm.result", { site: h("strong", null, made.site), until: new Date(made.expiresAt).toLocaleString() });
    const area = textArea("", { readonly: true, rows: 4, value: made.code, "aria-label": t("app.confirm.code_label", { site: made.site }), on: { focusin: () => area.select() } });
    this.result.set(h("p", null, text), area, button(t("app.confirm.copy"), { onClick: () => void this.copy() }));
  }

  private async copy(): Promise<void> {
    this.feedback.clear();
    try {
      await navigator.clipboard.writeText(this.code);
      if (this.active()) this.feedback.status(t("app.confirm.copied"));
    } catch {
      if (this.active()) this.feedback.error(t("app.confirm.copy_failed"));
    }
  }

  private setBusyState(busy: boolean): void {
    this.busy = busy;
    setBusy(this.requestForm, busy, [this.submit]);
  }
}

// ---------------------------------------------------------------------------
// The account page
// ---------------------------------------------------------------------------

type FeedbackArea = "claims" | "contacts" | "password" | "";
type ValueKind = "bool" | "date" | "text";
type ValueControl = ZestTextField | ZestComboBox | ZestDateTimePicker;

function valueKind(policy: SettableClaimPolicy | undefined): ValueKind {
  if (policy?.datatype === "bool") return "bool";
  return inputType(policy?.datatype) === "date" ? "date" : "text";
}

/** Give a text field the rules of the detail's data type. A text field has
 * no `number` type, so a number is text with a numeric keyboard and the
 * whole-number rule of a native number input (its default step is 1). */
function applyTextRules(field: ZestTextField, policy: SettableClaimPolicy | undefined): void {
  const type = inputType(policy?.datatype);
  field.type = type === "number" ? "text" : type;
  attribute(field, "inputmode", type === "number" ? "numeric" : null);
  attribute(field, "pattern", type === "number" ? "-?[0-9]+" : null);
  attribute(field, "maxlength", policy?.maxBytes);
}

class AccountPage extends Page {
  private claims: Claim[] = [];
  private contacts: VerifiedContactMethod[] = [];
  private policies: SettableClaimPolicy[] = [];
  private claimType = "";
  private status = "";
  private error = "";
  private area: FeedbackArea = "";
  private busy = false;
  private state: "loading" | "ready" | "failed" = "loading";
  private refreshCount = 0;
  private hero!: HTMLElement;
  private shown: "ready" | "other" | "" = "";
  private sections: Section[] = [];

  // Details
  private claimRegion = new Slot();
  private claimRemoveButtons: ZestPushButton[] = [];
  private claimSelect!: ZestComboBox;
  private claimDescription = new Slot();
  private valueSlot = new Slot();
  private valueControl?: ValueControl;
  private valueKind?: ValueKind;
  private claimSubmit = button(t("app.account.save_detail"), { type: "submit" });
  private claimForm!: HTMLFormElement;
  private claimFormSlot = new Slot();
  private claimStatus = new Slot();
  private claimError = new Slot();
  private claimsCard!: HTMLElement;

  // Contact methods
  private contactRows = new Slot();
  private contactRemoveButtons: ZestPushButton[] = [];
  private email?: ZestTextField;
  private contactPassword = textField(t("app.password.current"), { type: "password", name: "current-password", autocomplete: "current-password", required: true });
  private contactPasswordSlot = new Slot();
  private contactSubmit?: ZestPushButton;
  private contactForm!: HTMLFormElement;
  private contactStatus = new Slot();
  private contactError = new Slot();
  private contactsCard!: HTMLElement;

  // Password
  private oldPassword = textField(t("app.password.current"), { type: "password", name: "current-password", autocomplete: "current-password", required: true });
  private newPassword = textField(t("app.password.new"), { type: "password", name: "new-password", autocomplete: "new-password", "aria-describedby": "change-password-rule", required: true });
  private confirmation = textField(t("app.password.confirm_new"), { type: "password", name: "new-password-confirmation", autocomplete: "new-password", required: true });
  private passwordSubmit = button(t("app.account.password_submit"), { type: "submit" });
  private passwordForm?: HTMLFormElement;
  private passwordError = new Slot();
  private passwordCard?: HTMLElement;

  private generalError = new Slot();

  protected build(): Child {
    const user = this.context.session?.user;
    this.buildParts();
    this.hero = h("section", { class: "hero" }, h("p", { class: "eyebrow" }, t("app.account.eyebrow")), h("h1", null, user?.displayName ?? t("app.account.fallback_title")), h("p", null, h("code", null, user?.username)));
    const main = h("main", { class: "wrap" }, this.hero);
    this.renderBody();
    return main;
  }

  protected async start(): Promise<void> {
    await this.refresh();
  }

  // -- Building --------------------------------------------------------------

  private buildParts(): void {
    this.claimsCard = this.buildClaimsCard();
    this.contactsCard = this.buildContactsCard();
    this.passwordCard = this.buildPasswordCard();
  }

  private buildClaimsCard(): HTMLElement {
    this.claimSelect = comboBox(t("app.account.field_detail"), [], {
      on: { change: () => this.chooseClaimType(this.claimSelect.value) },
    });
    this.claimForm = form({ class: "inline-form", onSubmit: () => void this.setClaim() },
      h("div", null, this.claimSelect, this.claimDescription.anchor),
      this.valueSlot.anchor,
      this.claimSubmit);
    return h("section", { class: "card" },
      h("div", { class: "section-heading" }, h("div", null, h("h2", null, t("app.account.details_title")), h("p", null, t("app.account.details_intro")))),
      this.claimRegion.anchor,
      this.claimFormSlot.anchor,
      this.claimStatus.anchor,
      this.claimError.anchor);
  }

  private buildContactsCard(): HTMLElement {
    const canVerify = this.context.configuration.capabilities.includes("verify_contact");
    if (canVerify) {
      this.email = textField(t("app.account.email"), { type: "email", name: "email", autocomplete: "email", required: true });
      this.contactSubmit = button(t("app.account.verify_email"), { type: "submit" });
    }
    this.contactForm = form({ class: "inline-form", onSubmit: () => void this.requestContact() },
      hiddenUsername(this.context.session?.user.username ?? ""),
      this.contactRows.anchor,
      this.email ?? h("p", { class: "muted" }, t("app.account.contacts_unavailable")),
      this.contactPasswordSlot.anchor,
      this.contactSubmit);
    return h("section", { class: "card" },
      h("h2", null, t("app.account.contacts_title")),
      h("p", null, t("app.account.contacts_intro")),
      this.contactForm,
      this.contactStatus.anchor,
      this.contactError.anchor);
  }

  private buildPasswordCard(): HTMLElement | undefined {
    if (!this.context.configuration.capabilities.includes("password_login")) return undefined;
    const title = h("h2", null, t("app.account.password_title"));
    if (this.context.session?.user.passwordLocked) return h("section", { class: "card" }, title, h("p", null, t("app.account.password_locked")));
    this.passwordForm = form({ id: "change-password-form", name: "change-password", onSubmit: () => void this.changePassword() },
      hiddenUsername(this.context.session?.user.username ?? ""),
      this.oldPassword,
      this.newPassword,
      this.confirmation,
      this.passwordSubmit);
    return h("section", { class: "card" },
      title,
      h("p", { id: "change-password-rule" }, `${passwordRule(this.context.configuration)} ${t("app.account.password_signout_note")}`),
      this.passwordForm,
      this.passwordError.anchor);
  }

  // -- Rendering -------------------------------------------------------------

  /** Put `children` after the hero, in place of the old body. The body is
   * direct children of `main` (a flex box with a gap), with no wrapper. */
  private setBody(...children: Child[]): void {
    while (this.hero.nextSibling) this.hero.nextSibling.remove();
    this.hero.after(...nodes(children));
  }

  /** Show the loading or failed card, or the account sections. Each time
   * the account becomes ready, the other sections start again and load. */
  private renderBody(): void {
    if (this.state !== "ready") {
      this.shown = "other";
      this.sections = [];
      const failed = this.state === "failed";
      this.setBody(h("section", { class: "card", "aria-busy": this.state === "loading" ? "true" : "false" },
        h("p", { role: failed ? "alert" : "status" }, failed ? this.error : t("app.account.loading")),
        failed && button(t("app.common.try_again"), { onClick: () => this.tryAgain() })));
      return;
    }
    if (this.shown === "ready") return;
    this.shown = "ready";
    this.sections = [new DetailChoices(this, this.context), new ProfileList(this, this.context), new ActAsGrantList(this, this.context), new ConfirmationRequest(this, this.context)];
    this.setBody(this.claimsCard, this.contactsCard, this.sections.map((section) => section.nodes()), this.passwordCard, this.generalError.anchor);
    this.renderFeedback();
    for (const section of this.sections) void section.load();
  }

  private tryAgain(): void {
    this.state = "loading";
    this.error = "";
    this.renderBody();
    void this.refresh();
  }

  private renderData(): void {
    this.renderClaims();
    this.renderPolicies();
    this.renderContacts();
    this.applyBusy();
  }

  private renderClaims(): void {
    this.claimRemoveButtons = [];
    if (!this.claims.length) return this.claimRegion.set(h("p", { class: "muted" }, t("app.account.details_empty")));
    const header = h("tr", null, h("th", null, t("app.account.col_detail")), h("th", null, t("app.account.col_value")), h("th", null, t("app.account.col_confirmed")), h("th", null, t("app.account.col_action")));
    this.claimRegion.set(h("div", { class: "table-wrap" }, h("table", null, h("thead", null, header), h("tbody", null, this.claims.map((claim) => this.claimRow(claim))))));
  }

  private claimRow(claim: Claim): HTMLTableRowElement {
    const label = claimTypeLabel(claim.claimType);
    const remove = textButton(t("app.common.remove"), () => void this.removeClaim(claim.claimId), { "aria-label": t("app.account.claim_remove_label", { label }) });
    this.claimRemoveButtons.push(remove);
    const confirmed = claim.signatures.length ? t("app.account.confirmed_by", { domain: this.context.configuration.domain }) : t("app.account.not_confirmed");
    return h("tr", null, h("td", null, label), h("td", null, claimText(claim)), h("td", null, confirmed), h("td", null, remove));
  }

  private selectedPolicy(): SettableClaimPolicy | undefined {
    return this.policies.find((policy) => policy.claimType === this.claimType);
  }

  private renderPolicies(): void {
    this.claimFormSlot.set(this.policies.length > 0 && this.claimForm);
    this.claimSelect.options = this.policies.map((policy) => ({ value: policy.claimType, label: policy.label }));
    this.claimSelect.value = this.claimType;
    this.renderPolicyDetails(false);
  }

  /** The description and the value control of the selected detail. The
   * value control changes only when the kind of value changes; `clear` makes
   * a new, empty control (the person chose another detail). */
  private renderPolicyDetails(clear: boolean): void {
    const policy = this.selectedPolicy();
    this.claimDescription.set(policy?.description && h("small", null, policy.description));
    const kind = valueKind(policy);
    if (!clear && this.valueControl && kind === this.valueKind) {
      if (kind === "text") applyTextRules(this.valueControl as ZestTextField, policy);
      return;
    }
    const value = clear ? "" : this.valueControl?.value ?? "";
    this.valueKind = kind;
    const label = t("app.account.field_value");
    if (kind === "bool") {
      const box = comboBox(label, yesNoOptions(), { value, required: true });
      this.valueControl = box;
      this.valueSlot.set(box);
    } else if (kind === "date") {
      const picker = h("date-time-picker", { mode: "date", name: "claim-value", required: true, value: value || undefined });
      this.valueControl = picker;
      this.valueSlot.set(h("label", null, h("span", null, label), picker));
    } else {
      const field = textField(label, { value, required: true });
      applyTextRules(field, policy);
      this.valueControl = field;
      this.valueSlot.set(field);
    }
  }

  private chooseClaimType(claimType: string): void {
    this.claimType = claimType;
    this.renderPolicyDetails(true);
  }

  private renderContacts(): void {
    this.contactRemoveButtons = [];
    this.contactRows.set(this.contacts.length
      ? this.contacts.map((contact) => this.contactRow(contact))
      : h("p", { class: "muted" }, t("app.account.contacts_empty")));
    const canVerify = this.context.configuration.capabilities.includes("verify_contact");
    this.contactPasswordSlot.set((this.contacts.length > 0 || canVerify) && this.contactPassword);
  }

  private contactRow(contact: VerifiedContactMethod): HTMLDivElement {
    const remove = textButton(t("app.common.remove"), () => void this.removeContact(contact), { "aria-label": t("app.account.contact_remove_label", { destination: contact.destination }) });
    this.contactRemoveButtons.push(remove);
    return h("div", { class: "row" }, h("span", null, contact.destination), remove);
  }

  /** The status and the problem show under the section that caused them. */
  private renderFeedback(): void {
    statusLine(this.claimStatus, this.area === "claims" && this.status);
    alertLine(this.claimError, this.area === "claims" && this.error);
    statusLine(this.contactStatus, this.area === "contacts" && this.status);
    alertLine(this.contactError, this.area === "contacts" && this.error);
    alertLine(this.passwordError, this.area === "password" && this.error);
    alertLine(this.generalError, this.area === "" && this.error);
  }

  private feedback(change: { area?: FeedbackArea; status?: string; error?: string }): void {
    if (change.area !== undefined) this.area = change.area;
    if (change.status !== undefined) this.status = change.status;
    if (change.error !== undefined) this.error = change.error;
    this.renderFeedback();
  }

  /** Start an action: busy, its area, and no old messages. */
  private begin(area: FeedbackArea): void {
    this.setBusyState(true);
    this.feedback({ area, status: "", error: "" });
  }

  private setBusyState(busy: boolean): void {
    this.busy = busy;
    this.applyBusy();
  }

  private applyBusy(): void {
    for (const element of [this.claimForm, this.contactForm, this.passwordForm]) if (element) setBusy(element, this.busy);
    const buttons = [...this.claimRemoveButtons, ...this.contactRemoveButtons, this.claimSubmit, this.contactSubmit, this.passwordSubmit];
    setDisabled(buttons.filter((control): control is ZestPushButton => control !== undefined), this.busy);
  }

  // -- Loading and actions ---------------------------------------------------

  private async refresh(): Promise<void> {
    const count = ++this.refreshCount;
    try {
      const [account, verified, available] = await Promise.all([api.account.getMyInfo({}), api.account.listVerifiedContactMethods({}), api.account.listSettablePolicies({})]);
      if (!this.isActive() || count !== this.refreshCount) return;
      const settable = settablePolicies(available.policies);
      this.claims = account.claims;
      this.contacts = verified.contactMethods;
      this.policies = settable;
      if (!settable.some((policy) => policy.claimType === this.claimType)) this.claimType = settable[0]?.claimType ?? "";
      this.renderData();
      this.state = "ready";
      this.renderBody();
    } catch (cause) {
      if (!this.isActive() || count !== this.refreshCount) return;
      if (authenticationFailed(cause)) return this.context.navigate("/app/login");
      this.state = "failed";
      this.feedback({ area: "", error: t("app.account.load_failed") });
      this.renderBody();
    }
  }

  private async requestContact(): Promise<void> {
    if (this.busy || !this.email) return;
    this.begin("contacts");
    try {
      await api.account.requestContactVerification({ channel: "email", destination: this.email.value, currentPassword: this.contactPassword.value });
      if (!this.isActive()) return;
      this.feedback({ status: t("app.account.contact_sent") });
      this.email.value = "";
      this.contactPassword.value = "";
    } catch (cause) {
      if (this.isActive()) this.feedback({ error: currentPasswordMessage(cause, t("app.account.contact_send_failed")) });
    } finally {
      if (this.isActive()) this.setBusyState(false);
    }
  }

  private async setClaim(): Promise<void> {
    if (this.busy) return;
    this.begin("claims");
    const policy = this.selectedPolicy();
    const value = this.valueControl?.value ?? "";
    if (policy && claimValueTooLong(value, policy.maxBytes)) {
      this.setBusyState(false);
      return this.feedback({ error: t("app.claim.too_long", { label: policy.label, max: policy.maxBytes }) });
    }
    try {
      const result = await api.account.setMyClaim({ claimType: this.claimType, claimValue: value });
      if (!this.isActive()) return;
      if (this.valueControl) this.valueControl.value = "";
      await this.refresh();
      if (!this.isActive()) return;
      this.feedback({
        status: result.outcome === "verification_required"
          ? t("app.account.claim_needs_verification")
          : result.outcome === "queued"
            ? t("app.account.claim_queued")
            : t("app.account.claim_saved"),
      });
    } catch (cause) {
      if (this.isActive()) this.feedback({ error: message(cause, t("app.account.claim_save_failed")) });
    } finally {
      if (this.isActive()) this.setBusyState(false);
    }
  }

  private async removeContact(contact: VerifiedContactMethod): Promise<void> {
    if (this.busy) return;
    const currentPassword = this.contactPassword.value;
    if (!currentPassword) return this.feedback({ area: "contacts", error: t("app.account.password_first") });
    if (!window.confirm(t("app.account.contact_remove_confirm", { destination: contact.destination }))) return;
    this.begin("contacts");
    try {
      await api.account.revokeVerifiedContactMethod({ contactMethodId: contact.id, currentPassword });
      if (!this.isActive()) return;
      this.contactPassword.value = "";
      await this.refresh();
      if (!this.isActive()) return;
      this.feedback({ status: t("app.account.contact_removed") });
    } catch (cause) {
      if (this.isActive()) this.feedback({ error: currentPasswordMessage(cause, t("app.account.contact_remove_failed")) });
    } finally {
      if (this.isActive()) this.setBusyState(false);
    }
  }

  private async removeClaim(claimId: string): Promise<void> {
    if (this.busy) return;
    if (!window.confirm(t("app.account.claim_remove_confirm"))) return;
    this.begin("claims");
    try {
      await api.account.removeMyClaim({ claimId });
      if (!this.isActive()) return;
      await this.refresh();
      if (!this.isActive()) return;
      this.feedback({ status: t("app.account.claim_removed") });
    } catch (cause) {
      if (this.isActive()) this.feedback({ error: message(cause, t("app.account.claim_remove_failed")) });
    } finally {
      if (this.isActive()) this.setBusyState(false);
    }
  }

  private async changePassword(): Promise<void> {
    if (this.busy) return;
    this.begin("password");
    const newPassword = this.newPassword.value;
    if (newPassword !== this.confirmation.value) {
      this.setBusyState(false);
      return this.feedback({ error: t("app.password.mismatch_new") });
    }
    const lengthError = checkPassword(newPassword, this.context.configuration);
    if (lengthError) {
      this.setBusyState(false);
      return this.feedback({ error: lengthError });
    }
    try {
      await api.account.changePassword({ currentPassword: this.oldPassword.value, newPassword });
      this.oldPassword.value = "";
      this.newPassword.value = "";
      this.confirmation.value = "";
      // The password change ends the session. Go to the login page even
      // when the session refresh already replaced this page.
      await this.context.refreshSession();
      this.context.navigate("/app/login");
    } catch (cause) {
      if (this.isActive()) this.feedback({ error: currentPasswordMessage(cause, t("app.account.password_change_failed")) });
    } finally {
      if (this.isActive()) this.setBusyState(false);
    }
  }
}
