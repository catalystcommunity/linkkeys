// Consent pages: the authorization gateway and consent screen for apps on
// other domains, the local (unverified) app consent, and act-as consent.
import { api } from "../transport";
import { t } from "../i18n";
import { Page, createPage } from "../page";
import { button, checkBox, comboBox, fill, form, formatted, h, link, setBusy, show, textButton, textField, yesNoOptions, type Child } from "../dom";
import { loading, query, unavailable, type PageProps } from "../shared";
import type { AppAccessDenial, BrowserActAsInspectResponse, BrowserActAsParty, BrowserAuthorizationInspectResponse, BrowserConsentClaim, BrowserLocalRpInspectResponse } from "../generated/types.gen";
import {
  actAsHandoff,
  actAsRequestKey,
  authenticationFailed,
  authorizationHandoff,
  authorizationRequestIsTerminal,
  consentDecision,
  describeDuration,
  durationChoices,
  hasBlockedRequiredClaim,
  hasNewlyRequestedClaim,
  inputType,
  localRpFailureMessage,
  partyHeadline,
  partyTitle,
  partyTrustNotes,
  serviceMessage as message,
  standingAuthorization,
  withLoginContext,
} from "../ui-logic";

const authorizationRequestKey = "linkkeys-authorization-request";
const localRpRequestKey = "linkkeys-local-rp-request";

/** A submit button whose text changes while it is busy. */
function busyButton(idle: string, working: string): { element: ZestPushButton; busy(value: boolean): void } {
  const text = document.createTextNode(idle);
  const element = button(text, { type: "submit" });
  return { element, busy: (value) => { text.data = value ? working : idle; } };
}

/** An alert line, or nothing for no error. */
function alertLine(error: string): Child {
  return error && h("p", { class: "notice bad", role: "alert" }, error);
}

/** A status card: the request is checked, or why it stopped. */
function statusCard(error: string, checking: string, ...more: Child[]): HTMLElement {
  return h("section", { class: "card" }, h("p", { role: error ? "alert" : "status" }, error || checking), ...more);
}

function hero(eyebrow: string, title: string, ...more: Child[]): HTMLElement {
  return h("section", { class: "hero" }, h("p", { class: "eyebrow" }, eyebrow), h("h1", null, title), ...more);
}

/** Shown instead of the consent form when an app access policy blocks the
 * sign-in. The admin messages are plain text from the home domain. */
function accessBlocked(denial: AppAccessDenial): HTMLElement {
  return h("section", { class: "card" },
    h("p", null, denial.domain ? t("app.access_blocked.body", { app: denial.domain }) : t("app.access_blocked.body_local")),
    denial.messages.length > 0 && h("div", { class: "notice" },
      h("p", null, h("strong", null, t("app.access_blocked.admin_message"))),
      denial.messages.map((text) => h("p", null, text))),
    h("p", null, t("app.access_blocked.help")),
    link("/app/account", t("app.common.return_to_account")));
}

function accessBlockedPage(eyebrow: string, denial: AppAccessDenial): HTMLElement {
  return h("main", { class: "wrap narrow" }, hero(eyebrow, t("app.access_blocked.title")), accessBlocked(denial));
}

// ---------------------------------------------------------------------------
// Claim rows
// ---------------------------------------------------------------------------

/** The choices of a consent screen: which claims to release, and values for
 * claims that the user adds on this screen. */
interface ClaimChoices {
  selected: Record<string, boolean>;
  values: Record<string, string>;
}

/** One requested detail on a consent screen. */
class ConsentClaimRow {
  readonly element: HTMLElement;
  private check: ZestCheckBox;
  private requiredHint?: HTMLElement;
  private valueSlot?: HTMLElement;
  private valueField?: HTMLElement;

  constructor(private claim: BrowserConsentClaim, private choices: ClaimChoices) {
    const userChoice = claim.policy === "user";
    this.check = checkBox([
      h("span", null, claim.required ? t("app.consent.required_label", { label: claim.label }) : claim.label),
      claim.newlyRequested && h("span", { class: "pill new" }, t("app.consent.new_badge")),
    ], {
      checked: claim.policy === "forced_allow" || choices.selected[claim.claimType],
      disabled: !userChoice,
      required: claim.required && userChoice,
      on: { change: () => this.select(this.check.checked) },
    });
    this.check.classList.add("checkbox-label");
    if (claim.required && userChoice) this.requiredHint = h("small", null, t("app.consent.required_unselected"));
    if (!claim.available && claim.userSettable) this.valueSlot = h("div", { class: "consent-value" });
    this.element = h("div", { class: "consent-claim" },
      this.check,
      claim.policy === "forced_allow" && h("small", null, t("app.consent.forced_allow")),
      this.requiredHint,
      this.valueSlot,
      !claim.available && claim.requiresApproval && h("small", null, t("app.consent.needs_approval")),
      !claim.available && !claim.userSettable && !claim.requiresApproval && h("small", null, t("app.consent.not_in_profile")),
      claim.policy === "forced_deny" && h("small", null, t("app.consent.forced_deny")));
    this.update();
  }

  private released(): boolean {
    return this.claim.policy === "forced_allow" || Boolean(this.choices.selected[this.claim.claimType]);
  }

  private select(checked: boolean): void {
    this.choices.selected[this.claim.claimType] = checked;
    this.update();
  }

  /** Show the hint and the value field that follow from the selection. The
   * value field leaves the DOM when it is hidden, so that its `required`
   * rule does not stop the form. */
  private update(): void {
    if (this.requiredHint) show(this.requiredHint, !this.choices.selected[this.claim.claimType]);
    if (this.valueSlot) fill(this.valueSlot, this.released() && (this.valueField ??= this.makeValueField()));
  }

  private makeValueField(): HTMLElement {
    const { claim, choices } = this;
    const label = t("app.consent.add_value", { label: claim.label });
    const value = choices.values[claim.claimType] ?? "";
    const keep = (text: string) => { choices.values[claim.claimType] = text; };
    if (claim.datatype === "bool") {
      const box: ZestComboBox = comboBox(label, yesNoOptions(), { value, required: claim.required, on: { change: () => keep(box.value) } });
      return box;
    }
    const type = inputType(claim.datatype);
    if (type === "date") {
      const picker: ZestDateTimePicker = h("date-time-picker", { mode: "date", label, value: value || undefined, required: claim.required, on: { "date-changed": () => keep(picker.value) } });
      return h("label", null, h("span", null, label), picker);
    }
    // A number field allows whole numbers only, as a native number input
    // with the default step does.
    const field: ZestTextField = textField(label, {
      type: type === "number" ? "text" : type,
      inputmode: type === "number" ? "numeric" : undefined,
      maxlength: claim.maxBytes,
      value,
      required: claim.required,
      on: { input: () => keep(field.value) },
    });
    if (type === "number") field.setAttribute("pattern", "-?[0-9]+");
    return field;
  }

  /** While the form is busy, the user cannot change the selection. */
  setBusy(busy: boolean): void {
    this.check.disabled = this.claim.policy !== "user" || busy;
  }
}

/** The claim rows of a consent form, or the line for no claims. */
function claimRows(claims: BrowserConsentClaim[], choices: ClaimChoices): { nodes: Child; rows: ConsentClaimRow[] } {
  if (!claims.length) return { nodes: h("p", null, t("app.consent.no_claims")), rows: [] };
  const rows = claims.map((claim) => new ConsentClaimRow(claim, choices));
  return { nodes: rows.map((row) => row.element), rows };
}

function initialChoices(claims: BrowserConsentClaim[]): ClaimChoices {
  return { selected: Object.fromEntries(claims.map((claim) => [claim.claimType, claim.defaultGranted])), values: {} };
}

/** The parts of a claim consent form that change: the rows, the buttons,
 * and the error line. */
class ClaimForm {
  readonly element: HTMLFormElement;
  readonly choices: ClaimChoices;
  private rows: ConsentClaimRow[];
  private submitButton = busyButton(t("app.consent.continue"), t("app.consent.continuing"));
  private cancelButton: ZestPushButton;
  private errorSlot = h("div", { class: "feedback" });
  private loginSlot = h("div");

  constructor(claims: BrowserConsentClaim[], before: Child, onSubmit: () => void, onCancel: () => void) {
    this.choices = initialChoices(claims);
    const list = claimRows(claims, this.choices);
    this.rows = list.rows;
    this.cancelButton = textButton(t("app.common.cancel"), onCancel);
    this.element = form({ class: "card", onSubmit },
      before,
      list.nodes,
      h("div", { class: "button-row" }, this.submitButton.element, this.cancelButton),
      this.errorSlot,
      this.loginSlot);
  }

  update(state: { busy: boolean; submitDisabled: boolean; error: string; needsLogin?: boolean }): void {
    setBusy(this.element, state.busy);
    this.submitButton.busy(state.busy);
    this.submitButton.element.disabled = state.busy || state.submitDisabled;
    this.cancelButton.disabled = state.busy;
    for (const row of this.rows) row.setBusy(state.busy);
    fill(this.errorSlot, alertLine(state.error));
    fill(this.loginSlot, state.needsLogin && link("/app/login?next=/app/consent", t("app.consent.sign_in_again")));
  }
}

/** Replace `current` with `next` in the page, and return `next`. */
function swap(current: Element, next: HTMLElement): HTMLElement {
  if (current !== next) current.replaceWith(next);
  return next;
}

// ---------------------------------------------------------------------------
// Authorization for an app on another domain
// ---------------------------------------------------------------------------

class AuthorizeGatewayPage extends Page {
  protected build(): HTMLElement {
    return loading();
  }

  protected async start(): Promise<void> {
    const handoff = authorizationHandoff(window.location.search, window.location.hash, Boolean(this.context.session));
    if (!handoff) {
      this.replaceChildren(unavailable(t("app.authorize.invalid_title"), t("app.authorize.invalid_detail")));
      return;
    }
    sessionStorage.setItem(authorizationRequestKey, handoff.signedRequest);
    window.history.replaceState({}, "", window.location.pathname);
    this.context.navigate(handoff.path);
  }
}

export function authorizeGatewayPage(context: PageProps): Element {
  return createPage("linkkeys-authorize-gateway-page", AuthorizeGatewayPage, context);
}

class ConsentPage extends Page {
  private signedRequest = sessionStorage.getItem(authorizationRequestKey) ?? "";
  private consentContext?: BrowserAuthorizationInspectResponse;
  private claimForm?: ClaimForm;
  private busy = false;
  private error = "";
  private needsLogin = false;
  private restartRequired = false;
  private hero = h("section", { class: "hero" });
  private content: HTMLElement = h("section", { class: "card" });
  private main = h("main", { class: "wrap narrow" }, this.hero, this.content);

  protected build(): HTMLElement {
    this.refresh();
    return this.main;
  }

  protected async start(): Promise<void> {
    const signedRequest = this.signedRequest;
    if (!signedRequest) return this.set({ error: t("app.consent.missing") });
    try {
      const result = await api.browserAuthorization.inspect({ signedRequest });
      if (!this.isActive()) return;
      if (result.accessDenied) {
        sessionStorage.removeItem(authorizationRequestKey);
        this.replaceChildren(accessBlockedPage(t("app.consent.eyebrow"), result.accessDenied));
        return;
      }
      const authorizedClaims = standingAuthorization(result);
      if (authorizedClaims) {
        try {
          const completion = await api.browserAuthorization.complete({ signedRequest, authorizedClaims, claimTypesToSet: [], claimValuesToSet: [], useStandingGrant: true });
          if (!this.isActive()) return;
          sessionStorage.removeItem(authorizationRequestKey);
          window.location.assign(completion.redirectUrl);
          return;
        } catch (cause) {
          if (!this.isActive()) return;
          if (authenticationFailed(cause)) {
            this.showConsent(result);
            this.set({ needsLogin: true, error: t("app.consent.sign_in_again_message") });
          } else if (authorizationRequestIsTerminal(cause)) {
            this.showConsent(result);
            sessionStorage.removeItem(authorizationRequestKey);
            this.set({ restartRequired: true, error: t("app.consent.request_terminal") });
          } else {
            let latest = result;
            try { latest = await api.browserAuthorization.inspect({ signedRequest }); } catch { /* Use the prior safe disclosure. */ }
            if (!this.isActive()) return;
            this.showConsent(latest);
            this.set({ error: t("app.consent.saved_approval_failed") });
          }
          return;
        }
      }
      this.showConsent(result);
    } catch (cause) {
      if (!this.isActive()) return;
      if (authenticationFailed(cause)) this.set({ needsLogin: true, error: t("app.consent.sign_in_again_message") });
      else this.set({ error: t("app.consent.request_invalid") });
    }
  }

  private showConsent(result: BrowserAuthorizationInspectResponse): void {
    this.consentContext = result;
    this.claimForm = new ClaimForm(result.claims, [
      result.callbackHost && h("p", { class: "notice" }, formatted("app.consent.callback_host", { host: h("code", null, result.callbackHost) })),
      hasNewlyRequestedClaim(result.claims) && h("p", { class: "notice" }, t("app.consent.new_notice")),
      result.requestReason && h("p", { class: "notice" }, result.requestReason),
    ], () => void this.submit(), () => this.cancel());
    this.refresh();
  }

  private set(state: { busy?: boolean; error?: string; needsLogin?: boolean; restartRequired?: boolean }): void {
    Object.assign(this, state);
    this.refresh();
  }

  private refresh(): void {
    const context = this.consentContext;
    const title = context
      ? (hasNewlyRequestedClaim(context.claims) ? t("app.consent.new_title", { app: context.application?.displayName ?? context.relyingParty }) : t("app.consent.title"))
      : this.error ? t("app.consent.stopped_title") : t("app.consent.checking_title");
    const intro = context && (context.application
      ? t("app.consent.intro_application", { app: context.application.displayName, domain: context.relyingParty })
      : t("app.consent.intro", { app: context.relyingParty }));
    fill(this.hero, h("p", { class: "eyebrow" }, t("app.consent.eyebrow")), h("h1", null, title), intro && h("p", null, intro));
    if (context && this.claimForm) {
      this.content = swap(this.content, this.claimForm.element);
      this.claimForm.update({ busy: this.busy, submitDisabled: hasBlockedRequiredClaim(context.claims) || this.restartRequired, error: this.error, needsLogin: this.needsLogin });
    } else {
      this.content = swap(this.content, statusCard(this.error, t("app.consent.checking"), this.needsLogin && link("/app/login?next=/app/consent", t("app.consent.sign_in_again"))));
    }
  }

  private async submit(): Promise<void> {
    const claimForm = this.claimForm!;
    this.set({ busy: true, error: "" });
    const decision = consentDecision(this.consentContext?.claims ?? [], claimForm.choices.selected, claimForm.choices.values);
    if (decision.oversized) return this.set({ busy: false, error: t("app.claim.too_long", { label: decision.oversized.label, max: decision.oversized.maxBytes }) });
    try {
      const result = await api.browserAuthorization.complete({ signedRequest: this.signedRequest, authorizedClaims: decision.authorizedClaims, claimTypesToSet: decision.claimTypesToSet, claimValuesToSet: decision.claimValuesToSet });
      if (!this.isActive()) return;
      sessionStorage.removeItem(authorizationRequestKey);
      window.location.assign(result.redirectUrl);
    } catch (cause) {
      if (!this.isActive()) return;
      if (authenticationFailed(cause)) this.set({ busy: false, needsLogin: true, error: t("app.consent.sign_in_again_message") });
      else if (authorizationRequestIsTerminal(cause)) {
        sessionStorage.removeItem(authorizationRequestKey);
        this.set({ busy: false, restartRequired: true, error: t("app.consent.request_terminal") });
      } else this.set({ busy: false, error: message(cause, t("app.consent.complete_failed")) });
    }
  }

  private cancel(): void {
    sessionStorage.removeItem(authorizationRequestKey);
    this.context.navigate("/app/consent/cancelled");
  }
}

export function consentPage(context: PageProps): Element {
  return createPage("linkkeys-consent-page", ConsentPage, context);
}

// ---------------------------------------------------------------------------
// A local (unverified) app
// ---------------------------------------------------------------------------

class LocalRpGatewayPage extends Page {
  protected build(): HTMLElement {
    return loading();
  }

  protected async start(): Promise<void> {
    const signedRequest = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("request");
    if (!signedRequest) return this.context.navigate("/app/error?reason=missing");
    sessionStorage.setItem(localRpRequestKey, signedRequest);
    const username = query("username");
    window.history.replaceState({}, "", window.location.pathname);
    this.context.navigate(this.context.session ? "/app/local-rp/consent" : withLoginContext("/app/login", "/app/local-rp/consent", username));
  }
}

export function localRpGatewayPage(context: PageProps): Element {
  return createPage("linkkeys-local-rp-gateway-page", LocalRpGatewayPage, context);
}

class LocalRpConsentPage extends Page {
  private signedRequest = sessionStorage.getItem(localRpRequestKey) ?? "";
  private consentContext?: BrowserLocalRpInspectResponse;
  private claimForm?: ClaimForm;
  private busy = false;
  private error = "";
  private hero = h("section", { class: "hero" });
  private content: HTMLElement = h("section", { class: "card" });

  protected build(): HTMLElement {
    this.refresh();
    return h("main", { class: "wrap narrow" }, this.hero, this.content);
  }

  private finish(redirectUrl: string): void {
    sessionStorage.removeItem(localRpRequestKey);
    window.location.assign(redirectUrl);
  }

  protected async start(): Promise<void> {
    const signedRequest = this.signedRequest;
    if (!signedRequest) return this.set({ error: t("app.local_rp.missing") });
    try {
      const result = await api.browserAuthorization.inspectLocalRp({ signedRequest });
      if (!this.isActive()) return;
      if (result.accessDenied) sessionStorage.removeItem(localRpRequestKey);
      if (result.admission === "consent" && result.alreadyConsented && result.authorizedClaims) {
        try {
          const completion = await api.browserAuthorization.completeLocalRp({ signedRequest, authorizedClaims: result.authorizedClaims, claimTypesToSet: [], claimValuesToSet: [], useStandingGrant: true });
          if (!this.isActive()) return;
          return this.finish(completion.redirectUrl);
        } catch { /* Fall back to the consent screen. */ }
        if (!this.isActive()) return;
      }
      this.showConsent(result);
    } catch (cause) {
      if (!this.isActive()) return;
      if (authenticationFailed(cause) && !/^[a-z_]+$/.test((cause as Error).message)) return this.context.navigate("/app/login?next=/app/local-rp/consent");
      this.set({ error: localRpFailureMessage(cause) });
    }
  }

  private showConsent(result: BrowserLocalRpInspectResponse): void {
    this.consentContext = result;
    if (!result.accessDenied && result.admission !== "pending") {
      this.claimForm = new ClaimForm(result.claims, [
        h("div", { class: "notice" },
          h("p", null, h("strong", null, t("app.local_rp.unverified", { app: result.appName }))),
          h("p", null, t("app.local_rp.warning")),
          h("p", null, formatted("app.local_rp.callback_host", { host: h("code", null, result.callbackHost) })),
          h("p", null, h("small", null, formatted("app.local_rp.fingerprint", { fingerprint: h("code", { title: result.fingerprint }, result.fingerprint.slice(0, 16)) }))),
          result.firstSeenAt && h("p", null, h("small", null, t("app.local_rp.first_seen", { date: new Date(result.firstSeenAt).toLocaleString() })))),
        hasNewlyRequestedClaim(result.claims) && h("p", { class: "notice" }, t("app.consent.new_notice")),
        result.requestReason && h("p", { class: "notice" }, result.requestReason),
      ], () => void this.submit(), () => this.cancel());
    }
    this.refresh();
  }

  private set(state: { busy?: boolean; error?: string }): void {
    Object.assign(this, state);
    this.refresh();
  }

  private refresh(): void {
    const context = this.consentContext;
    const pending = context?.admission === "pending";
    const denied = context?.accessDenied;
    const title = denied ? t("app.access_blocked.title")
      : pending ? t("app.local_rp.pending_title")
      : context ? (hasNewlyRequestedClaim(context.claims) ? t("app.consent.new_title", { app: context.appName }) : t("app.consent.title"))
      : this.error ? t("app.consent.stopped_title") : t("app.consent.checking_title");
    fill(this.hero, h("p", { class: "eyebrow" }, t("app.local_rp.eyebrow")), h("h1", null, title), context && !pending && !denied && h("p", null, t("app.local_rp.intro", { app: context.appName })));
    if (!context) {
      this.content = swap(this.content, statusCard(this.error, t("app.consent.checking")));
    } else if (denied) {
      this.content = swap(this.content, accessBlocked(denied));
    } else if (pending) {
      this.content = swap(this.content, h("section", { class: "card" }, h("p", null, t("app.local_rp.pending_body", { app: context.appName })), link("/app/account", t("app.common.return_to_account"))));
    } else if (this.claimForm) {
      this.content = swap(this.content, this.claimForm.element);
      this.claimForm.update({ busy: this.busy, submitDisabled: hasBlockedRequiredClaim(context.claims), error: this.error });
    }
  }

  private async submit(): Promise<void> {
    const claimForm = this.claimForm!;
    this.set({ busy: true, error: "" });
    const decision = consentDecision(this.consentContext?.claims ?? [], claimForm.choices.selected, claimForm.choices.values);
    if (decision.oversized) return this.set({ busy: false, error: t("app.claim.too_long", { label: decision.oversized.label, max: decision.oversized.maxBytes }) });
    try {
      const result = await api.browserAuthorization.completeLocalRp({ signedRequest: this.signedRequest, authorizedClaims: decision.authorizedClaims, claimTypesToSet: decision.claimTypesToSet, claimValuesToSet: decision.claimValuesToSet });
      if (!this.isActive()) return;
      this.finish(result.redirectUrl);
    } catch (cause) {
      if (this.isActive()) this.set({ busy: false, error: localRpFailureMessage(cause) });
    }
  }

  private cancel(): void {
    sessionStorage.removeItem(localRpRequestKey);
    this.context.navigate("/app/local-rp/cancelled");
  }
}

export function localRpConsentPage(context: PageProps): Element {
  return createPage("linkkeys-local-rp-consent-page", LocalRpConsentPage, context);
}

// ---------------------------------------------------------------------------
// Act-as: one party acts for the user at another party
// ---------------------------------------------------------------------------

class ActAsGatewayPage extends Page {
  protected build(): HTMLElement {
    return loading();
  }

  protected async start(): Promise<void> {
    const handoff = actAsHandoff(window.location.hash, Boolean(this.context.session));
    if (!handoff) {
      this.replaceChildren(unavailable(t("app.act_as.link_invalid_title"), t("app.act_as.link_invalid_detail")));
      return;
    }
    sessionStorage.setItem(actAsRequestKey, handoff.signedRequest);
    window.history.replaceState({}, "", window.location.pathname);
    this.context.navigate(handoff.path);
  }
}

export function actAsGatewayPage(context: PageProps): Element {
  return createPage("linkkeys-act-as-gateway-page", ActAsGatewayPage, context);
}

function actAsPartyCard(role: string, party: BrowserActAsParty): HTMLElement {
  const fact = (term: string, value: Child) => [h("dt", null, term), h("dd", null, value)];
  return h("div", { class: "consent-claim" },
    h("p", { class: "eyebrow" }, role),
    h("p", null, h("strong", null, partyTitle(party))),
    h("ul", null, partyTrustNotes(party).map((note) => h("li", null, note))),
    h("dl", null,
      party.applicationId && fact(t("app.party.field.application"), party.applicationId),
      party.handle && fact(t("app.party.field.handle"), party.handle),
      party.domain && party.localRpName && fact(t("app.party.field.name"), party.localRpName),
      party.subjectUserId && fact(t("app.party.field.account_id"), h("code", null, party.subjectUserId)),
      party.localRpFingerprint && fact(t("app.party.field.fingerprint"), h("code", null, party.localRpFingerprint))));
}

function durationOptions(defaultSeconds: number, maxSeconds: number, allowZero: boolean): ZestOption[] {
  return durationChoices(defaultSeconds, maxSeconds, allowZero).map((value) => ({ value: String(value), label: describeDuration(value) }));
}

class ActAsConsentPage extends Page {
  private signedRequest = sessionStorage.getItem(actAsRequestKey) ?? "";
  private consentContext?: BrowserActAsInspectResponse;
  private selected: Record<string, boolean> = {};
  private lifetime = 0;
  private renewal = 0;
  private hero = h("section", { class: "hero" });
  private content: HTMLElement = statusCard("", t("app.act_as.checking"));
  // The parts of the form that change.
  private actForm?: HTMLFormElement;
  private checks: { box: ZestCheckBox; removed: boolean }[] = [];
  private durationBoxes: ZestComboBox[] = [];
  private submitButton = busyButton(t("app.act_as.allow"), t("app.act_as.submitting"));
  private cancelButton = textButton(t("app.common.cancel"), () => this.cancel());
  private selectOne = h("small", null, t("app.act_as.select_one"));
  private errorSlot = h("div", { class: "feedback" });

  protected build(): HTMLElement {
    this.renderHero();
    return h("main", { class: "wrap narrow" }, this.hero, this.content);
  }

  private approved(): string[] {
    return (this.consentContext?.entries ?? []).filter((entry) => !entry.removedByPolicy && this.selected[entry.scope]).map((entry) => entry.scope);
  }

  private renderHero(): void {
    const context = this.consentContext;
    fill(this.hero,
      h("p", { class: "eyebrow" }, t("app.act_as.eyebrow")),
      h("h1", null, t("app.act_as.title")),
      context && h("p", null, formatted("app.act_as.intro", { grantee: h("strong", null, partyHeadline(context.granteeParty)), audience: h("strong", null, partyHeadline(context.audienceParty)) })));
  }

  protected async start(): Promise<void> {
    if (!this.signedRequest) return this.showError(t("app.act_as.missing"));
    try {
      const result = await api.browserAuthorization.inspectActAs({ signedRequest: this.signedRequest });
      if (!this.isActive()) return;
      if (result.accessDenied) {
        sessionStorage.removeItem(actAsRequestKey);
        this.replaceChildren(accessBlockedPage(t("app.act_as.eyebrow"), result.accessDenied));
        return;
      }
      this.consentContext = result;
      this.selected = Object.fromEntries(result.entries.map((entry) => [entry.scope, !entry.removedByPolicy]));
      this.lifetime = result.defaultLifetimeSeconds;
      this.renewal = result.defaultRenewalWindowSeconds;
      this.renderHero();
      this.content = swap(this.content, this.buildForm(result));
      this.update(false, "");
    } catch (cause) {
      if (!this.isActive()) return;
      if (authenticationFailed(cause)) return this.context.navigate("/app/login?next=/app/act-as/consent");
      sessionStorage.removeItem(actAsRequestKey);
      this.showError(cause instanceof Error && cause.message ? t("app.act_as.inspect_failed_detail", { detail: cause.message }) : t("app.act_as.inspect_failed"));
    }
  }

  private showError(error: string): void {
    this.content = swap(this.content, statusCard(error, t("app.act_as.checking")));
  }

  private buildForm(context: BrowserActAsInspectResponse): HTMLFormElement {
    const entries = context.entries.map((entry) => {
      const box: ZestCheckBox = checkBox(h("span", null, entry.description ?? entry.scope), {
        checked: !entry.removedByPolicy && this.selected[entry.scope],
        disabled: entry.removedByPolicy,
        on: { change: () => { this.selected[entry.scope] = box.checked; this.updateSelection(); } },
      });
      box.classList.add("checkbox-label");
      this.checks.push({ box, removed: entry.removedByPolicy });
      return h("div", { class: "consent-claim" },
        box,
        entry.description && h("small", null, h("code", null, entry.scope)),
        entry.removedByPolicy && h("small", null, t("app.act_as.removed_by_policy")));
    });
    const lifetime: ZestComboBox = comboBox(t("app.act_as.lifetime"), durationOptions(context.defaultLifetimeSeconds, context.maxLifetimeSeconds, false), { value: String(this.lifetime), on: { change: () => { this.lifetime = Number(lifetime.value); } } });
    this.durationBoxes.push(lifetime);
    let renewal: ZestComboBox | undefined;
    if (context.maxRenewalWindowSeconds > 0) {
      renewal = comboBox(t("app.act_as.renewal"), durationOptions(context.defaultRenewalWindowSeconds, context.maxRenewalWindowSeconds, true), { value: String(this.renewal), on: { change: () => { this.renewal = Number(renewal!.value); } } });
      this.durationBoxes.push(renewal);
    }
    this.actForm = form({ class: "card", onSubmit: () => void this.submit() },
      actAsPartyCard(t("app.act_as.role_grantee"), context.granteeParty),
      actAsPartyCard(t("app.act_as.role_audience"), context.audienceParty),
      h("p", { class: "notice" }, t("app.act_as.scope_notice", { audience: partyHeadline(context.audienceParty) })),
      entries,
      lifetime,
      renewal,
      h("p", { class: "muted" }, t("app.act_as.stop_hint")),
      h("div", { class: "button-row" }, this.submitButton.element, this.cancelButton),
      this.selectOne,
      this.errorSlot);
    return this.actForm;
  }

  private busy = false;

  private updateSelection(): void {
    const none = this.approved().length === 0;
    this.submitButton.element.disabled = this.busy || none;
    show(this.selectOne, none);
  }

  private update(busy: boolean, error: string): void {
    this.busy = busy;
    if (this.actForm) setBusy(this.actForm, busy);
    this.submitButton.busy(busy);
    this.cancelButton.disabled = busy;
    for (const { box, removed } of this.checks) box.disabled = removed || busy;
    for (const box of this.durationBoxes) box.disabled = busy;
    fill(this.errorSlot, alertLine(error));
    this.updateSelection();
  }

  private async submit(): Promise<void> {
    this.update(true, "");
    try {
      const result = await api.browserAuthorization.completeActAs({ signedRequest: this.signedRequest, approvedScope: this.approved(), lifetimeSeconds: this.lifetime, renewalWindowSeconds: this.renewal });
      if (!this.isActive()) return;
      sessionStorage.removeItem(actAsRequestKey);
      window.location.assign(result.redirectUrl);
      this.update(false, "");
    } catch (cause) {
      if (!this.isActive()) return;
      if (authenticationFailed(cause)) return this.context.navigate("/app/login?next=/app/act-as/consent");
      this.update(false, cause instanceof Error && cause.message ? cause.message : t("app.act_as.complete_failed"));
    }
  }

  private cancel(): void {
    sessionStorage.removeItem(actAsRequestKey);
    this.context.navigate("/app/act-as/cancelled");
  }
}

export function actAsConsentPage(context: PageProps): Element {
  return createPage("linkkeys-act-as-consent-page", ActAsConsentPage, context);
}
