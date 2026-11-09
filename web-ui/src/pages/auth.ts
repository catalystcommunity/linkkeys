// Sign-in, password recovery, and contact verification pages.
import { api } from "../transport";
import { t } from "../i18n";
import { Page, createPage } from "../page";
import { Feedback, button, fill, form, h, link, setBusy, show, textField } from "../dom";
import { checkPassword, loading, passwordRule, query, unavailable, type PageProps } from "../shared";
import {
  loginFailureMessage,
  passwordManagerUsername,
  recoveryCompletionFailureMessage,
  recoveryLinkExpired,
  recoveryValidationFailureMessage,
  serviceMessage as message,
  transportFailed,
  verificationFailureMessage,
  withLoginContext,
} from "../ui-logic";

/** A continuation path, only when it stays inside the app. */
export function safeNext(value: string): string {
  return value.startsWith("/app/") ? value : "";
}

/** Read the `token` of the URL fragment, keep it in session storage under
 * `storageKey`, and remove the fragment from the address bar. Without a
 * fragment token, the stored token is used. */
export function takeFragmentToken(storageKey?: string): string {
  const fragmentToken = new URLSearchParams(window.location.hash.slice(1)).get("token");
  if (fragmentToken && storageKey) sessionStorage.setItem(storageKey, fragmentToken);
  const token = fragmentToken ?? (storageKey ? sessionStorage.getItem(storageKey) ?? "" : "");
  if (window.location.hash) window.history.replaceState({}, "", window.location.pathname + window.location.search);
  return token;
}

/** A submit button whose text changes while it is busy. */
function busyButton(idle: string, working: string): { element: ZestPushButton; busy(value: boolean): void } {
  const text = document.createTextNode(idle);
  const element = button(text, { type: "submit" });
  return { element, busy: (value) => { text.data = value ? working : idle; element.disabled = value; } };
}

function hero(eyebrow: string, title: string, ...more: HTMLElement[]): HTMLElement {
  return h("section", { class: "hero" }, h("p", { class: "eyebrow" }, eyebrow), h("h1", null, title), ...more);
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

class LoginPage extends Page {
  private username = textField(t("app.login.username"), { name: "username", value: query("username"), autocomplete: "username", autocapitalize: "none", spellcheck: false, required: true });
  private password = textField(t("app.login.password"), { name: "current-password", type: "password", autocomplete: "current-password", required: true });
  private submitButton = busyButton(t("app.login.submit"), t("app.login.submitting"));
  private feedback = new Feedback();
  private forgot?: HTMLAnchorElement;
  private loginForm?: HTMLFormElement;

  private continuation(): string {
    return safeNext(query("next")) || safeNext(window.location.pathname !== "/app/login" ? window.location.pathname : "");
  }

  private forgotHref(): string {
    return withLoginContext("/app/password/request", this.continuation(), this.username.value ?? "");
  }

  protected build(): HTMLElement {
    const { configuration } = this.context;
    if (!configuration.capabilities.includes("password_login")) return unavailable(t("app.login.unavailable_title"), t("app.common.contact_support"));
    this.username.id = "login-username";
    this.password.id = "login-password";
    if (configuration.capabilities.includes("reset_password")) {
      this.forgot = link(withLoginContext("/app/password/request", this.continuation(), query("username")), t("app.login.forgot"));
      this.username.addEventListener("input", () => { if (this.forgot) this.forgot.href = this.forgotHref(); });
    }
    this.loginForm = form({ id: "login-form", name: "login", class: "card", onSubmit: () => void this.submit() },
      this.username,
      this.password,
      this.submitButton.element,
      this.forgot && h("small", null, this.forgot),
      this.feedback.element);
    return h("main", { class: "wrap narrow" }, hero(configuration.domain, t("app.login.title"), h("p", null, t("app.login.intro"))), this.loginForm);
  }

  protected async start(): Promise<void> {
    if (!this.loginForm) return;
    // Start in the first empty field. The shell then keeps this focus and
    // does not move it to the heading.
    (this.username.value ? this.password : this.username).focus();
  }

  private async submit(): Promise<void> {
    if (!this.loginForm) return;
    this.setBusy(true);
    this.feedback.clear();
    try {
      await api.session.loginPassword({ username: this.username.value, password: this.password.value });
      if (!this.isActive()) return;
      this.password.value = "";
      await this.context.refreshSession();
      const requestedNext = query("next");
      const pathNext = window.location.pathname !== "/app/login" ? window.location.pathname : "";
      const next = requestedNext || pathNext;
      sessionStorage.removeItem("linkkeys-recovery-next");
      this.context.navigate(next.startsWith("/app/") ? next : "/app/account");
    } catch (cause) {
      if (this.isActive()) this.feedback.error(loginFailureMessage(cause));
    } finally {
      if (this.isActive()) this.setBusy(false);
    }
  }

  private setBusy(busy: boolean): void {
    setBusy(this.loginForm!, busy);
    this.submitButton.busy(busy);
  }
}

export function loginPage(context: PageProps): Element {
  return createPage("linkkeys-login-page", LoginPage, context);
}

// ---------------------------------------------------------------------------
// Password recovery request
// ---------------------------------------------------------------------------

class RequestPasswordPage extends Page {
  private continuation = safeNext(query("next"));
  private identifier!: ZestTextField;
  private submitButton = busyButton(t("app.recovery.send"), t("app.recovery.sending"));
  private feedback = new Feedback();
  private requestForm?: HTMLFormElement;

  protected build(): HTMLElement {
    const { configuration } = this.context;
    if (!configuration.capabilities.includes("reset_password")) return unavailable(t("app.recovery.unavailable_title"), t("app.common.contact_support"));
    this.identifier = textField(t("app.recovery.identifier"), { value: query("username"), autocomplete: "username", maxlength: 320, required: true, helper: t("app.recovery.identifier_hint", { domain: configuration.domain }) });
    this.requestForm = form({ class: "card", onSubmit: () => void this.submit() },
      h("p", null, t("app.recovery.request_intro")),
      this.identifier,
      this.submitButton.element,
      this.feedback.element);
    return h("main", { class: "wrap narrow" }, hero(t("app.recovery.eyebrow"), t("app.recovery.request_title")), this.requestForm);
  }

  private async submit(): Promise<void> {
    const requestForm = this.requestForm!;
    const identifier = this.identifier.value;
    setBusy(requestForm, true);
    this.submitButton.busy(true);
    this.feedback.clear();
    try {
      sessionStorage.setItem("linkkeys-recovery-identifier", identifier);
      if (this.continuation) sessionStorage.setItem("linkkeys-recovery-next", this.continuation);
      else sessionStorage.removeItem("linkkeys-recovery-next");
      await api.recovery.requestPasswordRecovery({ identifier });
      if (!this.isActive()) return;
      const loginUsername = passwordManagerUsername(identifier, this.context.configuration.domain);
      requestForm.replaceWith(h("section", { class: "card good" },
        h("h2", null, t("app.recovery.sent_title")),
        h("p", null, t("app.recovery.sent_body")),
        link(withLoginContext("/app/login", this.continuation, loginUsername), t("app.recovery.return_to_sign_in"))));
    } catch (cause) {
      if (this.isActive()) this.feedback.error(message(cause, t("app.recovery.request_failed")));
    } finally {
      if (this.isActive()) {
        setBusy(requestForm, false);
        this.submitButton.busy(false);
      }
    }
  }
}

export function requestPasswordPage(context: PageProps): Element {
  return createPage("linkkeys-request-password-page", RequestPasswordPage, context);
}

// ---------------------------------------------------------------------------
// Password reset from a recovery link
// ---------------------------------------------------------------------------

class ResetPasswordPage extends Page {
  private token = "";
  private continuation = "";
  private username!: ZestTextField;
  private password = textField(t("app.password.new"), { name: "new-password", type: "password", autocomplete: "new-password", required: true });
  private confirmation = textField(t("app.password.confirm_new"), { name: "new-password-confirmation", type: "password", autocomplete: "new-password", required: true });
  private submitButton = busyButton(t("app.recovery.set_password"), t("app.recovery.saving"));
  private feedback = new Feedback();
  private resetForm!: HTMLFormElement;
  // The card that shows while the link is checked, or why it is not valid.
  private checkCard = h("section", { class: "card" });
  private checkStatus = h("p", { role: "status" });
  private retryButton = button(t("app.common.try_again"), { onClick: () => void this.validateToken() });
  private requestNew = link("", t("app.recovery.request_new"));
  private content!: HTMLElement;

  protected build(): HTMLElement {
    const { configuration } = this.context;
    this.token = takeFragmentToken("linkkeys-recovery-token");
    this.continuation = safeNext(sessionStorage.getItem("linkkeys-recovery-next") ?? "");
    const storedIdentifier = sessionStorage.getItem("linkkeys-recovery-identifier") ?? "";
    this.username = textField(t("app.recovery.pm_username"), { name: "username", value: passwordManagerUsername(storedIdentifier, configuration.domain), autocomplete: "username", autocapitalize: "none", spellcheck: false, helper: t("app.recovery.pm_username_hint") });
    this.resetForm = form({ id: "reset-password-form", name: "reset-password", class: "card", onSubmit: () => void this.submit() },
      h("p", { id: "reset-password-rule" }, passwordRule(configuration)),
      this.username,
      this.password,
      this.confirmation,
      this.submitButton.element,
      this.feedback.element);
    this.checkCard.append(this.checkStatus, this.retryButton, this.requestNew);
    this.content = this.checkCard;
    return h("main", { class: "wrap narrow" }, hero(t("app.recovery.eyebrow"), t("app.recovery.reset_title")), this.content);
  }

  protected async start(): Promise<void> {
    await this.validateToken();
  }

  private showContent(next: HTMLElement): void {
    if (this.content === next) return;
    this.content.replaceWith(next);
    this.content = next;
  }

  /** Show the check card: still checking, or a problem with the link. */
  private showCheck(checking: boolean, error: string, retry: boolean): void {
    this.showContent(this.checkCard);
    setBusy(this.checkCard, checking);
    this.checkStatus.setAttribute("role", error ? "alert" : "status");
    this.checkStatus.textContent = error || t("app.recovery.checking");
    show(this.retryButton, retry);
    this.retryButton.disabled = checking;
    this.requestNew.href = withLoginContext("/app/password/request", this.continuation, this.username.value ?? "");
    show(this.requestNew, !retry && error);
  }

  private async validateToken(): Promise<void> {
    this.showCheck(true, "", false);
    try {
      await api.recovery.validatePasswordRecovery({ token: this.token });
      if (!this.isActive()) return;
      this.showContent(this.resetForm);
    } catch (cause) {
      if (this.isActive()) this.showCheck(false, recoveryValidationFailureMessage(cause), transportFailed(cause));
    }
  }

  private async submit(): Promise<void> {
    this.feedback.clear();
    const password = this.password.value;
    if (password !== this.confirmation.value) return this.feedback.error(t("app.password.mismatch"));
    const lengthError = checkPassword(password, this.context.configuration);
    if (lengthError) return this.feedback.error(lengthError);
    this.setBusy(true);
    try {
      await api.recovery.completePasswordRecovery({ token: this.token, newPassword: password });
      if (!this.isActive()) return;
      sessionStorage.removeItem("linkkeys-recovery-identifier");
      sessionStorage.removeItem("linkkeys-recovery-token");
      this.password.value = "";
      this.confirmation.value = "";
      this.showContent(h("section", { class: "card good" },
        h("h2", null, t("app.recovery.done_title")),
        h("p", null, t("app.recovery.done_body")),
        link(withLoginContext("/app/login", this.continuation, this.username.value ?? ""), this.continuation ? t("app.recovery.sign_in_continue") : t("app.recovery.sign_in"))));
    } catch (cause) {
      if (!this.isActive()) return;
      if (recoveryLinkExpired(cause)) this.showCheck(false, t("app.recovery.link_invalid"), false);
      else this.feedback.error(recoveryCompletionFailureMessage(cause));
    } finally {
      if (this.isActive()) this.setBusy(false);
    }
  }

  private setBusy(busy: boolean): void {
    setBusy(this.resetForm, busy);
    this.submitButton.busy(busy);
  }
}

export function resetPasswordPage(context: PageProps): Element {
  return createPage("linkkeys-reset-password-page", ResetPasswordPage, context);
}

// ---------------------------------------------------------------------------
// Contact verification
// ---------------------------------------------------------------------------

class VerifyContactPage extends Page {
  private token = "";
  private card = h("section", { class: "card" });
  private status = h("p", { role: "status" });
  private retryButton = button(t("app.common.try_again"), { onClick: () => void this.verify() });
  private otherAccount = h("p", null, link("/app/login?next=/app/verify/contact", t("app.verify_contact.other_account")));

  protected build(): HTMLElement {
    this.token = takeFragmentToken("linkkeys-contact-token");
    this.card.append(this.status, this.retryButton, this.otherAccount);
    return h("main", { class: "wrap narrow" }, hero(t("app.verify_contact.eyebrow"), t("app.verify_contact.title")), this.card);
  }

  protected async start(): Promise<void> {
    await this.verify();
  }

  private showState(checking: boolean, error: string, connectionFailure: boolean): void {
    setBusy(this.card, checking);
    this.status.setAttribute("role", error ? "alert" : "status");
    this.status.textContent = error || t("app.verify_contact.checking");
    show(this.retryButton, error && connectionFailure);
    this.retryButton.disabled = checking;
    show(this.otherAccount, error && !connectionFailure);
  }

  private async verify(): Promise<void> {
    this.showState(true, "", false);
    try {
      await api.account.confirmContactVerification({ token: this.token });
      if (!this.isActive()) return;
      sessionStorage.removeItem("linkkeys-contact-token");
      this.card.className = "card good";
      setBusy(this.card, false);
      fill(this.card,
        h("h2", null, t("app.verify_contact.done_title")),
        h("p", null, t("app.verify_contact.done_body")),
        link("/app/account", t("app.common.return_to_account")));
    } catch (cause) {
      if (this.isActive()) this.showState(false, verificationFailureMessage(cause), transportFailed(cause));
    }
  }
}

export function verifyContactPage(context: PageProps): Element {
  return createPage("linkkeys-verify-contact-page", VerifyContactPage, context);
}

/** A verification link opened without a session: keep the token and sign in
 * first. */
class VerifySignInPage extends Page {
  protected build(): HTMLElement {
    return loading();
  }

  protected async start(): Promise<void> {
    const token = new URLSearchParams(window.location.hash.slice(1)).get("token");
    if (token) sessionStorage.setItem("linkkeys-contact-token", token);
    window.history.replaceState({}, "", window.location.pathname);
    this.context.navigate("/app/login?next=/app/verify/contact");
  }
}

export function verifySignInPage(context: PageProps): Element {
  return createPage("linkkeys-verify-sign-in-page", VerifySignInPage, context);
}
