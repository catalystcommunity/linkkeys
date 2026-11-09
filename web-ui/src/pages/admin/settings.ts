// Domain settings: how long a sign-in lasts.
import { api } from "../../transport";
import { t } from "../../i18n";
import { button, fill, form, h, textField, type Child } from "../../dom";
import type { SignInPolicy } from "../../generated/types.gen";
import { serviceMessage as message } from "../../ui-logic";
import { AdminPage, Slot, adminHeader, numberText } from "./common";

export class AdminSettingsPage extends AdminPage {
  private policy?: SignInPolicy;
  private readonly content = new Slot();
  private readonly placeholder = h("p", { role: "status" }, t("app.settings.loading"));
  private readonly intro = h("p", { id: "sign-in-hours-help" });
  private readonly hours = textField(t("app.settings.hours"), { inputmode: "numeric", "aria-describedby": "sign-in-hours-help", required: true });

  protected build(): Child {
    const header = adminHeader(this.context.path, t("app.settings.title"));
    return [...header.nodes, h("section", { class: "card" }, h("h2", null, t("app.settings.sign_in_title")), this.content.anchor)];
  }

  protected async start(): Promise<void> {
    this.content.set(this.placeholder);
    await this.load(async () => {
      const current = await api.admin.getSignInPolicy({});
      if (!this.isActive()) return;
      this.showPolicy(current);
      const saveForm = this.busy.form(form({ class: "inline-form", onSubmit: () => void this.save() }, this.hours, this.busy.control(button(t("app.settings.save"), { type: "submit" }))));
      this.content.set(this.intro, saveForm, this.messages.element);
    }, () => t("app.settings.load_failed"));
  }

  protected showLoadError(text: string): void {
    this.messages.fail(text);
    if (this.policy) return;
    this.placeholder.setAttribute("role", "alert");
    fill(this.placeholder, text);
  }

  private showPolicy(policy: SignInPolicy): void {
    this.policy = policy;
    this.hours.value = String(policy.signInHours);
    fill(this.intro, t("app.settings.sign_in_intro", { default: policy.defaultSignInHours }));
  }

  private async save(): Promise<void> {
    this.messages.clear();
    const text = this.hours.value;
    const value = Number(text);
    const range = this.policy!;
    // The original `type=number` input with min, max, and step 1 refused the
    // same values: text that is not a number, a fraction, or out of range.
    if (!numberText(text) || !Number.isInteger(value) || value < range.minSignInHours || value > range.maxSignInHours) {
      return this.messages.fail(t("app.settings.hours_invalid", { min: range.minSignInHours, max: range.maxSignInHours }));
    }
    this.busy.set(true);
    try {
      const saved = await api.admin.setSignInPolicy({ signInHours: value });
      if (!this.isActive()) return;
      this.showPolicy(saved);
      this.messages.status(t("app.settings.saved", { hours: saved.signInHours }));
    } catch (cause) {
      if (this.isActive()) this.messages.fail(message(cause, t("app.settings.save_failed")));
    } finally {
      if (this.isActive()) this.busy.set(false);
    }
  }
}
