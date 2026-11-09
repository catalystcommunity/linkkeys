// Pieces shared by the admin pages: the header and tabs, the page base class
// with its load and action rules, the feedback lines, the busy state, and
// small control helpers.
import { t } from "../../i18n";
import { comboBox, fill, h, link, markCurrent, nodes, textField, type Child, type FieldOptions } from "../../dom";
import { Page } from "../../page";
import type { PageProps } from "../../shared";
import type { AdminUser, ClaimTypePolicy } from "../../generated/types.gen";
import { authenticationFailed, serviceMessage } from "../../ui-logic";

export type AdminContext = PageProps & { path: string };

/** Comma-separated text as a list, without blanks. */
export function list(text: string): string[] {
  return text.split(",").map((part) => part.trim()).filter(Boolean);
}

export function dispositionLabel(disposition: string): string {
  if (disposition === "forced_allow") return t("app.policy.disposition_allow");
  if (disposition === "forced_deny") return t("app.policy.disposition_deny");
  return t("app.policy.disposition_user");
}

export function when(value?: string): string {
  return value ? new Date(value).toLocaleString() : t("app.admin_user.never");
}

/** Options for a combo box that replaces a `<select>`. */
export function choices(values: string[], describe?: (value: string) => string): ZestOption[] {
  return values.map((value) => ({ value, label: describe ? describe(value) : value }));
}

/** Options for a combo box that replaces the claim type `<datalist>`. */
export function claimTypeOptions(types: ClaimTypePolicy[]): ZestOption[] {
  return types.map((type) => ({ value: type.claimType, label: type.label }));
}

/** Options for a combo box that replaces the username `<datalist>`. */
export function userOptions(users: AdminUser[]): ZestOption[] {
  return users.map((user) => ({ value: user.username, label: user.displayName }));
}

/** Replace the options of a combo box and keep its value. */
export function setOptions(box: ZestComboBox, options: ZestOption[]): void {
  const value = box.value;
  box.options = options;
  box.value = value;
}

/** A text field with no browser autocomplete, as each original policy field had. */
export function plainField(label: string, options: FieldOptions = {}): ZestTextField {
  return textField(label, { autocomplete: "off", ...options });
}

/** An editable combo box that replaces an `<input list>`. */
export function suggestField(label: string, options: ZestOption[] = [], settings: { required?: boolean; value?: string } = {}): ZestComboBox {
  return comboBox(label, options, { editable: true, ...settings });
}

/** A Zest check box with the original label class. */
export function flagBox(label: string): ZestCheckBox {
  return h("check-box", { class: "checkbox-label" }, label);
}

/** True for the text that a `type=number` input accepts. */
export function numberText(text: string): boolean {
  return /^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$/.test(text.trim());
}

/** A place in the DOM that holds zero or one node. The comment anchor keeps
 * the place, so the slot changes only its own node. (The `hidden` attribute
 * does not hide an element that the style sheet gives a `display`.) */
export class Slot {
  readonly anchor = document.createComment("");
  private current: Node[] = [];

  set(...children: Child[]): void {
    for (const node of this.current) (node as ChildNode).remove();
    this.current = nodes(children);
    this.anchor.after(...this.current);
  }

  get empty(): boolean {
    return this.current.length === 0;
  }
}

/** One status line and one alert line. The two are separate, as in the
 * original: a status can stay while a later problem shows. */
export class Messages {
  readonly element = h("div", { class: "feedback" });
  private statusText = "";
  private errorText = "";

  get error(): string {
    return this.errorText;
  }

  status(text: string): void {
    this.statusText = text;
    this.render();
  }

  fail(text: string): void {
    this.errorText = text;
    this.render();
  }

  clear(): void {
    this.statusText = "";
    this.errorText = "";
    this.render();
  }

  private render(): void {
    fill(this.element,
      this.statusText && h("p", { class: "notice good", role: "status" }, this.statusText),
      this.errorText && h("p", { class: "notice bad", role: "alert" }, this.errorText));
  }
}

type Toggle = { disabled: boolean };
type Busyable = Toggle | HTMLFormElement;

/** The busy state of a page: `aria-busy` on its forms, and its controls off. */
export class Busy {
  active = false;
  private readonly fixed: Busyable[] = [];
  private readonly regions = new Map<string, Busyable[]>();

  /** Add a form or a control that stays for the life of the page. */
  form<T extends HTMLFormElement>(element: T): T {
    return this.add(this.fixed, element);
  }

  control<T extends Toggle>(control: T): T {
    return this.add(this.fixed, control);
  }

  /** Start a group of forms and controls that a region makes again, for
   * example the buttons of table rows. The returned function adds one. */
  region(name: string): <T extends Busyable>(item: T) => T {
    const group: Busyable[] = [];
    this.regions.set(name, group);
    return (item) => this.add(group, item);
  }

  set(active: boolean): void {
    this.active = active;
    for (const item of this.fixed) this.apply(item);
    for (const group of this.regions.values()) for (const item of group) this.apply(item);
  }

  private add<T extends Busyable>(group: Busyable[], item: T): T {
    group.push(item);
    this.apply(item);
    return item;
  }

  private apply(item: Busyable): void {
    if (item instanceof HTMLFormElement) item.setAttribute("aria-busy", String(this.active));
    else item.disabled = this.active;
  }
}

const TABS: { path: string; label: () => string; current: (path: string) => boolean }[] = [
  { path: "/app/admin", label: () => t("app.admin_nav.accounts"), current: (path) => path === "/app/admin" || path === "/app/admin/" || path.startsWith("/app/admin/users/") },
  { path: "/app/admin/policy", label: () => t("app.admin_nav.policy"), current: (path) => path === "/app/admin/policy" },
  { path: "/app/admin/access", label: () => t("app.admin_nav.access"), current: (path) => path === "/app/admin/access" },
  { path: "/app/admin/approvals", label: () => t("app.admin_nav.approvals"), current: (path) => path === "/app/admin/approvals" },
  { path: "/app/admin/issue", label: () => t("app.admin_nav.issue"), current: (path) => path === "/app/admin/issue" },
  { path: "/app/admin/settings", label: () => t("app.admin_nav.settings"), current: (path) => path === "/app/admin/settings" },
];

/** The admin hero and the admin tabs. */
export function adminHeader(path: string, title: string, intro?: string): { nodes: Node[]; heading: HTMLHeadingElement } {
  const heading = h("h1", null, title);
  const tabs = TABS.map((tab) => {
    const anchor = link(tab.path, tab.label());
    markCurrent(anchor, tab.current(path));
    return anchor;
  });
  return {
    heading,
    nodes: [
      h("section", { class: "hero" }, h("p", { class: "eyebrow" }, t("app.admin.eyebrow")), heading, intro && h("p", null, intro)),
      h("nav", { class: "admin-tabs", "aria-label": t("app.admin_nav.label") }, ...tabs),
    ],
  };
}

/** The base class of each admin page. */
export abstract class AdminPage extends Page {
  declare context: AdminContext;
  protected readonly messages = new Messages();
  protected readonly busy = new Busy();

  /** Load the data again after an action. */
  protected async refresh(): Promise<void> {}

  /** Load data when the page opens, sending a signed-out person to sign in. */
  protected async load(work: () => Promise<void>, failure: () => string): Promise<void> {
    try {
      await work();
    } catch (cause) {
      if (!this.isActive()) return;
      if (authenticationFailed(cause)) this.context.navigate("/app/login?next=/app/admin");
      else this.showLoadError(serviceMessage(cause, failure()));
    }
  }

  /** Show a problem from the first load. */
  protected showLoadError(text: string): void {
    this.messages.fail(text);
  }

  /** Run one change, load the data again, and tell the result. */
  protected async act(work: () => Promise<unknown>, done: string, failed: string): Promise<boolean> {
    this.busy.set(true);
    this.messages.clear();
    try {
      await work();
      if (!this.isActive()) return false;
      await this.refresh();
      if (!this.isActive()) return false;
      this.messages.status(done);
      return true;
    } catch (cause) {
      if (this.isActive()) this.messages.fail(serviceMessage(cause, failed));
      return false;
    } finally {
      if (this.isActive()) this.busy.set(false);
    }
  }
}
