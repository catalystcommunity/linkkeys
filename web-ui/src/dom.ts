// Native DOM building for the LinkKeys UI. There is no virtual DOM and no
// signal graph: a page builds its elements one time, keeps references to the
// parts that change, and updates only those parts (Zest rule: "Change the
// parts of the DOM that changed").
import { format, t } from "./i18n";

export type Child = Node | string | number | false | null | undefined | Child[];

type Handler = (event: any) => void;

export interface Props {
  class?: string;
  /** Event listeners, by event name. */
  on?: Record<string, Handler>;
  /** Properties to assign, for values that are not text (for example a
   * combo box's `options`). Set them after the tag is defined. */
  props?: Record<string, unknown>;
  ref?: (element: any) => void;
  /** Any other key is an attribute. `true` gives an empty attribute;
   * `false`, `null`, and `undefined` leave it out. */
  [attribute: string]: unknown;
}

/** The DOM nodes for `children`, with text for strings and numbers. */
export function nodes(children: Child): Node[] {
  if (Array.isArray(children)) return children.flatMap(nodes);
  if (children === null || children === undefined || children === false) return [];
  if (children instanceof Node) return [children];
  return [document.createTextNode(String(children))];
}

/** Make an element with attributes, listeners, properties, and children. */
export function h<K extends keyof HTMLElementTagNameMap>(tag: K, props?: Props | null, ...children: Child[]): HTMLElementTagNameMap[K];
export function h(tag: string, props?: Props | null, ...children: Child[]): HTMLElement;
export function h(tag: string, props: Props | null = null, ...children: Child[]): HTMLElement {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(props ?? {})) {
    if (name === "on") for (const [event, handler] of Object.entries((value ?? {}) as Record<string, Handler>)) element.addEventListener(event, handler);
    else if (name === "props") Object.assign(element, value ?? {});
    else if (name === "ref") continue;
    else attribute(element, name, value);
  }
  element.append(...nodes(children));
  props?.ref?.(element);
  return element;
}

/** Set, or remove, one attribute. */
export function attribute(element: Element, name: string, value: unknown): void {
  if (value === false || value === null || value === undefined) element.removeAttribute(name);
  else element.setAttribute(name, value === true ? "" : String(value));
}

/** Replace the children of `element`. */
export function fill(element: Element, ...children: Child[]): void {
  element.replaceChildren(...nodes(children));
}

/** Show or hide an element. */
export function show(element: HTMLElement, visible: unknown): void {
  element.hidden = !visible;
}

/** A catalog message with markup in place of some placeholders. */
export function formatted(key: string, vars: Record<string, string | number | Node>): Node[] {
  return format<Node>(key, vars).map((part) => typeof part === "string" ? document.createTextNode(part) : part);
}

/** A link that the app routes without a page load. */
export function link(href: string, ...children: Child[]): HTMLAnchorElement {
  return h("a", { href, "data-linkkeys-nav": true }, ...children);
}

/** Mark the current link of a navigation group. */
export function markCurrent(anchor: HTMLAnchorElement, current: boolean): void {
  attribute(anchor, "aria-current", current ? "page" : null);
}

// ---------------------------------------------------------------------------
// Controls. Each helper makes a Zest control with its common attributes, so
// that the pages read like the forms they are.
// ---------------------------------------------------------------------------

export interface FieldOptions {
  name?: string;
  type?: string;
  value?: string;
  required?: boolean;
  autocomplete?: string;
  placeholder?: string;
  helper?: string;
  maxlength?: number;
  readonly?: boolean;
  inputmode?: string;
  autocapitalize?: string;
  spellcheck?: boolean;
  autofocus?: boolean;
  "aria-label"?: string;
  "aria-describedby"?: string;
  class?: string;
  on?: Record<string, Handler>;
}

/** A Zest text field. `label` is the visible label; pass `aria-label`
 * instead for a field with no visible label. */
export function textField(label: string, options: FieldOptions = {}): ZestTextField {
  const { on, value, spellcheck, ...attributes } = options;
  const field = h("text-field", { label: label || undefined, ...attributes, spellcheck: spellcheck === false ? "false" : undefined, on });
  if (value !== undefined) field.setAttribute("value", value);
  return field;
}

export function textArea(label: string, options: FieldOptions & { rows?: number } = {}): ZestTextArea {
  const { on, value, ...attributes } = options;
  const area = h("text-area", { label: label || undefined, ...attributes, on });
  if (value !== undefined) area.setAttribute("value", value);
  return area;
}

export function checkBox(label: Child, options: { checked?: boolean; disabled?: boolean; required?: boolean; name?: string; "aria-describedby"?: string; on?: Record<string, Handler> } = {}): ZestCheckBox {
  return h("check-box", { ...options }, label);
}

/** A Zest combo box. Editable boxes also accept typed text that is not one
 * of the options (it replaces the native `<input list>`). */
export function comboBox(label: string, options: ZestOption[], settings: { value?: string; editable?: boolean; required?: boolean; disabled?: boolean; placeholder?: string; name?: string; "aria-describedby"?: string; on?: Record<string, Handler> } = {}): ZestComboBox {
  const { value, on, ...attributes } = settings;
  const box = h("combo-box", { label, ...attributes, on, props: { options } });
  if (value !== undefined) box.setAttribute("value", value);
  return box;
}

/** A yes/no choice for a boolean value, with an empty "choose" option. */
export function yesNoOptions(): ZestOption[] {
  return [{ value: "", label: t("app.common.choose_value") }, { value: "true", label: t("app.common.yes") }, { value: "false", label: t("app.common.no") }];
}

export function button(text: Child, options: { type?: "button" | "submit"; variant?: "default" | "primary" | "danger" | "flat"; disabled?: boolean; "aria-label"?: string; class?: string; on?: Record<string, Handler>; onClick?: Handler } = {}): ZestPushButton {
  const { onClick, on, type = "button", variant = type === "submit" ? "primary" : undefined, ...attributes } = options;
  return h("push-button", { type, variant, ...attributes, on: { ...on, ...(onClick ? { click: onClick } : {}) } }, text);
}

/** A button that looks like a link, for secondary actions. */
export function textButton(text: Child, onClick: Handler, options: { disabled?: boolean; "aria-label"?: string } = {}): ZestPushButton {
  return button(text, { variant: "flat", class: "text-button", onClick, ...options });
}

/** Turn a group of controls on or off together. */
export function setDisabled(controls: Iterable<{ disabled: boolean }>, disabled: boolean): void {
  for (const control of controls) control.disabled = disabled;
}

// ---------------------------------------------------------------------------
// Feedback: one status line and one alert line for a section.
// ---------------------------------------------------------------------------

export class Feedback {
  readonly element = h("div", { class: "feedback" });

  /** Show a success message. */
  status(text: string): void {
    fill(this.element, text && h("p", { class: "notice good", role: "status" }, text));
  }

  /** Show a problem. */
  error(text: string): void {
    fill(this.element, text && h("p", { class: "notice bad", role: "alert" }, text));
  }

  clear(): void {
    fill(this.element);
  }
}

/** A form that calls `submit` with the native submit event prevented. Each
 * Zest control in it is form associated, so the browser checks `required`
 * and the other rules before the event. Enter in a `text-field` submits the
 * form through its first submit button, as with native controls. */
export function form(props: Props & { onSubmit: (event: SubmitEvent) => void }, ...children: Child[]): HTMLFormElement {
  const { onSubmit, on, ...rest } = props;
  return h("form", { ...rest, on: { ...on, submit: (event: SubmitEvent) => { event.preventDefault(); onSubmit(event); } } }, ...children);
}

/** Mark a form busy: `aria-busy`, and the given controls off. */
export function setBusy(element: HTMLElement, busy: boolean, controls: Iterable<{ disabled: boolean }> = []): void {
  attribute(element, "aria-busy", busy ? "true" : null);
  setDisabled(controls, busy);
}

/** The message of a status line for a load that is still running. */
export function loadingLine(text: string): HTMLParagraphElement {
  return h("p", { role: "status" }, text);
}

/** A visually hidden, read-only username field. It tells a password manager
 * which account a password form is for. */
export function hiddenUsername(username: string): ZestTextField {
  return textField("", { class: "visually-hidden", value: username, autocomplete: "username", readonly: true, "aria-label": t("app.login.username") });
}
