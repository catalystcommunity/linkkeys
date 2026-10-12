// UI strings come from the LinkKeys message catalog
// (`crates/liblinkkeys/i18n/<locale>.json`). The en-US catalog is bundled as
// the fallback, so the UI renders even when the server catalog cannot load.
// At start-up `loadTranslations` replaces it with the server's negotiated
// catalog, which is complete (en-US overlaid with the locale) and carries this
// domain's own claim labels.
import fallback from "../../crates/liblinkkeys/i18n/en-US.json";

type Messages = Record<string, string>;

let messages: Messages = fallback;
let locale = "en-US";

/** The message for `key`, with `{name}` placeholders replaced from `vars`. An
 * unknown key falls back to en-US, then to the key itself. */
export function t(key: string, vars: Record<string, string | number> = {}): string {
  return format(key, vars).join("");
}

/** True when the catalog has a message for `key`. */
export function has(key: string): boolean {
  return key in messages;
}

/** The message for `key` split around its placeholders, so a caller can put
 * markup (for example a bold name) in place of a placeholder. */
export function format<T>(key: string, vars: Record<string, string | number | T>): (string | T)[] {
  const template = messages[key] ?? (fallback as Messages)[key] ?? key;
  return template.split(/(\{[a-z_]+\})/).filter((part) => part !== "").map((part) => {
    const name = /^\{([a-z_]+)\}$/.exec(part)?.[1];
    if (name === undefined || !(name in vars)) return part;
    const value = vars[name];
    return typeof value === "number" ? String(value) : value;
  });
}

/** A counted message: `${key}.one` or `${key}.other`, chosen by the plural
 * rules of the served locale, with `{count}` filled in. */
export function plural(key: string, count: number, vars: Record<string, string | number> = {}): string {
  const rule = new Intl.PluralRules(locale).select(count);
  const chosen = `${key}.${rule}` in messages ? `${key}.${rule}` : `${key}.other`;
  return t(chosen, { ...vars, count });
}

/** The person-facing name of a claim type: this domain's label when it has
 * one, otherwise the type name in title case. */
export function claimTypeLabel(claimType: string): string {
  const label = messages[`claim.${claimType}.label`];
  return label ?? claimType.split("_").map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(" ");
}

/** Use a catalog served by the home domain. */
export function useCatalog(served: { locale: string; messages: Messages }): void {
  messages = { ...fallback, ...served.messages };
  locale = served.locale;
  if (typeof document !== "undefined") document.documentElement.lang = locale;
}

export function currentLocale(): string {
  return locale;
}
