import { readFileSync, readdirSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import enUS from "../../crates/liblinkkeys/i18n/en-US.json";
import { claimTypeLabel, currentLocale, format, plural, t, useCatalog } from "./i18n";

afterEach(() => useCatalog({ locale: "en-US", messages: {} }));

describe("message lookup", () => {
  it("uses the bundled en-US catalog before a server catalog loads", () => {
    expect(t("app.login.title")).toBe("Sign in");
  });

  it("fills placeholders and leaves unknown ones as written", () => {
    expect(t("app.claim.too_long", { label: "Email", max: 320 })).toBe("Email is too long. Use at most 320 bytes.");
    expect(t("app.claim.too_long", { label: "Email" })).toBe("Email is too long. Use at most {max} bytes.");
  });

  it("returns the key itself for a key no catalog has", () => {
    expect(t("app.no_such_key")).toBe("app.no_such_key");
  });

  it("splits a message around placeholders so markup can fill them", () => {
    const bold = { bold: "linkidspec.com" };
    expect(format("app.confirm.result", { site: bold, until: "tomorrow" })).toEqual(["Copy this code and paste it on ", bold, ". The code works until ", "tomorrow", "."]);
  });

  it("chooses the plural form for the count", () => {
    expect(plural("app.duration.day", 1)).toBe("1 day");
    expect(plural("app.duration.day", 3)).toBe("3 days");
  });

  it("overlays a served catalog on en-US and sets the locale", () => {
    useCatalog({ locale: "en-XA", messages: { "app.login.title": "[Śïğñ ïñ]", "claim.over_21.label": "Over 21" } });
    expect(currentLocale()).toBe("en-XA");
    expect(t("app.login.title")).toBe("[Śïğñ ïñ]");
    expect(t("app.login.intro")).toBe("Use your LinkKeys account to continue.");
    expect(claimTypeLabel("over_21")).toBe("Over 21");
  });

  it("names a claim type without a label in title case", () => {
    expect(claimTypeLabel("favorite_color")).toBe("Favorite Color");
    expect(claimTypeLabel("email")).toBe("Email address");
  });
});

describe("UI catalog coverage", () => {
  const catalog = enUS as Record<string, string>;
  const sources = readdirSync(new URL(".", import.meta.url))
    .filter((name) => /\.tsx?$/.test(name) && !name.endsWith(".test.ts"))
    .map((name) => readFileSync(new URL(name, import.meta.url), "utf8"))
    .join("\n");
  const literal = [...sources.matchAll(/\b(t|format(?:<[^>]+>)?)\("(app\.[^"]+)"/g)].map((match) => match[2]);
  const plurals = [...sources.matchAll(/\bplural\("(app\.[^"]+)"/g)].map((match) => match[1]);
  // Keys built at run time: `plural(`app.duration.${name}`)`, `pageTitle`,
  // and `reasonText`.
  const dynamicPrefixes = ["app.duration.", "app.page_title.", "app.error.reason."];

  it("has an en-US message for every key the UI uses", () => {
    const missing = [
      ...literal.filter((key) => !(key in catalog)),
      ...plurals.flatMap((key) => [`${key}.one`, `${key}.other`]).filter((key) => !(key in catalog)),
    ];
    expect(missing).toEqual([]);
  });

  it("has no unused UI keys in en-US", () => {
    const used = new Set([...literal, ...plurals.flatMap((key) => [`${key}.one`, `${key}.other`])]);
    const unused = Object.keys(catalog).filter((key) => key.startsWith("app.") && !used.has(key) && !dynamicPrefixes.some((prefix) => key.startsWith(prefix)));
    expect(unused).toEqual([]);
  });
});
