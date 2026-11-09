// @vitest-environment happy-dom
// The Zest control behavior that LinkKeys depends on. LinkKeys had its own
// fixes for these before Zest controls 0.1.2.
import { beforeAll, describe, expect, it } from "vitest";
import { defineControls } from "@catalystcommunity/controls";
import { textField } from "./dom";

const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

beforeAll(() => defineControls());

describe("Zest controls", () => {
  it("keep the host's aria-describedby on the inner input, with the field's own help", async () => {
    const rule = document.createElement("p");
    rule.id = "password-rule";
    const field = document.createElement("text-field");
    field.setAttribute("label", "New password");
    field.setAttribute("helper", "Use a password manager.");
    field.setAttribute("aria-describedby", "password-rule");
    document.body.append(rule, field);
    await settle();
    const ids = (field.querySelector("input")?.getAttribute("aria-describedby") ?? "").split(" ");
    expect(ids).toContain("password-rule");
    expect(ids.length).toBe(2);
  });

  it("name a push button's inner button from the host's aria-label", async () => {
    const action = document.createElement("push-button");
    action.setAttribute("aria-label", "Remove the email detail");
    action.textContent = "Remove";
    document.body.append(action);
    await settle();
    expect(action.querySelector("button")?.getAttribute("aria-label")).toBe("Remove the email detail");
  });

  it("give a username field's input no capitals and no spelling check", async () => {
    const field = textField("Username", { autocomplete: "username", autocapitalize: "none", spellcheck: false });
    document.body.append(field);
    await settle();
    const input = field.querySelector("input")!;
    expect(input.getAttribute("autocapitalize")).toBe("none");
    expect(input.getAttribute("spellcheck")).toBe("false");
  });
});
