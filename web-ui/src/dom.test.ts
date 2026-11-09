// @vitest-environment happy-dom
import { beforeAll, describe, expect, it, vi } from "vitest";
import { defineControls } from "@catalystcommunity/controls";
import { button, form, textField } from "./dom";

beforeAll(() => defineControls());

// happy-dom does not connect a custom element to its form, so Enter in a
// field cannot submit here. Check the part that makes the browser do it: the
// inner button of a light DOM submit button is a native submit button.
describe("form", () => {
  it("has a native default button, so Enter in a field submits it", async () => {
    const element = form({ onSubmit: vi.fn() }, textField("Name"), button("Other"), button("Save", { type: "submit" }));
    document.body.append(element);
    await new Promise((resolve) => setTimeout(resolve, 0));
    const inner = [...element.querySelectorAll("push-button button")].map((native) => (native as HTMLButtonElement).type);
    expect(inner).toEqual(["button", "submit"]);
    element.remove();
  });

  it("calls the submit handler with the native submit prevented", () => {
    const onSubmit = vi.fn();
    const element = form({ onSubmit });
    const event = new Event("submit", { cancelable: true });
    element.dispatchEvent(event);
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(event.defaultPrevented).toBe(true);
  });
});
