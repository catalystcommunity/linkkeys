import { beforeEach, describe, expect, it, vi } from "vitest";
import { createMemo, createRoot } from "solid-js";
import type { AsyncApiClient } from "./generated/client.async.gen";
import type { GetUiConfigurationResponse } from "./generated/types.gen";
import { RuntimeHost } from "./host";

function makeHost(): RuntimeHost {
  return new RuntimeHost(
    {} as AsyncApiClient,
    { extensions: [] } as unknown as GetUiConfigurationResponse,
    () => undefined,
    () => undefined,
  );
}

beforeEach(() => {
  vi.stubGlobal("document", { querySelector: () => null });
  vi.stubGlobal("CSS", { escape: (value: string) => value });
});

describe("RuntimeHost", () => {
  it("updates extension contributions after registration and removal", async () => {
    const host = makeHost();
    await createRoot(async (dispose) => {
      try {
        const navigationLabels = createMemo(() => host.navigationItems().map((item) => item.label));
        const routeTitle = createMemo(() => host.route("/app/example")?.title);

        expect(navigationLabels()).toEqual([]);
        expect(routeTitle()).toBeUndefined();

        await host.activate("example", (api) => {
          api.registerRoute({ path: "/app/example", title: "Example", render: () => undefined });
          api.registerNavigation({ path: "/app/example", label: "Example" });
        });
        expect(navigationLabels()).toEqual(["Example"]);
        expect(routeTitle()).toBe("Example");

        host.removeExtension("example");
        expect(navigationLabels()).toEqual([]);
        expect(routeTitle()).toBeUndefined();
      } finally {
        dispose();
      }
    });
  });

  it("removes partial contributions after activation fails", async () => {
    const host = makeHost();
    await expect(host.activate("broken", (api) => {
      api.registerRoute({ path: "/app/example", title: "Example", render: () => undefined });
      api.registerNavigation({ path: "/app/example", label: "Example" });
      throw new Error("activation failed");
    })).rejects.toThrow("activation failed");

    expect(host.route("/app/example")).toBeUndefined();
    expect(host.navigationItems()).toEqual([]);
  });

  it("rejects core paths", async () => {
    for (const [index, path] of [
      "/app/login/product",
      "/app/authorize",
      "/app/account/product",
      "/app/consent",
      "/app/verify/contact",
      "/app/password/reset",
      "/app/admin/product",
    ].entries()) {
      const host = makeHost();
      await expect(host.activate(`conflict-${index}`, (api) => {
        api.registerRoute({ path, title: "Conflict", render: () => undefined });
      })).rejects.toThrow("conflicts with a core route");
      expect(host.route(path)).toBeUndefined();
    }
  });

  it("uses the longest registered prefix for a child route", async () => {
    const host = makeHost();
    const parent = { path: "/app/example", title: "Parent", render: () => undefined };
    const child = { path: "/app/example/items", title: "Items", render: () => undefined };
    await host.activate("example", (api) => {
      api.registerRoute(parent);
      api.registerRoute(child);
    });

    expect(host.route("/app/example/items/42")).toBe(child);
    expect(host.routeOwner("/app/example/items/42")).toBe("example");
    expect(host.route("/app/example/other")).toBe(parent);
  });
});
