import { beforeEach, describe, expect, it, vi } from "vitest";
import { createMemo, createRoot } from "solid-js";
import type { AsyncApiClient } from "./generated/client.async.gen";
import type { BrowserSessionInfo, GetUiConfigurationResponse } from "./generated/types.gen";
import { RuntimeHost, type LinkKeysHostApiV1 } from "./host";

function makeHost(getSession: () => BrowserSessionInfo | undefined = () => undefined): RuntimeHost {
  return new RuntimeHost(
    {} as AsyncApiClient,
    { extensions: [] } as unknown as GetUiConfigurationResponse,
    () => undefined,
    getSession,
  );
}

const signedInSession = {
  user: { id: "user-1" },
  issuedAt: "2026-09-01T12:00:00Z",
} as BrowserSessionInfo;

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

  it("reactivates an extension after the session changes from signed out to signed in", async () => {
    let session: BrowserSessionInfo | undefined;
    const host = makeHost(() => session);
    const activate = vi.fn((api) => {
      if (!api.getSession()) return;
      api.registerRoute({ path: "/app/example", title: "Example", render: () => undefined });
      api.registerNavigation({ path: "/app/example", label: "Example" });
    });

    await host.activate("example", activate);
    expect(host.route("/app/example")).toBeUndefined();
    expect(host.navigationItems()).toEqual([]);

    session = signedInSession;
    expect(await host.reactivateExtensions()).toEqual([]);

    expect(activate).toHaveBeenCalledTimes(2);
    expect(host.route("/app/example")?.title).toBe("Example");
    expect(host.navigationItems().map((item) => item.label)).toEqual(["Example"]);
  });

  it("retries an extension that failed before sign-in", async () => {
    let session: BrowserSessionInfo | undefined;
    const host = makeHost(() => session);
    const activate = (api: LinkKeysHostApiV1) => {
      if (!api.getSession()) throw new Error("not signed in");
      api.registerRoute({ path: "/app/example", title: "Example", render: () => undefined });
    };

    await expect(host.activate("example", activate)).rejects.toThrow("not signed in");
    session = signedInSession;

    expect(await host.reactivateExtensions()).toEqual([]);
    expect(host.route("/app/example")?.title).toBe("Example");
  });

  it("rejects late registrations without removing the current activation", async () => {
    const host = makeHost();
    let finishOldActivation!: () => void;
    const oldActivation = host.activate("example", async (api) => {
      await new Promise<void>((resolve) => { finishOldActivation = resolve; });
      api.registerRoute({ path: "/app/old", title: "Old", render: () => undefined });
    });

    await host.activate("example", (api) => {
      api.registerRoute({ path: "/app/current", title: "Current", render: () => undefined });
    });
    finishOldActivation();

    await expect(oldActivation).rejects.toThrow("no longer active");
    expect(host.route("/app/old")).toBeUndefined();
    expect(host.route("/app/current")?.title).toBe("Current");
  });

  it("removes all old contributions before it reactivates any extension", async () => {
    let session: BrowserSessionInfo | undefined;
    const host = makeHost(() => session);
    await host.activate("signed-in", (api) => {
      if (api.getSession()) api.registerRoute({ path: "/app/shared", title: "Signed in", render: () => undefined });
    });
    await host.activate("signed-out", (api) => {
      if (!api.getSession()) api.registerRoute({ path: "/app/shared", title: "Signed out", render: () => undefined });
    });
    expect(host.routeOwner("/app/shared")).toBe("signed-out");

    session = signedInSession;
    expect(await host.reactivateExtensions()).toEqual([]);

    expect(host.route("/app/shared")?.title).toBe("Signed in");
    expect(host.routeOwner("/app/shared")).toBe("signed-in");
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
