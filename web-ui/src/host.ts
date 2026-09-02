import type { AsyncApiClient } from "./generated/client.async.gen";
import type { GetUiConfigurationResponse, BrowserSessionInfo } from "./generated/types.gen";
import { createSignal, type Accessor, type Setter } from "solid-js";

const CORE_PREFIXES = [
  "/app/login",
  "/app/authorize",
  "/app/account",
  "/app/consent",
  "/app/verify",
  "/app/password",
  "/app/admin"
];

export interface ExtensionRouteContext {
  path: string;
  navigate(path: string): void;
  clients: AsyncApiClient;
  configuration: GetUiConfigurationResponse;
  session?: BrowserSessionInfo;
}

export interface ExtensionRoute {
  path: string;
  title: string;
  render(container: HTMLElement, context: ExtensionRouteContext): void | (() => void) | Promise<void | (() => void)>;
}

export interface ExtensionNavigation {
  path: string;
  label: string;
  order?: number;
}

export interface LinkKeysHostApiV1 {
  readonly version: 1;
  readonly clients: AsyncApiClient;
  readonly configuration: GetUiConfigurationResponse;
  registerRoute(route: ExtensionRoute): void;
  registerNavigation(item: ExtensionNavigation): void;
  navigate(path: string): void;
  getSession(): BrowserSessionInfo | undefined;
}

export interface LinkKeysUiExtension {
  activate(host: LinkKeysHostApiV1): void | Promise<void>;
}

type ExtensionActivator = (api: LinkKeysHostApiV1) => void | Promise<void>;

const EXTENSION_TIMEOUT_MS = 5_000;

function validExtensionPath(path: string): boolean {
  return path.startsWith("/app/")
    && !path.includes("..")
    && !CORE_PREFIXES.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
}

export class RuntimeHost implements LinkKeysHostApiV1 {
  readonly version = 1 as const;
  private routes = new Map<string, ExtensionRoute>();
  private navigation = new Map<string, ExtensionNavigation>();
  private routeOwners = new Map<string, string>();
  private navigationOwners = new Map<string, string>();
  private disabledExtensions = new Set<string>();
  private activationGenerations = new Map<string, number>();
  private activators = new Map<string, ExtensionActivator>();
  private readonly revision: Accessor<number>;
  private readonly setRevision: Setter<number>;

  constructor(
    readonly clients: AsyncApiClient,
    readonly configuration: GetUiConfigurationResponse,
    private readonly navigateFn: (path: string) => void,
    private readonly sessionFn: () => BrowserSessionInfo | undefined
  ) {
    [this.revision, this.setRevision] = createSignal(0);
  }

  private changed(): void {
    this.setRevision((value) => value + 1);
  }

  registerRoute(route: ExtensionRoute): void {
    throw new Error("Use the extension-scoped host that LinkKeys passes to activate().");
  }

  private assertActive(extensionId: string, generation: number): void {
    if (this.disabledExtensions.has(extensionId) || this.activationGenerations.get(extensionId) !== generation) {
      throw new Error("The extension is no longer active.");
    }
  }

  private registerRouteFor(extensionId: string, generation: number, route: ExtensionRoute): void {
    this.assertActive(extensionId, generation);
    if (!validExtensionPath(route.path)) throw new Error(`The extension route ${route.path} conflicts with a core route.`);
    if (this.routes.has(route.path)) throw new Error(`The extension route ${route.path} is already registered.`);
    this.routes.set(route.path, route);
    this.routeOwners.set(route.path, extensionId);
    this.changed();
  }

  registerNavigation(item: ExtensionNavigation): void {
    throw new Error("Use the extension-scoped host that LinkKeys passes to activate().");
  }

  private registerNavigationFor(extensionId: string, generation: number, item: ExtensionNavigation): void {
    this.assertActive(extensionId, generation);
    if (!this.routes.has(item.path)) throw new Error(`The extension navigation path ${item.path} has no registered route.`);
    if (this.navigation.has(item.path)) throw new Error(`The extension navigation path ${item.path} is already registered.`);
    this.navigation.set(item.path, item);
    this.navigationOwners.set(item.path, extensionId);
    this.changed();
  }

  navigate(path: string): void { this.navigateFn(path); }
  getSession(): BrowserSessionInfo | undefined { return this.sessionFn(); }
  route(path: string): ExtensionRoute | undefined {
    this.revision();
    const match = [...this.routes.entries()]
      .filter(([prefix]) => path === prefix || path.startsWith(`${prefix}/`))
      .sort(([left], [right]) => right.length - left.length)[0];
    return match?.[1];
  }
  routeOwner(path: string): string | undefined {
    this.revision();
    const match = [...this.routeOwners.entries()]
      .filter(([prefix]) => path === prefix || path.startsWith(`${prefix}/`))
      .sort(([left], [right]) => right.length - left.length)[0];
    return match?.[1];
  }
  navigationItems(): ExtensionNavigation[] {
    this.revision();
    return [...this.navigation.values()].sort((left, right) => (left.order ?? 100) - (right.order ?? 100));
  }

  async activate(extensionId: string, callback: ExtensionActivator): Promise<void> {
    this.activators.set(extensionId, callback);
    const generation = (this.activationGenerations.get(extensionId) ?? 0) + 1;
    this.activationGenerations.set(extensionId, generation);
    this.disabledExtensions.delete(extensionId);
    this.removeRegistrations(extensionId);
    const api: LinkKeysHostApiV1 = {
      version: this.version,
      clients: this.clients,
      configuration: this.configuration,
      registerRoute: (route) => this.registerRouteFor(extensionId, generation, route),
      registerNavigation: (item) => this.registerNavigationFor(extensionId, generation, item),
      navigate: (path) => this.navigate(path),
      getSession: () => this.getSession()
    };
    try { await callback(api); }
    catch (error) {
      if (this.activationGenerations.get(extensionId) === generation) this.removeExtension(extensionId);
      throw error;
    }
  }

  private removeRegistrations(extensionId: string): void {
    for (const [path, owner] of this.navigationOwners) if (owner === extensionId) { this.navigation.delete(path); this.navigationOwners.delete(path); }
    for (const [path, owner] of this.routeOwners) if (owner === extensionId) { this.routes.delete(path); this.routeOwners.delete(path); }
    this.changed();
  }

  removeExtension(extensionId: string): void {
    this.disabledExtensions.add(extensionId);
    this.activationGenerations.set(extensionId, (this.activationGenerations.get(extensionId) ?? 0) + 1);
    this.removeRegistrations(extensionId);
    document.querySelector(`link[data-linkkeys-style="extension-${CSS.escape(extensionId)}"]`)?.remove();
  }

  async reactivateExtensions(): Promise<string[]> {
    const failures = this.configuration.extensions
      .filter((extension) => !this.activators.has(extension.id))
      .map((extension) => extension.id);
    for (const extensionId of this.activators.keys()) {
      this.disabledExtensions.add(extensionId);
      this.activationGenerations.set(extensionId, (this.activationGenerations.get(extensionId) ?? 0) + 1);
      this.removeRegistrations(extensionId);
    }
    for (const [extensionId, activate] of this.activators) {
      try {
        const stylesheetUrl = this.configuration.extensions.find((extension) => extension.id === extensionId)?.stylesheetUrl;
        if (stylesheetUrl) addStylesheet(stylesheetUrl, `extension-${extensionId}`);
        await Promise.race([
          this.activate(extensionId, activate),
          new Promise<never>((_, reject) => setTimeout(() => reject(new Error("The extension activation timed out.")), EXTENSION_TIMEOUT_MS))
        ]);
      } catch (error) {
        this.removeExtension(extensionId);
        failures.push(extensionId);
        console.error(`LinkKeys UI extension ${extensionId} could not start.`, error);
      }
    }
    return failures;
  }
}

export async function loadExtensions(host: RuntimeHost): Promise<string[]> {
  const failures: string[] = [];
  for (const extension of host.configuration.extensions) {
    try {
      if (extension.apiVersion !== host.version) throw new Error("The host API version is not supported.");
      if (extension.stylesheetUrl) addStylesheet(extension.stylesheetUrl, `extension-${extension.id}`);
      const module = await Promise.race([
        import(/* @vite-ignore */ extension.moduleUrl) as Promise<LinkKeysUiExtension>,
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error("The extension load timed out.")), EXTENSION_TIMEOUT_MS))
      ]);
      if (typeof module.activate !== "function") throw new Error("The extension has no activate function.");
      await Promise.race([
        host.activate(extension.id, (api) => module.activate(api)),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error("The extension activation timed out.")), EXTENSION_TIMEOUT_MS))
      ]);
    } catch (error) {
      host.removeExtension(extension.id);
      failures.push(extension.id);
      console.error(`LinkKeys UI extension ${extension.id} could not start.`, error);
    }
  }
  return failures;
}

export function addStylesheet(url: string, id: string): void {
  if (document.querySelector(`link[data-linkkeys-style="${id}"]`)) return;
  const link = document.createElement("link");
  link.rel = "stylesheet";
  link.href = url;
  link.dataset.linkkeysStyle = id;
  document.head.append(link);
}
