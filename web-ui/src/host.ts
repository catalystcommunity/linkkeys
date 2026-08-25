import type { AsyncApiClient } from "./generated/client.async.gen";
import type { GetUiConfigurationResponse, BrowserSessionInfo } from "./generated/types.gen";

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

  constructor(
    readonly clients: AsyncApiClient,
    readonly configuration: GetUiConfigurationResponse,
    private readonly navigateFn: (path: string) => void,
    private readonly changed: () => void,
    private readonly sessionFn: () => BrowserSessionInfo | undefined
  ) {}

  registerRoute(route: ExtensionRoute): void {
    throw new Error("Use the extension-scoped host that LinkKeys passes to activate().");
  }

  private registerRouteFor(extensionId: string, route: ExtensionRoute): void {
    if (this.disabledExtensions.has(extensionId)) throw new Error("The extension is no longer active.");
    if (!validExtensionPath(route.path)) throw new Error(`The extension route ${route.path} conflicts with a core route.`);
    if (this.routes.has(route.path)) throw new Error(`The extension route ${route.path} is already registered.`);
    this.routes.set(route.path, route);
    this.routeOwners.set(route.path, extensionId);
    this.changed();
  }

  registerNavigation(item: ExtensionNavigation): void {
    throw new Error("Use the extension-scoped host that LinkKeys passes to activate().");
  }

  private registerNavigationFor(extensionId: string, item: ExtensionNavigation): void {
    if (this.disabledExtensions.has(extensionId)) throw new Error("The extension is no longer active.");
    if (!this.routes.has(item.path)) throw new Error(`The extension navigation path ${item.path} has no registered route.`);
    if (this.navigation.has(item.path)) throw new Error(`The extension navigation path ${item.path} is already registered.`);
    this.navigation.set(item.path, item);
    this.navigationOwners.set(item.path, extensionId);
    this.changed();
  }

  navigate(path: string): void { this.navigateFn(path); }
  getSession(): BrowserSessionInfo | undefined { return this.sessionFn(); }
  route(path: string): ExtensionRoute | undefined {
    const match = [...this.routes.entries()]
      .filter(([prefix]) => path === prefix || path.startsWith(`${prefix}/`))
      .sort(([left], [right]) => right.length - left.length)[0];
    return match?.[1];
  }
  routeOwner(path: string): string | undefined {
    const match = [...this.routeOwners.entries()]
      .filter(([prefix]) => path === prefix || path.startsWith(`${prefix}/`))
      .sort(([left], [right]) => right.length - left.length)[0];
    return match?.[1];
  }
  navigationItems(): ExtensionNavigation[] {
    return [...this.navigation.values()].sort((left, right) => (left.order ?? 100) - (right.order ?? 100));
  }

  async activate(extensionId: string, callback: (api: LinkKeysHostApiV1) => void | Promise<void>): Promise<void> {
    this.disabledExtensions.delete(extensionId);
    const api: LinkKeysHostApiV1 = {
      version: this.version,
      clients: this.clients,
      configuration: this.configuration,
      registerRoute: (route) => this.registerRouteFor(extensionId, route),
      registerNavigation: (item) => this.registerNavigationFor(extensionId, item),
      navigate: (path) => this.navigate(path),
      getSession: () => this.getSession()
    };
    try { await callback(api); }
    catch (error) { this.removeExtension(extensionId); throw error; }
  }

  removeExtension(extensionId: string): void {
    this.disabledExtensions.add(extensionId);
    for (const [path, owner] of this.navigationOwners) if (owner === extensionId) { this.navigation.delete(path); this.navigationOwners.delete(path); }
    for (const [path, owner] of this.routeOwners) if (owner === extensionId) { this.routes.delete(path); this.routeOwners.delete(path); }
    document.querySelector(`link[data-linkkeys-style="extension-${CSS.escape(extensionId)}"]`)?.remove();
    this.changed();
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
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error("The extension load timed out.")), 5_000))
      ]);
      if (typeof module.activate !== "function") throw new Error("The extension has no activate function.");
      await Promise.race([
        host.activate(extension.id, (api) => module.activate(api)),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error("The extension activation timed out.")), 5_000))
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
