// The app shell: header, navigation, footer, session state, and routing.
// SimpleRouter owns the browser history; this shell decides which page a
// path shows, because that depends on the session and the admin permission.
import SimpleRouter from "@catalystcommunity/simple-router";
import { BaseComponent, defineElements } from "@catalystcommunity/base-components";
import { api } from "./transport";
import { RuntimeHost, loadExtensions, type ExtensionRoute } from "./host";
import { claimTypeLabel, t } from "./i18n";
import { button, fill, h, link, markCurrent, nodes, textButton, type Child } from "./dom";
import { loading, query, unavailable, type PageProps } from "./shared";
import { authenticationFailed, cleanupOnce, reasonText } from "./ui-logic";
import type { BrowserSessionInfo, GetUiConfigurationResponse } from "./generated/types.gen";
import { actAsConsentPage, actAsGatewayPage, authorizeGatewayPage, consentPage, localRpConsentPage, localRpGatewayPage } from "./pages/consent";
import { loginPage, requestPasswordPage, resetPasswordPage, verifyContactPage, verifySignInPage } from "./pages/auth";
import { accountPage } from "./pages/account";
import { adminAreaPage } from "./pages/admin";

const CORE_PATHS = ["/app/login", "/app/account", "/app/password", "/app/authorize", "/app/consent", "/app/local-rp", "/app/error", "/app/act-as", "/app/verify", "/app/admin"];

/** True when a core page owns `path`, so extensions cannot change what it shows. */
function corePath(path: string): boolean {
  return path === "/app" || path === "/app/" || CORE_PATHS.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
}

function sessionIdentity(value?: BrowserSessionInfo): string { return value ? `${value.user.id}:${value.issuedAt}` : ""; }

/** The page title for the last path segment of a UI route. */
function pageTitle(segment: string): string {
  const key = `app.page_title.${segment}`;
  const title = t(key);
  return title === key ? claimTypeLabel(segment) : title;
}

/** Hosts one extension page. The extension renders into a container that it
 * owns; its cleanup runs one time when the page goes away. */
class ExtensionHostPage extends BaseComponent {
  route!: ExtensionRoute;
  host!: RuntimeHost;
  path!: string;
  onFailure!: () => void;
  private cleanup: void | (() => void) = undefined;
  private accepted = false;
  private failed = false;
  private readonly runCleanup = cleanupOnce();

  connectedCallback(): void {
    super.connectedCallback();
    if (this.childElementCount) return;
    const container = h("div", { hidden: true });
    const status = h("section", { class: "card", "aria-busy": "true" }, h("p", { role: "status" }, t("app.extension.loading")));
    const body = h("div", null, status, container);
    this.append(h("main", { class: "wrap wide" }, h("section", { class: "hero" }, h("p", { class: "eyebrow" }, t("app.extension.eyebrow")), h("h1", null, this.route.title)), body));
    const context = { path: this.path, navigate: (path: string) => this.host.navigate(path), clients: this.host.clients, configuration: this.host.configuration, session: this.host.getSession() };
    const renderPromise = Promise.resolve().then(() => this.route.render(container, context));
    void renderPromise.then((lateCleanup) => { if (!this.accepted && (!this.isActive() || this.failed)) this.runCleanup(lateCleanup); }).catch(() => undefined);
    void (async () => {
      try {
        this.cleanup = await Promise.race([renderPromise, new Promise<never>((_, reject) => setTimeout(() => reject(new Error("The extension page timed out.")), 5_000))]);
        this.accepted = true;
        if (!this.isActive()) { this.runCleanup(this.cleanup); return; }
        status.remove(); container.hidden = false;
      } catch (cause) {
        console.error(`The ${this.route.title} extension page failed.`, cause);
        this.failed = true; this.onFailure();
        fill(body, h("section", { class: "card" }, h("p", { role: "alert" }, t("app.extension.failed")), button(t("app.common.try_again"), { onClick: () => window.location.reload() })));
      }
    })();
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    try { this.runCleanup(this.cleanup); } catch (cause) { console.error(`The ${this.route.title} extension cleanup failed.`, cause); }
  }
}

export class LinkKeysApp {
  private session?: BrowserSessionInfo;
  private sessionLoaded = false;
  private sessionError = false;
  private canAdmin = false;
  private extensionFailures: string[] = [];
  private extensionsLoaded = false;
  private readonly router = new SimpleRouter();
  private readonly host: RuntimeHost;
  private readonly outlet = h("div", { id: "main-content", tabindex: "-1" });
  private readonly navigation = h("nav");
  private readonly banner = h("div", { class: "global-banner", hidden: true });
  private renderedKey = "";
  private logoutButton?: ZestPushButton;
  // Zest moves a button's children into its inner button, so change the
  // label through this text node, not by replacing the children.
  private logoutLabel = document.createTextNode("");

  constructor(private readonly configuration: GetUiConfigurationResponse, private readonly root: HTMLElement) {
    this.host = new RuntimeHost(api, configuration, (path) => this.navigate(path), () => this.session);
    this.host.onChange(() => { this.renderNavigation(); this.renderRoute(); });
  }

  async start(): Promise<void> {
    const brand = link("/app", this.configuration.theme?.logoUrl ? h("img", { class: "brand-logo", src: this.configuration.theme.logoUrl, alt: "" }) : h("span", { class: "brand-mark" }, "LK"), h("span", null, this.configuration.display.siteName));
    const support = this.configuration.display.supportUrl;
    this.root.replaceChildren(
      h("a", { class: "skip-link", href: "#main-content", on: { click: (event: MouseEvent) => { event.preventDefault(); this.outlet.focus(); } } }, t("app.nav.skip")),
      h("header", { class: "site-header" }, brand, this.navigation),
      this.banner,
      this.outlet,
      h("footer", null, `LinkKeys · ${this.configuration.domain}`, support && [" · ", h("a", { href: support }, t("app.nav.support"))]),
    );
    document.addEventListener("click", this.click);
    this.router.eventSender = () => undefined;
    this.router.registerRoute("/app", () => this.showPath());
    this.router.registerRoute("/notfound", () => this.showPath(), [], true);
    this.renderNavigation();
    this.renderRoute();
    await this.refreshSession();
    try { this.extensionFailures = await loadExtensions(this.host); }
    finally { this.extensionsLoaded = true; this.renderNavigation(); this.renderRoute(); }
  }

  /** Go to `target`. A path outside `/app` loads as a normal page. */
  navigate(target: string): void {
    this.setLogoutError("");
    const url = new URL(target, window.location.origin);
    if (url.origin !== window.location.origin) return;
    if (url.pathname !== "/app" && !url.pathname.startsWith("/app/")) { window.location.assign(url); return; }
    this.router.changePage(url.pathname + url.search + url.hash);
  }

  private readonly click = (event: MouseEvent): void => {
    const anchor = (event.target as Element).closest<HTMLAnchorElement>("a[data-linkkeys-nav]");
    if (!anchor || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey) return;
    event.preventDefault();
    this.navigate(anchor.href);
  };

  /** A route change from the router: show the page and move the focus to its
   * heading, unless the page already put the focus in one of its fields. */
  private showPath(): void {
    this.setLogoutError("");
    this.renderedKey = "";
    this.renderRoute();
    this.renderNavigation();
    window.scrollTo(0, 0);
    window.requestAnimationFrame(() => {
      const active = document.activeElement;
      if (active && active !== this.outlet && this.outlet.contains(active)) return;
      const heading = this.outlet.querySelector<HTMLElement>("main h1");
      heading?.setAttribute("tabindex", "-1");
      heading?.focus();
    });
  }

  private async refreshSession(): Promise<void> {
    this.sessionError = false;
    try {
      const current = (await api.session.getCurrent({})).session;
      const changed = this.extensionsLoaded && sessionIdentity(this.session) !== sessionIdentity(current);
      this.session = current;
      if (current) {
        try { this.canAdmin = (await api.admin.checkPermission({ userId: current.user.id, relation: "admin", objectType: "domain", objectId: this.configuration.domain })).allowed; }
        catch { this.canAdmin = false; }
      } else this.canAdmin = false;
      if (changed) await this.reactivateExtensions();
    } catch (cause) {
      if (authenticationFailed(cause)) {
        const changed = this.extensionsLoaded && sessionIdentity(this.session) !== "";
        this.session = undefined; this.canAdmin = false;
        if (changed) await this.reactivateExtensions();
      } else this.sessionError = true;
    } finally {
      this.sessionLoaded = true;
      this.renderNavigation();
      this.renderRoute();
    }
  }

  private async reactivateExtensions(): Promise<void> {
    this.extensionsLoaded = false;
    try { this.extensionFailures = await this.host.reactivateExtensions(); }
    finally { this.extensionsLoaded = true; }
  }

  private async logout(): Promise<void> {
    if (this.logoutButton) { this.logoutButton.disabled = true; this.logoutLabel.data = t("app.nav.signing_out"); }
    this.setLogoutError("");
    try {
      await api.session.logout({});
      this.session = undefined; this.canAdmin = false;
      this.navigate("/app/login");
      await this.reactivateExtensions();
      this.renderNavigation(); this.renderRoute();
    } catch {
      this.setLogoutError(t("app.nav.sign_out_failed"));
      if (this.logoutButton) { this.logoutButton.disabled = false; this.logoutLabel.data = t("app.nav.sign_out"); }
    }
  }

  private setLogoutError(text: string): void {
    fill(this.banner, text && h("p", { class: "notice bad", role: "alert" }, text));
    this.banner.hidden = !text;
  }

  private renderNavigation(): void {
    const path = window.location.pathname;
    const item = (href: string, label: string, current: boolean) => { const anchor = link(href, label); markCurrent(anchor, current); return anchor; };
    const items: Child[] = [];
    if (this.session) {
      items.push(item("/app/account", t("app.nav.account"), path.startsWith("/app/account")));
      if (this.canAdmin) items.push(item("/app/admin", t("app.nav.admin"), path.startsWith("/app/admin")));
      if (this.extensionsLoaded) for (const entry of this.host.navigationItems()) items.push(item(entry.path, entry.label, path.startsWith(entry.path)));
      this.logoutLabel = document.createTextNode(t("app.nav.sign_out"));
      this.logoutButton = textButton(this.logoutLabel, () => void this.logout());
      items.push(this.logoutButton);
    } else {
      this.logoutButton = undefined;
      items.push(item("/app/login", t("app.nav.sign_in"), path === "/app/login"));
    }
    this.navigation.replaceChildren(...nodes(items));
  }

  /** Show the page for the current path, unless it already shows. A page is
   * made again only when what it depends on changes. */
  private renderRoute(): void {
    const path = window.location.pathname;
    const key = [path, window.location.search, this.sessionLoaded, this.sessionError, sessionIdentity(this.session), this.canAdmin, corePath(path) ? "" : `${this.extensionsLoaded}:${this.host.route(path)?.path ?? ""}`, path.startsWith("/app/admin") ? this.extensionFailures.join(",") : ""].join("|");
    if (key === this.renderedKey) return;
    this.renderedKey = key;
    const label = path.split("/").filter(Boolean).at(-1) ?? "home";
    document.title = `${pageTitle(label)} · ${this.configuration.display.siteName}`;
    this.outlet.replaceChildren(this.pageFor(path));
  }

  private pageFor(path: string): Element {
    const context: PageProps = { navigate: (target) => this.navigate(target), configuration: this.configuration, session: this.session, refreshSession: () => this.refreshSession(), extensionFailures: [...this.extensionFailures] };
    const signedIn = Boolean(this.session);
    if (!this.sessionLoaded) return loading();
    if (this.sessionError) return h("main", { class: "wrap narrow" }, h("section", { class: "card" }, h("h1", null, t("app.session.failed_title")), h("p", null, t("app.session.failed_body")), button(t("app.common.try_again"), { onClick: () => void this.refreshSession() })));
    if (path === "/app" || path === "/app/") return signedIn ? accountPage(context) : loginPage(context);
    if (path === "/app/login") return loginPage(context);
    if (path === "/app/account" || path.startsWith("/app/account/")) return signedIn ? accountPage(context) : loginPage(context);
    if (path === "/app/password/request") return requestPasswordPage(context);
    if (path === "/app/password/reset") return resetPasswordPage(context);
    if (path === "/app/authorize") return authorizeGatewayPage(context);
    if (path === "/app/consent") return signedIn ? consentPage(context) : loginPage(context);
    if (path === "/app/consent/cancelled") return unavailable(t("app.consent.cancelled_title"), t("app.consent.cancelled_body"), "/app/account");
    if (path === "/app/local-rp") return localRpGatewayPage(context);
    if (path === "/app/local-rp/consent") return signedIn ? localRpConsentPage(context) : loginPage(context);
    if (path === "/app/local-rp/cancelled") return unavailable(t("app.local_rp.cancelled_title"), t("app.local_rp.cancelled_body"), "/app/account");
    if (path === "/app/error") return unavailable(t("app.error.title"), reasonText(query("reason")), "/app/account");
    if (path === "/app/act-as") return actAsGatewayPage(context);
    if (path === "/app/act-as/consent") return signedIn ? actAsConsentPage(context) : loginPage(context);
    if (path === "/app/act-as/cancelled") return unavailable(t("app.act_as.cancelled_title"), t("app.act_as.cancelled_body"), "/app/account");
    if (path === "/app/verify/contact") return signedIn ? verifyContactPage(context) : verifySignInPage(context);
    if (path === "/app/admin" || path.startsWith("/app/admin/")) return signedIn && this.canAdmin ? adminAreaPage({ ...context, path }) : unavailable(t("app.admin.unavailable_title"), t("app.admin.unavailable_body"), "/app/account");
    if (!this.extensionsLoaded) return loading();
    const extension = this.host.route(path);
    if (extension) {
      if (!signedIn) return loginPage(context);
      const owner = this.host.routeOwner(path) ?? extension.title;
      defineElements({ "linkkeys-extension-page": ExtensionHostPage });
      const page = document.createElement("linkkeys-extension-page") as ExtensionHostPage;
      page.classList.add("lk-page");
      Object.assign(page, { route: extension, host: this.host, path, onFailure: () => { if (!this.extensionFailures.includes(owner)) this.extensionFailures = [...this.extensionFailures, owner]; } });
      return page;
    }
    return unavailable(t("app.not_found.title"), t("app.not_found.body"), "/app/account");
  }
}
