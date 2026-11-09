// The administration area: it routes each admin path to its page.
import { t } from "../i18n";
import { h } from "../dom";
import { createPage } from "../page";
import { unavailable } from "../shared";
import { AdminAccountsPage, AdminUserPage } from "./admin/accounts";
import { AdminPolicyPage } from "./admin/policy";
import { AdminAccessPage } from "./admin/access";
import { AdminApprovalsPage } from "./admin/approvals";
import { AdminIssuePage } from "./admin/issue";
import { AdminSettingsPage } from "./admin/settings";
import type { AdminContext } from "./admin/common";

const ADMIN_PATHS = ["/app/admin", "/app/admin/policy", "/app/admin/access", "/app/admin/approvals", "/app/admin/issue", "/app/admin/settings"];
const USER_PREFIX = "/app/admin/users/";

function notFound(): HTMLElement {
  return unavailable(t("app.not_found.title"), t("app.not_found.body"), "/app/admin", t("app.admin_nav.back"));
}

function adminPage(path: string, context: AdminContext): Element | undefined {
  if (path.startsWith(USER_PREFIX)) {
    let userId: string;
    try { userId = decodeURIComponent(path.slice(USER_PREFIX.length)); }
    catch { return undefined; }
    const page = createPage("lk-admin-user", AdminUserPage, context);
    page.userId = userId;
    return page;
  }
  if (path === "/app/admin/policy") return createPage("lk-admin-policy", AdminPolicyPage, context);
  if (path === "/app/admin/access") return createPage("lk-admin-access", AdminAccessPage, context);
  if (path === "/app/admin/approvals") return createPage("lk-admin-approvals", AdminApprovalsPage, context);
  if (path === "/app/admin/issue") return createPage("lk-admin-issue", AdminIssuePage, context);
  if (path === "/app/admin/settings") return createPage("lk-admin-settings", AdminSettingsPage, context);
  return createPage("lk-admin-accounts", AdminAccountsPage, context);
}

/** The admin page for `context.path`, or "not found" for an unknown admin path. */
export function adminAreaPage(context: AdminContext): Element {
  const path = context.path.replace(/\/$/, "");
  const known = ADMIN_PATHS.includes(path) || path.startsWith(USER_PREFIX);
  const page = known ? adminPage(path, context) : undefined;
  return page ? h("main", { class: "wrap wide" }, page) : notFound();
}
