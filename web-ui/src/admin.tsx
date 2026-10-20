// The administration area: accounts, one account's details, domain policy,
// the approval queue, issuing claims for another domain's request, and
// domain settings. Every page talks to the server through the generated
// CSIL client; the server checks each operation's permission.
import { For, Show, createSignal, onMount, type Component, type JSX } from "solid-js";
import { api } from "./transport";
import { claimTypeLabel, format, t } from "./i18n";
import type { AdminUser, AppAccessPolicy, AppAccessTarget, Claim, ClaimApproval, ClaimTypeLabel, ClaimTypePolicy, InspectSigningRequestResponse, IssuedClaimResult, PreviewAppAccessResponse, PreviewIssuerPolicyResponse, PreviewReleasePolicyResponse, Relation, ReleaseRule, SignInPolicy, TrustedIssuer, UserAuthenticationActivity } from "./generated/types.gen";
import { authenticationFailed, patternList, serviceMessage as message } from "./ui-logic";
import { Link, Unavailable, checkPassword, claimText, passwordRule, type PageProps } from "./shared";

const VALUE_TYPES = ["text", "url", "email", "bool", "int", "float", "decimal", "date", "timestamp", "opaque"];
const SET_RULES = ["user_self", "idp_on_request", "trusted_issuer_only", "admin_only", "deny"];
const SIGNING_RULES = ["self_signed", "verified", "attested", "unsigned"];
const RELATIONS = ["admin", "manage_users", "manage_claims", "api_access", "issue_claims", "ui_extension"];
const DISPOSITIONS = ["forced_allow", "forced_deny"];
const ACCESS_MODES = ["deny", "allow"];
const TARGET_KINDS = ["everyone", "user", "group", "claim"];
const CLAIM_OPERATORS = ["present", "absent", "equals", "age_under", "age_at_least"];

/** Comma-separated text as a list, without blanks. */
function list(text: string): string[] {
  return text.split(",").map((part) => part.trim()).filter(Boolean);
}

function dispositionLabel(disposition: string): string {
  return disposition === "forced_allow" ? t("app.policy.disposition_allow") : disposition === "forced_deny" ? t("app.policy.disposition_deny") : t("app.policy.disposition_user");
}

function when(value?: string): string {
  return value ? new Date(value).toLocaleString() : t("app.admin_user.never");
}

const Feedback: Component<{ status: string; error: string }> = (props) => <><Show when={props.status}><p class="notice good" role="status">{props.status}</p></Show><Show when={props.error}><p class="notice bad" role="alert">{props.error}</p></Show></>;

const AdminHeader: Component<{ path: string; title: string; intro?: string }> = (props) => {
  const pages: { path: string; label: () => string; current: (path: string) => boolean }[] = [
    { path: "/app/admin", label: () => t("app.admin_nav.accounts"), current: (path) => path === "/app/admin" || path === "/app/admin/" || path.startsWith("/app/admin/users/") },
    { path: "/app/admin/policy", label: () => t("app.admin_nav.policy"), current: (path) => path === "/app/admin/policy" },
    { path: "/app/admin/access", label: () => t("app.admin_nav.access"), current: (path) => path === "/app/admin/access" },
    { path: "/app/admin/approvals", label: () => t("app.admin_nav.approvals"), current: (path) => path === "/app/admin/approvals" },
    { path: "/app/admin/issue", label: () => t("app.admin_nav.issue"), current: (path) => path === "/app/admin/issue" },
    { path: "/app/admin/settings", label: () => t("app.admin_nav.settings"), current: (path) => path === "/app/admin/settings" },
  ];
  return <><section class="hero"><p class="eyebrow">{t("app.admin.eyebrow")}</p><h1>{props.title}</h1><Show when={props.intro}><p>{props.intro}</p></Show></section>
    <nav class="admin-tabs" aria-label={t("app.admin_nav.label")}><For each={pages}>{(page) => <Link href={page.path} current={page.current(props.path)}>{page.label()}</Link>}</For></nav></>;
};

/** Load data when a page opens, sending a signed-out person to sign in. */
function loader(props: PageProps, load: () => Promise<void>, setError: (text: string) => void, failure: () => string): () => Promise<void> {
  return async () => {
    try { await load(); }
    catch (cause) { if (authenticationFailed(cause)) props.navigate("/app/login?next=/app/admin"); else setError(message(cause, failure())); }
  };
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

const ReactivateAccount: Component<{ userId: string; username: string; configuration: PageProps["configuration"]; complete(): Promise<void>; fail(text: string): void }> = (props) => {
  const [password, setPassword] = createSignal(""); const [confirmation, setConfirmation] = createSignal(""); const [busy, setBusy] = createSignal(false);
  const submit = async (event: SubmitEvent) => {
    event.preventDefault();
    if (password() !== confirmation()) return props.fail(t("app.password.mismatch_new"));
    const lengthError = checkPassword(password(), props.configuration);
    if (lengthError) return props.fail(lengthError);
    setBusy(true);
    try { await api.admin.resetPassword({ userId: props.userId, newPassword: password() }); await api.admin.activateUser({ userId: props.userId }); setPassword(""); setConfirmation(""); await props.complete(); }
    catch { props.fail(t("app.admin.restore_failed", { username: props.username })); }
    finally { setBusy(false); }
  };
  return <form class="stacked-action" aria-busy={busy()} onSubmit={submit}><small>{passwordRule(props.configuration)}</small><input aria-label={t("app.admin.new_password_for", { username: props.username })} type="password" value={password()} onInput={(event) => setPassword(event.currentTarget.value)} autocomplete="new-password" required /><input aria-label={t("app.admin.confirm_password_for", { username: props.username })} type="password" value={confirmation()} onInput={(event) => setConfirmation(event.currentTarget.value)} autocomplete="new-password" required /><button type="submit" disabled={busy()}>{t("app.admin.restore_submit")}</button></form>;
};

const AdminAccounts: Component<PageProps & { path: string }> = (props) => {
  const [users, setUsers] = createSignal<AdminUser[]>([]); const [error, setError] = createSignal(""); const [status, setStatus] = createSignal(""); const [busy, setBusy] = createSignal(false);
  const [hasMore, setHasMore] = createSignal(false);
  const [username, setUsername] = createSignal(""); const [displayName, setDisplayName] = createSignal(""); const [password, setPassword] = createSignal(""); const [confirmation, setConfirmation] = createSignal("");
  const pageSize = 50;
  const refresh = async () => { const result = (await api.admin.listUsers({ limit: pageSize + 1 })).users; setUsers(result.slice(0, pageSize)); setHasMore(result.length > pageSize); };
  const loadMore = async () => { setBusy(true); setError(""); try { const result = (await api.admin.listUsers({ offset: users().length, limit: pageSize + 1 })).users; setUsers((current) => [...current, ...result.slice(0, pageSize)]); setHasMore(result.length > pageSize); } catch (cause) { setError(message(cause, t("app.admin.load_more_failed"))); } finally { setBusy(false); } };
  onMount(loader(props, refresh, setError, () => t("app.admin.no_access")));
  const createUser = async (event: SubmitEvent) => { event.preventDefault(); setError(""); setStatus(""); if (password() !== confirmation()) return setError(t("app.password.mismatch")); const lengthError = checkPassword(password(), props.configuration); if (lengthError) return setError(lengthError); setBusy(true); try { await api.admin.createUser({ username: username(), displayName: displayName(), password: password() }); setUsername(""); setDisplayName(""); setPassword(""); setConfirmation(""); await refresh(); setStatus(t("app.admin.created")); } catch (cause) { setError(message(cause, t("app.admin.create_failed"))); } finally { setBusy(false); } };
  const deactivate = async (userId: string, username: string) => { if (!window.confirm(t("app.admin.disable_confirm", { username }))) return; setBusy(true); setError(""); setStatus(""); try { await api.admin.deactivateUser({ userId }); await refresh(); setStatus(t("app.admin.disabled", { username })); } catch (cause) { setError(message(cause, t("app.admin.disable_failed"))); } finally { setBusy(false); } };
  return <><AdminHeader path={props.path} title={t("app.admin.title")} intro={t("app.admin.intro", { domain: props.configuration.domain })} /><section class="card"><Show when={!error() || users().length} fallback={<p class="notice bad" role="alert">{error()}</p>}>
    <Show when={props.extensionFailures?.length}><p class="operator-warning" role="status">{t("app.admin.extension_failures", { names: props.extensionFailures?.join(", ") ?? "" })}</p></Show>
    <form class="account-form" aria-busy={busy()} onSubmit={createUser}><p id="admin-password-rule">{passwordRule(props.configuration)}</p><label><span>{t("app.admin.username")}</span><input value={username()} onInput={(event) => setUsername(event.currentTarget.value)} autocomplete="off" maxlength="254" required /></label><label><span>{t("app.admin.display_name")}</span><input value={displayName()} onInput={(event) => setDisplayName(event.currentTarget.value)} maxlength="254" required /></label><label><span>{t("app.admin.initial_password")}</span><input type="password" value={password()} onInput={(event) => setPassword(event.currentTarget.value)} autocomplete="new-password" aria-describedby="admin-password-rule" required /></label><label><span>{t("app.admin.confirm_initial_password")}</span><input type="password" value={confirmation()} onInput={(event) => setConfirmation(event.currentTarget.value)} autocomplete="new-password" required /></label><button type="submit" disabled={busy()}>{t("app.admin.create")}</button></form>
    <div class="table-wrap"><table><thead><tr><th>{t("app.admin.col_username")}</th><th>{t("app.admin.col_display_name")}</th><th>{t("app.admin.col_status")}</th><th>{t("app.admin.col_created")}</th><th>{t("app.admin.col_action")}</th></tr></thead><tbody><For each={users()}>{(user) => <tr><td><Link href={`/app/admin/users/${encodeURIComponent(user.id)}`}><code>{user.username}</code></Link></td><td>{user.displayName}</td><td><span class="pill">{user.isActive ? t("app.admin.status_active") : t("app.admin.status_disabled")}</span></td><td>{new Date(user.createdAt).toLocaleDateString()}</td><td><Show when={user.id !== props.session?.user.id} fallback={<span class="muted">{t("app.admin.current_account")}</span>}><Show when={user.isActive} fallback={<ReactivateAccount userId={user.id} username={user.username} configuration={props.configuration} fail={setError} complete={async () => { await refresh(); setStatus(t("app.admin.restored", { username: user.username })); }} />}><button class="text-button" type="button" disabled={busy()} aria-label={t("app.admin.disable_label", { username: user.username })} onClick={() => deactivate(user.id, user.username)}>{t("app.admin.disable")}</button></Show></Show></td></tr>}</For></tbody></table></div>
    <Show when={hasMore()}><button type="button" disabled={busy()} onClick={loadMore}>{busy() ? t("app.admin.loading") : t("app.admin.load_more")}</button></Show>
    <Feedback status={status()} error={error()} />
  </Show></section></>;
};

// ---------------------------------------------------------------------------
// One account
// ---------------------------------------------------------------------------

const AdminUserPage: Component<PageProps & { path: string; userId: string }> = (props) => {
  const [user, setUser] = createSignal<AdminUser>(); const [activity, setActivity] = createSignal<UserAuthenticationActivity>();
  const [claims, setClaims] = createSignal<Claim[]>([]); const [relations, setRelations] = createSignal<Relation[]>([]); const [claimTypes, setClaimTypes] = createSignal<ClaimTypePolicy[]>([]);
  const [status, setStatus] = createSignal(""); const [error, setError] = createSignal(""); const [busy, setBusy] = createSignal(false);
  const [displayName, setDisplayName] = createSignal(""); const [password, setPassword] = createSignal(""); const [confirmation, setConfirmation] = createSignal("");
  const [claimType, setClaimType] = createSignal(""); const [claimValue, setClaimValue] = createSignal(""); const [expires, setExpires] = createSignal("");
  const [relation, setRelation] = createSignal("manage_claims"); const [objectType, setObjectType] = createSignal("domain"); const [objectId, setObjectId] = createSignal(props.configuration.domain);
  const self = () => props.userId === props.session?.user.id;
  const refresh = async () => {
    const userId = props.userId;
    const [found, seen, held, granted] = await Promise.all([api.admin.getUser({ userId }), api.admin.getUserAuthenticationActivity({ userId }), api.admin.getUserClaims({ userId }), api.admin.listRelations({ subjectType: "user", subjectId: userId })]);
    setUser(found.user); setDisplayName(found.user.displayName); setActivity(seen.activity); setClaims(held.claims); setRelations(granted.relations.filter((entry) => !entry.removedAt));
  };
  onMount(loader(props, async () => { await refresh(); setClaimTypes((await api.admin.listClaimTypes({})).claimTypes); }, setError, () => t("app.admin_user.load_failed")));
  const act = async (work: () => Promise<unknown>, done: string, failed: string) => {
    setBusy(true); setStatus(""); setError("");
    try { await work(); await refresh(); setStatus(done); return true; }
    catch (cause) { setError(message(cause, failed)); return false; }
    finally { setBusy(false); }
  };
  const saveName = (event: SubmitEvent) => { event.preventDefault(); void act(() => api.admin.updateUser({ userId: props.userId, displayName: displayName().trim() }), t("app.admin_user.name_saved"), t("app.admin_user.name_failed")); };
  const resetPassword = async (event: SubmitEvent) => {
    event.preventDefault(); setStatus(""); setError("");
    if (password() !== confirmation()) return setError(t("app.password.mismatch_new"));
    const lengthError = checkPassword(password(), props.configuration);
    if (lengthError) return setError(lengthError);
    if (await act(() => api.admin.resetPassword({ userId: props.userId, newPassword: password() }), t("app.admin_user.password_reset"), t("app.admin_user.password_reset_failed"))) { setPassword(""); setConfirmation(""); }
  };
  const setLock = (locked: boolean) => void act(() => api.admin.setUserPasswordLock({ userId: props.userId, locked }), locked ? t("app.admin_user.lock_saved") : t("app.admin_user.unlock_saved"), t("app.admin_user.lock_failed"));
  const deactivate = () => { if (window.confirm(t("app.admin.disable_confirm", { username: user()?.username ?? "" }))) void act(() => api.admin.deactivateUser({ userId: props.userId }), t("app.admin.disabled", { username: user()?.username ?? "" }), t("app.admin.disable_failed")); };
  const addClaim = async (event: SubmitEvent) => {
    event.preventDefault();
    if (await act(() => api.admin.setClaim({ userId: props.userId, claimType: claimType().trim(), claimValue: claimValue(), expiresAt: expires() ? `${expires()}T00:00:00Z` : undefined }), t("app.admin_user.claim_added"), t("app.admin_user.claim_add_failed"))) { setClaimValue(""); setExpires(""); }
  };
  const removeClaim = (claim: Claim) => { if (window.confirm(t("app.admin_user.claim_remove_confirm", { label: claimTypeLabel(claim.claimType) }))) void act(() => api.admin.removeClaim({ claimId: claim.claimId }), t("app.admin_user.claim_removed"), t("app.admin_user.claim_remove_failed")); };
  const grant = (event: SubmitEvent) => { event.preventDefault(); void act(() => api.admin.grantRelation({ subjectType: "user", subjectId: props.userId, relation: relation(), objectType: objectType(), objectId: objectId().trim() }), t("app.admin_user.relation_granted"), t("app.admin_user.relation_grant_failed")); };
  const revoke = (entry: Relation) => { if (window.confirm(t("app.admin_user.relation_remove_confirm", { relation: entry.relation, object: entry.objectId }))) void act(() => api.admin.removeRelation({ relationId: entry.id }), t("app.admin_user.relation_removed"), t("app.admin_user.relation_remove_failed")); };
  return <><AdminHeader path={props.path} title={user()?.displayName ?? t("app.admin_user.title")} />
    <Show when={user()} fallback={<section class="card"><p role={error() ? "alert" : "status"}>{error() || t("app.admin_user.loading")}</p></section>}>
      <section class="card"><h2>{t("app.admin_user.summary")}</h2>
        <dl class="facts"><dt>{t("app.admin.col_username")}</dt><dd><code>{user()!.username}</code></dd><dt>{t("app.party.field.account_id")}</dt><dd><code>{user()!.id}</code></dd><dt>{t("app.admin.col_status")}</dt><dd>{user()!.isActive ? t("app.admin.status_active") : t("app.admin.status_disabled")}</dd><dt>{t("app.admin.col_created")}</dt><dd>{when(user()!.createdAt)}</dd><dt>{t("app.admin_user.last_sign_in")}</dt><dd>{when(activity()?.lastAuthenticatedAt)}</dd><dt>{t("app.admin_user.last_seen")}</dt><dd>{when(activity()?.lastSeenAt)}</dd><dt>{t("app.admin_user.sign_in_count")}</dt><dd>{activity()?.successfulAuthenticationCount ?? 0}</dd><dt>{t("app.admin_user.active_sessions")}</dt><dd>{activity()?.activeBrowserSessionCount ?? 0}</dd></dl>
        <form class="inline-form" aria-busy={busy()} onSubmit={saveName}><label><span>{t("app.admin.display_name")}</span><input value={displayName()} onInput={(event) => setDisplayName(event.currentTarget.value)} maxlength="254" required /></label><button type="submit" disabled={busy()}>{t("app.admin_user.save_name")}</button></form>
        <Show when={!self()}><Show when={user()!.isActive} fallback={<ReactivateAccount userId={props.userId} username={user()!.username} configuration={props.configuration} fail={setError} complete={async () => { await refresh(); setStatus(t("app.admin.restored", { username: user()!.username })); }} />}><div class="button-row"><button class="text-button" type="button" disabled={busy()} onClick={deactivate}>{t("app.admin.disable")}</button></div></Show></Show>
        <Feedback status={status()} error={error()} />
      </section>
      <Show when={user()!.isActive && !self()}><section class="card"><h2>{t("app.admin_user.password_title")}</h2><p id="admin-reset-rule">{passwordRule(props.configuration)} {t("app.admin_user.password_intro")}</p>
        <form class="account-form" aria-busy={busy()} onSubmit={resetPassword}><input class="visually-hidden" type="text" name="username" value={user()!.username} autocomplete="username" readonly /><label><span>{t("app.password.new")}</span><input type="password" value={password()} onInput={(event) => setPassword(event.currentTarget.value)} autocomplete="new-password" aria-describedby="admin-reset-rule" required /></label><label><span>{t("app.password.confirm_new")}</span><input type="password" value={confirmation()} onInput={(event) => setConfirmation(event.currentTarget.value)} autocomplete="new-password" required /></label><button type="submit" disabled={busy()}>{t("app.admin_user.password_submit")}</button></form>
        <h3>{t("app.admin_user.lock_title")}</h3><p id="admin-lock-help">{t("app.admin_user.lock_intro")}</p>
        <label class="checkbox-label"><input type="checkbox" checked={user()!.passwordLocked === true} disabled={busy()} aria-describedby="admin-lock-help" onChange={(event) => setLock(event.currentTarget.checked)} /><span>{t("app.admin_user.lock_label")}</span></label>
      </section></Show>
      <section class="card"><h2>{t("app.admin_user.claims_title")}</h2>
        <Show when={claims().length} fallback={<p class="muted">{t("app.account.details_empty")}</p>}><div class="table-wrap"><table><thead><tr><th>{t("app.account.col_detail")}</th><th>{t("app.account.col_value")}</th><th>{t("app.admin_user.col_confirmed")}</th><th>{t("app.admin_user.col_expires")}</th><th>{t("app.account.col_action")}</th></tr></thead><tbody><For each={claims()}>{(claim) => <tr><td>{claimTypeLabel(claim.claimType)} <small><code>{claim.claimType}</code></small></td><td>{claimText(claim)}</td><td>{claim.signatures.length ? t("app.common.yes") : t("app.common.no")}</td><td>{when(claim.expiresAt)}</td><td><button class="text-button" type="button" disabled={busy()} onClick={() => removeClaim(claim)}>{t("app.common.remove")}</button></td></tr>}</For></tbody></table></div></Show>
        <form class="account-form" aria-busy={busy()} onSubmit={addClaim}><label><span>{t("app.account.field_detail")}</span><input list="admin-claim-types" value={claimType()} onInput={(event) => setClaimType(event.currentTarget.value)} autocomplete="off" required /></label><label><span>{t("app.account.field_value")}</span><input value={claimValue()} onInput={(event) => setClaimValue(event.currentTarget.value)} required /></label><label><span>{t("app.admin_user.expires_optional")}</span><input type="date" value={expires()} onInput={(event) => setExpires(event.currentTarget.value)} /></label><button type="submit" disabled={busy()}>{t("app.admin_user.add_claim")}</button></form>
        <datalist id="admin-claim-types"><For each={claimTypes()}>{(type) => <option value={type.claimType}>{type.label}</option>}</For></datalist>
      </section>
      <section class="card"><h2>{t("app.admin_user.relations_title")}</h2><p>{t("app.admin_user.relations_intro")}</p>
        <Show when={relations().length} fallback={<p class="muted">{t("app.admin_user.relations_empty")}</p>}><div class="table-wrap"><table><thead><tr><th>{t("app.admin_user.col_relation")}</th><th>{t("app.admin_user.col_object")}</th><th>{t("app.admin_user.col_since")}</th><th>{t("app.account.col_action")}</th></tr></thead><tbody><For each={relations()}>{(entry) => <tr><td><code>{entry.relation}</code></td><td>{entry.objectType} <code>{entry.objectId}</code></td><td>{when(entry.createdAt)}</td><td><button class="text-button" type="button" disabled={busy()} onClick={() => revoke(entry)}>{t("app.common.remove")}</button></td></tr>}</For></tbody></table></div></Show>
        <form class="account-form" aria-busy={busy()} onSubmit={grant}><label><span>{t("app.admin_user.col_relation")}</span><select value={relation()} onChange={(event) => setRelation(event.currentTarget.value)}><For each={RELATIONS}>{(value) => <option value={value}>{value}</option>}</For></select></label><label><span>{t("app.admin_user.object_type")}</span><select value={objectType()} onChange={(event) => { setObjectType(event.currentTarget.value); setObjectId(event.currentTarget.value === "domain" ? props.configuration.domain : ""); }}><option value="domain">domain</option><option value="claim_type">claim_type</option></select></label><label><span>{t("app.admin_user.object_id")}</span><input value={objectId()} onInput={(event) => setObjectId(event.currentTarget.value)} list={objectType() === "claim_type" ? "admin-claim-types" : undefined} required /></label><button type="submit" disabled={busy()}>{t("app.admin_user.grant")}</button></form>
      </section>
    </Show></>;
};

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

type ClaimTypeForm = { claimType: string; label: string; description: string; valueType: string; maxBytes: string; setRule: string; signingRule: string; userSettable: boolean; defaultAutoSign: boolean; requiresApproval: boolean; suggested: boolean };
const emptyClaimType = (): ClaimTypeForm => ({ claimType: "", label: "", description: "", valueType: "text", maxBytes: "33792", setRule: "user_self", signingRule: "self_signed", userSettable: false, defaultAutoSign: false, requiresApproval: false, suggested: false });

const Select: Component<{ label: string; value: string; options: string[]; onChange(value: string): void; describe?: (value: string) => string }> = (props) => <label><span>{props.label}</span><select value={props.value} onChange={(event) => props.onChange(event.currentTarget.value)}><For each={props.options}>{(value) => <option value={value}>{props.describe ? props.describe(value) : value}</option>}</For></select></label>;
const Check: Component<{ label: string; checked: boolean; onChange(value: boolean): void }> = (props) => <label class="checkbox-label"><input type="checkbox" checked={props.checked} onChange={(event) => props.onChange(event.currentTarget.checked)} /><span>{props.label}</span></label>;
const Field: Component<{ label: string; value: string; onInput(value: string): void; required?: boolean; placeholder?: string; list?: string; type?: string }> = (props) => <label><span>{props.label}</span><input type={props.type ?? "text"} value={props.value} onInput={(event) => props.onInput(event.currentTarget.value)} required={props.required} placeholder={props.placeholder} list={props.list} autocomplete="off" /></label>;

const AdminPolicy: Component<PageProps & { path: string }> = (props) => {
  const [types, setTypes] = createSignal<ClaimTypePolicy[]>([]); const [labels, setLabels] = createSignal<ClaimTypeLabel[]>([]); const [issuers, setIssuers] = createSignal<TrustedIssuer[]>([]); const [rules, setRules] = createSignal<ReleaseRule[]>([]);
  const [status, setStatus] = createSignal(""); const [error, setError] = createSignal(""); const [busy, setBusy] = createSignal(false);
  const [form, setForm] = createSignal<ClaimTypeForm>(emptyClaimType());
  const edit = (patch: Partial<ClaimTypeForm>) => setForm((current) => ({ ...current, ...patch }));
  const [label, setLabel] = createSignal({ claimType: "", locale: "", label: "", description: "" });
  const [issuer, setIssuer] = createSignal({ claimType: "", issuerDomain: "" });
  const [rule, setRule] = createSignal({ audience: "*", claimType: "", disposition: "forced_allow" });
  const [release, setRelease] = createSignal({ audience: "", required: "", optional: "", choices: "", available: "", tempAudience: "", tempClaimType: "", tempDisposition: "forced_allow" });
  const [releaseResult, setReleaseResult] = createSignal<PreviewReleasePolicyResponse>();
  const [issuerTest, setIssuerTest] = createSignal({ subjectDomain: "", deniedDomains: "", deniedTlds: "", issuerUserId: "", claimType: "" });
  const [issuerResult, setIssuerResult] = createSignal<PreviewIssuerPolicyResponse>();
  const refresh = async () => {
    const [registry, names, trusted, released] = await Promise.all([api.admin.listClaimTypes({}), api.admin.listClaimTypeLabels({}), api.admin.listTrustedIssuers({}), api.admin.listReleaseRules({})]);
    setTypes(registry.claimTypes); setLabels(names.labels); setIssuers(trusted.trustedIssuers); setRules(released.releaseRules);
  };
  onMount(loader(props, refresh, setError, () => t("app.policy.load_failed")));
  const act = async (work: () => Promise<unknown>, done: string, failed: string) => {
    setBusy(true); setStatus(""); setError("");
    try { await work(); await refresh(); setStatus(done); return true; }
    catch (cause) { setError(message(cause, failed)); return false; }
    finally { setBusy(false); }
  };
  const confirmRemove = (name: string, work: () => Promise<unknown>) => { if (window.confirm(t("app.policy.remove_confirm", { name }))) void act(work, t("app.policy.removed"), t("app.policy.remove_failed")); };
  const saveType = async (event: SubmitEvent) => {
    event.preventDefault(); const value = form(); const maxBytes = Number(value.maxBytes);
    if (!Number.isInteger(maxBytes) || maxBytes <= 0) return setError(t("app.policy.max_bytes_invalid"));
    if (await act(() => api.admin.setClaimType({ claimType: value.claimType.trim(), label: value.label.trim(), description: value.description.trim() || undefined, valueType: value.valueType, maxBytes, setRule: value.setRule, signingRule: value.signingRule, userSettable: value.userSettable, defaultAutoSign: value.defaultAutoSign, requiresApproval: value.requiresApproval, suggested: value.suggested }), t("app.policy.type_saved"), t("app.policy.type_save_failed"))) setForm(emptyClaimType());
  };
  const editType = (type: ClaimTypePolicy) => { setForm({ claimType: type.claimType, label: type.label, description: type.description, valueType: type.valueType, maxBytes: String(type.maxBytes), setRule: type.setRule, signingRule: type.signingRule, userSettable: type.userSettable, defaultAutoSign: type.defaultAutoSign, requiresApproval: type.requiresApproval, suggested: type.suggested }); document.getElementById("claim-type-form")?.scrollIntoView({ behavior: "smooth" }); };
  const saveLabel = (event: SubmitEvent) => { event.preventDefault(); const value = label(); void act(() => api.admin.setClaimTypeLabel({ claimType: value.claimType, locale: value.locale.trim(), label: value.label.trim(), description: value.description.trim() || undefined }), t("app.policy.label_saved"), t("app.policy.label_save_failed")); };
  const addIssuer = (event: SubmitEvent) => { event.preventDefault(); const value = issuer(); void act(() => api.admin.addTrustedIssuer({ claimType: value.claimType, issuerDomain: value.issuerDomain.trim() }), t("app.policy.issuer_added"), t("app.policy.issuer_add_failed")); };
  const saveRule = (event: SubmitEvent) => { event.preventDefault(); const value = rule(); void act(() => api.admin.setReleaseRule({ audience: value.audience.trim(), claimType: value.claimType, disposition: value.disposition }), t("app.policy.rule_saved"), t("app.policy.rule_save_failed")); };
  const previewRelease = async (event: SubmitEvent) => {
    event.preventDefault(); setError(""); const value = release();
    try { setReleaseResult(await api.admin.previewReleasePolicy({ audience: value.audience.trim(), requiredClaims: list(value.required), optionalClaims: list(value.optional), availableClaims: list(value.available), userChoices: list(value.choices), tempAudience: value.tempAudience.trim() || undefined, tempClaimType: value.tempClaimType.trim() || undefined, tempDisposition: value.tempClaimType.trim() ? value.tempDisposition : undefined })); }
    catch (cause) { setError(message(cause, t("app.policy.preview_failed"))); }
  };
  const previewIssuer = async (event: SubmitEvent) => {
    event.preventDefault(); setError(""); const value = issuerTest();
    try { setIssuerResult(await api.admin.previewIssuerPolicy({ subjectDomain: value.subjectDomain.trim(), deniedDomains: value.deniedDomains.trim() ? list(value.deniedDomains) : undefined, deniedTlds: value.deniedTlds.trim() ? list(value.deniedTlds) : undefined, issuerUserId: value.issuerUserId.trim() || undefined, claimType: value.claimType.trim() || undefined })); }
    catch (cause) { setError(message(cause, t("app.policy.preview_failed"))); }
  };
  const flags = (type: ClaimTypePolicy) => [type.userSettable && t("app.policy.flag_user_settable"), type.defaultAutoSign && t("app.policy.flag_auto_sign"), type.requiresApproval && t("app.policy.flag_approval"), type.suggested && t("app.policy.flag_suggested")].filter(Boolean).join(", ");
  return <><AdminHeader path={props.path} title={t("app.policy.title")} intro={t("app.policy.intro")} />
    <Feedback status={status()} error={error()} />
    <datalist id="policy-claim-types"><For each={types()}>{(type) => <option value={type.claimType}>{type.label}</option>}</For></datalist>
    <section class="card"><h2>{t("app.policy.types_title")}</h2><p>{t("app.policy.types_intro")}</p>
      <div class="table-wrap"><table><thead><tr><th>{t("app.policy.col_type")}</th><th>{t("app.policy.col_name")}</th><th>{t("app.policy.col_value_type")}</th><th>{t("app.policy.col_set_rule")}</th><th>{t("app.policy.col_signing")}</th><th>{t("app.policy.col_flags")}</th><th>{t("app.account.col_action")}</th></tr></thead><tbody><For each={types()}>{(type) => <tr><td><code>{type.claimType}</code></td><td>{type.label}</td><td>{type.valueType}</td><td>{type.setRule}</td><td>{type.signingRule}</td><td><small>{flags(type)}</small></td><td><div class="button-row"><button class="text-button" type="button" onClick={() => editType(type)}>{t("app.policy.edit")}</button><button class="text-button" type="button" disabled={busy()} onClick={() => confirmRemove(type.claimType, () => api.admin.removeClaimType({ claimType: type.claimType }))}>{t("app.common.remove")}</button></div></td></tr>}</For></tbody></table></div>
      <h3>{t("app.policy.type_form_title")}</h3>
      <form id="claim-type-form" class="account-form" aria-busy={busy()} onSubmit={saveType}>
        <Field label={t("app.policy.field_type")} value={form().claimType} onInput={(value) => edit({ claimType: value })} required placeholder="pronouns" />
        <Field label={t("app.policy.field_name")} value={form().label} onInput={(value) => edit({ label: value })} required />
        <Field label={t("app.policy.field_description")} value={form().description} onInput={(value) => edit({ description: value })} />
        <Select label={t("app.policy.col_value_type")} value={form().valueType} options={VALUE_TYPES} onChange={(value) => edit({ valueType: value })} />
        <Field label={t("app.policy.field_max_bytes")} type="number" value={form().maxBytes} onInput={(value) => edit({ maxBytes: value })} required />
        <Select label={t("app.policy.col_set_rule")} value={form().setRule} options={SET_RULES} onChange={(value) => edit({ setRule: value })} />
        <Select label={t("app.policy.col_signing")} value={form().signingRule} options={SIGNING_RULES} onChange={(value) => edit({ signingRule: value })} />
        <div><Check label={t("app.policy.flag_user_settable")} checked={form().userSettable} onChange={(value) => edit({ userSettable: value })} /><Check label={t("app.policy.flag_auto_sign")} checked={form().defaultAutoSign} onChange={(value) => edit({ defaultAutoSign: value })} /><Check label={t("app.policy.flag_approval")} checked={form().requiresApproval} onChange={(value) => edit({ requiresApproval: value })} /><Check label={t("app.policy.flag_suggested")} checked={form().suggested} onChange={(value) => edit({ suggested: value })} /></div>
        <div class="button-row"><button type="submit" disabled={busy()}>{t("app.policy.type_save")}</button><button class="text-button" type="button" onClick={() => setForm(emptyClaimType())}>{t("app.policy.clear")}</button></div>
      </form>
    </section>
    <section class="card"><h2>{t("app.policy.labels_title")}</h2><p>{t("app.policy.labels_intro")}</p>
      <Show when={labels().length} fallback={<p class="muted">{t("app.policy.labels_empty")}</p>}><div class="table-wrap"><table><thead><tr><th>{t("app.policy.col_type")}</th><th>{t("app.policy.col_locale")}</th><th>{t("app.policy.col_name")}</th><th>{t("app.policy.field_description")}</th><th>{t("app.account.col_action")}</th></tr></thead><tbody><For each={labels()}>{(entry) => <tr><td><code>{entry.claimType}</code></td><td>{entry.locale}</td><td>{entry.label}</td><td>{entry.description ?? ""}</td><td><button class="text-button" type="button" disabled={busy()} onClick={() => confirmRemove(`${entry.claimType} (${entry.locale})`, () => api.admin.removeClaimTypeLabel({ claimType: entry.claimType, locale: entry.locale }))}>{t("app.common.remove")}</button></td></tr>}</For></tbody></table></div></Show>
      <form class="account-form" aria-busy={busy()} onSubmit={saveLabel}><Field label={t("app.policy.col_type")} value={label().claimType} onInput={(value) => setLabel({ ...label(), claimType: value })} list="policy-claim-types" required /><Field label={t("app.policy.col_locale")} value={label().locale} onInput={(value) => setLabel({ ...label(), locale: value })} placeholder="es-ES" required /><Field label={t("app.policy.col_name")} value={label().label} onInput={(value) => setLabel({ ...label(), label: value })} required /><Field label={t("app.policy.field_description")} value={label().description} onInput={(value) => setLabel({ ...label(), description: value })} /><button type="submit" disabled={busy()}>{t("app.policy.label_save")}</button></form>
    </section>
    <section class="card"><h2>{t("app.policy.issuers_title")}</h2><p>{t("app.policy.issuers_intro")}</p>
      <Show when={issuers().length} fallback={<p class="muted">{t("app.policy.issuers_empty")}</p>}><div class="table-wrap"><table><thead><tr><th>{t("app.policy.col_type")}</th><th>{t("app.policy.col_issuer")}</th><th>{t("app.account.col_action")}</th></tr></thead><tbody><For each={issuers()}>{(entry) => <tr><td><code>{entry.claimType}</code></td><td>{entry.issuerDomain}</td><td><button class="text-button" type="button" disabled={busy()} onClick={() => confirmRemove(`${entry.issuerDomain} → ${entry.claimType}`, () => api.admin.removeTrustedIssuer({ claimType: entry.claimType, issuerDomain: entry.issuerDomain }))}>{t("app.common.remove")}</button></td></tr>}</For></tbody></table></div></Show>
      <form class="account-form" aria-busy={busy()} onSubmit={addIssuer}><Field label={t("app.policy.col_type")} value={issuer().claimType} onInput={(value) => setIssuer({ ...issuer(), claimType: value })} list="policy-claim-types" required /><Field label={t("app.policy.col_issuer")} value={issuer().issuerDomain} onInput={(value) => setIssuer({ ...issuer(), issuerDomain: value })} placeholder="issuer.example" required /><button type="submit" disabled={busy()}>{t("app.policy.issuer_add")}</button></form>
      <h3>{t("app.policy.issuer_preview_title")}</h3><p>{t("app.policy.issuer_preview_intro")}</p>
      <form class="account-form" onSubmit={previewIssuer}><Field label={t("app.policy.field_subject_domain")} value={issuerTest().subjectDomain} onInput={(value) => setIssuerTest({ ...issuerTest(), subjectDomain: value })} placeholder="example.com" required /><Field label={t("app.policy.field_denied_domains")} value={issuerTest().deniedDomains} onInput={(value) => setIssuerTest({ ...issuerTest(), deniedDomains: value })} placeholder={t("app.policy.use_configured")} /><Field label={t("app.policy.field_denied_tlds")} value={issuerTest().deniedTlds} onInput={(value) => setIssuerTest({ ...issuerTest(), deniedTlds: value })} placeholder={t("app.policy.use_configured")} /><Field label={t("app.policy.field_issuer_user")} value={issuerTest().issuerUserId} onInput={(value) => setIssuerTest({ ...issuerTest(), issuerUserId: value })} /><Field label={t("app.policy.col_type")} value={issuerTest().claimType} onInput={(value) => setIssuerTest({ ...issuerTest(), claimType: value })} list="policy-claim-types" /><button type="submit">{t("app.policy.preview")}</button></form>
      <Show when={issuerResult()}>{(result) => <div class="notice"><p>{result().allowed ? t("app.policy.issuer_allowed") : t("app.policy.issuer_denied")} <small>({result().reason})</small></p><p><small>{t("app.policy.denies_used", { domains: result().deniedDomains.join(", ") || "—", tlds: result().deniedTlds.join(", ") || "—" })}</small></p><Show when={result().userCanIssue !== undefined}><p>{result().userCanIssue ? t("app.policy.user_can_issue") : t("app.policy.user_cannot_issue")}</p></Show><p><small>{t("app.policy.claim_ttl", { seconds: result().attestedClaimTtlSeconds })}</small></p></div>}</Show>
    </section>
    <section class="card"><h2>{t("app.policy.rules_title")}</h2><p>{t("app.policy.rules_intro")}</p>
      <Show when={rules().length} fallback={<p class="muted">{t("app.policy.rules_empty")}</p>}><div class="table-wrap"><table><thead><tr><th>{t("app.policy.col_audience")}</th><th>{t("app.policy.col_type")}</th><th>{t("app.policy.col_disposition")}</th><th>{t("app.account.col_action")}</th></tr></thead><tbody><For each={rules()}>{(entry) => <tr><td><code>{entry.audience}</code></td><td><code>{entry.claimType}</code></td><td>{dispositionLabel(entry.disposition)}</td><td><button class="text-button" type="button" disabled={busy()} onClick={() => confirmRemove(`${entry.audience} / ${entry.claimType}`, () => api.admin.removeReleaseRule({ audience: entry.audience, claimType: entry.claimType }))}>{t("app.common.remove")}</button></td></tr>}</For></tbody></table></div></Show>
      <form class="account-form" aria-busy={busy()} onSubmit={saveRule}><Field label={t("app.policy.col_audience")} value={rule().audience} onInput={(value) => setRule({ ...rule(), audience: value })} placeholder="* or app.example" required /><Field label={t("app.policy.col_type")} value={rule().claimType} onInput={(value) => setRule({ ...rule(), claimType: value })} list="policy-claim-types" required /><Select label={t("app.policy.col_disposition")} value={rule().disposition} options={DISPOSITIONS} describe={dispositionLabel} onChange={(value) => setRule({ ...rule(), disposition: value })} /><button type="submit" disabled={busy()}>{t("app.policy.rule_save")}</button></form>
      <h3>{t("app.policy.release_preview_title")}</h3><p>{t("app.policy.release_preview_intro")}</p>
      <form class="account-form" onSubmit={previewRelease}><Field label={t("app.policy.col_audience")} value={release().audience} onInput={(value) => setRelease({ ...release(), audience: value })} placeholder="app.example" required /><Field label={t("app.policy.field_required")} value={release().required} onInput={(value) => setRelease({ ...release(), required: value })} placeholder="display_name, email" /><Field label={t("app.policy.field_optional")} value={release().optional} onInput={(value) => setRelease({ ...release(), optional: value })} placeholder="over_21" /><Field label={t("app.policy.field_choices")} value={release().choices} onInput={(value) => setRelease({ ...release(), choices: value })} /><Field label={t("app.policy.field_available")} value={release().available} onInput={(value) => setRelease({ ...release(), available: value })} placeholder={t("app.policy.all_requested")} /><Field label={t("app.policy.field_temp_audience")} value={release().tempAudience} onInput={(value) => setRelease({ ...release(), tempAudience: value })} placeholder="* or app.example" /><Field label={t("app.policy.field_temp_type")} value={release().tempClaimType} onInput={(value) => setRelease({ ...release(), tempClaimType: value })} list="policy-claim-types" /><Select label={t("app.policy.field_temp_disposition")} value={release().tempDisposition} options={DISPOSITIONS} describe={dispositionLabel} onChange={(value) => setRelease({ ...release(), tempDisposition: value })} /><button type="submit">{t("app.policy.preview")}</button></form>
      <Show when={releaseResult()}>{(result) => <div class="notice"><p>{t("app.policy.preview_shared", { claims: result().authorizedClaims.join(", ") || "—" })}</p><p><small>{t("app.policy.preview_rules", { allow: result().forcedAllow.join(", ") || "—", deny: result().forcedDeny.join(", ") || "—" })}</small></p>
        <div class="table-wrap"><table><thead><tr><th>{t("app.policy.col_type")}</th><th>{t("app.policy.col_requested")}</th><th>{t("app.policy.col_available")}</th><th>{t("app.policy.col_disposition")}</th><th>{t("app.policy.col_starts")}</th></tr></thead><tbody><For each={result().rows}>{(row) => <tr><td><code>{row.claimType}</code></td><td>{row.required ? t("app.policy.required") : t("app.policy.optional")}</td><td>{row.available ? t("app.common.yes") : t("app.common.no")}</td><td>{dispositionLabel(row.policy)}{row.locked ? ` (${t("app.policy.locked")})` : ""}</td><td>{row.defaultGranted ? t("app.policy.checked") : t("app.policy.unchecked")}</td></tr>}</For></tbody></table></div></div>}</Show>
    </section>
  </>;
};

// ---------------------------------------------------------------------------
// App access
// ---------------------------------------------------------------------------

type AccessForm = { id?: string; name: string; mode: string; patterns: string; message: string; targets: AppAccessTarget[] };
const emptyAccessForm = (): AccessForm => ({ name: "", mode: "deny", patterns: "", message: "", targets: [] });
const emptyTarget = () => ({ kind: "user", user: "", groupName: "", claimType: "", claimOperator: "age_under", claimValue: "" });

function accessModeLabel(mode: string): string {
  return mode === "allow" ? t("app.access.mode_allow") : t("app.access.mode_deny");
}

function operatorLabel(operator: string): string {
  return t(`app.access.operator_${operator}`);
}

const AdminAccess: Component<PageProps & { path: string }> = (props) => {
  const [policies, setPolicies] = createSignal<AppAccessPolicy[]>([]); const [users, setUsers] = createSignal<AdminUser[]>([]); const [types, setTypes] = createSignal<ClaimTypePolicy[]>([]);
  const [status, setStatus] = createSignal(""); const [error, setError] = createSignal(""); const [busy, setBusy] = createSignal(false);
  const [form, setForm] = createSignal<AccessForm>(emptyAccessForm()); const [target, setTarget] = createSignal(emptyTarget());
  const [test, setTest] = createSignal({ user: "", domain: "" }); const [testResult, setTestResult] = createSignal<PreviewAppAccessResponse>();
  const edit = (patch: Partial<AccessForm>) => setForm((current) => ({ ...current, ...patch }));
  const editTarget = (patch: Partial<ReturnType<typeof emptyTarget>>) => setTarget((current) => ({ ...current, ...patch }));
  const refresh = async () => setPolicies((await api.admin.listAppAccessPolicies({})).policies);
  onMount(loader(props, async () => {
    const [stored, accounts, registry] = await Promise.all([api.admin.listAppAccessPolicies({}), api.admin.listUsers({ limit: 1000 }), api.admin.listClaimTypes({})]);
    setPolicies(stored.policies); setUsers(accounts.users.filter((user) => !user.purgedAt)); setTypes(registry.claimTypes);
  }, setError, () => t("app.access.load_failed")));
  const userById = (id?: string) => users().find((user) => user.id === id);
  const userByName = (name: string) => users().find((user) => user.username === name.trim() || user.id === name.trim());
  const targetText = (entry: AppAccessTarget): string => {
    switch (entry.kind) {
      case "everyone": return t("app.access.target_everyone");
      case "user": return t("app.access.target_user", { user: userById(entry.userId)?.username ?? entry.userId ?? "" });
      case "group": return t("app.access.target_group", { group: entry.groupName ?? "" });
      default: return t("app.access.target_claim", { label: claimTypeLabel(entry.claimType ?? ""), condition: operatorLabel(entry.claimOperator ?? ""), value: entry.claimValue ?? "" }).trim();
    }
  };
  const addTarget = (event: Event) => {
    event.preventDefault(); setError("");
    const value = target(); let next: AppAccessTarget;
    if (value.kind === "user") {
      const user = userByName(value.user);
      if (!user) return setError(t("app.access.user_unknown", { user: value.user.trim() }));
      next = { kind: "user", userId: user.id };
    } else if (value.kind === "group") {
      if (!value.groupName.trim()) return setError(t("app.access.group_required"));
      next = { kind: "group", groupName: value.groupName.trim() };
    } else if (value.kind === "claim") {
      if (!value.claimType.trim()) return setError(t("app.access.claim_required"));
      const takesValue = !["present", "absent"].includes(value.claimOperator);
      if (takesValue && !value.claimValue.trim()) return setError(t("app.access.value_required"));
      next = { kind: "claim", claimType: value.claimType.trim(), claimOperator: value.claimOperator, claimValue: takesValue ? value.claimValue.trim() : undefined };
    } else next = { kind: "everyone" };
    edit({ targets: [...form().targets, next] }); setTarget({ ...emptyTarget(), kind: value.kind });
  };
  const removeTarget = (index: number) => edit({ targets: form().targets.filter((_, position) => position !== index) });
  const save = async (event: SubmitEvent) => {
    event.preventDefault(); const value = form(); setBusy(true); setStatus(""); setError("");
    try {
      await api.admin.setAppAccessPolicy({ id: value.id, name: value.name.trim(), mode: value.mode, patterns: patternList(value.patterns), message: value.message.trim() || undefined, targets: value.targets });
      await refresh(); setForm(emptyAccessForm()); setStatus(t("app.access.saved", { name: value.name.trim() }));
    } catch (cause) { setError(message(cause, t("app.access.save_failed"))); }
    finally { setBusy(false); }
  };
  const editPolicy = (policy: AppAccessPolicy) => { setForm({ id: policy.id, name: policy.name, mode: policy.mode, patterns: policy.patterns.join("\n"), message: policy.message ?? "", targets: [...policy.targets] }); document.getElementById("access-policy-form")?.scrollIntoView({ behavior: "smooth" }); };
  const remove = async (policy: AppAccessPolicy) => {
    if (!window.confirm(t("app.policy.remove_confirm", { name: policy.name }))) return;
    setBusy(true); setStatus(""); setError("");
    try { await api.admin.removeAppAccessPolicy({ id: policy.id }); await refresh(); if (form().id === policy.id) setForm(emptyAccessForm()); setStatus(t("app.policy.removed")); }
    catch (cause) { setError(message(cause, t("app.policy.remove_failed"))); }
    finally { setBusy(false); }
  };
  const runTest = async (event: SubmitEvent) => {
    event.preventDefault(); setError(""); setTestResult(undefined);
    const user = userByName(test().user);
    if (!user) return setError(t("app.access.user_unknown", { user: test().user.trim() }));
    try { setTestResult(await api.admin.previewAppAccess({ userId: user.id, domain: test().domain.trim() || undefined })); }
    catch (cause) { setError(message(cause, t("app.policy.preview_failed"))); }
  };
  return <><AdminHeader path={props.path} title={t("app.access.title")} intro={t("app.access.intro")} />
    <Feedback status={status()} error={error()} />
    <datalist id="access-users"><For each={users()}>{(user) => <option value={user.username}>{user.displayName}</option>}</For></datalist>
    <datalist id="access-claim-types"><For each={types()}>{(type) => <option value={type.claimType}>{type.label}</option>}</For></datalist>
    <section class="card"><h2>{t("app.access.list_title")}</h2><p>{t("app.access.rules")}</p>
      <Show when={policies().length} fallback={<p class="muted">{t("app.access.empty")}</p>}><div class="table-wrap"><table><thead><tr><th>{t("app.access.col_name")}</th><th>{t("app.access.col_mode")}</th><th>{t("app.access.col_patterns")}</th><th>{t("app.access.col_targets")}</th><th>{t("app.access.col_message")}</th><th>{t("app.account.col_action")}</th></tr></thead>
        <tbody><For each={policies()}>{(policy) => <tr><td>{policy.name}</td><td><span class="pill">{accessModeLabel(policy.mode)}</span></td><td><For each={policy.patterns}>{(pattern) => <><code>{pattern}</code> </>}</For></td><td><Show when={policy.targets.length} fallback={<small class="muted">{t("app.access.targets_none")}</small>}><small>{policy.targets.map(targetText).join("; ")}</small></Show></td><td><small>{policy.message ?? ""}</small></td><td><div class="button-row"><button class="text-button" type="button" onClick={() => editPolicy(policy)}>{t("app.policy.edit")}</button><button class="text-button" type="button" disabled={busy()} onClick={() => remove(policy)}>{t("app.common.remove")}</button></div></td></tr>}</For></tbody></table></div></Show>
    </section>
    <section class="card" id="access-policy-form"><h2>{form().id ? t("app.access.form_edit_title", { name: form().name }) : t("app.access.form_title")}</h2>
      <form class="account-form" aria-busy={busy()} onSubmit={save}>
        <Field label={t("app.access.col_name")} value={form().name} onInput={(value) => edit({ name: value })} required />
        <Select label={t("app.access.col_mode")} value={form().mode} options={ACCESS_MODES} describe={accessModeLabel} onChange={(value) => edit({ mode: value })} />
        <label><span>{t("app.access.col_patterns")}</span><textarea rows="4" value={form().patterns} onInput={(event) => edit({ patterns: event.currentTarget.value })} placeholder={"*.ru\nshop.example"} aria-describedby="access-pattern-help" required /><small id="access-pattern-help">{t("app.access.patterns_help")}</small></label>
        <label><span>{t("app.access.field_message")}</span><textarea rows="2" maxlength="1000" value={form().message} onInput={(event) => edit({ message: event.currentTarget.value })} aria-describedby="access-message-help" /><small id="access-message-help">{t("app.access.message_help")}</small></label>
        <fieldset><legend>{t("app.access.col_targets")}</legend>
          <Show when={form().targets.length} fallback={<p class="muted">{t("app.access.targets_none")}</p>}><ul><For each={form().targets}>{(entry, index) => <li>{targetText(entry)} <button class="text-button" type="button" onClick={() => removeTarget(index())}>{t("app.common.remove")}</button></li>}</For></ul></Show>
          <div class="inline-form">
            <Select label={t("app.access.target_kind")} value={target().kind} options={TARGET_KINDS} describe={(kind) => t(`app.access.kind_${kind}`)} onChange={(value) => editTarget({ kind: value })} />
            <Show when={target().kind === "user"}><Field label={t("app.admin.col_username")} value={target().user} onInput={(value) => editTarget({ user: value })} list="access-users" /></Show>
            <Show when={target().kind === "group"}><Field label={t("app.access.field_group")} value={target().groupName} onInput={(value) => editTarget({ groupName: value })} /></Show>
            <Show when={target().kind === "claim"}>
              <Field label={t("app.access.field_claim_type")} value={target().claimType} onInput={(value) => editTarget({ claimType: value })} list="access-claim-types" />
              <Select label={t("app.access.field_condition")} value={target().claimOperator} options={CLAIM_OPERATORS} describe={operatorLabel} onChange={(value) => editTarget({ claimOperator: value })} />
              <Show when={!["present", "absent"].includes(target().claimOperator)}><Field label={target().claimOperator.startsWith("age_") ? t("app.access.field_age") : t("app.account.field_value")} type={target().claimOperator.startsWith("age_") ? "number" : "text"} value={target().claimValue} onInput={(value) => editTarget({ claimValue: value })} /></Show>
            </Show>
            <button type="button" onClick={addTarget}>{t("app.access.add_target")}</button>
          </div>
          <Show when={target().kind === "claim"}><small>{t("app.access.claim_help")}</small></Show>
        </fieldset>
        <div class="button-row"><button type="submit" disabled={busy()}>{t("app.access.save")}</button><button class="text-button" type="button" onClick={() => { setForm(emptyAccessForm()); setTarget(emptyTarget()); }}>{t("app.policy.clear")}</button></div>
      </form>
    </section>
    <section class="card"><h2>{t("app.access.test_title")}</h2><p>{t("app.access.test_intro")}</p>
      <form class="inline-form" onSubmit={runTest}><Field label={t("app.admin.col_username")} value={test().user} onInput={(value) => setTest({ ...test(), user: value })} list="access-users" required /><Field label={t("app.access.field_domain")} value={test().domain} onInput={(value) => setTest({ ...test(), domain: value })} placeholder={t("app.access.local_app")} /><button type="submit">{t("app.policy.preview")}</button></form>
      <Show when={testResult()}>{(result) => <div class={result().allowed ? "notice good" : "notice bad"}><p>{result().allowed ? t("app.access.test_allowed") : t("app.access.test_blocked", { policies: result().blockingPolicies.join(", ") })}</p><p><small>{t("app.access.test_applied", { policies: result().appliedPolicies.join(", ") || "—" })}</small></p><For each={result().messages}>{(text) => <p><small>{text}</small></p>}</For></div>}</Show>
    </section>
  </>;
};

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

function approvalValue(approval: ClaimApproval): string {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(approval.claimValue); }
  catch { return t("app.account.binary_value"); }
}

const AdminApprovals: Component<PageProps & { path: string }> = (props) => {
  const [approvals, setApprovals] = createSignal<ClaimApproval[]>([]); const [loaded, setLoaded] = createSignal(false);
  const [status, setStatus] = createSignal(""); const [error, setError] = createSignal(""); const [busy, setBusy] = createSignal("");
  const refresh = async () => { setApprovals((await api.admin.listPendingClaimApprovals({})).approvals); setLoaded(true); };
  onMount(loader(props, refresh, setError, () => t("app.approvals.load_failed")));
  const decide = async (approval: ClaimApproval, approve: boolean) => {
    setBusy(approval.id); setStatus(""); setError("");
    try { if (approve) await api.admin.approveClaim({ approvalId: approval.id }); else await api.admin.rejectClaim({ approvalId: approval.id }); await refresh(); setStatus(approve ? t("app.approvals.approved") : t("app.approvals.rejected")); }
    catch (cause) { setError(message(cause, t("app.approvals.failed"))); }
    finally { setBusy(""); }
  };
  return <><AdminHeader path={props.path} title={t("app.approvals.title")} intro={t("app.approvals.intro")} />
    <section class="card"><Show when={approvals().length} fallback={<p class="muted">{loaded() ? t("app.approvals.empty") : t("app.approvals.loading")}</p>}>
      <div class="table-wrap"><table><thead><tr><th>{t("app.party.field.account_id")}</th><th>{t("app.account.col_detail")}</th><th>{t("app.account.col_value")}</th><th>{t("app.approvals.col_requested")}</th><th>{t("app.account.col_action")}</th></tr></thead><tbody><For each={approvals()}>{(approval) => <tr><td><Link href={`/app/admin/users/${encodeURIComponent(approval.userId)}`}><code>{approval.userId}</code></Link></td><td>{claimTypeLabel(approval.claimType)}</td><td>{approvalValue(approval)}</td><td>{new Date(approval.createdAt).toLocaleString()}</td><td><div class="button-row"><button type="button" disabled={busy() === approval.id} onClick={() => decide(approval, true)}>{t("app.approvals.approve")}</button><button class="text-button" type="button" disabled={busy() === approval.id} onClick={() => decide(approval, false)}>{t("app.approvals.reject")}</button></div></td></tr>}</For></tbody></table></div>
    </Show><Feedback status={status()} error={error()} /></section></>;
};

// ---------------------------------------------------------------------------
// Issue claims for another domain's request
// ---------------------------------------------------------------------------

const IssueResult: Component<{ result: IssuedClaimResult; domain: string }> = (props) => {
  const [copied, setCopied] = createSignal(false);
  const copy = async () => { try { await navigator.clipboard.writeText(props.result.claimCode ?? ""); setCopied(true); } catch { setCopied(false); } };
  const name = () => claimTypeLabel(props.result.claimType);
  return <div class="consent-claim">
    <Show when={props.result.outcome === "deposited"}><p class="notice good">{t("app.issue.deposited", { label: name(), domain: props.domain })}</p></Show>
    <Show when={props.result.outcome === "handoff"}><p class="notice">{t("app.issue.handoff", { label: name(), domain: props.domain, reason: props.result.message ?? "" })}</p><textarea readonly rows="3" aria-label={t("app.issue.code_label", { label: name() })} value={props.result.claimCode ?? ""} onFocus={(event) => event.currentTarget.select()} /><div class="button-row"><button type="button" onClick={copy}>{t("app.confirm.copy")}</button><Show when={copied()}><small role="status">{t("app.confirm.copied")}</small></Show></div></Show>
    <Show when={props.result.outcome === "skipped"}><p class="notice">{t("app.issue.skipped", { label: name(), reason: props.result.message ?? "" })}</p></Show>
    <Show when={props.result.outcome === "failed"}><p class="notice bad">{t("app.issue.failed", { label: name(), reason: props.result.message ?? "" })}</p></Show>
  </div>;
};

const AdminIssue: Component<PageProps & { path: string }> = (props) => {
  const [code, setCode] = createSignal(""); const [request, setRequest] = createSignal<InspectSigningRequestResponse>(); const [values, setValues] = createSignal<Record<string, string>>({});
  const [results, setResults] = createSignal<IssuedClaimResult[]>([]); const [error, setError] = createSignal(""); const [busy, setBusy] = createSignal(false);
  const inspect = async (event: SubmitEvent) => {
    event.preventDefault(); setBusy(true); setError(""); setRequest(undefined); setResults([]); setValues({});
    try { setRequest(await api.browserIssuer.inspectSigningRequest({ signedRequest: code().trim() })); }
    catch (cause) { if (authenticationFailed(cause)) props.navigate("/app/login?next=/app/admin/issue"); else setError(cause instanceof Error && cause.message ? cause.message : t("app.issue.inspect_failed")); }
    finally { setBusy(false); }
  };
  const issue = async (event: SubmitEvent) => {
    event.preventDefault(); setBusy(true); setError("");
    const chosen = Object.entries(values()).filter(([, value]) => value.trim());
    try { setResults((await api.browserIssuer.issueForSigningRequest({ signedRequest: code().trim(), claimTypes: chosen.map(([type]) => type), claimValues: chosen.map(([, value]) => value.trim()) })).results); }
    catch (cause) { setError(cause instanceof Error && cause.message ? cause.message : t("app.issue.issue_failed")); }
    finally { setBusy(false); }
  };
  const restart = () => { setCode(""); setRequest(undefined); setResults([]); setValues({}); setError(""); };
  return <><AdminHeader path={props.path} title={t("app.issue.title")} intro={t("app.issue.intro", { domain: props.configuration.domain })} />
    <section class="card"><Show when={!request()} fallback={<>
      <p>{format<JSX.Element>("app.issue.request_from", { subject: <code>{request()!.subjectUserId}@{request()!.subjectDomain}</code> })}</p>
      <p><small>{t("app.issue.request_until", { until: new Date(request()!.expiresAt).toLocaleString() })}</small></p>
      <Show when={!results().length} fallback={<><For each={results()}>{(result) => <IssueResult result={result} domain={request()!.subjectDomain} />}</For><button type="button" onClick={restart}>{t("app.issue.another")}</button></>}>
        <form aria-busy={busy()} onSubmit={issue}><p>{t("app.issue.values_intro")}</p>
          <For each={request()!.requestedClaimTypes}>{(type) => <Show when={request()!.issuableClaimTypes.includes(type)} fallback={<p class="muted">{t("app.issue.not_allowed", { label: claimTypeLabel(type) })}</p>}><label><span>{claimTypeLabel(type)} <small><code>{type}</code></small></span><input value={values()[type] ?? ""} onInput={(event) => { const value = event.currentTarget.value; setValues((current) => ({ ...current, [type]: value })); }} /></label></Show>}</For>
          <div class="button-row"><button type="submit" disabled={busy() || !Object.values(values()).some((value) => value.trim())}>{busy() ? t("app.issue.signing") : t("app.issue.sign")}</button><button class="text-button" type="button" onClick={restart}>{t("app.common.cancel")}</button></div>
        </form>
      </Show></>}>
      <form aria-busy={busy()} onSubmit={inspect}><label><span>{t("app.issue.code")}</span><textarea rows="5" value={code()} onInput={(event) => setCode(event.currentTarget.value)} required /></label><button type="submit" disabled={busy()}>{busy() ? t("app.issue.checking") : t("app.issue.check")}</button></form>
    </Show><Feedback status="" error={error()} /></section></>;
};

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

const AdminSettings: Component<PageProps & { path: string }> = (props) => {
  const [policy, setPolicy] = createSignal<SignInPolicy>(); const [hours, setHours] = createSignal("");
  const [status, setStatus] = createSignal(""); const [error, setError] = createSignal(""); const [busy, setBusy] = createSignal(false);
  onMount(loader(props, async () => { const current = await api.admin.getSignInPolicy({}); setPolicy(current); setHours(String(current.signInHours)); }, setError, () => t("app.settings.load_failed")));
  const save = async (event: SubmitEvent) => {
    event.preventDefault(); setStatus(""); setError("");
    const value = Number(hours()); const range = policy()!;
    if (!Number.isInteger(value) || value < range.minSignInHours || value > range.maxSignInHours) return setError(t("app.settings.hours_invalid", { min: range.minSignInHours, max: range.maxSignInHours }));
    setBusy(true);
    try { const saved = await api.admin.setSignInPolicy({ signInHours: value }); setPolicy(saved); setHours(String(saved.signInHours)); setStatus(t("app.settings.saved", { hours: saved.signInHours })); }
    catch (cause) { setError(message(cause, t("app.settings.save_failed"))); }
    finally { setBusy(false); }
  };
  return <><AdminHeader path={props.path} title={t("app.settings.title")} />
    <section class="card"><h2>{t("app.settings.sign_in_title")}</h2>
      <Show when={policy()} fallback={<p role={error() ? "alert" : "status"}>{error() || t("app.settings.loading")}</p>}>
        <p id="sign-in-hours-help">{t("app.settings.sign_in_intro", { default: policy()!.defaultSignInHours })}</p>
        <form class="inline-form" aria-busy={busy()} onSubmit={save}><label><span>{t("app.settings.hours")}</span><input type="number" min={policy()!.minSignInHours} max={policy()!.maxSignInHours} step="1" value={hours()} onInput={(event) => setHours(event.currentTarget.value)} aria-describedby="sign-in-hours-help" required /></label><button type="submit" disabled={busy()}>{t("app.settings.save")}</button></form>
        <Feedback status={status()} error={error()} />
      </Show>
    </section></>;
};

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

const ADMIN_PATHS = ["/app/admin", "/app/admin/policy", "/app/admin/access", "/app/admin/approvals", "/app/admin/issue", "/app/admin/settings"];

export const AdminArea: Component<PageProps & { path: string }> = (props) => {
  const path = () => props.path.replace(/\/$/, "");
  const known = () => ADMIN_PATHS.includes(path()) || path().startsWith("/app/admin/users/");
  const page = (): JSX.Element => {
    const current = path();
    if (current.startsWith("/app/admin/users/")) return <AdminUserPage {...props} userId={decodeURIComponent(current.slice("/app/admin/users/".length))} />;
    if (current === "/app/admin/policy") return <AdminPolicy {...props} />;
    if (current === "/app/admin/access") return <AdminAccess {...props} />;
    if (current === "/app/admin/approvals") return <AdminApprovals {...props} />;
    if (current === "/app/admin/issue") return <AdminIssue {...props} />;
    if (current === "/app/admin/settings") return <AdminSettings {...props} />;
    return <AdminAccounts {...props} />;
  };
  return <Show when={known()} fallback={<Unavailable title={t("app.not_found.title")} detail={t("app.not_found.body")} destination="/app/admin" action={t("app.admin_nav.back")} />}><main class="wrap wide">{page()}</main></Show>;
};
