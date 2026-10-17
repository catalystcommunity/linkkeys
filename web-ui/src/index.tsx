import { For, Show, createEffect, createSignal, onCleanup, onMount, type Component, type JSX } from "solid-js";
import { render } from "solid-js/web";
import "./styles.css";
import { api } from "./transport";
import { RuntimeHost, addStylesheet, loadExtensions, type ExtensionRoute } from "./host";
import { claimTypeLabel, format, t, useCatalog } from "./i18n";
import { AdminArea } from "./admin";
import { Link, Loading, Unavailable, checkPassword, claimText, passwordRule, query, type PageProps } from "./shared";
import type { BrowserConsentClaim, BrowserLocalRpInspectResponse, MyClaimSetting, Profile, ActAsGrantSummary, BrowserActAsInspectResponse, BrowserActAsParty, BrowserSessionInfo, Claim, GetUiConfigurationResponse, SettableClaimPolicy, VerifiedContactMethod } from "./generated/types.gen";
import { fromSigningRequestCbor, toSignedSigningRequestCbor } from "./generated/codec.gen";
import { consentDecision, localRpFailureMessage, reasonText, actAsGrantState, actAsHandoff, base64UrlUnpadded, confirmationDetails, siteDomain, actAsRequestKey, applicationLabel, describeDuration, durationChoices, partyHeadline, partyTitle, partyTrustNotes, authenticationFailed, authorizationHandoff, authorizationRequestIsTerminal, claimValueTooLong, cleanupOnce, currentPasswordMessage, hasBlockedRequiredClaim, hasNewlyRequestedClaim, inputType, loginFailureMessage, passwordLengthError, passwordManagerUsername, recoveryCompletionFailureMessage, recoveryLinkExpired, recoveryValidationFailureMessage, serviceMessage as message, standingAuthorization, transportFailed, verificationFailureMessage, withLoginContext } from "./ui-logic";





function safeNext(value: string): string { return value.startsWith("/app/") ? value : ""; }
function withNext(path: string, next: string): string { return next ? `${path}?next=${encodeURIComponent(next)}` : path; }
function sessionIdentity(value?: BrowserSessionInfo): string { return value ? `${value.user.id}:${value.issuedAt}` : ""; }

function takeFragmentToken(storageKey?: string): string {
  const fragmentToken = new URLSearchParams(window.location.hash.slice(1)).get("token");
  if (fragmentToken && storageKey) sessionStorage.setItem(storageKey, fragmentToken);
  const token = fragmentToken ?? (storageKey ? sessionStorage.getItem(storageKey) ?? "" : "");
  if (window.location.hash) window.history.replaceState({}, "", window.location.pathname + window.location.search);
  return token;
}

const Login: Component<PageProps> = (props) => {
  const [username, setUsername] = createSignal(query("username"));
  const [password, setPassword] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");
  const continuation = () => safeNext(query("next")) || safeNext(window.location.pathname !== "/app/login" ? window.location.pathname : "");
  const submit = async (event: SubmitEvent) => {
    event.preventDefault(); setBusy(true); setError("");
    try {
      await api.session.loginPassword({ username: username(), password: password() });
      setPassword(""); await props.refreshSession();
      const requestedNext = query("next");
      const pathNext = window.location.pathname !== "/app/login" ? window.location.pathname : "";
      const next = requestedNext || pathNext;
      sessionStorage.removeItem("linkkeys-recovery-next");
      props.navigate(next.startsWith("/app/") ? next : "/app/account");
    } catch (cause) { setError(loginFailureMessage(cause)); }
    finally { setBusy(false); }
  };
  if (!props.configuration.capabilities.includes("password_login")) return <Unavailable title={t("app.login.unavailable_title")} detail={t("app.common.contact_support")} />;
  return <main class="wrap narrow"><section class="hero"><p class="eyebrow">{props.configuration.domain}</p><h1>{t("app.login.title")}</h1><p>{t("app.login.intro")}</p></section>
    <form id="login-form" name="login" class="card" onSubmit={submit}>
      <label><span>{t("app.login.username")}</span><input id="login-username" name="username" value={username()} onInput={(event) => setUsername(event.currentTarget.value)} autocomplete="username" autocapitalize="none" spellcheck={false} required autofocus /></label>
      <label><span>{t("app.login.password")}</span><input id="login-password" name="current-password" type="password" value={password()} onInput={(event) => setPassword(event.currentTarget.value)} autocomplete="current-password" required /></label>
      <button type="submit" disabled={busy()}>{busy() ? t("app.login.submitting") : t("app.login.submit")}</button>
      <Show when={props.configuration.capabilities.includes("reset_password")}><small><Link href={withLoginContext("/app/password/request", continuation(), username())}>{t("app.login.forgot")}</Link></small></Show>
      <Show when={error()}><p class="notice bad" role="alert">{error()}</p></Show>
    </form></main>;
};

const AuthorizeGateway: Component<PageProps> = (props) => {
  const [missing, setMissing] = createSignal(false);
  onMount(() => {
    const handoff = authorizationHandoff(window.location.search, window.location.hash, Boolean(props.session));
    if (!handoff) return setMissing(true);
    sessionStorage.setItem("linkkeys-authorization-request", handoff.signedRequest);
    window.history.replaceState({}, "", window.location.pathname);
    props.navigate(handoff.path);
  });
  return <Show when={!missing()} fallback={<Unavailable title={t("app.authorize.invalid_title")} detail={t("app.authorize.invalid_detail")} />}><Loading /></Show>;
};

/** One requested detail on a consent screen. */
const ConsentClaimRow: Component<{ claim: BrowserConsentClaim; selected: Record<string, boolean>; values: Record<string, string>; busy: boolean; onSelect(claimType: string, checked: boolean): void; onValue(claimType: string, value: string): void }> = (props) => <div class="consent-claim"><label class="checkbox-label"><input type="checkbox" checked={props.claim.policy === "forced_allow" || props.selected[props.claim.claimType]} disabled={props.claim.policy !== "user" || props.busy} required={props.claim.required && props.claim.policy === "user"} onChange={(event) => props.onSelect(props.claim.claimType, event.currentTarget.checked)} /><span>{props.claim.required ? t("app.consent.required_label", { label: props.claim.label }) : props.claim.label}</span><Show when={props.claim.newlyRequested}><span class="pill new">{t("app.consent.new_badge")}</span></Show></label><Show when={props.claim.policy === "forced_allow"}><small>{t("app.consent.forced_allow")}</small></Show><Show when={props.claim.required && props.claim.policy === "user" && !props.selected[props.claim.claimType]}><small>{t("app.consent.required_unselected")}</small></Show><Show when={!props.claim.available && props.claim.userSettable && (props.claim.policy === "forced_allow" || props.selected[props.claim.claimType])}><label><span>{t("app.consent.add_value", { label: props.claim.label })}</span><Show when={props.claim.datatype === "bool"} fallback={<input type={inputType(props.claim.datatype)} maxlength={props.claim.maxBytes} value={props.values[props.claim.claimType] ?? ""} onInput={(event) => props.onValue(props.claim.claimType, event.currentTarget.value)} required={props.claim.required} />}><select value={props.values[props.claim.claimType] ?? ""} onChange={(event) => props.onValue(props.claim.claimType, event.currentTarget.value)} required={props.claim.required}><option value="">{t("app.common.choose_value")}</option><option value="true">{t("app.common.yes")}</option><option value="false">{t("app.common.no")}</option></select></Show></label></Show><Show when={!props.claim.available && props.claim.requiresApproval}><small>{t("app.consent.needs_approval")}</small></Show><Show when={!props.claim.available && !props.claim.userSettable && !props.claim.requiresApproval}><small>{t("app.consent.not_in_profile")}</small></Show><Show when={props.claim.policy === "forced_deny"}><small>{t("app.consent.forced_deny")}</small></Show></div>;

const Consent: Component<PageProps> = (props) => {
  const signedRequest = sessionStorage.getItem("linkkeys-authorization-request") ?? "";
  const [context, setContext] = createSignal<Awaited<ReturnType<typeof api.browserAuthorization.inspect>>>();
  const [selected, setSelected] = createSignal<Record<string, boolean>>({});
  const [values, setValues] = createSignal<Record<string, string>>({});
  const [busy, setBusy] = createSignal(false); const [error, setError] = createSignal(""); const [needsLogin, setNeedsLogin] = createSignal(false); const [restartRequired, setRestartRequired] = createSignal(false);
  const blockedRequired = () => hasBlockedRequiredClaim(context()?.claims ?? []);
  const showConsent = (result: NonNullable<ReturnType<typeof context>>) => {
    setContext(result);
    setSelected(Object.fromEntries(result.claims.map((claim) => [claim.claimType, claim.defaultGranted])));
  };
  onMount(async () => {
    if (!signedRequest) return setError(t("app.consent.missing"));
    try {
      const result = await api.browserAuthorization.inspect({ signedRequest });
      const authorizedClaims = standingAuthorization(result);
      if (authorizedClaims) {
        try {
          const completion = await api.browserAuthorization.complete({ signedRequest, authorizedClaims, claimTypesToSet: [], claimValuesToSet: [], useStandingGrant: true });
          sessionStorage.removeItem("linkkeys-authorization-request");
          window.location.assign(completion.redirectUrl);
          return;
        } catch (cause) {
          if (authenticationFailed(cause)) { showConsent(result); setNeedsLogin(true); setError(t("app.consent.sign_in_again_message")); }
          else if (authorizationRequestIsTerminal(cause)) { showConsent(result); sessionStorage.removeItem("linkkeys-authorization-request"); setRestartRequired(true); setError(t("app.consent.request_terminal")); }
          else {
            let latest = result;
            try { latest = await api.browserAuthorization.inspect({ signedRequest }); } catch { /* Use the prior safe disclosure. */ }
            showConsent(latest);
            setError(t("app.consent.saved_approval_failed"));
          }
          return;
        }
      }
      showConsent(result);
    } catch (cause) {
      if (authenticationFailed(cause)) {
        setNeedsLogin(true);
        setError(t("app.consent.sign_in_again_message"));
      } else setError(t("app.consent.request_invalid"));
    }
  });
  const submit = async (event: SubmitEvent) => {
    event.preventDefault(); setBusy(true); setError("");
    const decision = consentDecision(context()?.claims ?? [], selected(), values());
    if (decision.oversized) { setBusy(false); return setError(t("app.claim.too_long", { label: decision.oversized.label, max: decision.oversized.maxBytes })); }
    try {
      const result = await api.browserAuthorization.complete({ signedRequest, authorizedClaims: decision.authorizedClaims, claimTypesToSet: decision.claimTypesToSet, claimValuesToSet: decision.claimValuesToSet });
      sessionStorage.removeItem("linkkeys-authorization-request");
      window.location.assign(result.redirectUrl);
    } catch (cause) {
      if (authenticationFailed(cause)) { setNeedsLogin(true); setError(t("app.consent.sign_in_again_message")); }
      else if (authorizationRequestIsTerminal(cause)) { sessionStorage.removeItem("linkkeys-authorization-request"); setRestartRequired(true); setError(t("app.consent.request_terminal")); }
      else setError(message(cause, t("app.consent.complete_failed")));
      setBusy(false);
    }
  };
  const cancel = () => { sessionStorage.removeItem("linkkeys-authorization-request"); props.navigate("/app/consent/cancelled"); };
  return <main class="wrap narrow"><section class="hero"><p class="eyebrow">{t("app.consent.eyebrow")}</p><h1>{context() ? (hasNewlyRequestedClaim(context()!.claims) ? t("app.consent.new_title", { app: context()!.relyingParty }) : t("app.consent.title")) : error() ? t("app.consent.stopped_title") : t("app.consent.checking_title")}</h1><Show when={context()}><p>{t("app.consent.intro", { app: context()!.relyingParty })}</p></Show></section><Show when={context()} fallback={<section class="card"><p role={error() ? "alert" : "status"}>{error() || t("app.consent.checking")}</p><Show when={needsLogin()}><Link href="/app/login?next=/app/consent">{t("app.consent.sign_in_again")}</Link></Show></section>}>
    <form class="card" aria-busy={busy()} onSubmit={submit}><Show when={hasNewlyRequestedClaim(context()!.claims)}><p class="notice">{t("app.consent.new_notice")}</p></Show><Show when={context()!.requestReason}><p class="notice">{context()!.requestReason}</p></Show><Show when={context()!.claims.length} fallback={<p>{t("app.consent.no_claims")}</p>}><For each={context()!.claims}>{(claim) => <ConsentClaimRow claim={claim} selected={selected()} values={values()} busy={busy()} onSelect={(claimType, checked) => setSelected((current) => ({ ...current, [claimType]: checked }))} onValue={(claimType, value) => setValues((current) => ({ ...current, [claimType]: value }))} />}</For></Show><div class="button-row"><button type="submit" disabled={busy() || blockedRequired() || restartRequired()}>{busy() ? t("app.consent.continuing") : t("app.consent.continue")}</button><button class="text-button" type="button" disabled={busy()} onClick={cancel}>{t("app.common.cancel")}</button></div><Show when={error()}><p class="notice bad" role="alert">{error()}</p></Show><Show when={needsLogin()}><Link href="/app/login?next=/app/consent">{t("app.consent.sign_in_again")}</Link></Show></form>
  </Show></main>;
};



const localRpRequestKey = "linkkeys-local-rp-request";

const LocalRpGateway: Component<PageProps> = (props) => {
  onMount(() => {
    const signedRequest = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("request");
    if (!signedRequest) return props.navigate("/app/error?reason=missing");
    sessionStorage.setItem(localRpRequestKey, signedRequest);
    const username = query("username");
    window.history.replaceState({}, "", window.location.pathname);
    props.navigate(props.session ? "/app/local-rp/consent" : withLoginContext("/app/login", "/app/local-rp/consent", username));
  });
  return <Loading />;
};

const LocalRpConsent: Component<PageProps> = (props) => {
  const signedRequest = sessionStorage.getItem(localRpRequestKey) ?? "";
  const [context, setContext] = createSignal<BrowserLocalRpInspectResponse>();
  const [selected, setSelected] = createSignal<Record<string, boolean>>({});
  const [values, setValues] = createSignal<Record<string, string>>({});
  const [busy, setBusy] = createSignal(false); const [error, setError] = createSignal("");
  const finish = (redirectUrl: string) => { sessionStorage.removeItem(localRpRequestKey); window.location.assign(redirectUrl); };
  onMount(async () => {
    if (!signedRequest) return setError(t("app.local_rp.missing"));
    try {
      const result = await api.browserAuthorization.inspectLocalRp({ signedRequest });
      if (result.admission === "consent" && result.alreadyConsented && result.authorizedClaims) {
        try { return finish((await api.browserAuthorization.completeLocalRp({ signedRequest, authorizedClaims: result.authorizedClaims, claimTypesToSet: [], claimValuesToSet: [], useStandingGrant: true })).redirectUrl); }
        catch { /* Fall back to the consent screen. */ }
      }
      setContext(result);
      setSelected(Object.fromEntries(result.claims.map((claim) => [claim.claimType, claim.defaultGranted])));
    } catch (cause) {
      if (authenticationFailed(cause) && !/^[a-z_]+$/.test((cause as Error).message)) return props.navigate("/app/login?next=/app/local-rp/consent");
      setError(localRpFailureMessage(cause));
    }
  });
  const submit = async (event: SubmitEvent) => {
    event.preventDefault(); setBusy(true); setError("");
    const decision = consentDecision(context()?.claims ?? [], selected(), values());
    if (decision.oversized) { setBusy(false); return setError(t("app.claim.too_long", { label: decision.oversized.label, max: decision.oversized.maxBytes })); }
    try { finish((await api.browserAuthorization.completeLocalRp({ signedRequest, authorizedClaims: decision.authorizedClaims, claimTypesToSet: decision.claimTypesToSet, claimValuesToSet: decision.claimValuesToSet })).redirectUrl); }
    catch (cause) { setError(localRpFailureMessage(cause)); setBusy(false); }
  };
  const cancel = () => { sessionStorage.removeItem(localRpRequestKey); props.navigate("/app/local-rp/cancelled"); };
  const pending = () => context()?.admission === "pending";
  const title = () => pending() ? t("app.local_rp.pending_title") : context() ? (hasNewlyRequestedClaim(context()!.claims) ? t("app.consent.new_title", { app: context()!.appName }) : t("app.consent.title")) : error() ? t("app.consent.stopped_title") : t("app.consent.checking_title");
  return <main class="wrap narrow"><section class="hero"><p class="eyebrow">{t("app.local_rp.eyebrow")}</p><h1>{title()}</h1><Show when={context() && !pending()}><p>{t("app.local_rp.intro", { app: context()!.appName })}</p></Show></section>
    <Show when={context()} fallback={<section class="card"><p role={error() ? "alert" : "status"}>{error() || t("app.consent.checking")}</p></section>}>
      <Show when={!pending()} fallback={<section class="card"><p>{t("app.local_rp.pending_body", { app: context()!.appName })}</p><Link href="/app/account">{t("app.common.return_to_account")}</Link></section>}>
        <form class="card" aria-busy={busy()} onSubmit={submit}>
          <div class="notice"><p><strong>{t("app.local_rp.unverified", { app: context()!.appName })}</strong></p><p>{t("app.local_rp.warning")}</p><p>{format<JSX.Element>("app.local_rp.callback_host", { host: <code>{context()!.callbackHost}</code> })}</p><p><small>{format<JSX.Element>("app.local_rp.fingerprint", { fingerprint: <code title={context()!.fingerprint}>{context()!.fingerprint.slice(0, 16)}</code> })}</small></p><Show when={context()!.firstSeenAt}><p><small>{t("app.local_rp.first_seen", { date: new Date(context()!.firstSeenAt!).toLocaleString() })}</small></p></Show></div>
          <Show when={hasNewlyRequestedClaim(context()!.claims)}><p class="notice">{t("app.consent.new_notice")}</p></Show>
          <Show when={context()!.requestReason}><p class="notice">{context()!.requestReason}</p></Show>
          <Show when={context()!.claims.length} fallback={<p>{t("app.consent.no_claims")}</p>}><For each={context()!.claims}>{(claim) => <ConsentClaimRow claim={claim} selected={selected()} values={values()} busy={busy()} onSelect={(claimType, checked) => setSelected((current) => ({ ...current, [claimType]: checked }))} onValue={(claimType, value) => setValues((current) => ({ ...current, [claimType]: value }))} />}</For></Show>
          <div class="button-row"><button type="submit" disabled={busy() || hasBlockedRequiredClaim(context()!.claims)}>{busy() ? t("app.consent.continuing") : t("app.consent.continue")}</button><button class="text-button" type="button" disabled={busy()} onClick={cancel}>{t("app.common.cancel")}</button></div>
          <Show when={error()}><p class="notice bad" role="alert">{error()}</p></Show>
        </form>
      </Show>
    </Show></main>;
};

const ActAsGateway: Component<PageProps> = (props) => {
  const [missing, setMissing] = createSignal(false);
  onMount(() => {
    const handoff = actAsHandoff(window.location.hash, Boolean(props.session));
    if (!handoff) return setMissing(true);
    sessionStorage.setItem(actAsRequestKey, handoff.signedRequest);
    window.history.replaceState({}, "", window.location.pathname);
    props.navigate(handoff.path);
  });
  return <Show when={!missing()} fallback={<Unavailable title={t("app.act_as.link_invalid_title")} detail={t("app.act_as.link_invalid_detail")} />}><Loading /></Show>;
};

const ActAsPartyCard: Component<{ role: string; party: BrowserActAsParty }> = (props) => (
  <div class="consent-claim"><p class="eyebrow">{props.role}</p><p><strong>{partyTitle(props.party)}</strong></p>
    <ul><For each={partyTrustNotes(props.party)}>{(note) => <li>{note}</li>}</For></ul>
    <dl>
      <Show when={props.party.applicationId}><dt>{t("app.party.field.application")}</dt><dd>{props.party.applicationId}</dd></Show>
      <Show when={props.party.handle}><dt>{t("app.party.field.handle")}</dt><dd>{props.party.handle}</dd></Show>
      <Show when={props.party.domain && props.party.localRpName}><dt>{t("app.party.field.name")}</dt><dd>{props.party.localRpName}</dd></Show>
      <Show when={props.party.subjectUserId}><dt>{t("app.party.field.account_id")}</dt><dd><code>{props.party.subjectUserId}</code></dd></Show>
      <Show when={props.party.localRpFingerprint}><dt>{t("app.party.field.fingerprint")}</dt><dd><code>{props.party.localRpFingerprint}</code></dd></Show>
    </dl></div>
);

const ActAsConsent: Component<PageProps> = (props) => {
  const signedRequest = sessionStorage.getItem(actAsRequestKey) ?? "";
  const [context, setContext] = createSignal<BrowserActAsInspectResponse>();
  const [selected, setSelected] = createSignal<Record<string, boolean>>({});
  const [lifetime, setLifetime] = createSignal(0);
  const [renewal, setRenewal] = createSignal(0);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");
  const approved = () => (context()?.entries ?? []).filter((entry) => !entry.removedByPolicy && selected()[entry.scope]).map((entry) => entry.scope);
  onMount(async () => {
    if (!signedRequest) return setError(t("app.act_as.missing"));
    try {
      const result = await api.browserAuthorization.inspectActAs({ signedRequest });
      setContext(result);
      setSelected(Object.fromEntries(result.entries.map((entry) => [entry.scope, !entry.removedByPolicy])));
      setLifetime(result.defaultLifetimeSeconds);
      setRenewal(result.defaultRenewalWindowSeconds);
    } catch (cause) {
      if (authenticationFailed(cause)) return props.navigate("/app/login?next=/app/act-as/consent");
      sessionStorage.removeItem(actAsRequestKey);
      setError(cause instanceof Error && cause.message ? t("app.act_as.inspect_failed_detail", { detail: cause.message }) : t("app.act_as.inspect_failed"));
    }
  });
  const submit = async (event: SubmitEvent) => {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const result = await api.browserAuthorization.completeActAs({ signedRequest, approvedScope: approved(), lifetimeSeconds: lifetime(), renewalWindowSeconds: renewal() });
      sessionStorage.removeItem(actAsRequestKey);
      window.location.assign(result.redirectUrl);
    } catch (cause) {
      if (authenticationFailed(cause)) return props.navigate("/app/login?next=/app/act-as/consent");
      setError(cause instanceof Error && cause.message ? cause.message : t("app.act_as.complete_failed"));
    } finally { setBusy(false); }
  };
  const cancel = () => { sessionStorage.removeItem(actAsRequestKey); props.navigate("/app/act-as/cancelled"); };
  return <main class="wrap narrow"><section class="hero"><p class="eyebrow">{t("app.act_as.eyebrow")}</p><h1>{t("app.act_as.title")}</h1>
    <Show when={context()}><p>{format<JSX.Element>("app.act_as.intro", { grantee: <strong>{partyHeadline(context()!.granteeParty)}</strong>, audience: <strong>{partyHeadline(context()!.audienceParty)}</strong> })}</p></Show></section>
    <Show when={context()} fallback={<section class="card"><p role={error() ? "alert" : "status"}>{error() || t("app.act_as.checking")}</p></section>}>
      <form class="card" aria-busy={busy()} onSubmit={submit}>
        <ActAsPartyCard role={t("app.act_as.role_grantee")} party={context()!.granteeParty} />
        <ActAsPartyCard role={t("app.act_as.role_audience")} party={context()!.audienceParty} />
        <p class="notice">{t("app.act_as.scope_notice", { audience: partyHeadline(context()!.audienceParty) })}</p>
        <For each={context()!.entries}>{(entry) => <div class="consent-claim"><label class="checkbox-label"><input type="checkbox" checked={!entry.removedByPolicy && selected()[entry.scope]} disabled={entry.removedByPolicy || busy()} onChange={(event) => setSelected((current) => ({ ...current, [entry.scope]: event.currentTarget.checked }))} /><span>{entry.description ?? entry.scope}</span></label><Show when={entry.description}><small><code>{entry.scope}</code></small></Show><Show when={entry.removedByPolicy}><small>{t("app.act_as.removed_by_policy")}</small></Show></div>}</For>
        <label><span>{t("app.act_as.lifetime")}</span><select value={String(lifetime())} disabled={busy()} onChange={(event) => setLifetime(Number(event.currentTarget.value))}><For each={durationChoices(context()!.defaultLifetimeSeconds, context()!.maxLifetimeSeconds, false)}>{(value) => <option value={String(value)}>{describeDuration(value)}</option>}</For></select></label>
        <Show when={context()!.maxRenewalWindowSeconds > 0}><label><span>{t("app.act_as.renewal")}</span><select value={String(renewal())} disabled={busy()} onChange={(event) => setRenewal(Number(event.currentTarget.value))}><For each={durationChoices(context()!.defaultRenewalWindowSeconds, context()!.maxRenewalWindowSeconds, true)}>{(value) => <option value={String(value)}>{describeDuration(value)}</option>}</For></select></label></Show>
        <p class="muted">{t("app.act_as.stop_hint")}</p>
        <div class="button-row"><button type="submit" disabled={busy() || approved().length === 0}>{busy() ? t("app.act_as.submitting") : t("app.act_as.allow")}</button><button class="text-button" type="button" disabled={busy()} onClick={cancel}>{t("app.common.cancel")}</button></div>
        <Show when={approved().length === 0}><small>{t("app.act_as.select_one")}</small></Show>
        <Show when={error()}><p class="notice bad" role="alert">{error()}</p></Show>
      </form>
    </Show></main>;
};

const ActAsGrantList: Component<PageProps> = (props) => {
  const [grants, setGrants] = createSignal<ActAsGrantSummary[]>([]);
  const [error, setError] = createSignal("");
  const [busy, setBusy] = createSignal("");
  const load = async () => {
    try { setGrants((await api.account.listActAsGrants({})).grants); }
    catch (cause) { if (authenticationFailed(cause)) props.navigate("/app/login"); else setError(t("app.act_as_list.load_failed")); }
  };
  onMount(load);
  const revoke = async (grantId: string) => {
    setBusy(grantId); setError("");
    try { await api.account.revokeActAsGrant({ grantId }); await load(); }
    catch { setError(t("app.act_as_list.stop_failed")); }
    finally { setBusy(""); }
  };
  const active = () => grants().filter((grant) => actAsGrantState(grant, new Date()) === "active");
  return <section class="card"><h2>{t("app.act_as_list.title")}</h2>
    <Show when={active().length} fallback={<p class="muted">{t("app.act_as_list.empty")}</p>}>
      <ul><For each={active()}>{(grant) => <li>{format<JSX.Element>("app.act_as_list.item", { grantee: <strong>{applicationLabel(grant.grantee.application, t("app.act_as_list.local_application"))}</strong>, audience: applicationLabel(grant.audience), scopes: grant.approvedScope.join(", ") })} <small>{grant.renewableUntil !== grant.expiresAt ? t("app.act_as_list.until_renewable", { until: new Date(grant.expiresAt).toLocaleString(), renewable: new Date(grant.renewableUntil).toLocaleString() }) : t("app.act_as_list.until", { until: new Date(grant.expiresAt).toLocaleString() })}</small> <button class="text-button" type="button" disabled={busy() === grant.grantId} onClick={() => revoke(grant.grantId)}>{busy() === grant.grantId ? t("app.act_as_list.stopping") : t("app.act_as_list.stop")}</button></li>}</For></ul>
    </Show>
    <Show when={error()}><p class="notice bad" role="alert">{error()}</p></Show>
  </section>;
};

const DetailChoices: Component<PageProps> = (props) => {
  const [policies, setPolicies] = createSignal<SettableClaimPolicy[]>([]);
  const [settings, setSettings] = createSignal<MyClaimSetting[]>([]);
  const [status, setStatus] = createSignal("");
  const [error, setError] = createSignal("");
  const [busy, setBusy] = createSignal("");
  const load = async () => {
    try {
      const [available, mine] = await Promise.all([api.account.listSettablePolicies({}), api.account.getMyClaimSettings({})]);
      setPolicies(available.policies.filter((policy) => policy.signingRule !== "verified")); setSettings(mine.settings);
    } catch (cause) { if (authenticationFailed(cause)) props.navigate("/app/login"); else setError(t("app.choices.load_failed")); }
  };
  onMount(load);
  const setting = (claimType: string) => settings().find((entry) => entry.claimType === claimType);
  const change = async (claimType: string, save: () => Promise<unknown>) => {
    setBusy(claimType); setStatus(""); setError("");
    try { await save(); await load(); setStatus(t("app.choices.saved")); }
    catch (cause) { setError(message(cause, t("app.choices.save_failed"))); await load(); }
    finally { setBusy(""); }
  };
  return <Show when={policies().length}><section class="card"><h2>{t("app.choices.title")}</h2><p>{t("app.choices.intro")}</p>
    <For each={policies()}>{(policy) => <fieldset class="consent-claim" disabled={busy() === policy.claimType}><legend>{policy.label}</legend>
      <label class="checkbox-label"><input type="checkbox" checked={setting(policy.claimType)?.sharedWithEveryApp ?? false} onChange={(event) => { const share = event.currentTarget.checked; void change(policy.claimType, () => api.account.setMyClaimSharing({ claimType: policy.claimType, share })); }} /><span>{t("app.choices.share_every_app")}</span></label>
      <Show when={policy.signingRule === "self_signed"}><label class="checkbox-label"><input type="checkbox" checked={setting(policy.claimType)?.keepVerified ?? false} onChange={(event) => { const keepVerified = event.currentTarget.checked; void change(policy.claimType, () => api.account.setMyClaimKeepVerified({ claimType: policy.claimType, keepVerified })); }} /><span>{t("app.choices.keep_verified", { domain: props.configuration.domain })}</span></label></Show>
    </fieldset>}</For>
    <Show when={status()}><p class="notice good" role="status">{status()}</p></Show><Show when={error()}><p class="notice bad" role="alert">{error()}</p></Show>
  </section></Show>;
};

const ProfileList: Component<PageProps> = (props) => {
  const [profiles, setProfiles] = createSignal<Profile[]>([]);
  const [maxProfiles, setMaxProfiles] = createSignal(1);
  const [label, setLabel] = createSignal("");
  const [status, setStatus] = createSignal("");
  const [error, setError] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const load = async () => {
    try { const mine = await api.account.getMyClaimSettings({}); setProfiles(mine.profiles); setMaxProfiles(mine.maxProfiles); }
    catch (cause) { if (authenticationFailed(cause)) props.navigate("/app/login"); else setError(t("app.profiles.load_failed")); }
  };
  onMount(load);
  const create = async (event: SubmitEvent) => {
    event.preventDefault(); setBusy(true); setStatus(""); setError("");
    try { await api.account.createProfile({ label: label().trim() || undefined }); setLabel(""); await load(); setStatus(t("app.profiles.created")); }
    catch (cause) { setError(message(cause, t("app.profiles.create_failed"))); }
    finally { setBusy(false); }
  };
  return <Show when={maxProfiles() > 1}><section class="card"><h2>{t("app.profiles.title")}</h2><p>{t("app.profiles.intro")}</p>
    <ul><For each={profiles()}>{(profile) => <li>{profile.label ?? t("app.profiles.unnamed")} <small><code>{profile.id}@{profile.domain}</code></small></li>}</For></ul>
    <Show when={profiles().length < maxProfiles()} fallback={<p class="muted">{t("app.profiles.limit_reached", { count: maxProfiles() })}</p>}>
      <form class="inline-form" aria-busy={busy()} onSubmit={create}><label><span>{t("app.profiles.label")}</span><input type="text" name="profile-label" value={label()} onInput={(event) => setLabel(event.currentTarget.value)} maxlength="64" autocomplete="off" /></label><button type="submit" disabled={busy()}>{t("app.profiles.create")}</button></form>
    </Show>
    <Show when={status()}><p class="notice good" role="status">{status()}</p></Show><Show when={error()}><p class="notice bad" role="alert">{error()}</p></Show>
  </section></Show>;
};

const ConfirmationRequest: Component<PageProps> = (props) => {
  const [site, setSite] = createSignal("");
  const [details, setDetails] = createSignal("");
  const [result, setResult] = createSignal<{ site: string; code: string; expiresAt: string }>();
  const [status, setStatus] = createSignal("");
  const [error, setError] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const create = async (event: SubmitEvent) => {
    event.preventDefault(); setStatus(""); setError(""); setResult(undefined);
    const issuerDomain = siteDomain(site());
    const requestedClaimTypes = confirmationDetails(details());
    if (!issuerDomain) return setError(t("app.confirm.site_invalid"));
    if (!requestedClaimTypes.length) return setError(t("app.confirm.details_missing"));
    setBusy(true);
    try {
      const { signedRequest } = await api.account.requestVerification({ issuerDomain, requestedClaimTypes });
      setResult({ site: issuerDomain, code: base64UrlUnpadded(toSignedSigningRequestCbor(signedRequest)), expiresAt: fromSigningRequestCbor(signedRequest.request).expiresAt });
    } catch (cause) {
      if (authenticationFailed(cause)) props.navigate("/app/login");
      else setError(message(cause, t("app.confirm.failed")));
    } finally { setBusy(false); }
  };
  const copy = async () => {
    setStatus(""); setError("");
    try { await navigator.clipboard.writeText(result()!.code); setStatus(t("app.confirm.copied")); }
    catch { setError(t("app.confirm.copy_failed")); }
  };
  return <section class="card"><h2>{t("app.confirm.title")}</h2><p id="confirmation-help">{t("app.confirm.intro")}</p>
    <form id="confirmation-request-form" name="confirmation-request" aria-busy={busy()} onSubmit={create}>
      <label><span>{t("app.confirm.site")}</span><input type="text" name="confirmation-site" value={site()} onInput={(event) => setSite(event.currentTarget.value)} placeholder={t("app.confirm.site_placeholder")} autocomplete="off" inputmode="url" required /></label>
      <label><span>{t("app.confirm.details")}</span><input type="text" name="confirmation-details" value={details()} onInput={(event) => setDetails(event.currentTarget.value)} autocomplete="off" required /><small>{t("app.confirm.details_hint")}</small></label>
      <button type="submit" disabled={busy()}>{t("app.confirm.submit")}</button>
    </form>
    <Show when={result()}>{(made) => <><p>{format<JSX.Element>("app.confirm.result", { site: <strong>{made().site}</strong>, until: new Date(made().expiresAt).toLocaleString() })}</p><textarea readonly rows="4" aria-label={t("app.confirm.code_label", { site: made().site })} value={made().code} onFocus={(event) => event.currentTarget.select()} /><button type="button" onClick={copy}>{t("app.confirm.copy")}</button></>}</Show>
    <Show when={status()}><p class="notice good" role="status">{status()}</p></Show><Show when={error()}><p class="notice bad" role="alert">{error()}</p></Show>
  </section>;
};

const Account: Component<PageProps> = (props) => {
  const [claims, setClaims] = createSignal<Claim[]>([]);
  const [contacts, setContacts] = createSignal<VerifiedContactMethod[]>([]);
  const [policies, setPolicies] = createSignal<SettableClaimPolicy[]>([]);
  const [email, setEmail] = createSignal("");
  const [contactPassword, setContactPassword] = createSignal("");
  const [claimType, setClaimType] = createSignal("");
  const [claimValue, setClaimValue] = createSignal("");
  const [oldPassword, setOldPassword] = createSignal("");
  const [newPassword, setNewPassword] = createSignal("");
  const [confirmation, setConfirmation] = createSignal("");
  const [status, setStatus] = createSignal("");
  const [error, setError] = createSignal("");
  const [feedbackArea, setFeedbackArea] = createSignal<"claims" | "contacts" | "password" | "">("");
  const [busy, setBusy] = createSignal(false);
  const [accountState, setAccountState] = createSignal<"loading" | "ready" | "failed">("loading");
  const selectedPolicy = () => policies().find((policy) => policy.claimType === claimType());
  const refresh = async () => {
    try {
      const [account, verified, available] = await Promise.all([api.account.getMyInfo({}), api.account.listVerifiedContactMethods({}), api.account.listSettablePolicies({})]);
      const settable = available.policies.filter((policy) => policy.signingRule !== "verified");
      setClaims(account.claims); setContacts(verified.contactMethods); setPolicies(settable);
      if (!settable.some((policy) => policy.claimType === claimType())) setClaimType(settable[0]?.claimType ?? "");
      setAccountState("ready");
    } catch (cause) {
      if (authenticationFailed(cause)) props.navigate("/app/login");
      else { setAccountState("failed"); setFeedbackArea(""); setError(t("app.account.load_failed")); }
    }
  };
  onMount(refresh);
  const requestContact = async (event: SubmitEvent) => {
    event.preventDefault(); setBusy(true); setFeedbackArea("contacts"); setStatus(""); setError("");
    try { await api.account.requestContactVerification({ channel: "email", destination: email(), currentPassword: contactPassword() }); setStatus(t("app.account.contact_sent")); setEmail(""); setContactPassword(""); }
    catch (cause) { setError(currentPasswordMessage(cause, t("app.account.contact_send_failed"))); }
    finally { setBusy(false); }
  };
  const setClaim = async (event: SubmitEvent) => {
    event.preventDefault(); setBusy(true); setFeedbackArea("claims"); setStatus(""); setError("");
    const policy = selectedPolicy();
    if (policy && claimValueTooLong(claimValue(), policy.maxBytes)) { setBusy(false); return setError(t("app.claim.too_long", { label: policy.label, max: policy.maxBytes })); }
    try {
      const result = await api.account.setMyClaim({ claimType: claimType(), claimValue: claimValue() });
      setClaimValue(""); await refresh();
      setStatus(result.outcome === "verification_required"
        ? t("app.account.claim_needs_verification")
        : result.outcome === "queued"
          ? t("app.account.claim_queued")
          : t("app.account.claim_saved"));
    } catch (cause) { setError(message(cause, t("app.account.claim_save_failed"))); }
    finally { setBusy(false); }
  };
  const removeContact = async (contact: VerifiedContactMethod) => {
    if (!contactPassword()) { setFeedbackArea("contacts"); setError(t("app.account.password_first")); return; }
    if (!window.confirm(t("app.account.contact_remove_confirm", { destination: contact.destination }))) return;
    setBusy(true); setFeedbackArea("contacts"); setStatus(""); setError("");
    try { await api.account.revokeVerifiedContactMethod({ contactMethodId: contact.id, currentPassword: contactPassword() }); setContactPassword(""); await refresh(); setStatus(t("app.account.contact_removed")); }
    catch (cause) { setError(currentPasswordMessage(cause, t("app.account.contact_remove_failed"))); }
    finally { setBusy(false); }
  };
  const removeClaim = async (claimId: string) => {
    if (!window.confirm(t("app.account.claim_remove_confirm"))) return;
    setBusy(true); setFeedbackArea("claims"); setStatus(""); setError("");
    try { await api.account.removeMyClaim({ claimId }); await refresh(); setStatus(t("app.account.claim_removed")); }
    catch (cause) { setError(message(cause, t("app.account.claim_remove_failed"))); }
    finally { setBusy(false); }
  };
  const changePassword = async (event: SubmitEvent) => {
    event.preventDefault(); setBusy(true); setFeedbackArea("password"); setStatus(""); setError("");
    if (newPassword() !== confirmation()) { setBusy(false); return setError(t("app.password.mismatch_new")); }
    const lengthError = checkPassword(newPassword(), props.configuration);
    if (lengthError) { setBusy(false); return setError(lengthError); }
    try { await api.account.changePassword({ currentPassword: oldPassword(), newPassword: newPassword() }); setOldPassword(""); setNewPassword(""); setConfirmation(""); await props.refreshSession(); props.navigate("/app/login"); }
    catch (cause) { setError(currentPasswordMessage(cause, t("app.account.password_change_failed"))); }
    finally { setBusy(false); }
  };
  return <main class="wrap"><section class="hero"><p class="eyebrow">{t("app.account.eyebrow")}</p><h1>{props.session?.user.displayName ?? t("app.account.fallback_title")}</h1><p><code>{props.session?.user.username}</code></p></section><Show when={accountState() === "ready"} fallback={<section class="card" aria-busy={accountState() === "loading"}><p role={accountState() === "failed" ? "alert" : "status"}>{accountState() === "failed" ? error() : t("app.account.loading")}</p><Show when={accountState() === "failed"}><button type="button" onClick={() => { setAccountState("loading"); setError(""); void refresh(); }}>{t("app.common.try_again")}</button></Show></section>}>
    <section class="card"><div class="section-heading"><div><h2>{t("app.account.details_title")}</h2><p>{t("app.account.details_intro")}</p></div></div>
      <Show when={claims().length} fallback={<p class="muted">{t("app.account.details_empty")}</p>}><div class="table-wrap"><table><thead><tr><th>{t("app.account.col_detail")}</th><th>{t("app.account.col_value")}</th><th>{t("app.account.col_confirmed")}</th><th>{t("app.account.col_action")}</th></tr></thead><tbody><For each={claims()}>{(claim) => <tr><td>{claimTypeLabel(claim.claimType)}</td><td>{claimText(claim)}</td><td>{claim.signatures.length ? t("app.account.confirmed_by", { domain: props.configuration.domain }) : t("app.account.not_confirmed")}</td><td><button class="text-button" type="button" disabled={busy()} aria-label={t("app.account.claim_remove_label", { label: claimTypeLabel(claim.claimType) })} onClick={() => removeClaim(claim.claimId)}>{t("app.common.remove")}</button></td></tr>}</For></tbody></table></div></Show>
      <Show when={policies().length}><form class="inline-form" aria-busy={busy()} onSubmit={setClaim}><label><span>{t("app.account.field_detail")}</span><select value={claimType()} onChange={(event) => { setClaimType(event.currentTarget.value); setClaimValue(""); }}><For each={policies()}>{(policy) => <option value={policy.claimType}>{policy.label}</option>}</For></select><Show when={selectedPolicy()?.description}><small>{selectedPolicy()?.description}</small></Show></label><label><span>{t("app.account.field_value")}</span><Show when={selectedPolicy()?.datatype === "bool"} fallback={<input type={inputType(selectedPolicy()?.datatype)} maxlength={selectedPolicy()?.maxBytes} value={claimValue()} onInput={(event) => setClaimValue(event.currentTarget.value)} required />}><select value={claimValue()} onChange={(event) => setClaimValue(event.currentTarget.value)} required><option value="">{t("app.common.choose_value")}</option><option value="true">{t("app.common.yes")}</option><option value="false">{t("app.common.no")}</option></select></Show></label><button type="submit" disabled={busy()}>{t("app.account.save_detail")}</button></form></Show>
      <Show when={feedbackArea() === "claims" && status()}><p class="notice good" role="status">{status()}</p></Show><Show when={feedbackArea() === "claims" && error()}><p class="notice bad" role="alert">{error()}</p></Show>
    </section>
    <section class="card"><h2>{t("app.account.contacts_title")}</h2><p>{t("app.account.contacts_intro")}</p>
      <form class="inline-form" aria-busy={busy()} onSubmit={requestContact}>
        <input class="visually-hidden" type="text" name="username" value={props.session?.user.username ?? ""} autocomplete="username" readonly />
        <Show when={contacts().length} fallback={<p class="muted">{t("app.account.contacts_empty")}</p>}><For each={contacts()}>{(contact) => <div class="row"><span>{contact.destination}</span><button class="text-button" type="button" disabled={busy()} aria-label={t("app.account.contact_remove_label", { destination: contact.destination })} onClick={() => removeContact(contact)}>{t("app.common.remove")}</button></div>}</For></Show>
        <Show when={props.configuration.capabilities.includes("verify_contact")} fallback={<p class="muted">{t("app.account.contacts_unavailable")}</p>}><label><span>{t("app.account.email")}</span><input type="email" name="email" value={email()} onInput={(event) => setEmail(event.currentTarget.value)} autocomplete="email" required /></label></Show>
        <Show when={contacts().length || props.configuration.capabilities.includes("verify_contact")}><label><span>{t("app.password.current")}</span><input type="password" name="current-password" value={contactPassword()} onInput={(event) => setContactPassword(event.currentTarget.value)} autocomplete="current-password" required /></label></Show>
        <Show when={props.configuration.capabilities.includes("verify_contact")}><button type="submit" disabled={busy()}>{t("app.account.verify_email")}</button></Show>
      </form>
      <Show when={feedbackArea() === "contacts" && status()}><p class="notice good" role="status">{status()}</p></Show><Show when={feedbackArea() === "contacts" && error()}><p class="notice bad" role="alert">{error()}</p></Show>
    </section>
    <DetailChoices {...props} />
    <ProfileList {...props} />
    <ActAsGrantList {...props} />
    <ConfirmationRequest {...props} />
    <Show when={props.configuration.capabilities.includes("password_login")}><section class="card"><h2>{t("app.account.password_title")}</h2><p id="change-password-rule">{passwordRule(props.configuration)} {t("app.account.password_signout_note")}</p><form id="change-password-form" name="change-password" aria-busy={busy()} onSubmit={changePassword}>
      <input class="visually-hidden" type="text" name="username" value={props.session?.user.username ?? ""} autocomplete="username" readonly />
      <label><span>{t("app.password.current")}</span><input type="password" name="current-password" value={oldPassword()} onInput={(event) => setOldPassword(event.currentTarget.value)} autocomplete="current-password" required /></label>
      <label><span>{t("app.password.new")}</span><input type="password" name="new-password" value={newPassword()} onInput={(event) => setNewPassword(event.currentTarget.value)} autocomplete="new-password" aria-describedby="change-password-rule" required /></label>
      <label><span>{t("app.password.confirm_new")}</span><input type="password" name="new-password-confirmation" value={confirmation()} onInput={(event) => setConfirmation(event.currentTarget.value)} autocomplete="new-password" required /></label>
      <button type="submit" disabled={busy()}>{t("app.account.password_submit")}</button></form>
      <Show when={feedbackArea() === "password" && error()}><p class="notice bad" role="alert">{error()}</p></Show>
    </section></Show>
    <Show when={feedbackArea() === "" && error()}><p class="notice bad" role="alert">{error()}</p></Show></Show>
  </main>;
};

const RequestPassword: Component<PageProps> = (props) => {
  const [identifier, setIdentifier] = createSignal(query("username")); const [sent, setSent] = createSignal(false); const [busy, setBusy] = createSignal(false); const [error, setError] = createSignal("");
  const continuation = safeNext(query("next"));
  const loginUsername = () => passwordManagerUsername(identifier(), props.configuration.domain);
  const submit = async (event: SubmitEvent) => { event.preventDefault(); setBusy(true); setError(""); try { sessionStorage.setItem("linkkeys-recovery-identifier", identifier()); if (continuation) sessionStorage.setItem("linkkeys-recovery-next", continuation); else sessionStorage.removeItem("linkkeys-recovery-next"); await api.recovery.requestPasswordRecovery({ identifier: identifier() }); setSent(true); } catch (cause) { setError(message(cause, t("app.recovery.request_failed"))); } finally { setBusy(false); } };
  if (!props.configuration.capabilities.includes("reset_password")) return <Unavailable title={t("app.recovery.unavailable_title")} detail={t("app.common.contact_support")} />;
  return <main class="wrap narrow"><section class="hero"><p class="eyebrow">{t("app.recovery.eyebrow")}</p><h1>{t("app.recovery.request_title")}</h1></section><Show when={!sent()} fallback={<section class="card good"><h2>{t("app.recovery.sent_title")}</h2><p>{t("app.recovery.sent_body")}</p><Link href={withLoginContext("/app/login", continuation, loginUsername())}>{t("app.recovery.return_to_sign_in")}</Link></section>}>
    <form class="card" aria-busy={busy()} onSubmit={submit}><p>{t("app.recovery.request_intro")}</p><label><span>{t("app.recovery.identifier")}</span><input value={identifier()} onInput={(event) => setIdentifier(event.currentTarget.value)} autocomplete="username" maxlength="320" required /><small>{t("app.recovery.identifier_hint", { domain: props.configuration.domain })}</small></label><button type="submit" disabled={busy()}>{busy() ? t("app.recovery.sending") : t("app.recovery.send")}</button><Show when={error()}><p class="notice bad" role="alert">{error()}</p></Show></form></Show></main>;
};

const ResetPassword: Component<PageProps> = (props) => {
  const token = takeFragmentToken("linkkeys-recovery-token"); const storedIdentifier = sessionStorage.getItem("linkkeys-recovery-identifier") ?? ""; const [username, setUsername] = createSignal(passwordManagerUsername(storedIdentifier, props.configuration.domain)); const [password, setPassword] = createSignal(""); const [confirmation, setConfirmation] = createSignal(""); const [valid, setValid] = createSignal(false); const [done, setDone] = createSignal(false); const [busy, setBusy] = createSignal(false); const [checking, setChecking] = createSignal(true); const [retryValidation, setRetryValidation] = createSignal(false); const [error, setError] = createSignal("");
  const continuation = safeNext(sessionStorage.getItem("linkkeys-recovery-next") ?? "");
  const validateToken = async () => { setChecking(true); setRetryValidation(false); setError(""); try { await api.recovery.validatePasswordRecovery({ token }); setValid(true); } catch (cause) { setError(recoveryValidationFailureMessage(cause)); setRetryValidation(transportFailed(cause)); } finally { setChecking(false); } };
  onMount(validateToken);
  const submit = async (event: SubmitEvent) => { event.preventDefault(); setBusy(true); setError(""); if (password() !== confirmation()) { setBusy(false); return setError(t("app.password.mismatch")); } const lengthError = checkPassword(password(), props.configuration); if (lengthError) { setBusy(false); return setError(lengthError); } try { await api.recovery.completePasswordRecovery({ token, newPassword: password() }); sessionStorage.removeItem("linkkeys-recovery-identifier"); sessionStorage.removeItem("linkkeys-recovery-token"); setPassword(""); setConfirmation(""); setDone(true); } catch (cause) { if (recoveryLinkExpired(cause)) { setValid(false); setRetryValidation(false); setError(t("app.recovery.link_invalid")); } else setError(recoveryCompletionFailureMessage(cause)); } finally { setBusy(false); } };
  return <main class="wrap narrow"><section class="hero"><p class="eyebrow">{t("app.recovery.eyebrow")}</p><h1>{t("app.recovery.reset_title")}</h1></section><Show when={!done()} fallback={<section class="card good"><h2>{t("app.recovery.done_title")}</h2><p>{t("app.recovery.done_body")}</p><Link href={withLoginContext("/app/login", continuation, username())}>{continuation ? t("app.recovery.sign_in_continue") : t("app.recovery.sign_in")}</Link></section>}>
    <Show when={valid()} fallback={<section class="card" aria-busy={checking()}><p role={error() ? "alert" : "status"}>{error() || t("app.recovery.checking")}</p><Show when={retryValidation()} fallback={<Show when={error()}><Link href={withLoginContext("/app/password/request", continuation, username())}>{t("app.recovery.request_new")}</Link></Show>}><button type="button" disabled={checking()} onClick={validateToken}>{t("app.common.try_again")}</button></Show></section>}><form id="reset-password-form" name="reset-password" class="card" aria-busy={busy()} onSubmit={submit}>
      <p id="reset-password-rule">{passwordRule(props.configuration)}</p>
      <label><span>{t("app.recovery.pm_username")}</span><input type="text" name="username" value={username()} onInput={(event) => setUsername(event.currentTarget.value)} autocomplete="username" autocapitalize="none" spellcheck={false} /><small>{t("app.recovery.pm_username_hint")}</small></label>
      <label><span>{t("app.password.new")}</span><input type="password" name="new-password" value={password()} onInput={(event) => setPassword(event.currentTarget.value)} autocomplete="new-password" aria-describedby="reset-password-rule" required /></label>
      <label><span>{t("app.password.confirm_new")}</span><input type="password" name="new-password-confirmation" value={confirmation()} onInput={(event) => setConfirmation(event.currentTarget.value)} autocomplete="new-password" required /></label>
      <button type="submit" disabled={busy()}>{busy() ? t("app.recovery.saving") : t("app.recovery.set_password")}</button><Show when={error()}><p class="notice bad" role="alert">{error()}</p></Show></form></Show></Show></main>;
};

const VerifyContact: Component<PageProps> = (props) => {
  const [done, setDone] = createSignal(false); const [checking, setChecking] = createSignal(true); const [connectionFailure, setConnectionFailure] = createSignal(false); const [error, setError] = createSignal("");
  const token = takeFragmentToken("linkkeys-contact-token");
  const verify = async () => { setChecking(true); setConnectionFailure(false); setError(""); try { await api.account.confirmContactVerification({ token }); sessionStorage.removeItem("linkkeys-contact-token"); setDone(true); } catch (cause) { setConnectionFailure(transportFailed(cause)); setError(verificationFailureMessage(cause)); } finally { setChecking(false); } };
  onMount(verify);
  return <main class="wrap narrow"><section class="hero"><p class="eyebrow">{t("app.verify_contact.eyebrow")}</p><h1>{t("app.verify_contact.title")}</h1></section><section class={`card ${done() ? "good" : ""}`} aria-busy={checking()}><Show when={done()} fallback={<><p role={error() ? "alert" : "status"}>{error() || t("app.verify_contact.checking")}</p><Show when={error()}><Show when={connectionFailure()} fallback={<p><Link href="/app/login?next=/app/verify/contact">{t("app.verify_contact.other_account")}</Link></p>}><button type="button" disabled={checking()} onClick={verify}>{t("app.common.try_again")}</button></Show></Show></>}><h2>{t("app.verify_contact.done_title")}</h2><p>{t("app.verify_contact.done_body")}</p><Link href="/app/account">{t("app.common.return_to_account")}</Link></Show></section></main>;
};

const VerifySignIn: Component<{ navigate(path: string): void }> = (props) => {
  onMount(() => {
    const token = new URLSearchParams(window.location.hash.slice(1)).get("token");
    if (token) sessionStorage.setItem("linkkeys-contact-token", token);
    window.history.replaceState({}, "", window.location.pathname);
    props.navigate("/app/login?next=/app/verify/contact");
  });
  return <Loading />;
};

const ExtensionPage: Component<{ route: ExtensionRoute; host: RuntimeHost; path: string; onFailure(): void }> = (props) => {
  let container!: HTMLDivElement; let cleanup: void | (() => void); let disposed = false; let accepted = false; const runCleanup = cleanupOnce(); const [loading, setLoading] = createSignal(true); const [error, setError] = createSignal(false);
  onMount(async () => {
    const renderPromise = Promise.resolve().then(() => props.route.render(container, { path: props.path, navigate: (path) => props.host.navigate(path), clients: props.host.clients, configuration: props.host.configuration, session: props.host.getSession() }));
    void renderPromise.then((lateCleanup) => { if (!accepted && (disposed || error())) runCleanup(lateCleanup); }).catch(() => undefined);
    try {
      cleanup = await Promise.race([renderPromise, new Promise<never>((_, reject) => setTimeout(() => reject(new Error("The extension page timed out.")), 5_000))]);
      accepted = true;
      if (disposed) runCleanup(cleanup);
    } catch (cause) { console.error(`The ${props.route.title} extension page failed.`, cause); props.onFailure(); setError(true); }
    finally { setLoading(false); }
  });
  onCleanup(() => { disposed = true; try { runCleanup(cleanup); } catch (cause) { console.error(`The ${props.route.title} extension cleanup failed.`, cause); } });
  return <main class="wrap wide"><section class="hero"><p class="eyebrow">{t("app.extension.eyebrow")}</p><h1>{props.route.title}</h1></section><Show when={!error()} fallback={<section class="card"><p role="alert">{t("app.extension.failed")}</p><button type="button" onClick={() => window.location.reload()}>{t("app.common.try_again")}</button></section>}><Show when={loading()}><section class="card" aria-busy="true"><p role="status">{t("app.extension.loading")}</p></section></Show><div ref={container} hidden={loading()} /></Show></main>;
};

const App: Component<{ configuration: GetUiConfigurationResponse }> = (props) => {
  const [path, setPath] = createSignal(window.location.pathname); const [session, setSession] = createSignal<BrowserSessionInfo>(); const [sessionLoaded, setSessionLoaded] = createSignal(false); const [sessionError, setSessionError] = createSignal(false); const [canAdmin, setCanAdmin] = createSignal(false); const [extensionFailures, setExtensionFailures] = createSignal<string[]>([]); const [extensionsLoaded, setExtensionsLoaded] = createSignal(false); const [logoutBusy, setLogoutBusy] = createSignal(false); const [logoutError, setLogoutError] = createSignal("");
  const showPath = (nextPath: string) => { setPath(nextPath); window.scrollTo(0, 0); window.requestAnimationFrame(() => { const heading = document.querySelector<HTMLElement>("main h1"); heading?.setAttribute("tabindex", "-1"); heading?.focus(); }); };
  const navigate = (target: string) => {
    setLogoutError("");
    const url = new URL(target, window.location.origin);
    if (url.origin !== window.location.origin) return;
    if (url.pathname !== "/app" && !url.pathname.startsWith("/app/")) {
      window.location.assign(url);
      return;
    }
    window.history.pushState({}, "", url);
    showPath(url.pathname);
  };
  const host = new RuntimeHost(api, props.configuration, navigate, session);
  const reactivateExtensions = async () => {
    setExtensionsLoaded(false);
    try { setExtensionFailures(await host.reactivateExtensions()); }
    finally { setExtensionsLoaded(true); }
  };
  const refreshSession = async () => {
    setSessionError(false);
    try {
      const current = (await api.session.getCurrent({})).session;
      const sessionChanged = extensionsLoaded() && sessionIdentity(session()) !== sessionIdentity(current);
      setSession(current);
      if (current) { try { const permission = await api.admin.checkPermission({ userId: current.user.id, relation: "admin", objectType: "domain", objectId: props.configuration.domain }); setCanAdmin(permission.allowed); } catch { setCanAdmin(false); } }
      else setCanAdmin(false);
      if (sessionChanged) await reactivateExtensions();
    } catch (cause) {
      if (authenticationFailed(cause)) {
        const sessionChanged = extensionsLoaded() && sessionIdentity(session()) !== sessionIdentity();
        setSession(undefined); setCanAdmin(false);
        if (sessionChanged) await reactivateExtensions();
      }
      else setSessionError(true);
    } finally { setSessionLoaded(true); }
  };
  const pop = () => { setLogoutError(""); showPath(window.location.pathname); };
  const click = (event: MouseEvent) => { const anchor = (event.target as Element).closest<HTMLAnchorElement>("a[data-linkkeys-nav]"); if (!anchor || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey) return; event.preventDefault(); navigate(anchor.href); };
  onMount(async () => { window.addEventListener("popstate", pop); document.addEventListener("click", click); await refreshSession(); try { setExtensionFailures(await loadExtensions(host)); } finally { setExtensionsLoaded(true); } });
  onCleanup(() => { window.removeEventListener("popstate", pop); document.removeEventListener("click", click); });
  const logout = async () => { setLogoutBusy(true); setLogoutError(""); try { await api.session.logout({}); setSession(undefined); setCanAdmin(false); navigate("/app/login"); await reactivateExtensions(); } catch { setLogoutError(t("app.nav.sign_out_failed")); } finally { setLogoutBusy(false); } };
  createEffect(() => { const label = path().split("/").filter(Boolean).at(-1) ?? "home"; document.title = `${pageTitle(label)} · ${props.configuration.display.siteName}`; });
  const page = () => { const current = path(); const common = { navigate, configuration: props.configuration, session: session(), refreshSession, extensionFailures: extensionFailures() };
    if (!sessionLoaded()) return <Loading />;
    if (sessionError()) return <main class="wrap narrow"><section class="card"><h1>{t("app.session.failed_title")}</h1><p>{t("app.session.failed_body")}</p><button type="button" onClick={refreshSession}>{t("app.common.try_again")}</button></section></main>;
    if (current === "/app" || current === "/app/") return session() ? <Account {...common} /> : <Login {...common} />;
    if (current === "/app/login") return <Login {...common} />;
    if (current === "/app/account" || current.startsWith("/app/account/")) return session() ? <Account {...common} /> : <Login {...common} />;
    if (current === "/app/password/request") return <RequestPassword {...common} />;
    if (current === "/app/password/reset") return <ResetPassword {...common} />;
    if (current === "/app/authorize") return <AuthorizeGateway {...common} />;
    if (current === "/app/consent") return session() ? <Consent {...common} /> : <Login {...common} />;
    if (current === "/app/consent/cancelled") return <Unavailable title={t("app.consent.cancelled_title")} detail={t("app.consent.cancelled_body")} destination="/app/account" />;
    if (current === "/app/local-rp") return <LocalRpGateway {...common} />;
    if (current === "/app/local-rp/consent") return session() ? <LocalRpConsent {...common} /> : <Login {...common} />;
    if (current === "/app/local-rp/cancelled") return <Unavailable title={t("app.local_rp.cancelled_title")} detail={t("app.local_rp.cancelled_body")} destination="/app/account" />;
    if (current === "/app/error") return <Unavailable title={t("app.error.title")} detail={reasonText(query("reason"))} destination="/app/account" />;
    if (current === "/app/act-as") return <ActAsGateway {...common} />;
    if (current === "/app/act-as/consent") return session() ? <ActAsConsent {...common} /> : <Login {...common} />;
    if (current === "/app/act-as/cancelled") return <Unavailable title={t("app.act_as.cancelled_title")} detail={t("app.act_as.cancelled_body")} destination="/app/account" />;
    if (current === "/app/verify/contact") return session() ? <VerifyContact {...common} /> : <VerifySignIn navigate={navigate} />;
    if (current === "/app/admin" || current.startsWith("/app/admin/")) return session() && canAdmin() ? <AdminArea {...common} path={current} /> : <Unavailable title={t("app.admin.unavailable_title")} detail={t("app.admin.unavailable_body")} destination="/app/account" />;
    if (!extensionsLoaded()) return <Loading />;
    const extension = host.route(current); if (extension) { const owner = host.routeOwner(current) ?? extension.title; return session() ? <ExtensionPage route={extension} host={host} path={current} onFailure={() => setExtensionFailures((values) => values.includes(owner) ? values : [...values, owner])} /> : <Login {...common} />; }
    return <Unavailable title={t("app.not_found.title")} detail={t("app.not_found.body")} destination="/app/account" />;
  };
  return <><a class="skip-link" href="#main-content">{t("app.nav.skip")}</a><header class="site-header"><Link href="/app"><Show when={props.configuration.theme?.logoUrl} fallback={<span class="brand-mark">LK</span>}><img class="brand-logo" src={props.configuration.theme?.logoUrl} alt="" /></Show><span>{props.configuration.display.siteName}</span></Link><nav><Show when={session()}><Link href="/app/account" current={path().startsWith("/app/account")}>{t("app.nav.account")}</Link><Show when={canAdmin()}><Link href="/app/admin" current={path().startsWith("/app/admin")}>{t("app.nav.admin")}</Link></Show><Show when={extensionsLoaded()}><For each={host.navigationItems()}>{(item) => <Link href={item.path} current={path().startsWith(item.path)}>{item.label}</Link>}</For></Show></Show><Show when={session()} fallback={<Link href="/app/login" current={path() === "/app/login"}>{t("app.nav.sign_in")}</Link>}><button class="text-button" disabled={logoutBusy()} onClick={logout}>{logoutBusy() ? t("app.nav.signing_out") : t("app.nav.sign_out")}</button></Show></nav></header>
    <Show when={logoutError()}><div class="global-banner"><p class="notice bad" role="alert">{logoutError()}</p></div></Show>
    <div id="main-content" tabindex="-1">{page()}</div><footer>LinkKeys · {props.configuration.domain}<Show when={props.configuration.display.supportUrl}> · <a href={props.configuration.display.supportUrl}>{t("app.nav.support")}</a></Show></footer></>;
};

/** The page title for the last path segment of a UI route. */
function pageTitle(segment: string): string {
  const key = `app.page_title.${segment}`;
  const title = t(key);
  return title === key ? claimTypeLabel(segment) : title;
}

/** Load the home domain's catalog for this browser's languages. The bundled
 * en-US catalog stays in use when this fails, so the UI still starts. */
async function loadCatalog(): Promise<void> {
  try { useCatalog(await api.i18n.getTranslations({ locale: query("lang") || undefined, acceptLanguage: navigator.languages.join(",") })); }
  catch (error) { console.warn("The LinkKeys message catalog could not load. Using en-US.", error); }
}

async function start(): Promise<void> {
  try {
    const [configuration] = await Promise.all([api.ui.getConfiguration({}), loadCatalog()]);
    document.title = configuration.display.siteName;
    if (configuration.theme?.stylesheetUrl) addStylesheet(configuration.theme.stylesheetUrl, "operator-theme");
    if (configuration.theme?.faviconUrl) { const favicon = document.createElement("link"); favicon.rel = "icon"; favicon.href = configuration.theme.faviconUrl; document.head.append(favicon); }
    render(() => <App configuration={configuration} />, document.getElementById("root")!);
  } catch (error) {
    console.error("The LinkKeys UI could not start.", error);
    const main = document.createElement("main"); main.className = "wrap narrow";
    const card = document.createElement("section"); card.className = "card";
    const title = document.createElement("h1"); title.textContent = t("app.start.failed_title");
    const detail = document.createElement("p"); detail.textContent = t("app.start.failed_body");
    card.append(title, detail); main.append(card);
    document.getElementById("root")!.replaceChildren(main);
  }
}

void start();
