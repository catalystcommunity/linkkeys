import { For, Show, createEffect, createSignal, onCleanup, onMount, type Component, type JSX } from "solid-js";
import { render } from "solid-js/web";
import "./styles.css";
import { api } from "./transport";
import { RuntimeHost, addStylesheet, loadExtensions, type ExtensionRoute } from "./host";
import type { BrowserSessionInfo, Claim, GetUiConfigurationResponse, SettableClaimPolicy, VerifiedContactMethod } from "./generated/types.gen";
import { authenticationFailed, authorizationRequestIsTerminal, claimValueTooLong, cleanupOnce, currentPasswordMessage, hasBlockedRequiredClaim, inputType, loginFailureMessage, passwordLengthError, passwordManagerUsername, recoveryCompletionFailureMessage, recoveryLinkExpired, recoveryValidationFailureMessage, serviceMessage as message, transportFailed, verificationFailureMessage } from "./ui-logic";

type PageProps = { navigate(path: string): void; configuration: GetUiConfigurationResponse; session?: BrowserSessionInfo; refreshSession(): Promise<void>; extensionFailures?: string[] };

function query(name: string): string { return new URLSearchParams(window.location.search).get(name) ?? ""; }

function safeNext(value: string): string { return value.startsWith("/app/") ? value : ""; }
function withNext(path: string, next: string): string { return next ? `${path}?next=${encodeURIComponent(next)}` : path; }

function takeFragmentToken(storageKey?: string): string {
  const fragmentToken = new URLSearchParams(window.location.hash.slice(1)).get("token");
  if (fragmentToken && storageKey) sessionStorage.setItem(storageKey, fragmentToken);
  const token = fragmentToken ?? (storageKey ? sessionStorage.getItem(storageKey) ?? "" : "");
  if (window.location.hash) window.history.replaceState({}, "", window.location.pathname + window.location.search);
  return token;
}

function passwordRule(configuration: GetUiConfigurationResponse): string {
  const policy = configuration.passwordPolicy;
  return policy ? `Use at least ${policy.minLength} characters.` : "Use at least 8 characters.";
}

function checkPassword(value: string, configuration: GetUiConfigurationResponse): string {
  return passwordLengthError(value, configuration.passwordPolicy?.minLength ?? 8, configuration.passwordPolicy?.maxLength ?? 1024);
}

function claimLabel(value: string): string {
  return value.split("_").map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(" ");
}

const Link: Component<{ href: string; current?: boolean; children: JSX.Element }> = (props) => (
  <a href={props.href} data-linkkeys-nav aria-current={props.current ? "page" : undefined}>{props.children}</a>
);

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
  if (!props.configuration.capabilities.includes("password_login")) return <Unavailable title="Password sign-in is not available" detail="Contact this site's support team for help." />;
  return <main class="wrap narrow"><section class="hero"><p class="eyebrow">{props.configuration.domain}</p><h1>Sign in</h1><p>Use your LinkKeys account to continue.</p></section>
    <form id="login-form" name="login" class="card" onSubmit={submit}>
      <label><span>Username</span><input id="login-username" name="username" value={username()} onInput={(event) => setUsername(event.currentTarget.value)} autocomplete="username" autocapitalize="none" spellcheck={false} required autofocus /></label>
      <label><span>Password</span><input id="login-password" name="current-password" type="password" value={password()} onInput={(event) => setPassword(event.currentTarget.value)} autocomplete="current-password" required /></label>
      <button type="submit" disabled={busy()}>{busy() ? "Signing in…" : "Sign in"}</button>
      <Show when={props.configuration.capabilities.includes("reset_password")}><small><Link href={withNext("/app/password/request", continuation())}>Forgot your password?</Link></small></Show>
      <Show when={error()}><p class="notice bad" role="alert">{error()}</p></Show>
    </form></main>;
};

const AuthorizeGateway: Component<PageProps> = (props) => {
  const [missing, setMissing] = createSignal(false);
  onMount(() => {
    const signedRequest = new URLSearchParams(window.location.hash.slice(1)).get("request");
    if (!signedRequest) return setMissing(true);
    sessionStorage.setItem("linkkeys-authorization-request", signedRequest);
    window.history.replaceState({}, "", window.location.pathname);
    props.navigate(props.session ? "/app/consent" : "/app/login?next=/app/consent");
  });
  return <Show when={!missing()} fallback={<Unavailable title="Application sign-in link is invalid" detail="Return to the application and start sign-in again." />}><Loading /></Show>;
};

const Consent: Component<PageProps> = (props) => {
  const signedRequest = sessionStorage.getItem("linkkeys-authorization-request") ?? "";
  const [context, setContext] = createSignal<Awaited<ReturnType<typeof api.browserAuthorization.inspect>>>();
  const [selected, setSelected] = createSignal<Record<string, boolean>>({});
  const [values, setValues] = createSignal<Record<string, string>>({});
  const [busy, setBusy] = createSignal(false); const [error, setError] = createSignal(""); const [needsLogin, setNeedsLogin] = createSignal(false); const [restartRequired, setRestartRequired] = createSignal(false);
  const blockedRequired = () => hasBlockedRequiredClaim(context()?.claims ?? []);
  onMount(async () => {
    if (!signedRequest) return setError("This sign-in request is missing. Start again from the application.");
    try {
      const result = await api.browserAuthorization.inspect({ signedRequest });
      setContext(result);
      setSelected(Object.fromEntries(result.claims.map((claim) => [claim.claimType, claim.defaultGranted])));
    } catch (cause) {
      if (authenticationFailed(cause)) {
        setNeedsLogin(true);
        setError("Sign in again to continue this application sign-in.");
      } else setError("This sign-in request is invalid or expired. Start again from the application.");
    }
  });
  const submit = async (event: SubmitEvent) => {
    event.preventDefault(); setBusy(true); setError("");
    const claims = context()?.claims ?? [];
    const authorizedClaims = claims.filter((claim) => claim.policy === "forced_allow" || (claim.policy === "user" && selected()[claim.claimType])).map((claim) => claim.claimType);
    const entries = claims.filter((claim) => authorizedClaims.includes(claim.claimType) && !claim.available && values()[claim.claimType]?.trim());
    const oversized = entries.find((claim) => claimValueTooLong(values()[claim.claimType].trim(), claim.maxBytes));
    if (oversized) { setBusy(false); return setError(`${oversized.label} is too long. Use at most ${oversized.maxBytes} bytes.`); }
    try {
      const result = await api.browserAuthorization.complete({ signedRequest, authorizedClaims, claimTypesToSet: entries.map((claim) => claim.claimType), claimValuesToSet: entries.map((claim) => values()[claim.claimType].trim()) });
      sessionStorage.removeItem("linkkeys-authorization-request");
      window.location.assign(result.redirectUrl);
    } catch (cause) {
      if (authenticationFailed(cause)) { setNeedsLogin(true); setError("Sign in again to continue this application sign-in."); }
      else if (authorizationRequestIsTerminal(cause)) { sessionStorage.removeItem("linkkeys-authorization-request"); setRestartRequired(true); setError("This sign-in request is invalid or expired. Return to the application and start sign-in again."); }
      else setError(message(cause, "Could not finish sign-in. Review your choices and try again."));
      setBusy(false);
    }
  };
  const cancel = () => { sessionStorage.removeItem("linkkeys-authorization-request"); props.navigate("/app/consent/cancelled"); };
  return <main class="wrap narrow"><section class="hero"><p class="eyebrow">Application sign-in</p><h1>Choose what to share</h1><Show when={context()}><p>{context()!.relyingParty} requests information from your profile.</p></Show></section><Show when={context()} fallback={<section class="card"><p role={error() ? "alert" : "status"}>{error() || "Checking the sign-in request…"}</p><Show when={needsLogin()}><Link href="/app/login?next=/app/consent">Sign in again</Link></Show></section>}>
    <form class="card" aria-busy={busy()} onSubmit={submit}><Show when={context()!.requestReason}><p class="notice">{context()!.requestReason}</p></Show><Show when={context()!.claims.length} fallback={<p>This application does not request profile details.</p>}><For each={context()!.claims}>{(claim) => <div class="consent-claim"><label class="checkbox-label"><input type="checkbox" checked={claim.policy === "forced_allow" || selected()[claim.claimType]} disabled={claim.policy !== "user" || busy()} required={claim.required && claim.policy === "user"} onChange={(event) => setSelected((current) => ({ ...current, [claim.claimType]: event.currentTarget.checked }))} /><span>{claim.label}{claim.required ? " (required by the application)" : ""}</span></label><Show when={claim.policy === "forced_allow"}><small>This site always shares this detail.</small></Show><Show when={claim.required && claim.policy === "user" && !selected()[claim.claimType]}><small>Share this detail to continue. Select Cancel if you do not want to share it.</small></Show><Show when={!claim.available && claim.userSettable && (claim.policy === "forced_allow" || selected()[claim.claimType])}><label><span>Add {claim.label}</span><Show when={claim.datatype === "bool"} fallback={<input type={inputType(claim.datatype)} maxlength={claim.maxBytes} value={values()[claim.claimType] ?? ""} onInput={(event) => setValues((current) => ({ ...current, [claim.claimType]: event.currentTarget.value }))} required={claim.required} />}><select value={values()[claim.claimType] ?? ""} onChange={(event) => setValues((current) => ({ ...current, [claim.claimType]: event.currentTarget.value }))} required={claim.required}><option value="">Choose a value</option><option value="true">Yes</option><option value="false">No</option></select></Show></label></Show><Show when={!claim.available && claim.requiresApproval}><small>This detail needs operator approval. Add it to your account, and wait for approval before you continue.</small></Show><Show when={!claim.available && !claim.userSettable && !claim.requiresApproval}><small>This detail is not in your profile. Add it to your account or contact support before you continue.</small></Show><Show when={claim.policy === "forced_deny"}><small>This site does not allow this detail to be shared. Select Cancel and contact support.</small></Show></div>}</For></Show><div class="button-row"><button type="submit" disabled={busy() || blockedRequired() || restartRequired()}>{busy() ? "Continuing…" : "Continue"}</button><button class="text-button" type="button" disabled={busy()} onClick={cancel}>Cancel</button></div><Show when={error()}><p class="notice bad" role="alert">{error()}</p></Show><Show when={needsLogin()}><Link href="/app/login?next=/app/consent">Sign in again</Link></Show></form>
  </Show></main>;
};

function claimText(claim: Claim): string {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(claim.claimValue); }
  catch { return "Binary value"; }
}

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
      else { setAccountState("failed"); setFeedbackArea(""); setError("Could not load your account. Try again."); }
    }
  };
  onMount(refresh);
  const requestContact = async (event: SubmitEvent) => {
    event.preventDefault(); setBusy(true); setFeedbackArea("contacts"); setStatus(""); setError("");
    try { await api.account.requestContactVerification({ channel: "email", destination: email(), currentPassword: contactPassword() }); setStatus("Check your email for the verification link."); setEmail(""); setContactPassword(""); }
    catch (cause) { setError(currentPasswordMessage(cause, "Could not send the verification message.")); }
    finally { setBusy(false); }
  };
  const setClaim = async (event: SubmitEvent) => {
    event.preventDefault(); setBusy(true); setFeedbackArea("claims"); setStatus(""); setError("");
    const policy = selectedPolicy();
    if (policy && claimValueTooLong(claimValue(), policy.maxBytes)) { setBusy(false); return setError(`${policy.label} is too long. Use at most ${policy.maxBytes} bytes.`); }
    try {
      const result = await api.account.setMyClaim({ claimType: claimType(), claimValue: claimValue() });
      setClaimValue(""); await refresh();
      setStatus(result.outcome === "verification_required"
        ? "This detail requires verification."
        : result.outcome === "queued"
          ? "The detail was submitted for approval."
          : "The detail was saved.");
    } catch (cause) { setError(message(cause, "Could not save the claim.")); }
    finally { setBusy(false); }
  };
  const removeContact = async (contact: VerifiedContactMethod) => {
    if (!contactPassword()) { setFeedbackArea("contacts"); setError("Enter your current password first."); return; }
    if (!window.confirm(`Remove ${contact.destination} as a verified contact and recovery address?`)) return;
    setBusy(true); setFeedbackArea("contacts"); setStatus(""); setError("");
    try { await api.account.revokeVerifiedContactMethod({ contactMethodId: contact.id, currentPassword: contactPassword() }); setContactPassword(""); await refresh(); setStatus("The verified contact was removed."); }
    catch (cause) { setError(currentPasswordMessage(cause, "Could not remove the verified contact.")); }
    finally { setBusy(false); }
  };
  const removeClaim = async (claimId: string) => {
    if (!window.confirm("Remove this profile detail? Applications will no longer receive it.")) return;
    setBusy(true); setFeedbackArea("claims"); setStatus(""); setError("");
    try { await api.account.removeMyClaim({ claimId }); await refresh(); setStatus("The claim was removed."); }
    catch (cause) { setError(message(cause, "Could not remove the claim.")); }
    finally { setBusy(false); }
  };
  const changePassword = async (event: SubmitEvent) => {
    event.preventDefault(); setBusy(true); setFeedbackArea("password"); setStatus(""); setError("");
    if (newPassword() !== confirmation()) { setBusy(false); return setError("The new passwords do not match."); }
    const lengthError = checkPassword(newPassword(), props.configuration);
    if (lengthError) { setBusy(false); return setError(lengthError); }
    try { await api.account.changePassword({ currentPassword: oldPassword(), newPassword: newPassword() }); setOldPassword(""); setNewPassword(""); setConfirmation(""); await props.refreshSession(); props.navigate("/app/login"); }
    catch (cause) { setError(currentPasswordMessage(cause, "Could not change your password.")); }
    finally { setBusy(false); }
  };
  return <main class="wrap"><section class="hero"><p class="eyebrow">Account</p><h1>{props.session?.user.displayName ?? "Your account"}</h1><p><code>{props.session?.user.username}</code></p></section><Show when={accountState() === "ready"} fallback={<section class="card" aria-busy={accountState() === "loading"}><p role={accountState() === "failed" ? "alert" : "status"}>{accountState() === "failed" ? error() : "Loading your account…"}</p><Show when={accountState() === "failed"}><button type="button" onClick={() => { setAccountState("loading"); setError(""); void refresh(); }}>Try again</button></Show></section>}>
    <section class="card"><div class="section-heading"><div><h2>Profile details</h2><p>You choose which details to share with each application.</p></div></div>
      <Show when={claims().length} fallback={<p class="muted">No profile details are stored.</p>}><div class="table-wrap"><table><thead><tr><th>Detail</th><th>Value</th><th>Action</th></tr></thead><tbody><For each={claims()}>{(claim) => <tr><td>{claimLabel(claim.claimType)}</td><td>{claimText(claim)}</td><td><button class="text-button" type="button" disabled={busy()} aria-label={`Remove ${claimLabel(claim.claimType)}`} onClick={() => removeClaim(claim.claimId)}>Remove</button></td></tr>}</For></tbody></table></div></Show>
      <Show when={policies().length}><form class="inline-form" aria-busy={busy()} onSubmit={setClaim}><label><span>Detail</span><select value={claimType()} onChange={(event) => { setClaimType(event.currentTarget.value); setClaimValue(""); }}><For each={policies()}>{(policy) => <option value={policy.claimType}>{policy.label}</option>}</For></select><Show when={selectedPolicy()?.description}><small>{selectedPolicy()?.description}</small></Show></label><label><span>Value</span><Show when={selectedPolicy()?.datatype === "bool"} fallback={<input type={inputType(selectedPolicy()?.datatype)} maxlength={selectedPolicy()?.maxBytes} value={claimValue()} onInput={(event) => setClaimValue(event.currentTarget.value)} required />}><select value={claimValue()} onChange={(event) => setClaimValue(event.currentTarget.value)} required><option value="">Choose a value</option><option value="true">Yes</option><option value="false">No</option></select></Show></label><button type="submit" disabled={busy()}>Save detail</button></form></Show>
      <Show when={feedbackArea() === "claims" && status()}><p class="notice good" role="status">{status()}</p></Show><Show when={feedbackArea() === "claims" && error()}><p class="notice bad" role="alert">{error()}</p></Show>
    </section>
    <section class="card"><h2>Verified contacts</h2><p>A verified email address can reset your password.</p>
      <form class="inline-form" aria-busy={busy()} onSubmit={requestContact}>
        <input class="visually-hidden" type="text" name="username" value={props.session?.user.username ?? ""} autocomplete="username" readonly />
        <Show when={contacts().length} fallback={<p class="muted">You do not have a verified contact.</p>}><For each={contacts()}>{(contact) => <div class="row"><span>{contact.destination}</span><button class="text-button" type="button" disabled={busy()} aria-label={`Remove verified contact ${contact.destination}`} onClick={() => removeContact(contact)}>Remove</button></div>}</For></Show>
        <Show when={props.configuration.capabilities.includes("verify_contact")} fallback={<p class="muted">Email verification is not available on this site.</p>}><label><span>Email address</span><input type="email" name="email" value={email()} onInput={(event) => setEmail(event.currentTarget.value)} autocomplete="email" required /></label></Show>
        <Show when={contacts().length || props.configuration.capabilities.includes("verify_contact")}><label><span>Current password</span><input type="password" name="current-password" value={contactPassword()} onInput={(event) => setContactPassword(event.currentTarget.value)} autocomplete="current-password" required /></label></Show>
        <Show when={props.configuration.capabilities.includes("verify_contact")}><button type="submit" disabled={busy()}>Verify email</button></Show>
      </form>
      <Show when={feedbackArea() === "contacts" && status()}><p class="notice good" role="status">{status()}</p></Show><Show when={feedbackArea() === "contacts" && error()}><p class="notice bad" role="alert">{error()}</p></Show>
    </section>
    <Show when={props.configuration.capabilities.includes("password_login")}><section class="card"><h2>Change password</h2><p id="change-password-rule">{passwordRule(props.configuration)} Changing your password signs you out on every device.</p><form id="change-password-form" name="change-password" aria-busy={busy()} onSubmit={changePassword}>
      <input class="visually-hidden" type="text" name="username" value={props.session?.user.username ?? ""} autocomplete="username" readonly />
      <label><span>Current password</span><input type="password" name="current-password" value={oldPassword()} onInput={(event) => setOldPassword(event.currentTarget.value)} autocomplete="current-password" required /></label>
      <label><span>New password</span><input type="password" name="new-password" value={newPassword()} onInput={(event) => setNewPassword(event.currentTarget.value)} autocomplete="new-password" aria-describedby="change-password-rule" required /></label>
      <label><span>Confirm new password</span><input type="password" name="new-password-confirmation" value={confirmation()} onInput={(event) => setConfirmation(event.currentTarget.value)} autocomplete="new-password" required /></label>
      <button type="submit" disabled={busy()}>Change password</button></form>
      <Show when={feedbackArea() === "password" && error()}><p class="notice bad" role="alert">{error()}</p></Show>
    </section></Show>
    <Show when={feedbackArea() === "" && error()}><p class="notice bad" role="alert">{error()}</p></Show></Show>
  </main>;
};

const RequestPassword: Component<PageProps> = (props) => {
  const [identifier, setIdentifier] = createSignal(""); const [sent, setSent] = createSignal(false); const [busy, setBusy] = createSignal(false); const [error, setError] = createSignal("");
  const continuation = safeNext(query("next"));
  const submit = async (event: SubmitEvent) => { event.preventDefault(); setBusy(true); setError(""); try { sessionStorage.setItem("linkkeys-recovery-identifier", identifier()); if (continuation) sessionStorage.setItem("linkkeys-recovery-next", continuation); else sessionStorage.removeItem("linkkeys-recovery-next"); await api.recovery.requestPasswordRecovery({ identifier: identifier() }); setSent(true); } catch (cause) { setError(message(cause, "Could not request password recovery.")); } finally { setBusy(false); } };
  if (!props.configuration.capabilities.includes("reset_password")) return <Unavailable title="Password recovery is not available" detail="Contact this site's support team for help." />;
  return <main class="wrap narrow"><section class="hero"><p class="eyebrow">Account recovery</p><h1>Reset your password</h1></section><Show when={!sent()} fallback={<section class="card good"><h2>Check your messages</h2><p>If the account has a verified recovery contact, LinkKeys sent a reset link.</p><Link href={withNext("/app/login", continuation)}>Return to sign in</Link></section>}>
    <form class="card" aria-busy={busy()} onSubmit={submit}><p>Enter your username or verified email address.</p><label><span>Username or email</span><input value={identifier()} onInput={(event) => setIdentifier(event.currentTarget.value)} autocomplete="username" maxlength="320" required /></label><button type="submit" disabled={busy()}>{busy() ? "Sending…" : "Send reset link"}</button><Show when={error()}><p class="notice bad" role="alert">{error()}</p></Show></form></Show></main>;
};

const ResetPassword: Component<PageProps> = (props) => {
  const token = takeFragmentToken("linkkeys-recovery-token"); const storedIdentifier = sessionStorage.getItem("linkkeys-recovery-identifier") ?? ""; const [username, setUsername] = createSignal(passwordManagerUsername(storedIdentifier)); const [password, setPassword] = createSignal(""); const [confirmation, setConfirmation] = createSignal(""); const [valid, setValid] = createSignal(false); const [done, setDone] = createSignal(false); const [busy, setBusy] = createSignal(false); const [checking, setChecking] = createSignal(true); const [retryValidation, setRetryValidation] = createSignal(false); const [error, setError] = createSignal("");
  const continuation = safeNext(sessionStorage.getItem("linkkeys-recovery-next") ?? "");
  const validateToken = async () => { setChecking(true); setRetryValidation(false); setError(""); try { await api.recovery.validatePasswordRecovery({ token }); setValid(true); } catch (cause) { setError(recoveryValidationFailureMessage(cause)); setRetryValidation(transportFailed(cause)); } finally { setChecking(false); } };
  onMount(validateToken);
  const submit = async (event: SubmitEvent) => { event.preventDefault(); setBusy(true); setError(""); if (password() !== confirmation()) { setBusy(false); return setError("The passwords do not match."); } const lengthError = checkPassword(password(), props.configuration); if (lengthError) { setBusy(false); return setError(lengthError); } try { await api.recovery.completePasswordRecovery({ token, newPassword: password() }); sessionStorage.removeItem("linkkeys-recovery-identifier"); sessionStorage.removeItem("linkkeys-recovery-token"); setPassword(""); setConfirmation(""); setDone(true); } catch (cause) { if (recoveryLinkExpired(cause)) { setValid(false); setRetryValidation(false); setError("This recovery link is invalid or expired."); } else setError(recoveryCompletionFailureMessage(cause)); } finally { setBusy(false); } };
  return <main class="wrap narrow"><section class="hero"><p class="eyebrow">Account recovery</p><h1>Set a new password</h1></section><Show when={!done()} fallback={<section class="card good"><h2>Password changed</h2><p>All earlier browser sessions are now signed out.</p><Link href={withNext("/app/login", continuation)}>{continuation ? "Sign in and continue" : "Sign in"}</Link></section>}>
    <Show when={valid()} fallback={<section class="card" aria-busy={checking()}><p role={error() ? "alert" : "status"}>{error() || "Checking the recovery link…"}</p><Show when={retryValidation()} fallback={<Show when={error()}><Link href={withNext("/app/password/request", continuation)}>Request a new reset link</Link></Show>}><button type="button" disabled={checking()} onClick={validateToken}>Try again</button></Show></section>}><form id="reset-password-form" name="reset-password" class="card" aria-busy={busy()} onSubmit={submit}>
      <p id="reset-password-rule">{passwordRule(props.configuration)}</p>
      <label><span>Password manager username (optional)</span><input type="text" name="username" value={username()} onInput={(event) => setUsername(event.currentTarget.value)} autocomplete="username" autocapitalize="none" spellcheck={false} /><small>This value helps your password manager update the saved login. LinkKeys does not use it to choose the account.</small></label>
      <label><span>New password</span><input type="password" name="new-password" value={password()} onInput={(event) => setPassword(event.currentTarget.value)} autocomplete="new-password" aria-describedby="reset-password-rule" required /></label>
      <label><span>Confirm new password</span><input type="password" name="new-password-confirmation" value={confirmation()} onInput={(event) => setConfirmation(event.currentTarget.value)} autocomplete="new-password" required /></label>
      <button type="submit" disabled={busy()}>{busy() ? "Saving…" : "Set password"}</button><Show when={error()}><p class="notice bad" role="alert">{error()}</p></Show></form></Show></Show></main>;
};

const VerifyContact: Component<PageProps> = (props) => {
  const [done, setDone] = createSignal(false); const [checking, setChecking] = createSignal(true); const [connectionFailure, setConnectionFailure] = createSignal(false); const [error, setError] = createSignal("");
  const token = takeFragmentToken("linkkeys-contact-token");
  const verify = async () => { setChecking(true); setConnectionFailure(false); setError(""); try { await api.account.confirmContactVerification({ token }); sessionStorage.removeItem("linkkeys-contact-token"); setDone(true); } catch (cause) { setConnectionFailure(transportFailed(cause)); setError(verificationFailureMessage(cause)); } finally { setChecking(false); } };
  onMount(verify);
  return <main class="wrap narrow"><section class="hero"><p class="eyebrow">Contact verification</p><h1>Verify your contact</h1></section><section class={`card ${done() ? "good" : ""}`} aria-busy={checking()}><Show when={done()} fallback={<><p role={error() ? "alert" : "status"}>{error() || "Checking the verification link…"}</p><Show when={error()}><Show when={connectionFailure()} fallback={<p><Link href="/app/login?next=/app/verify/contact">Sign in with another account</Link></p>}><button type="button" disabled={checking()} onClick={verify}>Try again</button></Show></Show></>}><h2>Contact verified</h2><p>Your email address is verified and can be used for account recovery.</p><Link href="/app/account">Return to your account</Link></Show></section></main>;
};

const ReactivateAccount: Component<{ userId: string; username: string; configuration: GetUiConfigurationResponse; complete(): Promise<void>; fail(text: string): void }> = (props) => {
  const [password, setPassword] = createSignal(""); const [confirmation, setConfirmation] = createSignal(""); const [busy, setBusy] = createSignal(false);
  const submit = async (event: SubmitEvent) => {
    event.preventDefault();
    if (password() !== confirmation()) return props.fail("The new passwords do not match.");
    const lengthError = checkPassword(password(), props.configuration);
    if (lengthError) return props.fail(lengthError);
    setBusy(true);
    try { await api.admin.resetPassword({ userId: props.userId, newPassword: password() }); await api.admin.activateUser({ userId: props.userId }); setPassword(""); setConfirmation(""); await props.complete(); }
    catch { props.fail(`Could not restore sign-in for ${props.username}.`); }
    finally { setBusy(false); }
  };
  return <form class="stacked-action" aria-busy={busy()} onSubmit={submit}><small>{passwordRule(props.configuration)}</small><input aria-label={`New password for ${props.username}`} type="password" value={password()} onInput={(event) => setPassword(event.currentTarget.value)} autocomplete="new-password" required /><input aria-label={`Confirm new password for ${props.username}`} type="password" value={confirmation()} onInput={(event) => setConfirmation(event.currentTarget.value)} autocomplete="new-password" required /><button type="submit" disabled={busy()}>Set password and enable</button></form>;
};

const Admin: Component<PageProps> = (props) => {
  const [users, setUsers] = createSignal<Awaited<ReturnType<typeof api.admin.listUsers>>["users"]>([]); const [error, setError] = createSignal(""); const [status, setStatus] = createSignal(""); const [busy, setBusy] = createSignal(false);
  const [hasMore, setHasMore] = createSignal(false);
  const [username, setUsername] = createSignal(""); const [displayName, setDisplayName] = createSignal(""); const [password, setPassword] = createSignal(""); const [confirmation, setConfirmation] = createSignal("");
  const pageSize = 50;
  const refresh = async () => { const result = (await api.admin.listUsers({ limit: pageSize + 1 })).users; setUsers(result.slice(0, pageSize)); setHasMore(result.length > pageSize); };
  const loadMore = async () => { setBusy(true); setError(""); try { const result = (await api.admin.listUsers({ offset: users().length, limit: pageSize + 1 })).users; setUsers((current) => [...current, ...result.slice(0, pageSize)]); setHasMore(result.length > pageSize); } catch (cause) { setError(message(cause, "Could not load more accounts.")); } finally { setBusy(false); } };
  onMount(async () => { try { await refresh(); } catch (cause) { setError(message(cause, "You do not have access to core administration.")); } });
  const createUser = async (event: SubmitEvent) => { event.preventDefault(); setError(""); setStatus(""); if (password() !== confirmation()) return setError("The passwords do not match."); const lengthError = checkPassword(password(), props.configuration); if (lengthError) return setError(lengthError); setBusy(true); try { await api.admin.createUser({ username: username(), displayName: displayName(), password: password() }); setUsername(""); setDisplayName(""); setPassword(""); setConfirmation(""); await refresh(); setStatus("The account was created."); } catch (cause) { setError(message(cause, "Could not create the account.")); } finally { setBusy(false); } };
  const deactivate = async (userId: string, username: string) => { if (!window.confirm(`Disable ${username} and revoke every sign-in credential? This action signs the person out on every device.`)) return; setBusy(true); setError(""); setStatus(""); try { await api.admin.deactivateUser({ userId }); await refresh(); setStatus(`${username} is disabled. A new password is required before the account can be enabled.`); } catch (cause) { setError(message(cause, "Could not disable the account.")); } finally { setBusy(false); } };
  return <main class="wrap wide"><section class="hero"><p class="eyebrow">Administration</p><h1>Accounts</h1><p>Core account administration for {props.configuration.domain}.</p></section><section class="card"><Show when={!error() || users().length} fallback={<p class="notice bad" role="alert">{error()}</p>}>
    <Show when={props.extensionFailures?.length}><p class="operator-warning" role="status">Some UI extensions could not start: {props.extensionFailures?.join(", ")}.</p></Show>
    <form class="account-form" aria-busy={busy()} onSubmit={createUser}><p id="admin-password-rule">{passwordRule(props.configuration)}</p><label><span>Username</span><input value={username()} onInput={(event) => setUsername(event.currentTarget.value)} autocomplete="off" maxlength="254" required /></label><label><span>Display name</span><input value={displayName()} onInput={(event) => setDisplayName(event.currentTarget.value)} maxlength="254" required /></label><label><span>Initial password</span><input type="password" value={password()} onInput={(event) => setPassword(event.currentTarget.value)} autocomplete="new-password" aria-describedby="admin-password-rule" required /></label><label><span>Confirm initial password</span><input type="password" value={confirmation()} onInput={(event) => setConfirmation(event.currentTarget.value)} autocomplete="new-password" required /></label><button type="submit" disabled={busy()}>Create account</button></form>
    <div class="table-wrap"><table><thead><tr><th>Username</th><th>Display name</th><th>Status</th><th>Created</th><th>Action</th></tr></thead><tbody><For each={users()}>{(user) => <tr><td><code>{user.username}</code></td><td>{user.displayName}</td><td><span class="pill">{user.isActive ? "Active" : "Disabled"}</span></td><td>{new Date(user.createdAt).toLocaleDateString()}</td><td><Show when={user.id !== props.session?.user.id} fallback={<span class="muted">Current account</span>}><Show when={user.isActive} fallback={<ReactivateAccount userId={user.id} username={user.username} configuration={props.configuration} fail={setError} complete={async () => { await refresh(); setStatus(`${user.username} can sign in with the new password.`); }} />}><button class="text-button" type="button" disabled={busy()} aria-label={`Disable account ${user.username} and revoke sign-in`} onClick={() => deactivate(user.id, user.username)}>Disable account and revoke sign-in</button></Show></Show></td></tr>}</For></tbody></table></div>
    <Show when={hasMore()}><button type="button" disabled={busy()} onClick={loadMore}>{busy() ? "Loading…" : "Load more accounts"}</button></Show>
    <Show when={status()}><p class="notice good" role="status">{status()}</p></Show><Show when={error()}><p class="notice bad" role="alert">{error()}</p></Show>
  </Show></section></main>;
};

const Unavailable: Component<{ title: string; detail: string; destination?: string; action?: string }> = (props) => <main class="wrap narrow"><section class="card"><h1>{props.title}</h1><p>{props.detail}</p><Show when={props.destination}><Link href={props.destination!}>{props.action ?? "Return to your account"}</Link></Show></section></main>;
const Loading: Component = () => <main class="wrap narrow" aria-busy="true"><section class="card"><h1>Loading</h1><p role="status">Connecting to LinkKeys…</p></section></main>;
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
  return <main class="wrap wide"><section class="hero"><p class="eyebrow">Extension</p><h1>{props.route.title}</h1></section><Show when={!error()} fallback={<section class="card"><p role="alert">This page is not available. You can still use the rest of LinkKeys.</p><button type="button" onClick={() => window.location.reload()}>Try again</button></section>}><Show when={loading()}><section class="card" aria-busy="true"><p role="status">Loading this page…</p></section></Show><div ref={container} hidden={loading()} /></Show></main>;
};

const App: Component<{ configuration: GetUiConfigurationResponse }> = (props) => {
  const [path, setPath] = createSignal(window.location.pathname); const [revision, setRevision] = createSignal(0); const [session, setSession] = createSignal<BrowserSessionInfo>(); const [sessionLoaded, setSessionLoaded] = createSignal(false); const [sessionError, setSessionError] = createSignal(false); const [canAdmin, setCanAdmin] = createSignal(false); const [extensionFailures, setExtensionFailures] = createSignal<string[]>([]); const [extensionsLoaded, setExtensionsLoaded] = createSignal(false); const [logoutBusy, setLogoutBusy] = createSignal(false); const [logoutError, setLogoutError] = createSignal("");
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
  const refreshSession = async () => {
    setSessionError(false);
    try {
      const current = (await api.session.getCurrent({})).session;
      setSession(current);
      if (current) { try { const permission = await api.admin.checkPermission({ userId: current.user.id, relation: "admin", objectType: "domain", objectId: props.configuration.domain }); setCanAdmin(permission.allowed); } catch { setCanAdmin(false); } }
      else setCanAdmin(false);
    } catch (cause) {
      if (authenticationFailed(cause)) { setSession(undefined); setCanAdmin(false); }
      else setSessionError(true);
    } finally { setSessionLoaded(true); }
  };
  const host = new RuntimeHost(api, props.configuration, navigate, () => setRevision((value) => value + 1), session);
  const pop = () => { setLogoutError(""); showPath(window.location.pathname); };
  const click = (event: MouseEvent) => { const anchor = (event.target as Element).closest<HTMLAnchorElement>("a[data-linkkeys-nav]"); if (!anchor || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey) return; event.preventDefault(); navigate(anchor.href); };
  onMount(async () => { window.addEventListener("popstate", pop); document.addEventListener("click", click); await refreshSession(); try { setExtensionFailures(await loadExtensions(host)); } finally { setExtensionsLoaded(true); } });
  onCleanup(() => { window.removeEventListener("popstate", pop); document.removeEventListener("click", click); });
  const logout = async () => { setLogoutBusy(true); setLogoutError(""); try { await api.session.logout({}); setSession(undefined); navigate("/app/login"); } catch { setLogoutError("Could not sign out. Check your connection and try again."); } finally { setLogoutBusy(false); } };
  createEffect(() => { const label = path().split("/").filter(Boolean).at(-1) ?? "home"; document.title = `${claimLabel(label)} · ${props.configuration.display.siteName}`; });
  const page = () => { revision(); const current = path(); const common = { navigate, configuration: props.configuration, session: session(), refreshSession, extensionFailures: extensionFailures() };
    if (!sessionLoaded()) return <Loading />;
    if (sessionError()) return <main class="wrap narrow"><section class="card"><h1>Could not check your session</h1><p>LinkKeys could not connect to the account service.</p><button type="button" onClick={refreshSession}>Try again</button></section></main>;
    if (current === "/app" || current === "/app/") return session() ? <Account {...common} /> : <Login {...common} />;
    if (current === "/app/login") return <Login {...common} />;
    if (current === "/app/account" || current.startsWith("/app/account/")) return session() ? <Account {...common} /> : <Login {...common} />;
    if (current === "/app/password/request") return <RequestPassword {...common} />;
    if (current === "/app/password/reset") return <ResetPassword {...common} />;
    if (current === "/app/authorize") return <AuthorizeGateway {...common} />;
    if (current === "/app/consent") return session() ? <Consent {...common} /> : <Login {...common} />;
    if (current === "/app/consent/cancelled") return <Unavailable title="Application sign-in cancelled" detail="LinkKeys did not send your profile details to the application." destination="/app/account" />;
    if (current === "/app/verify/contact") return session() ? <VerifyContact {...common} /> : <VerifySignIn navigate={navigate} />;
    if (current === "/app/admin" || current.startsWith("/app/admin/")) return session() && canAdmin() ? <Admin {...common} /> : <Unavailable title="Administration is not available" detail="Your account does not have access to this page." destination="/app/account" />;
    if (!extensionsLoaded()) return <Loading />;
    const extension = host.route(current); if (extension) { const owner = host.routeOwner(current) ?? extension.title; return session() ? <ExtensionPage route={extension} host={host} path={current} onFailure={() => setExtensionFailures((values) => values.includes(owner) ? values : [...values, owner])} /> : <Login {...common} />; }
    return <Unavailable title="Page not found" detail="This UI route is not registered." destination="/app/account" />;
  };
  return <><a class="skip-link" href="#main-content">Skip to content</a><header class="site-header"><Link href="/app"><Show when={props.configuration.theme?.logoUrl} fallback={<span class="brand-mark">LK</span>}><img class="brand-logo" src={props.configuration.theme?.logoUrl} alt="" /></Show><span>{props.configuration.display.siteName}</span></Link><nav><Show when={session()}><Link href="/app/account" current={path().startsWith("/app/account")}>Account</Link><Show when={canAdmin()}><Link href="/app/admin" current={path().startsWith("/app/admin")}>Admin</Link></Show><For each={host.navigationItems()}>{(item) => <Link href={item.path} current={path().startsWith(item.path)}>{item.label}</Link>}</For></Show><Show when={session()} fallback={<Link href="/app/login" current={path() === "/app/login"}>Sign in</Link>}><button class="text-button" disabled={logoutBusy()} onClick={logout}>{logoutBusy() ? "Signing out…" : "Sign out"}</button></Show></nav></header>
    <Show when={logoutError()}><div class="global-banner"><p class="notice bad" role="alert">{logoutError()}</p></div></Show>
    <div id="main-content" tabindex="-1">{page()}</div><footer>LinkKeys · {props.configuration.domain}<Show when={props.configuration.display.supportUrl}> · <a href={props.configuration.display.supportUrl}>Support</a></Show></footer></>;
};

async function start(): Promise<void> {
  try {
    const configuration = await api.ui.getConfiguration({});
    document.title = configuration.display.siteName;
    if (configuration.theme?.stylesheetUrl) addStylesheet(configuration.theme.stylesheetUrl, "operator-theme");
    if (configuration.theme?.faviconUrl) { const favicon = document.createElement("link"); favicon.rel = "icon"; favicon.href = configuration.theme.faviconUrl; document.head.append(favicon); }
    render(() => <App configuration={configuration} />, document.getElementById("root")!);
  } catch (error) {
    console.error("The LinkKeys UI could not start.", error);
    document.getElementById("root")!.innerHTML = '<main class="wrap narrow"><section class="card"><h1>LinkKeys is unavailable</h1><p>The UI could not connect to the server. Reload this page or contact the operator.</p></section></main>';
  }
}

void start();
