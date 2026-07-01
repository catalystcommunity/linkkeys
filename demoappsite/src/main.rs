use rocket::form::FromForm;
use rocket::http::{Cookie, CookieJar, SameSite};
use rocket::response::content::RawHtml;
use rocket::response::Redirect;
use rocket::{Config, State};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Serialize, Deserialize)]
struct Session {
    user_id: String,
    domain: String,
    display_name: String,
    claims: Vec<SessionClaim>,
    expires_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct SessionClaim {
    claim_type: String,
    claim_value: String,
    /// Distinct domains that signed this claim (the trust-relevant attribution).
    signing_domains: Vec<String>,
    /// Number of signatures (keys) over the claim.
    key_count: usize,
}

/// Stored in a cookie during the login redirect to verify the callback.
#[derive(Serialize, Deserialize)]
struct AuthState {
    nonce: String,
    domain: String,
    api_base: String,
}

/// Configuration for the RP service connection over the LinkKeys TCP transport.
struct RpConfig {
    /// The RP server's TCP endpoint (`host:port`).
    tcp_addr: String,
    /// DNS-published fingerprints pinning the RP server's TLS cert. The demo
    /// holds no domain key, so it presents no client cert and authenticates with
    /// the API key; it still pins the server cert so it only talks to its RP.
    fingerprints: Vec<String>,
    api_key: String,
    domain: String,
    required_claims: Vec<String>,
}

/// Call an `Rp` helper op on the RP server over the CSIL-RPC TCP transport. The
/// client is blocking, so it runs on a blocking thread; the demo presents no
/// client cert and authenticates with its API key.
async fn rp_call<Req, Resp>(
    rp: &RpConfig,
    op: &'static str,
    req: Req,
    encode: fn(&Req) -> Vec<u8>,
    decode: fn(&[u8]) -> Result<Resp, liblinkkeys::generated::codec::CsilCborError>,
) -> Result<Resp, String> {
    let addr = rp.tcp_addr.clone();
    let fingerprints = rp.fingerprints.clone();
    let api_key = rp.api_key.clone();
    let payload = encode(&req);
    let resp_bytes = tokio::task::spawn_blocking(move || {
        linkkeys_rpc_client::send_request(
            &addr,
            fingerprints,
            None,
            "Rp",
            op,
            payload,
            Some(&api_key),
        )
    })
    .await
    .map_err(|e| format!("RP task join failed: {}", e))?
    .map_err(|e| format!("RP {} failed: {}", op, e))?;
    decode(&resp_bytes).map_err(|e| format!("RP {} decode failed: {}", op, e))
}

fn get_own_origin() -> String {
    if let Ok(origin) = env::var("PUBLIC_ORIGIN") {
        return origin;
    }
    let port: u16 = env::var("DEMO_PORT")
        .unwrap_or_else(|_| "9090".to_string())
        .parse()
        .unwrap_or(9090);
    format!("https://localhost:{}", port)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn parse_claim_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Shared page chrome: responsive, mobile-first, widens to use available space on
/// desktop. Injected via a `{style}` placeholder so CSS braces need no escaping.
const PAGE_STYLE: &str = r#"
:root {
  --accent: #2563eb; --accent-soft: #eaf1ff;
  --bg: #f5f7fa; --card: #ffffff; --border: #e4e8ee;
  --text: #1f2733; --muted: #647084; --ok: #15803d; --ok-soft: #e8f6ec;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg); color: var(--text); line-height: 1.5;
  margin: 0; padding: clamp(16px, 4vw, 40px);
}
.wrap { max-width: 1080px; margin: 0 auto; }
.narrow { max-width: 460px; margin: 0 auto; }
h1, h2, h3 { line-height: 1.2; }
h1 { font-size: clamp(1.5rem, 3.5vw, 2.1rem); margin: 0 0 4px; }
.sub { color: var(--muted); margin: 0 0 24px; }
.card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 12px; padding: clamp(16px, 3vw, 24px);
  box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04);
}
.card + .card, .card + section, section + section { margin-top: 20px; }
.badge {
  display: inline-flex; align-items: center; gap: 6px;
  background: var(--ok-soft); color: var(--ok);
  font-weight: 600; font-size: 0.85rem; padding: 6px 12px; border-radius: 999px;
}
.kv { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 0; }
.kv dt { color: var(--muted); }
.kv dd { margin: 0; word-break: break-all; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
code {
  background: #f0f2f5; padding: 2px 6px; border-radius: 5px; font-size: 0.88em;
}
.claims-grid {
  display: grid; gap: 16px; margin-top: 4px;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
}
.claim {
  border: 1px solid var(--border); border-radius: 10px; padding: 16px;
  background: var(--card); display: flex; flex-direction: column; gap: 10px;
}
.claim-type {
  font-size: 0.72rem; letter-spacing: 0.06em; text-transform: uppercase;
  color: var(--accent); font-weight: 700;
}
.claim-value { font-size: 1.05rem; font-weight: 600; word-break: break-word; }
.claim-meta { margin-top: auto; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.domain-chip {
  display: inline-flex; align-items: center; gap: 6px;
  background: var(--accent-soft); color: var(--accent);
  font-weight: 600; font-size: 0.82rem; padding: 4px 10px; border-radius: 8px;
}
.keys { color: var(--muted); font-size: 0.8rem; }
.empty { color: var(--muted); font-style: italic; }
form.inline { margin-top: 24px; }
input[type="text"] {
  display: block; width: 100%; padding: 12px 14px; margin: 10px 0 4px;
  border: 1px solid var(--border); border-radius: 8px; font-size: 1rem;
}
label { font-weight: 600; font-size: 0.9rem; }
button {
  font-size: 1rem; font-weight: 600; padding: 12px 20px; border-radius: 8px;
  border: none; cursor: pointer; background: var(--accent); color: #fff;
}
button.secondary { background: #eef0f3; color: var(--text); }
button:hover { filter: brightness(0.96); }
a { color: var(--accent); }
.info { background: var(--accent-soft); color: #1e3a8a; padding: 12px 14px; border-radius: 8px; font-size: 0.9rem; }
.error { color: #b42318; background: #fdecec; padding: 12px 14px; border-radius: 8px; }
@media (max-width: 520px) { .kv { grid-template-columns: 1fr; gap: 2px 0; } .kv dt { margin-top: 8px; } }
"#;

fn get_session(cookies: &CookieJar<'_>) -> Option<Session> {
    cookies
        .get_private("session")
        .and_then(|c| serde_json::from_str(c.value()).ok())
        .filter(|s: &Session| {
            chrono::DateTime::parse_from_rfc3339(&s.expires_at)
                .map(|exp| chrono::Utc::now() < exp)
                .unwrap_or(false)
        })
}

fn set_session(cookies: &CookieJar<'_>, session: &Session) {
    let json = serde_json::to_string(session).expect("Session serialization");
    let mut cookie = Cookie::new("session", json);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookies.add_private(cookie);
}

fn error_page(message: &str) -> RawHtml<String> {
    RawHtml(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Demo App - Error</title>
<style>{style}</style>
</head>
<body>
<div class="narrow">
  <section class="card">
    <h2>Authentication Error</h2>
    <p class="error">{message}</p>
    <p style="margin-top:16px"><a href="/">&larr; Back to login</a></p>
  </section>
</div>
</body>
</html>"#,
        style = PAGE_STYLE,
        message = html_escape(message),
    ))
}

// -- Routes --

#[rocket::get("/")]
fn index(cookies: &CookieJar<'_>) -> RawHtml<String> {
    if let Some(session) = get_session(cookies) {
        return dashboard(&session);
    }
    login_form(None)
}

fn login_form(error: Option<&str>) -> RawHtml<String> {
    let error_html = error
        .map(|e| format!(r#"<p class="error">{}</p>"#, html_escape(e)))
        .unwrap_or_default();

    RawHtml(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Demo App - LinkKeys Login</title>
<style>{style}</style>
</head>
<body>
<div class="narrow">
  <h1>Demo Application</h1>
  <p class="sub">Authenticated with <strong>LinkKeys</strong>.</p>
  <section class="card">
    <div class="info">Enter your identity as <code>username@domain</code> or just <code>domain</code> to log in.</div>
    {error}
    <form method="POST" action="/login" class="inline">
      <label for="identity">Your Identity</label>
      <input id="identity" type="text" name="identity" placeholder="you@example.com" autofocus />
      <button type="submit">Log In with LinkKeys</button>
    </form>
  </section>
</div>
</body>
</html>"#,
        style = PAGE_STYLE,
        error = error_html,
    ))
}

fn dashboard(session: &Session) -> RawHtml<String> {
    let claims_html = if session.claims.is_empty() {
        r#"<p class="empty">No claims shared.</p>"#.to_string()
    } else {
        let cards: String = session
            .claims
            .iter()
            .map(|c| {
                // One chip per signing domain — the trust-relevant attribution.
                let domains: String = if c.signing_domains.is_empty() {
                    r#"<span class="keys">unsigned</span>"#.to_string()
                } else {
                    c.signing_domains
                        .iter()
                        .map(|d| {
                            format!(
                                r#"<span class="domain-chip">&#x1F510; {}</span>"#,
                                html_escape(d)
                            )
                        })
                        .collect()
                };
                let keys = format!(
                    "signed by {} key{}",
                    c.key_count,
                    if c.key_count == 1 { "" } else { "s" }
                );
                format!(
                    r#"<div class="claim">
  <div class="claim-type">{ctype}</div>
  <div class="claim-value">{value}</div>
  <div class="claim-meta">{domains}<span class="keys">{keys}</span></div>
</div>"#,
                    ctype = html_escape(&c.claim_type),
                    value = html_escape(&c.claim_value),
                    domains = domains,
                    keys = keys,
                )
            })
            .collect();
        format!(r#"<div class="claims-grid">{cards}</div>"#)
    };

    RawHtml(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Demo App - Dashboard</title>
<style>{style}</style>
</head>
<body>
<div class="wrap">
  <h1>Demo App Dashboard</h1>
  <p class="sub">Welcome back, {display_name}.</p>

  <section class="card">
    <span class="badge">&#x2714; Identity cryptographically verified</span>
    <dl class="kv" style="margin-top:16px">
      <dt>Identity</dt><dd><code>{user_id}@{domain}</code></dd>
      <dt>User ID</dt><dd><code>{user_id}</code></dd>
      <dt>Domain</dt><dd><code>{domain}</code></dd>
      <dt>Display Name</dt><dd>{display_name}</dd>
    </dl>
  </section>

  <section>
    <h3>Claims</h3>
    {claims}
  </section>

  <form method="POST" action="/claims/age-checks" class="inline">
    <button type="submit">Request Age Checks</button>
  </form>
  <p><a href="/attest/linkidspec">Get a linkidspec signature</a></p>

  <form method="POST" action="/logout" class="inline">
    <button type="submit" class="secondary">Log Out</button>
  </form>
</div>
</body>
</html>"#,
        style = PAGE_STYLE,
        user_id = html_escape(&session.user_id),
        domain = html_escape(&session.domain),
        display_name = html_escape(&session.display_name),
        claims = claims_html,
    ))
}

#[derive(FromForm)]
struct LoginForm {
    identity: String,
}

#[derive(FromForm)]
struct AttestationForm {
    request: String,
}

/// Parse "user@domain" or just "domain" into (user_hint, domain).
fn parse_identity(input: &str) -> (Option<&str>, &str) {
    match input.rsplit_once('@') {
        Some((user, domain)) if !user.is_empty() && !domain.is_empty() => (Some(user), domain),
        _ => (None, input),
    }
}

/// Resolve a domain's HTTPS API base URL via its `_linkkeys_apis` DNS TXT
/// record (the `https=host[:port][/path]` field; the scheme is implied).
/// Falls back to `https://{domain}` if no record is found. The demo is a
/// browser-facing relying party, so it uses the HTTPS endpoint by design.
async fn resolve_api_base(domain: &str) -> String {
    use hickory_resolver::TokioAsyncResolver;

    let dns_name = format!("_linkkeys_apis.{}", domain);
    let fallback = || format!("https://{}", domain);

    let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(e) => {
            log::warn!("DNS resolver init failed, falling back to direct: {}", e);
            return fallback();
        }
    };

    match resolver.txt_lookup(&dns_name).await {
        Ok(response) => {
            for record in response.iter() {
                let txt = record.to_string();
                // Look for "v=lk1 ... https=<host[:port][/path]>".
                if txt.starts_with("v=lk1 ") {
                    for part in txt.split_whitespace() {
                        if let Some(value) = part.strip_prefix("https=") {
                            let url = format!("https://{}", value);
                            log::info!("Resolved {} -> {}", domain, url);
                            return url;
                        }
                    }
                }
            }
            log::info!("No _linkkeys_apis https= for {}, using direct", domain);
            fallback()
        }
        Err(e) => {
            log::info!("DNS lookup failed for {}: {}, using direct", dns_name, e);
            fallback()
        }
    }
}

fn simple_url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => out.push(c),
            _ => {
                for b in c.to_string().as_bytes() {
                    out.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    out
}

// The RP `Rp` service responses are the generated CSIL types
// (`liblinkkeys::generated::types`): RpSignResponse, RpDecryptResponse,
// RpVerifyResponse (carrying IdentityAssertion), and UserInfo. The demo decodes
// straight into them — no hand-rolled mirror structs.
use liblinkkeys::generated::types as lk;

fn demo_initial_claim_request() -> lk::ClaimRequest {
    lk::ClaimRequest {
        required: vec![
            lk::RequestedClaim {
                claim_type: "display_name".to_string(),
                datatype: "text".to_string(),
            },
            lk::RequestedClaim {
                claim_type: "handle".to_string(),
                datatype: "text".to_string(),
            },
        ],
        optional: vec![
            lk::RequestedClaim {
                claim_type: "email".to_string(),
                datatype: "email".to_string(),
            },
            lk::RequestedClaim {
                claim_type: "over_21".to_string(),
                datatype: "bool".to_string(),
            },
            lk::RequestedClaim {
                claim_type: "address".to_string(),
                datatype: "text".to_string(),
            },
        ],
    }
}

fn demo_age_update_claim_request() -> lk::ClaimRequest {
    let mut request = demo_initial_claim_request();
    request.optional.extend([
        lk::RequestedClaim {
            claim_type: "over_13".to_string(),
            datatype: "bool".to_string(),
        },
        lk::RequestedClaim {
            claim_type: "over_16".to_string(),
            datatype: "bool".to_string(),
        },
        lk::RequestedClaim {
            claim_type: "over_18".to_string(),
            datatype: "bool".to_string(),
        },
    ]);
    request
}

async fn begin_linkkeys_redirect(
    cookies: &CookieJar<'_>,
    rp_config: &RpConfig,
    domain: &str,
    user_hint: Option<&str>,
    requested_claims: lk::ClaimRequest,
    flow_context: Option<lk::AuthFlowContext>,
) -> Result<Redirect, RawHtml<String>> {
    let api_base = resolve_api_base(domain).await;
    let nonce = uuid::Uuid::new_v4().to_string();
    let origin = get_own_origin();
    let callback_url = format!("{}/callback", origin);

    let sign_result = rp_call(
        rp_config,
        "sign-request",
        lk::RpSignRequest {
            callback_url: callback_url.clone(),
            nonce: nonce.clone(),
            requested_claims: Some(requested_claims),
            flow_context,
        },
        liblinkkeys::generated::encode_rp_sign_request,
        liblinkkeys::generated::decode_rp_sign_response,
    )
    .await
    .map_err(|e| login_form(Some(&format!("Failed to contact RP service: {}", e))))?;

    let auth_state = AuthState {
        nonce: nonce.clone(),
        domain: domain.to_string(),
        api_base: api_base.clone(),
    };
    let state_json = serde_json::to_string(&auth_state).expect("AuthState serialization");
    let mut state_cookie = Cookie::new("auth_state", state_json);
    state_cookie.set_same_site(SameSite::Lax);
    state_cookie.set_path("/");
    state_cookie.set_http_only(true);
    state_cookie.set_secure(true);
    cookies.add_private(state_cookie);

    let redirect_url = format!(
        "{}/auth/authorize?callback_url={}&nonce={}&user_hint={}&relying_party={}&signed_request={}",
        api_base,
        simple_url_encode(&callback_url),
        simple_url_encode(&nonce),
        simple_url_encode(user_hint.unwrap_or("")),
        simple_url_encode(&rp_config.domain),
        simple_url_encode(&sign_result.signed_request),
    );

    Ok(Redirect::found(redirect_url))
}

#[rocket::post("/login", data = "<form>")]
async fn login(
    cookies: &CookieJar<'_>,
    rp_config: &State<RpConfig>,
    form: rocket::form::Form<LoginForm>,
) -> Result<Redirect, RawHtml<String>> {
    let (user_hint, domain) = parse_identity(form.identity.trim());

    if domain.is_empty() {
        return Err(login_form(Some(
            "Please enter your identity (e.g. you@example.com)",
        )));
    }

    if !domain.contains('.') && !domain.contains(':') {
        return Err(login_form(Some(
            "That doesn't look like a domain. Try something like you@example.com or example.com",
        )));
    }

    begin_linkkeys_redirect(
        cookies,
        rp_config,
        domain,
        user_hint,
        demo_initial_claim_request(),
        None,
    )
    .await
}

#[rocket::post("/claims/age-checks")]
async fn request_age_checks(
    cookies: &CookieJar<'_>,
    rp_config: &State<RpConfig>,
) -> Result<Redirect, RawHtml<String>> {
    let session =
        get_session(cookies).ok_or_else(|| error_page("No active session found — log in first"))?;
    begin_linkkeys_redirect(
        cookies,
        rp_config,
        &session.domain,
        None,
        demo_age_update_claim_request(),
        Some(lk::AuthFlowContext {
            flow: "claims_update".to_string(),
            prior_session: Some(session.user_id),
            request_reason: Some("linkidspec.com now supports age-tier checks".to_string()),
        }),
    )
    .await
}

fn attestation_page(message: Option<&str>, error: Option<&str>) -> RawHtml<String> {
    let msg_html = message
        .map(|m| format!(r#"<p class="ok">{}</p>"#, html_escape(m)))
        .unwrap_or_default();
    let error_html = error
        .map(|e| format!(r#"<p class="err">{}</p>"#, html_escape(e)))
        .unwrap_or_default();
    RawHtml(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Demo App - Sign Claim</title>
<style>{style}</style>
</head>
<body>
<div class="narrow">
  <h1>LinkIDSpec Signature</h1>
  <p class="sub">Paste a LinkKeys signing request addressed to <strong>linkidspec.com</strong>. This demo will automatically sign <code>linkidspec_signed</code> with today's UTC date and try to deposit it back to your home domain.</p>
  <section class="card">
    {msg}
    {err}
    <form method="POST" action="/attest/linkidspec">
      <label for="request">Signing Request</label>
      <textarea id="request" name="request" rows="8" style="width:100%" required></textarea>
      <button type="submit">Sign Request</button>
    </form>
  </section>
  <p><a href="/">Back</a></p>
</div>
</body>
</html>"#,
        style = PAGE_STYLE,
        msg = msg_html,
        err = error_html,
    ))
}

#[rocket::get("/attest/linkidspec")]
fn attest_linkidspec_form() -> RawHtml<String> {
    attestation_page(None, None)
}

#[rocket::post("/attest/linkidspec", data = "<form>")]
async fn attest_linkidspec_submit(
    rp_config: &State<RpConfig>,
    form: rocket::form::Form<AttestationForm>,
) -> RawHtml<String> {
    use base64ct::{Base64UrlUnpadded, Encoding as _};

    let request_bytes = match Base64UrlUnpadded::decode_vec(form.request.trim()) {
        Ok(bytes) => bytes,
        Err(_) => {
            return attestation_page(
                None,
                Some("That does not look like base64url(CBOR(SignedSigningRequest))."),
            )
        }
    };
    let signed_request = match liblinkkeys::generated::decode_signed_signing_request(&request_bytes)
    {
        Ok(request) => request,
        Err(_) => {
            return attestation_page(None, Some("That signing request could not be decoded."))
        }
    };
    let today = chrono::Utc::now().date_naive().to_string();
    let resp = match rp_call(
        rp_config,
        "issue-attestation",
        lk::RpIssueAttestationRequest {
            signed_request,
            claim_type: "linkidspec_signed".to_string(),
            claim_value: today.as_bytes().to_vec(),
        },
        liblinkkeys::generated::encode_rp_issue_attestation_request,
        liblinkkeys::generated::decode_rp_issue_attestation_response,
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => return attestation_page(None, Some(&format!("Could not sign request: {}", e))),
    };
    let status = if resp.deposited {
        "signed and deposited to your home domain"
    } else {
        "signed, but deposit failed; try again later"
    };
    attestation_page(
        Some(&format!("Issued linkidspec_signed={} ({})", today, status)),
        None,
    )
}

#[rocket::get("/callback?<encrypted_token>")]
async fn callback(
    cookies: &CookieJar<'_>,
    rp_config: &State<RpConfig>,
    encrypted_token: &str,
) -> Result<Redirect, RawHtml<String>> {
    // 1. Retrieve and clear auth state
    let auth_state: AuthState = cookies
        .get_private("auth_state")
        .and_then(|c| serde_json::from_str(c.value()).ok())
        .ok_or_else(|| error_page("No auth state found — login flow may have expired"))?;
    cookies.remove_private("auth_state");

    // 2. Call the RP server (over TCP) to decrypt the token.
    let decrypt_result = rp_call(
        rp_config,
        "decrypt-token",
        lk::RpDecryptRequest {
            encrypted_token: encrypted_token.to_string(),
        },
        liblinkkeys::generated::encode_rp_decrypt_request,
        liblinkkeys::generated::decode_rp_decrypt_response,
    )
    .await
    .map_err(|e| error_page(&format!("Failed to decrypt token: {}", e)))?;

    // 3. Call the RP server to verify the assertion against the domain's keys.
    let verify_result = rp_call(
        rp_config,
        "verify-assertion",
        lk::RpVerifyRequest {
            signed_assertion: decrypt_result.signed_assertion.clone(),
            expected_domain: auth_state.domain.clone(),
        },
        liblinkkeys::generated::encode_rp_verify_request,
        liblinkkeys::generated::decode_rp_verify_response,
    )
    .await
    .map_err(|e| error_page(&format!("Failed to verify assertion: {}", e)))?;

    let assertion = &verify_result.assertion;

    // 4. Verify nonce
    if assertion.nonce != auth_state.nonce {
        return Err(error_page("Nonce mismatch — possible replay attack"));
    }

    // 5. Verify domain
    if assertion.domain != auth_state.domain {
        return Err(error_page("Domain mismatch"));
    }

    // 6. Fetch user info via our RP server. The IDP's /userinfo binds the
    // redemption to the audience (us), and only our RP server holds the domain
    // key — so we delegate the fetch to it rather than calling the IDP directly.
    let user_info = rp_call(
        rp_config,
        "userinfo-fetch",
        lk::RpUserInfoRequest {
            token: decrypt_result.signed_assertion.clone(),
            api_base: auth_state.api_base.clone(),
            domain: auth_state.domain.clone(),
        },
        liblinkkeys::generated::encode_rp_user_info_request,
        liblinkkeys::generated::decode_user_info,
    )
    .await
    .map_err(|e| error_page(&format!("Failed to fetch user info: {}", e)))?;

    let claims: Vec<SessionClaim> = user_info
        .claims
        .iter()
        .map(|c| {
            // claim_value is raw bytes (UTF-8 for the demo's text claims).
            let value = String::from_utf8_lossy(&c.claim_value).to_string();
            // Distinct signing domains, preserving first-seen order.
            let mut signing_domains: Vec<String> = Vec::new();
            for sig in &c.signatures {
                if !signing_domains.contains(&sig.domain) {
                    signing_domains.push(sig.domain.clone());
                }
            }
            SessionClaim {
                claim_type: c.claim_type.clone(),
                claim_value: value,
                signing_domains,
                key_count: c.signatures.len(),
            }
        })
        .collect();

    let missing_required: Vec<&str> = rp_config
        .required_claims
        .iter()
        .map(String::as_str)
        .filter(|required| !claims.iter().any(|c| c.claim_type == *required))
        .collect();
    if !missing_required.is_empty() {
        return Err(error_page(&format!(
            "Required claims were not shared: {}",
            missing_required.join(", ")
        )));
    }

    // 7. Build session
    let session = Session {
        user_id: user_info.user_id,
        domain: user_info.domain,
        display_name: user_info.display_name,
        claims,
        expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
    };

    set_session(cookies, &session);
    Ok(Redirect::found("/"))
}

#[rocket::post("/logout")]
fn logout(cookies: &CookieJar<'_>) -> Redirect {
    cookies.remove_private("session");
    Redirect::found("/")
}

// -- Launch --

fn generate_self_signed_cert() -> (String, String) {
    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("Failed to generate self-signed cert");
    (
        certified_key.cert.pem(),
        certified_key.key_pair.serialize_pem(),
    )
}

#[rocket::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let port: u16 = env::var("DEMO_PORT")
        .unwrap_or_else(|_| "9090".to_string())
        .parse()
        .unwrap_or(9090);

    let disable_tls = env::var("DISABLE_TLS").unwrap_or_default() == "true";

    let tls = if disable_tls {
        log::info!("Starting demoappsite HTTP on port {} (TLS disabled)", port);
        None
    } else {
        log::info!("Starting demoappsite HTTPS on port {}", port);
        let (cert_pem, key_pem) = generate_self_signed_cert();
        Some(rocket::config::TlsConfig::from_bytes(
            cert_pem.as_bytes(),
            key_pem.as_bytes(),
        ))
    };

    let config = Config {
        port,
        address: "0.0.0.0".parse().unwrap(),
        tls,
        secret_key: rocket::config::SecretKey::generate().expect("Failed to generate secret key"),
        ..Config::default()
    };

    let rp_config = RpConfig {
        tcp_addr: env::var("RP_TCP_ADDR")
            .unwrap_or_else(|_| format!("127.0.0.1:{}", liblinkkeys::dns::DEFAULT_TCP_PORT)),
        fingerprints: env::var("RP_FINGERPRINTS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        api_key: env::var("RP_API_KEY").unwrap_or_else(|_| {
            log::warn!("RP_API_KEY not set — RP service calls will fail");
            String::new()
        }),
        domain: env::var("RP_DOMAIN").unwrap_or_else(|_| "localhost".to_string()),
        required_claims: parse_claim_list(
            &env::var("REQUIRED_CLAIMS").unwrap_or_else(|_| "display_name,handle".to_string()),
        ),
    };
    if rp_config.fingerprints.is_empty() {
        log::warn!(
            "RP_FINGERPRINTS not set — TCP calls to the RP server will fail to pin its cert"
        );
    }

    if let Err(e) = rocket::custom(config)
        .mount(
            "/",
            rocket::routes![
                index,
                login,
                request_age_checks,
                attest_linkidspec_form,
                attest_linkidspec_submit,
                callback,
                logout
            ],
        )
        .manage(rp_config)
        .launch()
        .await
    {
        log::error!("demoappsite failed: {}", e);
        std::process::exit(1);
    }
}
