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

/// Configuration for the RP service connection.
struct RpConfig {
    service_url: String,
    api_key: String,
    domain: String,
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

fn build_reqwest_client() -> reqwest::Client {
    let mut builder = reqwest::Client::builder();
    if env::var("ALLOW_INVALID_CERTS").unwrap_or_default() == "true" {
        log::warn!("TLS certificate verification disabled (ALLOW_INVALID_CERTS=true)");
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build().expect("Failed to build HTTP client")
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
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

/// Response from the RP service's /v1alpha/sign-request.json endpoint
#[derive(Deserialize)]
struct SignRequestResponse {
    signed_request: String,
}

/// Response from the RP service's /v1alpha/decrypt-token.json endpoint
#[derive(Deserialize)]
struct DecryptTokenResponse {
    signed_assertion: String,
}

/// Response from the RP service's /v1alpha/verify-assertion.json endpoint
#[derive(Deserialize)]
struct VerifyAssertionResponse {
    assertion: AssertionData,
    #[allow(dead_code)]
    verified: bool,
}

#[derive(Deserialize)]
struct AssertionData {
    #[allow(dead_code)]
    user_id: String,
    domain: String,
    nonce: String,
    #[allow(dead_code)]
    audience: String,
    #[allow(dead_code)]
    display_name: Option<String>,
}

/// User info response from the domain server's /v1alpha/userinfo.json endpoint
#[derive(Deserialize)]
struct UserInfoResponse {
    user_id: String,
    domain: String,
    display_name: String,
    claims: Vec<ClaimResponse>,
}

#[derive(Deserialize)]
struct ClaimResponse {
    claim_type: String,
    claim_value: serde_json::Value,
    signatures: Vec<ClaimSignatureResponse>,
}

#[derive(Deserialize)]
struct ClaimSignatureResponse {
    domain: String,
    // signed_by_key_id / signature are present on the wire but unused for display.
}

#[rocket::post("/login", data = "<form>")]
async fn login(
    cookies: &CookieJar<'_>,
    client: &State<reqwest::Client>,
    rp_config: &State<RpConfig>,
    form: rocket::form::Form<LoginForm>,
) -> Result<Redirect, RawHtml<String>> {
    let (user_hint, domain) = parse_identity(form.identity.trim());

    if domain.is_empty() {
        return Err(login_form(Some("Please enter your identity (e.g. you@example.com)")));
    }

    if !domain.contains('.') && !domain.contains(':') {
        return Err(login_form(Some(
            "That doesn't look like a domain. Try something like you@example.com or example.com",
        )));
    }

    let api_base = resolve_api_base(domain).await;
    let nonce = uuid::Uuid::new_v4().to_string();
    let origin = get_own_origin();
    let callback_url = format!("{}/callback", origin);

    // Call RP service to sign the auth request
    let sign_resp = client
        .post(format!("{}/v1alpha/sign-request.json", rp_config.service_url))
        .header("Authorization", format!("Bearer {}", rp_config.api_key))
        .json(&serde_json::json!({
            "callback_url": callback_url,
            "nonce": nonce,
        }))
        .send()
        .await
        .map_err(|e| login_form(Some(&format!("Failed to contact RP service: {}", e))))?;

    if !sign_resp.status().is_success() {
        return Err(login_form(Some("RP service failed to sign auth request")));
    }

    let sign_result: SignRequestResponse = sign_resp
        .json()
        .await
        .map_err(|e| login_form(Some(&format!("Invalid RP service response: {}", e))))?;

    // Store auth state for callback verification
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

    // Redirect to domain server with signed request
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

#[rocket::get("/callback?<encrypted_token>")]
async fn callback(
    cookies: &CookieJar<'_>,
    client: &State<reqwest::Client>,
    rp_config: &State<RpConfig>,
    encrypted_token: &str,
) -> Result<Redirect, RawHtml<String>> {
    // 1. Retrieve and clear auth state
    let auth_state: AuthState = cookies
        .get_private("auth_state")
        .and_then(|c| serde_json::from_str(c.value()).ok())
        .ok_or_else(|| error_page("No auth state found — login flow may have expired"))?;
    cookies.remove_private("auth_state");

    // 2. Call RP service to decrypt the token
    let decrypt_resp = client
        .post(format!("{}/v1alpha/decrypt-token.json", rp_config.service_url))
        .header("Authorization", format!("Bearer {}", rp_config.api_key))
        .json(&serde_json::json!({ "encrypted_token": encrypted_token }))
        .send()
        .await
        .map_err(|e| error_page(&format!("Failed to decrypt token: {}", e)))?;

    if !decrypt_resp.status().is_success() {
        return Err(error_page("RP service failed to decrypt token"));
    }

    let decrypt_result: DecryptTokenResponse = decrypt_resp
        .json()
        .await
        .map_err(|e| error_page(&format!("Invalid decrypt response: {}", e)))?;

    // 3. Call RP service to verify the assertion against the domain's keys
    let verify_resp = client
        .post(format!("{}/v1alpha/verify-assertion.json", rp_config.service_url))
        .header("Authorization", format!("Bearer {}", rp_config.api_key))
        .json(&serde_json::json!({
            "signed_assertion": decrypt_result.signed_assertion,
            "expected_domain": auth_state.domain,
        }))
        .send()
        .await
        .map_err(|e| error_page(&format!("Failed to verify assertion: {}", e)))?;

    if !verify_resp.status().is_success() {
        return Err(error_page("Assertion verification failed"));
    }

    let verify_result: VerifyAssertionResponse = verify_resp
        .json()
        .await
        .map_err(|e| error_page(&format!("Invalid verify response: {}", e)))?;

    let assertion = &verify_result.assertion;

    // 4. Verify nonce
    if assertion.nonce != auth_state.nonce {
        return Err(error_page("Nonce mismatch — possible replay attack"));
    }

    // 5. Verify domain
    if assertion.domain != auth_state.domain {
        return Err(error_page("Domain mismatch"));
    }

    // 6. Fetch user info via our RP service. The IDP's /userinfo now requires a
    // proof-of-possession signature binding the request to us (the audience),
    // and only our RP service holds the domain signing key — so we delegate the
    // sign-and-fetch to it rather than calling the IDP directly.
    let userinfo_resp = client
        .post(format!("{}/v1alpha/userinfo-fetch.json", rp_config.service_url))
        .header("Authorization", format!("Bearer {}", rp_config.api_key))
        .json(&serde_json::json!({
            "token": decrypt_result.signed_assertion,
            "api_base": auth_state.api_base,
        }))
        .send()
        .await
        .map_err(|e| error_page(&format!("Failed to fetch user info: {}", e)))?;

    let user_info: UserInfoResponse = userinfo_resp
        .json()
        .await
        .map_err(|e| error_page(&format!("Failed to decode user info: {}", e)))?;

    // 7. Build session
    let session = Session {
        user_id: user_info.user_id,
        domain: user_info.domain,
        display_name: user_info.display_name,
        claims: user_info.claims.iter().map(|c| {
            let value = match &c.claim_value {
                serde_json::Value::Array(arr) => {
                    // CBOR bytes come as JSON array of integers
                    let bytes: Vec<u8> = arr.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect();
                    String::from_utf8_lossy(&bytes).to_string()
                }
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
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
        }).collect(),
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
    (certified_key.cert.pem(), certified_key.key_pair.serialize_pem())
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
        secret_key: rocket::config::SecretKey::generate()
            .expect("Failed to generate secret key"),
        ..Config::default()
    };

    let client = build_reqwest_client();

    let rp_config = RpConfig {
        service_url: env::var("RP_SERVICE_URL")
            .unwrap_or_else(|_| "https://127.0.0.1:8443".to_string()),
        api_key: env::var("RP_API_KEY")
            .unwrap_or_else(|_| {
                log::warn!("RP_API_KEY not set — RP service calls will fail");
                String::new()
            }),
        domain: env::var("RP_DOMAIN")
            .unwrap_or_else(|_| "localhost".to_string()),
    };

    if let Err(e) = rocket::custom(config)
        .mount("/", rocket::routes![index, login, callback, logout])
        .manage(client)
        .manage(rp_config)
        .launch()
        .await
    {
        log::error!("demoappsite failed: {}", e);
        std::process::exit(1);
    }
}
