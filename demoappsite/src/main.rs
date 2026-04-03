use rocket::form::FromForm;
use rocket::http::{Cookie, CookieJar, SameSite};
use rocket::response::content::RawHtml;
use rocket::response::Redirect;
use rocket::{Config, State};
use serde::{Deserialize, Serialize};
use std::env;

use liblinkkeys::generated::types::UserInfo;

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
    signed_by_fingerprint: String,
}

/// Stored in a cookie during the login redirect to verify the callback.
#[derive(Serialize, Deserialize)]
struct AuthState {
    nonce: String,
    domain: String,
    api_base: String,
}

fn get_own_origin() -> String {
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
<html>
<head><title>Demo App - Error</title>
<style>
body {{ font-family: sans-serif; max-width: 500px; margin: 80px auto; }}
.error {{ color: red; background: #fff0f0; padding: 16px; border-radius: 4px; }}
a {{ display: inline-block; margin-top: 16px; }}
</style>
</head>
<body>
<h2>Authentication Error</h2>
<div class="error"><p>{}</p></div>
<a href="/">Back to login</a>
</body>
</html>"#,
        html_escape(message)
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
<html>
<head><title>Demo App - LinkKeys Login</title>
<style>
body {{ font-family: sans-serif; max-width: 500px; margin: 80px auto; }}
input {{ display: block; width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; }}
button {{ padding: 10px 20px; margin-top: 12px; cursor: pointer; }}
.error {{ color: red; }}
h2 {{ color: #333; }}
.info {{ background: #f0f0f0; padding: 12px; border-radius: 4px; margin: 16px 0; font-size: 0.9em; }}
</style>
</head>
<body>
<h2>Demo Application</h2>
<p>This site uses <strong>LinkKeys</strong> for authentication.</p>
<div class="info">Enter your identity as <code>username@domain</code> or just <code>domain</code> to log in.</div>
{error}
<form method="POST" action="/login">
  <label>Your Identity</label>
  <input type="text" name="identity" placeholder="you@example.com" autofocus />
  <button type="submit">Log In with LinkKeys</button>
</form>
</body>
</html>"#,
        error = error_html,
    ))
}

fn dashboard(session: &Session) -> RawHtml<String> {
    let mut claims_html = String::new();
    if session.claims.is_empty() {
        claims_html.push_str("<p><em>No claims shared.</em></p>");
    } else {
        claims_html.push_str("<table><tr><th>Type</th><th>Value</th><th>Signed By</th></tr>");
        for c in &session.claims {
            let short_fp = if c.signed_by_fingerprint.len() >= 16 {
                &c.signed_by_fingerprint[..16]
            } else {
                &c.signed_by_fingerprint
            };
            claims_html.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td><code title=\"{fp}\">{short}...</code></td></tr>",
                html_escape(&c.claim_type),
                html_escape(&c.claim_value),
                fp = html_escape(&c.signed_by_fingerprint),
                short = html_escape(short_fp),
            ));
        }
        claims_html.push_str("</table>");
    }

    RawHtml(format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Demo App - Dashboard</title>
<style>
body {{ font-family: sans-serif; max-width: 600px; margin: 80px auto; }}
table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #f5f5f5; }}
code {{ background: #eee; padding: 2px 4px; border-radius: 2px; font-size: 0.85em; }}
button {{ padding: 10px 20px; margin-top: 12px; cursor: pointer; background: #c00; color: white; border: none; border-radius: 4px; }}
.identity {{ background: #f0f8f0; padding: 16px; border-radius: 4px; margin: 16px 0; }}
.verified {{ color: green; font-weight: bold; }}
</style>
</head>
<body>
<h2>Demo App Dashboard</h2>
<p class="verified">Identity cryptographically verified</p>
<div class="identity">
  <p><strong>User ID:</strong> <code>{user_id}</code></p>
  <p><strong>Domain:</strong> <code>{domain}</code></p>
  <p><strong>Display Name:</strong> {display_name}</p>
  <p><strong>Identity:</strong> <code>{user_id}@{domain}</code></p>
</div>
<h3>Claims</h3>
{claims}
<form method="POST" action="/logout">
  <button type="submit">Log Out</button>
</form>
</body>
</html>"#,
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

/// Resolve a domain's LinkKeys API base URL via DNS TXT lookup.
/// Falls back to `https://{domain}` if no TXT record is found.
async fn resolve_api_base(domain: &str) -> String {
    use hickory_resolver::TokioAsyncResolver;

    let dns_name = liblinkkeys::dns::linkkeys_dns_name(domain);

    let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(e) => {
            log::warn!("DNS resolver init failed, falling back to direct: {}", e);
            return format!("https://{}", domain);
        }
    };

    match resolver.txt_lookup(&dns_name).await {
        Ok(response) => {
            for record in response.iter() {
                let txt = record.to_string();
                if let Ok(parsed) = liblinkkeys::dns::parse_linkkeys_txt(&txt) {
                    log::info!("Resolved {} -> {}", domain, parsed.api_base);
                    return parsed.api_base;
                }
            }
            log::info!("No LinkKeys TXT record for {}, using direct", domain);
            format!("https://{}", domain)
        }
        Err(e) => {
            log::info!("DNS lookup failed for {}: {}, using direct", dns_name, e);
            format!("https://{}", domain)
        }
    }
}

#[rocket::post("/login", data = "<form>")]
async fn login(cookies: &CookieJar<'_>, form: rocket::form::Form<LoginForm>) -> Result<Redirect, RawHtml<String>> {
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
        "{}/auth/authorize?callback_url={}&nonce={}&user_hint={}",
        api_base,
        simple_url_encode(&callback_url),
        simple_url_encode(&nonce),
        simple_url_encode(user_hint.unwrap_or("")),
    );

    Ok(Redirect::found(redirect_url))
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

#[rocket::get("/callback?<token>")]
async fn callback(
    cookies: &CookieJar<'_>,
    client: &State<reqwest::Client>,
    token: &str,
) -> Result<Redirect, RawHtml<String>> {
    let err = |msg: &str| Err(error_page(msg));

    // 1. Retrieve and clear auth state (nonce + expected domain)
    let auth_state: AuthState = cookies
        .get_private("auth_state")
        .and_then(|c| serde_json::from_str(c.value()).ok())
        .ok_or_else(|| error_page("No auth state found — login flow may have expired"))?;
    cookies.remove_private("auth_state");

    // 2. Decode the assertion to get domain and nonce
    let signed = liblinkkeys::encoding::assertion_from_url_param(token)
        .map_err(|_| error_page("Invalid token encoding"))?;

    let inner_assertion: liblinkkeys::generated::types::IdentityAssertion =
        ciborium::de::from_reader(signed.assertion.as_slice())
            .map_err(|_| error_page("Failed to decode assertion"))?;

    // 3. Verify nonce matches what we sent
    if inner_assertion.nonce != auth_state.nonce {
        return err("Nonce mismatch — possible replay attack");
    }

    // 4. Verify domain matches what the user requested login to
    if inner_assertion.domain != auth_state.domain {
        return err("Domain mismatch — assertion came from a different domain than requested");
    }

    // 5. Fetch domain keys using the resolved API base (from DNS or fallback)
    let api_base = &auth_state.api_base;
    let keys_url = format!("{}/v1alpha/domain-keys", api_base);
    let keys_resp = client
        .get(&keys_url)
        .send()
        .await
        .map_err(|e| error_page(&format!("Failed to fetch domain keys from {}: {}", keys_url, e)))?;

    let keys_bytes = keys_resp
        .bytes()
        .await
        .map_err(|e| error_page(&format!("Failed to read domain keys response: {}", e)))?;

    let domain_keys_resp: liblinkkeys::generated::types::GetDomainKeysResponse =
        ciborium::de::from_reader(keys_bytes.as_ref())
            .map_err(|e| error_page(&format!("Failed to decode domain keys: {}", e)))?;

    // 6. Verify the signature against the domain's public keys
    liblinkkeys::assertions::verify_assertion(&signed, &domain_keys_resp.keys)
        .map_err(|e| error_page(&format!("Assertion verification failed: {}", e)))?;

    // 7. Fetch user info + claims from domain server using the token
    let userinfo_url = format!("{}/v1alpha/userinfo.json", api_base);
    let userinfo_resp = client
        .post(&userinfo_url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&serde_json::json!({"token": token})).unwrap())
        .send()
        .await
        .map_err(|e| error_page(&format!("Failed to fetch user info: {}", e)))?;

    let userinfo_text = userinfo_resp
        .text()
        .await
        .map_err(|e| error_page(&format!("Failed to read user info: {}", e)))?;

    let user_info: UserInfo = serde_json::from_str(&userinfo_text)
        .map_err(|e| error_page(&format!("Failed to decode user info: {}", e)))?;

    // 8. Build fingerprint lookup from domain keys
    let key_fingerprints: std::collections::HashMap<String, String> = domain_keys_resp
        .keys
        .iter()
        .map(|k| (k.key_id.clone(), k.fingerprint.clone()))
        .collect();

    // 9. Set session cookie
    let session = Session {
        user_id: user_info.user_id,
        domain: user_info.domain,
        display_name: user_info.display_name,
        claims: user_info
            .claims
            .iter()
            .map(|c| SessionClaim {
                claim_type: c.claim_type.clone(),
                claim_value: String::from_utf8_lossy(&c.claim_value).to_string(),
                signed_by_fingerprint: key_fingerprints
                    .get(&c.signed_by_key_id)
                    .cloned()
                    .unwrap_or_else(|| c.signed_by_key_id.clone()),
            })
            .collect(),
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

    if let Err(e) = rocket::custom(config)
        .mount("/", rocket::routes![index, login, callback, logout])
        .manage(client)
        .launch()
        .await
    {
        log::error!("demoappsite failed: {}", e);
        std::process::exit(1);
    }
}
