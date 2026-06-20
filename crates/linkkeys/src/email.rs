//! Outbound email seam. There is no SMTP integration yet: by default we log the
//! message (including the verification link) at info level so dogfood deployments
//! can complete the flow by copying the link from the logs. A real provider
//! plugs in here behind the same `send` function.
//!
//! TODO(later-session): add an SMTP / provider backend gated by env config
//! (e.g. `SMTP_URL`); keep the log fallback for local/dev.

/// Send an email. Returns `Ok` once handed off (here: logged). Never logs the
/// body at a level that would leak secrets in production — the verification link
/// is a single-use, short-lived token, logged at info deliberately for dogfood.
pub fn send(to: &str, subject: &str, body: &str) -> Result<(), String> {
    log::info!("[email] to={} subject={:?}\n{}", to, subject, body);
    Ok(())
}

/// Convenience for the verification message.
pub fn send_verification_email(to: &str, link: &str) -> Result<(), String> {
    let body = format!(
        "Confirm this email address to verify it with your LinkKeys domain:\n\n{}\n\nIf you didn't request this, ignore this message.",
        link
    );
    send(to, "Verify your email address", &body)
}
