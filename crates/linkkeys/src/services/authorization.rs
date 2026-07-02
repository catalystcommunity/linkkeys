use crate::db::DbPool;

pub const RELATION_ADMIN: &str = "admin";
pub const RELATION_MANAGE_USERS: &str = "manage_users";
pub const RELATION_MANAGE_CLAIMS: &str = "manage_claims";
pub const RELATION_API_ACCESS: &str = "api_access";
pub const RELATION_ISSUE_CLAIMS: &str = "issue_claims";

/// Check if a user has a specific permission on an object.
/// admin relation implies all others on the same object.
/// Uses DbPool::check_permission which handles group traversal.
pub fn user_has_permission(
    pool: &DbPool,
    user_id: &str,
    relation: &str,
    object_type: &str,
    object_id: &str,
) -> bool {
    pool.check_permission(user_id, relation, object_type, object_id)
        .unwrap_or(false)
}

/// A target user is "protected" — only a full `admin` may reset its password,
/// deactivate it, or remove its credentials — if it is a bootstrap admin account
/// (`is_admin_account`) or currently holds the `admin` relation on the domain.
/// This closes the escalation where a `manage_users` operator seizes an admin
/// account via password reset (SEC-04). Fail closed: a lookup error treats the
/// target as protected.
pub fn is_protected_admin_target(pool: &DbPool, target_user_id: &str) -> bool {
    match pool.find_user_by_id(target_user_id) {
        Ok(u) if u.is_admin_account => return true,
        Ok(_) => {}
        Err(diesel::result::Error::NotFound) => return false,
        Err(_) => return true,
    }
    let domain = crate::conversions::get_domain_name();
    user_has_permission(pool, target_user_id, RELATION_ADMIN, "domain", &domain)
}

/// Whether `caller_id` is permitted to perform an account-takeover-capable
/// operation (reset-password / deactivate / remove-credential) against
/// `target_user_id`. A protected admin target may only be managed by a caller
/// who also holds `admin`. Non-protected targets are governed by the ordinary
/// `manage_users` relation checked at the call site.
pub fn caller_may_manage_target(pool: &DbPool, caller_id: &str, target_user_id: &str) -> bool {
    if !is_protected_admin_target(pool, target_user_id) {
        return true;
    }
    let domain = crate::conversions::get_domain_name();
    user_has_permission(pool, caller_id, RELATION_ADMIN, "domain", &domain)
}

/// Map admin service operations to required relations.
/// Returns None for Account ops (self-service, no relation needed).
pub fn required_relation_for_op(service: &str, op: &str) -> Option<&'static str> {
    match service {
        "Admin" => Some(match op {
            "list-users" | "get-user" | "create-user" | "update-user" | "deactivate-user"
            | "reset-password" | "remove-credential" => RELATION_MANAGE_USERS,
            "set-claim" | "remove-claim" => RELATION_MANAGE_CLAIMS,
            "grant-relation" | "remove-relation" | "list-relations" | "check-permission" => {
                RELATION_ADMIN
            }
            _ => RELATION_ADMIN,
        }),
        // The Rp service exposes the domain signing/decryption keys as oracles
        // (sign-request, decrypt-token) to a browser-facing RP server. It must
        // require a dedicated api_access relation, not merely a valid API key —
        // otherwise any active user's key can drive those oracles (SEC-06).
        "Rp" => Some(RELATION_API_ACCESS),
        "Account" => None, // Self-service, no relation needed
        _ => None,
    }
}
