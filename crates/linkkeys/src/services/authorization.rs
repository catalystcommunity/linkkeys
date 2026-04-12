use crate::db::DbPool;

pub const RELATION_ADMIN: &str = "admin";
pub const RELATION_MANAGE_USERS: &str = "manage_users";
pub const RELATION_MANAGE_CLAIMS: &str = "manage_claims";
pub const RELATION_API_ACCESS: &str = "api_access";

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

/// Map admin service operations to required relations.
/// Returns None for Account ops (self-service, no relation needed).
pub fn required_relation_for_op(service: &str, op: &str) -> Option<&'static str> {
    match service {
        "Admin" => Some(match op {
            "list-users" | "get-user" | "create-user" | "update-user"
            | "deactivate-user" | "reset-password" | "remove-credential" => RELATION_MANAGE_USERS,
            "set-claim" | "remove-claim" => RELATION_MANAGE_CLAIMS,
            "grant-relation" | "remove-relation" | "list-relations" | "check-permission" => {
                RELATION_ADMIN
            }
            _ => RELATION_ADMIN,
        }),
        "Account" => None, // Self-service, no relation needed
        _ => None,
    }
}
