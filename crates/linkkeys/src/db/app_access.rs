//! Persistence for app access policies (`app_access_policies`,
//! `app_access_policy_patterns`, `app_access_policy_targets`). Pure storage
//! only; validation and evaluation live in `crate::services::app_access` and
//! `liblinkkeys::app_access`.
//!
//! A policy is always written whole: `save` replaces its patterns and targets
//! in one transaction, so a reader never sees half of an edit.

use crate::db::models::{AppAccessPolicy, AppAccessTarget};
use std::collections::HashMap;

fn assemble(
    policies: Vec<(String, String, String, Option<String>)>,
    patterns: Vec<(String, String)>,
    targets: Vec<(String, AppAccessTarget)>,
) -> Vec<AppAccessPolicy> {
    let mut patterns_by_policy: HashMap<String, Vec<String>> = HashMap::new();
    for (policy_id, pattern) in patterns {
        patterns_by_policy
            .entry(policy_id)
            .or_default()
            .push(pattern);
    }
    let mut targets_by_policy: HashMap<String, Vec<AppAccessTarget>> = HashMap::new();
    for (policy_id, target) in targets {
        targets_by_policy.entry(policy_id).or_default().push(target);
    }
    policies
        .into_iter()
        .map(|(id, name, mode, message)| AppAccessPolicy {
            patterns: patterns_by_policy.remove(&id).unwrap_or_default(),
            targets: targets_by_policy.remove(&id).unwrap_or_default(),
            id,
            name,
            mode,
            message,
        })
        .collect()
}

#[cfg(feature = "postgres")]
pub mod pg {
    use super::assemble;
    use crate::db::models::pg::{AppAccessPatternRow, AppAccessPolicyRow, AppAccessTargetRow};
    use crate::db::models::{AppAccessPolicy, AppAccessTarget};
    use crate::schema::pg::{
        app_access_policies, app_access_policy_patterns, app_access_policy_targets,
    };
    use diesel::prelude::*;

    fn parse_id(id: &str) -> QueryResult<uuid::Uuid> {
        id.parse().map_err(|_| diesel::result::Error::NotFound)
    }

    pub fn list(conn: &mut diesel::PgConnection) -> QueryResult<Vec<AppAccessPolicy>> {
        let policies: Vec<AppAccessPolicyRow> = app_access_policies::table
            .order(app_access_policies::name.asc())
            .select(AppAccessPolicyRow::as_select())
            .load(conn)?;
        let patterns: Vec<AppAccessPatternRow> = app_access_policy_patterns::table
            .order(app_access_policy_patterns::pattern.asc())
            .select(AppAccessPatternRow::as_select())
            .load(conn)?;
        let targets: Vec<AppAccessTargetRow> = app_access_policy_targets::table
            .order(app_access_policy_targets::id.asc())
            .select(AppAccessTargetRow::as_select())
            .load(conn)?;
        Ok(assemble(
            policies
                .into_iter()
                .map(|r| (r.id.to_string(), r.name, r.mode, r.message))
                .collect(),
            patterns
                .into_iter()
                .map(|r| (r.policy_id.to_string(), r.pattern))
                .collect(),
            targets
                .into_iter()
                .map(|r| {
                    (
                        r.policy_id.to_string(),
                        AppAccessTarget {
                            kind: r.kind,
                            user_id: r.user_id.map(|id| id.to_string()),
                            group_name: r.group_name,
                            claim_type: r.claim_type,
                            claim_operator: r.claim_operator,
                            claim_value: r.claim_value,
                        },
                    )
                })
                .collect(),
        ))
    }

    pub fn save(conn: &mut diesel::PgConnection, policy: &AppAccessPolicy) -> QueryResult<()> {
        let id = parse_id(&policy.id)?;
        let targets = policy
            .targets
            .iter()
            .map(|t| {
                Ok(AppAccessTargetRow {
                    id: uuid::Uuid::now_v7(),
                    policy_id: id,
                    kind: t.kind.clone(),
                    user_id: t.user_id.as_deref().map(parse_id).transpose()?,
                    group_name: t.group_name.clone(),
                    claim_type: t.claim_type.clone(),
                    claim_operator: t.claim_operator.clone(),
                    claim_value: t.claim_value.clone(),
                })
            })
            .collect::<QueryResult<Vec<_>>>()?;
        conn.transaction(|conn| {
            let row = AppAccessPolicyRow {
                id,
                name: policy.name.clone(),
                mode: policy.mode.clone(),
                message: policy.message.clone(),
            };
            diesel::insert_into(app_access_policies::table)
                .values(&row)
                .on_conflict(app_access_policies::id)
                .do_update()
                .set(&row)
                .execute(conn)?;
            diesel::delete(
                app_access_policy_patterns::table
                    .filter(app_access_policy_patterns::policy_id.eq(id)),
            )
            .execute(conn)?;
            diesel::delete(
                app_access_policy_targets::table
                    .filter(app_access_policy_targets::policy_id.eq(id)),
            )
            .execute(conn)?;
            let patterns: Vec<AppAccessPatternRow> = policy
                .patterns
                .iter()
                .map(|pattern| AppAccessPatternRow {
                    policy_id: id,
                    pattern: pattern.clone(),
                })
                .collect();
            diesel::insert_into(app_access_policy_patterns::table)
                .values(&patterns)
                .execute(conn)?;
            diesel::insert_into(app_access_policy_targets::table)
                .values(&targets)
                .execute(conn)?;
            Ok(())
        })
    }

    pub fn delete(conn: &mut diesel::PgConnection, id: &str) -> QueryResult<usize> {
        diesel::delete(app_access_policies::table.find(parse_id(id)?)).execute(conn)
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use super::assemble;
    use crate::db::models::sqlite::{AppAccessPatternRow, AppAccessPolicyRow, AppAccessTargetRow};
    use crate::db::models::{AppAccessPolicy, AppAccessTarget};
    use crate::schema::sqlite::{
        app_access_policies, app_access_policy_patterns, app_access_policy_targets,
    };
    use diesel::prelude::*;

    pub fn list(conn: &mut diesel::SqliteConnection) -> QueryResult<Vec<AppAccessPolicy>> {
        let policies: Vec<AppAccessPolicyRow> = app_access_policies::table
            .order(app_access_policies::name.asc())
            .select(AppAccessPolicyRow::as_select())
            .load(conn)?;
        let patterns: Vec<AppAccessPatternRow> = app_access_policy_patterns::table
            .order(app_access_policy_patterns::pattern.asc())
            .select(AppAccessPatternRow::as_select())
            .load(conn)?;
        let targets: Vec<AppAccessTargetRow> = app_access_policy_targets::table
            .order(app_access_policy_targets::id.asc())
            .select(AppAccessTargetRow::as_select())
            .load(conn)?;
        Ok(assemble(
            policies
                .into_iter()
                .map(|r| (r.id, r.name, r.mode, r.message))
                .collect(),
            patterns
                .into_iter()
                .map(|r| (r.policy_id, r.pattern))
                .collect(),
            targets
                .into_iter()
                .map(|r| {
                    (
                        r.policy_id,
                        AppAccessTarget {
                            kind: r.kind,
                            user_id: r.user_id,
                            group_name: r.group_name,
                            claim_type: r.claim_type,
                            claim_operator: r.claim_operator,
                            claim_value: r.claim_value,
                        },
                    )
                })
                .collect(),
        ))
    }

    pub fn save(conn: &mut diesel::SqliteConnection, policy: &AppAccessPolicy) -> QueryResult<()> {
        conn.transaction(|conn| {
            let row = AppAccessPolicyRow {
                id: policy.id.clone(),
                name: policy.name.clone(),
                mode: policy.mode.clone(),
                message: policy.message.clone(),
            };
            diesel::insert_into(app_access_policies::table)
                .values(&row)
                .on_conflict(app_access_policies::id)
                .do_update()
                .set(&row)
                .execute(conn)?;
            diesel::delete(
                app_access_policy_patterns::table
                    .filter(app_access_policy_patterns::policy_id.eq(&policy.id)),
            )
            .execute(conn)?;
            diesel::delete(
                app_access_policy_targets::table
                    .filter(app_access_policy_targets::policy_id.eq(&policy.id)),
            )
            .execute(conn)?;
            for pattern in &policy.patterns {
                diesel::insert_into(app_access_policy_patterns::table)
                    .values(&AppAccessPatternRow {
                        policy_id: policy.id.clone(),
                        pattern: pattern.clone(),
                    })
                    .execute(conn)?;
            }
            for target in &policy.targets {
                diesel::insert_into(app_access_policy_targets::table)
                    .values(&AppAccessTargetRow {
                        id: uuid::Uuid::now_v7().to_string(),
                        policy_id: policy.id.clone(),
                        kind: target.kind.clone(),
                        user_id: target.user_id.clone(),
                        group_name: target.group_name.clone(),
                        claim_type: target.claim_type.clone(),
                        claim_operator: target.claim_operator.clone(),
                        claim_value: target.claim_value.clone(),
                    })
                    .execute(conn)?;
            }
            Ok(())
        })
    }

    pub fn delete(conn: &mut diesel::SqliteConnection, id: &str) -> QueryResult<usize> {
        diesel::delete(app_access_policies::table.find(id)).execute(conn)
    }
}
