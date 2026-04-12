#[cfg(feature = "postgres")]
pub mod pg {
    use diesel::prelude::*;

    use crate::db::models::pg::{NewRelationRow, RelationRow};
    use crate::db::models::Relation;
    use crate::schema::pg::relations;

    pub fn create(
        conn: &mut diesel::PgConnection,
        subject_type: &str,
        subject_id: &str,
        relation: &str,
        object_type: &str,
        object_id: &str,
    ) -> QueryResult<Relation> {
        let new_row = NewRelationRow {
            id: uuid::Uuid::now_v7(),
            subject_type: subject_type.to_string(),
            subject_id: subject_id.to_string(),
            relation: relation.to_string(),
            object_type: object_type.to_string(),
            object_id: object_id.to_string(),
        };

        diesel::insert_into(relations::table)
            .values(&new_row)
            .get_result::<RelationRow>(conn)
            .map(Into::into)
    }

    pub fn remove(conn: &mut diesel::PgConnection, relation_id: &str) -> QueryResult<Relation> {
        let id: uuid::Uuid = relation_id
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        diesel::update(relations::table.find(id))
            .set((
                relations::removed_at.eq(Some(chrono::Utc::now())),
                relations::updated_at.eq(chrono::Utc::now()),
            ))
            .get_result::<RelationRow>(conn)
            .map(Into::into)
    }

    pub fn list_for_subject(
        conn: &mut diesel::PgConnection,
        subject_type: &str,
        subject_id: &str,
    ) -> QueryResult<Vec<Relation>> {
        relations::table
            .filter(relations::subject_type.eq(subject_type))
            .filter(relations::subject_id.eq(subject_id))
            .filter(relations::removed_at.is_null())
            .load::<RelationRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn list_for_object(
        conn: &mut diesel::PgConnection,
        object_type: &str,
        object_id: &str,
    ) -> QueryResult<Vec<Relation>> {
        relations::table
            .filter(relations::object_type.eq(object_type))
            .filter(relations::object_id.eq(object_id))
            .filter(relations::removed_at.is_null())
            .load::<RelationRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn check_direct(
        conn: &mut diesel::PgConnection,
        subject_type: &str,
        subject_id: &str,
        relation: &str,
        object_type: &str,
        object_id: &str,
    ) -> QueryResult<bool> {
        use diesel::dsl::exists;
        use diesel::select;

        select(exists(
            relations::table
                .filter(relations::subject_type.eq(subject_type))
                .filter(relations::subject_id.eq(subject_id))
                .filter(relations::relation.eq(relation))
                .filter(relations::object_type.eq(object_type))
                .filter(relations::object_id.eq(object_id))
                .filter(relations::removed_at.is_null()),
        ))
        .get_result(conn)
    }

    pub fn find_by_id(conn: &mut diesel::PgConnection, id: &str) -> QueryResult<Relation> {
        let uid: uuid::Uuid = id
            .parse()
            .map_err(|_| diesel::result::Error::NotFound)?;
        relations::table
            .find(uid)
            .first::<RelationRow>(conn)
            .map(Into::into)
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite {
    use diesel::prelude::*;

    use crate::db::models::sqlite::{NewRelationRow, RelationRow};
    use crate::db::models::Relation;
    use crate::schema::sqlite::relations;

    pub fn create(
        conn: &mut diesel::SqliteConnection,
        subject_type: &str,
        subject_id: &str,
        relation: &str,
        object_type: &str,
        object_id: &str,
    ) -> QueryResult<Relation> {
        let new_row = NewRelationRow {
            id: uuid::Uuid::now_v7().to_string(),
            subject_type: subject_type.to_string(),
            subject_id: subject_id.to_string(),
            relation: relation.to_string(),
            object_type: object_type.to_string(),
            object_id: object_id.to_string(),
        };
        let id = new_row.id.clone();

        diesel::insert_into(relations::table)
            .values(&new_row)
            .execute(conn)?;

        relations::table
            .filter(relations::id.eq(&id))
            .first::<RelationRow>(conn)
            .map(Into::into)
    }

    pub fn remove(
        conn: &mut diesel::SqliteConnection,
        relation_id: &str,
    ) -> QueryResult<Relation> {
        let now = chrono::Utc::now().to_rfc3339();
        diesel::update(relations::table.find(relation_id))
            .set((
                relations::removed_at.eq(Some(&now)),
                relations::updated_at.eq(&now),
            ))
            .execute(conn)?;

        relations::table
            .find(relation_id)
            .first::<RelationRow>(conn)
            .map(Into::into)
    }

    pub fn list_for_subject(
        conn: &mut diesel::SqliteConnection,
        subject_type: &str,
        subject_id: &str,
    ) -> QueryResult<Vec<Relation>> {
        relations::table
            .filter(relations::subject_type.eq(subject_type))
            .filter(relations::subject_id.eq(subject_id))
            .filter(relations::removed_at.is_null())
            .load::<RelationRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn list_for_object(
        conn: &mut diesel::SqliteConnection,
        object_type: &str,
        object_id: &str,
    ) -> QueryResult<Vec<Relation>> {
        relations::table
            .filter(relations::object_type.eq(object_type))
            .filter(relations::object_id.eq(object_id))
            .filter(relations::removed_at.is_null())
            .load::<RelationRow>(conn)
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub fn check_direct(
        conn: &mut diesel::SqliteConnection,
        subject_type: &str,
        subject_id: &str,
        relation: &str,
        object_type: &str,
        object_id: &str,
    ) -> QueryResult<bool> {
        use diesel::dsl::exists;
        use diesel::select;

        select(exists(
            relations::table
                .filter(relations::subject_type.eq(subject_type))
                .filter(relations::subject_id.eq(subject_id))
                .filter(relations::relation.eq(relation))
                .filter(relations::object_type.eq(object_type))
                .filter(relations::object_id.eq(object_id))
                .filter(relations::removed_at.is_null()),
        ))
        .get_result(conn)
    }

    pub fn find_by_id(conn: &mut diesel::SqliteConnection, id: &str) -> QueryResult<Relation> {
        relations::table
            .find(id)
            .first::<RelationRow>(conn)
            .map(Into::into)
    }
}
