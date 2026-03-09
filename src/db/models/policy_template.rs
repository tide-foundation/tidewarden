use derive_more::{AsRef, From};
use macros::UuidFromParam;
use serde_json::Value;

use crate::api::EmptyResult;
use crate::db::schema::policy_templates;
use crate::db::DbConn;
use crate::error::MapResult;
use diesel::prelude::*;

use super::OrganizationId;

#[derive(Clone, Debug, AsRef, DieselNewType, From, FromForm, PartialEq, Eq, Hash, Serialize, Deserialize, UuidFromParam)]
pub struct PolicyTemplateId(String);

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = policy_templates)]
#[diesel(primary_key(uuid))]
pub struct PolicyTemplate {
    pub uuid: PolicyTemplateId,
    pub org_uuid: OrganizationId,
    pub name: String,
    pub description: String,
    pub cs_code: String,
    pub parameters: String,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl PolicyTemplate {
    pub fn new(
        org_uuid: OrganizationId,
        name: String,
        description: String,
        cs_code: String,
        parameters: String,
        created_by: String,
    ) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            uuid: PolicyTemplateId(crate::util::get_uuid()),
            org_uuid,
            name,
            description,
            cs_code,
            parameters,
            created_by,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn to_json(&self) -> Value {
        let params: Value = serde_json::from_str(&self.parameters).unwrap_or(Value::Array(vec![]));
        json!({
            "id": self.uuid,
            "name": self.name,
            "description": self.description,
            "csCode": self.cs_code,
            "parameters": params,
            "createdBy": self.created_by,
        })
    }
}

impl PolicyTemplate {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(policy_templates::table)
                    .values(self)
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(policy_templates::table)
                            .filter(policy_templates::uuid.eq(&self.uuid))
                            .set(self)
                            .execute(conn)
                            .map_res("Error saving policy_template")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving policy_template")
            }
            postgresql {
                diesel::insert_into(policy_templates::table)
                    .values(self)
                    .on_conflict(policy_templates::uuid)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving policy_template")
            }
        }
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(policy_templates::table.filter(policy_templates::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error deleting policy_template")
        }}
    }

    pub async fn find_by_uuid(uuid: &PolicyTemplateId, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            policy_templates::table
                .filter(policy_templates::uuid.eq(uuid))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            policy_templates::table
                .filter(policy_templates::org_uuid.eq(org_uuid))
                .order(policy_templates::created_at.desc())
                .load::<Self>(conn)
                .expect("Error loading policy_templates")
        }}
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(policy_templates::table.filter(policy_templates::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error deleting policy_templates")
        }}
    }
}
