use derive_more::{AsRef, From};
use macros::UuidFromParam;
use serde_json::Value;

use crate::api::EmptyResult;
use crate::db::schema::role_policies;
use crate::db::DbConn;
use crate::error::MapResult;
use diesel::prelude::*;

use super::OrganizationId;

#[derive(Clone, Debug, AsRef, DieselNewType, From, FromForm, PartialEq, Eq, Hash, Serialize, Deserialize, UuidFromParam)]
pub struct RolePolicyId(String);

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = role_policies)]
#[diesel(primary_key(uuid))]
pub struct RolePolicy {
    pub uuid: RolePolicyId,
    pub org_uuid: OrganizationId,
    pub role_name: String,
    pub enabled: bool,
    pub contract_type: String,
    pub approval_type: String,
    pub execution_type: String,
    pub threshold: i32,
    pub template_id: Option<String>,
    pub template_params: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl RolePolicy {
    pub fn new(
        org_uuid: OrganizationId,
        role_name: String,
        enabled: bool,
        contract_type: String,
        approval_type: String,
        execution_type: String,
        threshold: i32,
        template_id: Option<String>,
        template_params: String,
    ) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            uuid: RolePolicyId(crate::util::get_uuid()),
            org_uuid,
            role_name,
            enabled,
            contract_type,
            approval_type,
            execution_type,
            threshold,
            template_id,
            template_params,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn to_json(&self) -> Value {
        let params: Value = serde_json::from_str(&self.template_params).unwrap_or(json!({}));
        json!({
            "roleName": self.role_name,
            "enabled": self.enabled,
            "contractType": self.contract_type,
            "approvalType": self.approval_type,
            "executionType": self.execution_type,
            "threshold": self.threshold,
            "templateId": self.template_id,
            "templateParams": params,
            "createdAt": self.created_at.to_string(),
            "updatedAt": self.updated_at.to_string(),
        })
    }
}

impl RolePolicy {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(role_policies::table)
                    .values(self)
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(role_policies::table)
                            .filter(role_policies::uuid.eq(&self.uuid))
                            .set(self)
                            .execute(conn)
                            .map_res("Error saving role_policy")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving role_policy")
            }
            postgresql {
                diesel::insert_into(role_policies::table)
                    .values(self)
                    .on_conflict(role_policies::uuid)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving role_policy")
            }
        }
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(role_policies::table.filter(role_policies::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error deleting role_policy")
        }}
    }

    pub async fn find_by_org_and_role_name(org_uuid: &OrganizationId, role_name: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            role_policies::table
                .filter(role_policies::org_uuid.eq(org_uuid))
                .filter(role_policies::role_name.eq(role_name))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn delete_by_org_and_role_name(org_uuid: &OrganizationId, role_name: &str, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(
                role_policies::table
                    .filter(role_policies::org_uuid.eq(org_uuid))
                    .filter(role_policies::role_name.eq(role_name))
            )
            .execute(conn)
            .map_res("Error deleting role_policy")
        }}
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            role_policies::table
                .filter(role_policies::org_uuid.eq(org_uuid))
                .load::<Self>(conn)
                .expect("Error loading role_policies")
        }}
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(role_policies::table.filter(role_policies::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error deleting role_policies")
        }}
    }
}
