use derive_more::{AsRef, From};
use macros::UuidFromParam;
use serde_json::Value;

use crate::api::EmptyResult;
use crate::db::schema::policy_logs;
use crate::db::DbConn;
use crate::error::MapResult;
use diesel::prelude::*;

use super::OrganizationId;

#[derive(Clone, Debug, AsRef, DieselNewType, From, FromForm, PartialEq, Eq, Hash, Serialize, Deserialize, UuidFromParam)]
pub struct PolicyLogId(String);

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = policy_logs)]
#[diesel(primary_key(uuid))]
pub struct PolicyLog {
    pub uuid: PolicyLogId,
    pub org_uuid: OrganizationId,
    pub policy_id: String,
    pub role_id: String,
    pub action: String,
    pub performed_by: String,
    pub performed_by_email: Option<String>,
    pub timestamp: i64,
    pub policy_status: Option<String>,
    pub policy_threshold: Option<i32>,
    pub approval_count: Option<i32>,
    pub rejection_count: Option<i32>,
    pub details: Option<String>,
}

impl PolicyLog {
    pub fn new(
        org_uuid: OrganizationId,
        policy_id: String,
        role_id: String,
        action: String,
        performed_by: String,
        performed_by_email: Option<String>,
    ) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            uuid: PolicyLogId(crate::util::get_uuid()),
            org_uuid,
            policy_id,
            role_id,
            action,
            performed_by,
            performed_by_email,
            timestamp: now,
            policy_status: None,
            policy_threshold: None,
            approval_count: None,
            rejection_count: None,
            details: None,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "policyId": self.policy_id,
            "roleId": self.role_id,
            "action": self.action,
            "performedBy": self.performed_by,
            "performedByEmail": self.performed_by_email,
            "timestamp": self.timestamp,
            "createdAt": self.timestamp / 1000,
            "policyStatus": self.policy_status,
            "policyThreshold": self.policy_threshold,
            "approvalCount": self.approval_count,
            "rejectionCount": self.rejection_count,
            "details": self.details,
        })
    }
}

impl PolicyLog {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(policy_logs::table)
                    .values(self)
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(policy_logs::table)
                            .filter(policy_logs::uuid.eq(&self.uuid))
                            .set(self)
                            .execute(conn)
                            .map_res("Error saving policy_log")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving policy_log")
            }
            postgresql {
                diesel::insert_into(policy_logs::table)
                    .values(self)
                    .on_conflict(policy_logs::uuid)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving policy_log")
            }
        }
    }

    pub async fn find_by_org_paginated(
        org_uuid: &OrganizationId,
        offset: i64,
        limit: i64,
        conn: &DbConn,
    ) -> Vec<Self> {
        db_run! { conn: {
            policy_logs::table
                .filter(policy_logs::org_uuid.eq(org_uuid))
                .order(policy_logs::timestamp.desc())
                .offset(offset)
                .limit(limit)
                .load::<Self>(conn)
                .expect("Error loading policy_logs")
        }}
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(policy_logs::table.filter(policy_logs::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error deleting policy_logs")
        }}
    }
}
