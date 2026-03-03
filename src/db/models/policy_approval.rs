use derive_more::{AsRef, From};
use macros::UuidFromParam;
use serde_json::Value;

use crate::api::EmptyResult;
use crate::db::schema::policy_approvals;
use crate::db::DbConn;
use crate::error::MapResult;
use diesel::prelude::*;

use super::OrganizationId;

#[derive(Clone, Debug, AsRef, DieselNewType, From, FromForm, PartialEq, Eq, Hash, Serialize, Deserialize, UuidFromParam)]
pub struct PolicyApprovalId(String);

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = policy_approvals)]
#[diesel(primary_key(uuid))]
pub struct PolicyApproval {
    pub uuid: PolicyApprovalId,
    pub org_uuid: OrganizationId,
    pub role_id: String,
    pub requested_by: String,
    pub requested_by_email: Option<String>,
    pub threshold: i32,
    pub approval_count: i32,
    pub rejection_count: i32,
    pub commit_ready: bool,
    pub approved_by: String,
    pub denied_by: String,
    pub status: String,
    pub timestamp: i64,
    pub policy_request_data: String,
    pub contract_code: Option<String>,
}

impl PolicyApproval {
    pub fn new(
        org_uuid: OrganizationId,
        role_id: String,
        requested_by: String,
        requested_by_email: Option<String>,
        threshold: i32,
        policy_request_data: String,
        contract_code: Option<String>,
    ) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            uuid: PolicyApprovalId(crate::util::get_uuid()),
            org_uuid,
            role_id,
            requested_by,
            requested_by_email,
            threshold,
            approval_count: 0,
            rejection_count: 0,
            commit_ready: false,
            approved_by: "[]".to_string(),
            denied_by: "[]".to_string(),
            status: "pending".to_string(),
            timestamp: now,
            policy_request_data,
            contract_code,
        }
    }

    pub fn to_json(&self) -> Value {
        let approved_by: Value = serde_json::from_str(&self.approved_by).unwrap_or(Value::Array(vec![]));
        let denied_by: Value = serde_json::from_str(&self.denied_by).unwrap_or(Value::Array(vec![]));
        json!({
            "id": self.uuid,
            "roleId": self.role_id,
            "requestedBy": self.requested_by,
            "requestedByEmail": self.requested_by_email,
            "threshold": self.threshold,
            "approvalCount": self.approval_count,
            "rejectionCount": self.rejection_count,
            "commitReady": self.commit_ready,
            "approvedBy": approved_by,
            "deniedBy": denied_by,
            "status": self.status,
            "timestamp": self.timestamp,
            "policyRequestData": self.policy_request_data,
            "contractCode": self.contract_code,
        })
    }
}

impl PolicyApproval {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(policy_approvals::table)
                    .values(self)
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(policy_approvals::table)
                            .filter(policy_approvals::uuid.eq(&self.uuid))
                            .set(self)
                            .execute(conn)
                            .map_res("Error saving policy_approval")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving policy_approval")
            }
            postgresql {
                diesel::insert_into(policy_approvals::table)
                    .values(self)
                    .on_conflict(policy_approvals::uuid)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving policy_approval")
            }
        }
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(policy_approvals::table.filter(policy_approvals::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error deleting policy_approval")
        }}
    }

    pub async fn find_by_uuid(uuid: &PolicyApprovalId, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            policy_approvals::table
                .filter(policy_approvals::uuid.eq(uuid))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_pending_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            policy_approvals::table
                .filter(policy_approvals::org_uuid.eq(org_uuid))
                .filter(policy_approvals::status.eq("pending"))
                .order(policy_approvals::timestamp.desc())
                .load::<Self>(conn)
                .expect("Error loading policy_approvals")
        }}
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            policy_approvals::table
                .filter(policy_approvals::org_uuid.eq(org_uuid))
                .order(policy_approvals::timestamp.desc())
                .load::<Self>(conn)
                .expect("Error loading policy_approvals")
        }}
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(policy_approvals::table.filter(policy_approvals::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error deleting policy_approvals")
        }}
    }
}
