use derive_more::{AsRef, From};
use macros::UuidFromParam;
use serde_json::Value;

use crate::api::EmptyResult;
use crate::db::schema::tide_user_roles;
use crate::db::DbConn;
use crate::error::MapResult;
use diesel::prelude::*;

use super::{MembershipId, OrganizationId};

#[derive(Clone, Debug, AsRef, DieselNewType, From, FromForm, PartialEq, Eq, Hash, Serialize, Deserialize, UuidFromParam)]
pub struct TideUserRoleId(String);

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = tide_user_roles)]
#[diesel(primary_key(uuid))]
pub struct TideUserRole {
    pub uuid: TideUserRoleId,
    pub org_uuid: OrganizationId,
    pub membership_uuid: MembershipId,
    pub role_name: String,
    pub created_at: i64,
}

impl TideUserRole {
    pub fn new(org_uuid: OrganizationId, membership_uuid: MembershipId, role_name: String) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            uuid: TideUserRoleId(crate::util::get_uuid()),
            org_uuid,
            membership_uuid,
            role_name,
            created_at: now,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "orgUuid": self.org_uuid,
            "membershipUuid": self.membership_uuid,
            "roleName": self.role_name,
            "createdAt": self.created_at,
        })
    }

    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                diesel::replace_into(tide_user_roles::table)
                    .values(self)
                    .execute(conn)
                    .map_res("Error saving tide user role")
            }
            postgresql {
                diesel::insert_into(tide_user_roles::table)
                    .values(self)
                    .on_conflict(tide_user_roles::uuid)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving tide user role")
            }
        }
    }

    pub async fn delete(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(tide_user_roles::table.filter(tide_user_roles::uuid.eq(&self.uuid)))
                .execute(conn)
                .map_res("Error deleting tide user role")
        }}
    }

    pub async fn find_by_membership(membership_uuid: &MembershipId, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            tide_user_roles::table
                .filter(tide_user_roles::membership_uuid.eq(membership_uuid))
                .load::<Self>(conn)
                .expect("Error loading tide user roles")
        }}
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            tide_user_roles::table
                .filter(tide_user_roles::org_uuid.eq(org_uuid))
                .load::<Self>(conn)
                .expect("Error loading tide user roles")
        }}
    }

    pub async fn find_by_membership_and_role(
        membership_uuid: &MembershipId,
        role_name: &str,
        conn: &DbConn,
    ) -> Option<Self> {
        db_run! { conn: {
            tide_user_roles::table
                .filter(tide_user_roles::membership_uuid.eq(membership_uuid))
                .filter(tide_user_roles::role_name.eq(role_name))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn delete_by_membership_and_role(
        membership_uuid: &MembershipId,
        role_name: &str,
        conn: &DbConn,
    ) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(
                tide_user_roles::table
                    .filter(tide_user_roles::membership_uuid.eq(membership_uuid))
                    .filter(tide_user_roles::role_name.eq(role_name)),
            )
            .execute(conn)
            .map_res("Error deleting tide user role")
        }}
    }

    pub async fn delete_all_by_membership(membership_uuid: &MembershipId, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(
                tide_user_roles::table.filter(tide_user_roles::membership_uuid.eq(membership_uuid)),
            )
            .execute(conn)
            .map_res("Error deleting tide user roles")
        }}
    }
}
