use derive_more::{AsRef, From};
use macros::UuidFromParam;
use serde_json::Value;

use crate::api::EmptyResult;
use crate::db::schema::tide_roles;
use crate::db::DbConn;
use crate::error::MapResult;
use diesel::prelude::*;

use super::OrganizationId;

#[derive(Clone, Debug, AsRef, DieselNewType, From, FromForm, PartialEq, Eq, Hash, Serialize, Deserialize, UuidFromParam)]
pub struct TideRoleId(String);

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = tide_roles)]
#[diesel(primary_key(uuid))]
pub struct TideRole {
    pub uuid: TideRoleId,
    pub org_uuid: OrganizationId,
    pub name: String,
    pub description: String,
    pub client_role: bool,
    pub role_type: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl TideRole {
    pub fn new(org_uuid: OrganizationId, name: String, description: String, client_role: bool, role_type: String) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            uuid: TideRoleId(crate::util::get_uuid()),
            org_uuid,
            name,
            description,
            client_role,
            role_type,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "name": self.name,
            "description": self.description,
            "clientRole": self.client_role,
            "roleType": self.role_type,
        })
    }
}

impl TideRole {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(tide_roles::table)
                    .values(self)
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(tide_roles::table)
                            .filter(tide_roles::uuid.eq(&self.uuid))
                            .set(self)
                            .execute(conn)
                            .map_res("Error saving tide_role")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving tide_role")
            }
            postgresql {
                diesel::insert_into(tide_roles::table)
                    .values(self)
                    .on_conflict(tide_roles::uuid)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving tide_role")
            }
        }
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(tide_roles::table.filter(tide_roles::uuid.eq(self.uuid)))
                .execute(conn)
                .map_res("Error deleting tide_role")
        }}
    }

    pub async fn find_by_uuid(uuid: &TideRoleId, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            tide_roles::table
                .filter(tide_roles::uuid.eq(uuid))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_by_org_and_name(org_uuid: &OrganizationId, name: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            tide_roles::table
                .filter(tide_roles::org_uuid.eq(org_uuid))
                .filter(tide_roles::name.eq(name))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            tide_roles::table
                .filter(tide_roles::org_uuid.eq(org_uuid))
                .order(tide_roles::name.asc())
                .load::<Self>(conn)
                .expect("Error loading tide_roles")
        }}
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(tide_roles::table.filter(tide_roles::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error deleting tide_roles")
        }}
    }
}
