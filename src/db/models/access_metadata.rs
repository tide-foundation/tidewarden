use derive_more::{AsRef, From};
use macros::IdFromParam;
use serde_json::Value;

use crate::api::EmptyResult;
use crate::db::schema::access_metadata;
use crate::db::DbConn;
use crate::error::MapResult;
use diesel::prelude::*;

use super::OrganizationId;

#[derive(Clone, Debug, AsRef, DieselNewType, From, FromForm, PartialEq, Eq, Hash, Serialize, Deserialize, IdFromParam)]
pub struct AccessMetadataId(String);

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = access_metadata)]
#[diesel(primary_key(change_set_id))]
pub struct AccessMetadata {
    pub change_set_id: AccessMetadataId,
    pub org_uuid: OrganizationId,
    pub username: String,
    pub user_email: Option<String>,
    pub client_id: Option<String>,
    pub role: Option<String>,
    pub timestamp: i64,
    pub action_type: Option<String>,
    pub change_set_type: Option<String>,
}

impl AccessMetadata {
    pub fn new(
        change_set_id: String,
        org_uuid: OrganizationId,
        username: String,
        user_email: Option<String>,
        client_id: Option<String>,
        role: Option<String>,
        timestamp: i64,
        action_type: Option<String>,
        change_set_type: Option<String>,
    ) -> Self {
        Self {
            change_set_id: AccessMetadataId(change_set_id),
            org_uuid,
            username,
            user_email,
            client_id,
            role,
            timestamp,
            action_type,
            change_set_type,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "changeSetId": self.change_set_id,
            "username": self.username,
            "userEmail": self.user_email,
            "clientId": self.client_id,
            "role": self.role,
            "timestamp": self.timestamp,
            "actionType": self.action_type,
            "changeSetType": self.change_set_type,
        })
    }
}

impl AccessMetadata {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(access_metadata::table)
                    .values(self)
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(access_metadata::table)
                            .filter(access_metadata::change_set_id.eq(&self.change_set_id))
                            .set(self)
                            .execute(conn)
                            .map_res("Error saving access_metadata")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving access_metadata")
            }
            postgresql {
                diesel::insert_into(access_metadata::table)
                    .values(self)
                    .on_conflict(access_metadata::change_set_id)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving access_metadata")
            }
        }
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(access_metadata::table.filter(access_metadata::change_set_id.eq(self.change_set_id)))
                .execute(conn)
                .map_res("Error deleting access_metadata")
        }}
    }

    pub async fn find_by_change_set_id(change_set_id: &AccessMetadataId, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            access_metadata::table
                .filter(access_metadata::change_set_id.eq(change_set_id))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            access_metadata::table
                .filter(access_metadata::org_uuid.eq(org_uuid))
                .order(access_metadata::timestamp.desc())
                .load::<Self>(conn)
                .expect("Error loading access_metadata")
        }}
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(access_metadata::table.filter(access_metadata::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error deleting access_metadata")
        }}
    }
}
