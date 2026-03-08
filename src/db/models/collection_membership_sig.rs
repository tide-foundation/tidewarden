use serde_json::Value;

use crate::api::EmptyResult;
use crate::db::schema::collection_membership_sigs;
use crate::db::DbConn;
use crate::error::MapResult;
use diesel::prelude::*;

use super::OrganizationId;

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = collection_membership_sigs)]
#[diesel(primary_key(collection_id))]
pub struct CollectionMembershipSig {
    pub collection_id: String,
    pub org_uuid: OrganizationId,
    pub membership_data: String,
    pub signature: String,
    pub signed_by: String,
    pub updated_at: i64,
}

impl CollectionMembershipSig {
    pub fn new(
        collection_id: String,
        org_uuid: OrganizationId,
        membership_data: String,
        signature: String,
        signed_by: String,
    ) -> Self {
        Self {
            collection_id,
            org_uuid,
            membership_data,
            signature,
            signed_by,
            updated_at: chrono::Utc::now().timestamp_millis(),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "collectionId": self.collection_id,
            "membershipData": self.membership_data,
            "signature": self.signature,
            "signedBy": self.signed_by,
            "updatedAt": self.updated_at,
        })
    }
}

impl CollectionMembershipSig {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(collection_membership_sigs::table)
                    .values(self)
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(collection_membership_sigs::table)
                            .filter(collection_membership_sigs::collection_id.eq(&self.collection_id))
                            .set(self)
                            .execute(conn)
                            .map_res("Error saving collection_membership_sig")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving collection_membership_sig")
            }
            postgresql {
                diesel::insert_into(collection_membership_sigs::table)
                    .values(self)
                    .on_conflict(collection_membership_sigs::collection_id)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving collection_membership_sig")
            }
        }
    }

    pub async fn find_by_collection(collection_id: &str, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            collection_membership_sigs::table
                .filter(collection_membership_sigs::collection_id.eq(collection_id))
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Vec<Self> {
        db_run! { conn: {
            collection_membership_sigs::table
                .filter(collection_membership_sigs::org_uuid.eq(org_uuid))
                .load::<Self>(conn)
                .expect("Error loading collection_membership_sigs")
        }}
    }

    pub async fn delete(self, conn: &DbConn) -> EmptyResult {
        db_run! { conn: {
            diesel::delete(
                collection_membership_sigs::table
                    .filter(collection_membership_sigs::collection_id.eq(self.collection_id))
            )
            .execute(conn)
            .map_res("Error deleting collection_membership_sig")
        }}
    }
}
