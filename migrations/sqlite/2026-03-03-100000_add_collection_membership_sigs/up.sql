CREATE TABLE collection_membership_sigs (
    collection_id TEXT NOT NULL PRIMARY KEY,
    org_uuid      TEXT NOT NULL REFERENCES organizations(uuid),
    membership_data TEXT NOT NULL,
    signature     TEXT NOT NULL,
    signed_by     TEXT NOT NULL,
    updated_at    BIGINT NOT NULL
);
