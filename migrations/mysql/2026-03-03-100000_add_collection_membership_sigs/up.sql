CREATE TABLE collection_membership_sigs (
    collection_id VARCHAR(255) NOT NULL PRIMARY KEY,
    org_uuid      VARCHAR(40)  NOT NULL,
    membership_data TEXT       NOT NULL,
    signature     TEXT         NOT NULL,
    signed_by     VARCHAR(255) NOT NULL,
    updated_at    BIGINT       NOT NULL,
    FOREIGN KEY (org_uuid) REFERENCES organizations(uuid)
);
