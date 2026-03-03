CREATE TABLE tide_user_roles (
    uuid          TEXT NOT NULL PRIMARY KEY,
    org_uuid      TEXT NOT NULL REFERENCES organizations(uuid),
    membership_uuid TEXT NOT NULL REFERENCES users_organizations(uuid),
    role_name     TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    UNIQUE(membership_uuid, role_name)
);
