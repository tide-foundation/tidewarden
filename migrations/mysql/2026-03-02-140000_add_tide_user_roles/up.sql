CREATE TABLE tide_user_roles (
    uuid          VARCHAR(40) NOT NULL PRIMARY KEY,
    org_uuid      VARCHAR(40) NOT NULL REFERENCES organizations(uuid),
    membership_uuid VARCHAR(40) NOT NULL REFERENCES users_organizations(uuid),
    role_name     TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    UNIQUE(membership_uuid, role_name(255))
);
