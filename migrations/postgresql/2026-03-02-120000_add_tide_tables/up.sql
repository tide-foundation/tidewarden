CREATE TABLE policy_templates (
    uuid          VARCHAR(40)  NOT NULL PRIMARY KEY,
    org_uuid      VARCHAR(40)  NOT NULL REFERENCES organizations(uuid),
    name          TEXT         NOT NULL,
    description   TEXT         NOT NULL DEFAULT '',
    cs_code       TEXT         NOT NULL DEFAULT '',
    parameters    TEXT         NOT NULL DEFAULT '[]',
    created_by    TEXT         NOT NULL DEFAULT '',
    created_at    BIGINT       NOT NULL DEFAULT 0,
    updated_at    BIGINT       NOT NULL DEFAULT 0
);

CREATE TABLE policy_approvals (
    uuid                VARCHAR(40)  NOT NULL PRIMARY KEY,
    org_uuid            VARCHAR(40)  NOT NULL REFERENCES organizations(uuid),
    role_id             TEXT         NOT NULL DEFAULT '',
    requested_by        TEXT         NOT NULL DEFAULT '',
    requested_by_email  TEXT,
    threshold           INTEGER      NOT NULL DEFAULT 1,
    approval_count      INTEGER      NOT NULL DEFAULT 0,
    rejection_count     INTEGER      NOT NULL DEFAULT 0,
    commit_ready        BOOLEAN      NOT NULL DEFAULT FALSE,
    approved_by         TEXT         NOT NULL DEFAULT '[]',
    denied_by           TEXT         NOT NULL DEFAULT '[]',
    status              VARCHAR(20)  NOT NULL DEFAULT 'pending',
    timestamp           BIGINT       NOT NULL DEFAULT 0,
    policy_request_data TEXT         NOT NULL DEFAULT '',
    contract_code       TEXT
);

CREATE TABLE access_metadata (
    change_set_id   VARCHAR(255) NOT NULL PRIMARY KEY,
    org_uuid        VARCHAR(40)  NOT NULL REFERENCES organizations(uuid),
    username        TEXT         NOT NULL DEFAULT '',
    user_email      TEXT,
    client_id       TEXT,
    role            TEXT,
    timestamp       BIGINT       NOT NULL DEFAULT 0,
    action_type     TEXT,
    change_set_type TEXT
);
