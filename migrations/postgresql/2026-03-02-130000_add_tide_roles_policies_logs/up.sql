CREATE TABLE tide_roles (
    uuid          VARCHAR(40)  NOT NULL PRIMARY KEY,
    org_uuid      VARCHAR(40)  NOT NULL REFERENCES organizations(uuid),
    name          TEXT         NOT NULL,
    description   TEXT         NOT NULL DEFAULT '',
    client_role   BOOLEAN      NOT NULL DEFAULT FALSE,
    role_type     VARCHAR(20)  NOT NULL DEFAULT 'realm',
    created_at    BIGINT       NOT NULL DEFAULT 0,
    updated_at    BIGINT       NOT NULL DEFAULT 0
);

CREATE TABLE role_policies (
    uuid            VARCHAR(40)  NOT NULL PRIMARY KEY,
    org_uuid        VARCHAR(40)  NOT NULL REFERENCES organizations(uuid),
    role_name       VARCHAR(255) NOT NULL,
    enabled         BOOLEAN      NOT NULL DEFAULT FALSE,
    contract_type   TEXT         NOT NULL DEFAULT '',
    approval_type   VARCHAR(20)  NOT NULL DEFAULT 'implicit',
    execution_type  VARCHAR(20)  NOT NULL DEFAULT 'public',
    threshold       INTEGER      NOT NULL DEFAULT 1,
    template_id     TEXT,
    template_params TEXT         NOT NULL DEFAULT '{}',
    created_at      BIGINT       NOT NULL DEFAULT 0,
    updated_at      BIGINT       NOT NULL DEFAULT 0
);

CREATE TABLE policy_logs (
    uuid                VARCHAR(40)  NOT NULL PRIMARY KEY,
    org_uuid            VARCHAR(40)  NOT NULL REFERENCES organizations(uuid),
    policy_id           TEXT         NOT NULL DEFAULT '',
    role_id             TEXT         NOT NULL DEFAULT '',
    action              TEXT         NOT NULL DEFAULT '',
    performed_by        TEXT         NOT NULL DEFAULT '',
    performed_by_email  TEXT,
    timestamp           BIGINT       NOT NULL DEFAULT 0,
    policy_status       TEXT,
    policy_threshold    INTEGER,
    approval_count      INTEGER,
    rejection_count     INTEGER,
    details             TEXT
);
