-- PostgreSQL migration for the versioned SecurePAM policy store (matches securepam_policy_engine/db.py).
-- Rows are append-only per version; only is_current is flipped when a new version is published.
CREATE TABLE IF NOT EXISTS policies (
    id            BIGSERIAL PRIMARY KEY,
    policy_id     VARCHAR(64)  NOT NULL,
    version       INTEGER      NOT NULL CHECK (version >= 1),
    name          VARCHAR(200) NOT NULL,
    enabled       BOOLEAN      NOT NULL DEFAULT TRUE,
    is_current    BOOLEAN      NOT NULL DEFAULT TRUE,
    definition    JSONB        NOT NULL,
    changed_by    VARCHAR(128) NOT NULL,
    change_note   VARCHAR(500) NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_policy_version UNIQUE (policy_id, version)
);
CREATE INDEX IF NOT EXISTS ix_policies_policy_id  ON policies (policy_id);
CREATE INDEX IF NOT EXISTS ix_policies_is_current ON policies (is_current);
-- Exactly one current version per policy_id:
CREATE UNIQUE INDEX IF NOT EXISTS uq_policies_one_current ON policies (policy_id) WHERE is_current;
