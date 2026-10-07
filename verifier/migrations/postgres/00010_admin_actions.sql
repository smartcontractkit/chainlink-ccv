-- +goose Up
-- Admin console action log. The console runs in the verifier process and audits its
-- mutations here, in the verifier's own application database.
CREATE TABLE IF NOT EXISTS ccv_admin_actions (
    id           BIGSERIAL PRIMARY KEY,
    actor        TEXT        NOT NULL,
    action       TEXT        NOT NULL,
    target       TEXT        NOT NULL DEFAULT '',
    operation_id TEXT        NOT NULL DEFAULT '',
    outcome      TEXT        NOT NULL,
    detail       TEXT        NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ccv_admin_actions_created_at_idx ON ccv_admin_actions (created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS ccv_admin_actions;
