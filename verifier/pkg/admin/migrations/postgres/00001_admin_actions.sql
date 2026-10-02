-- +goose Up
CREATE TABLE IF NOT EXISTS ccv_admin_actions (
    id           BIGSERIAL PRIMARY KEY,
    actor        TEXT        NOT NULL,
    action       TEXT        NOT NULL,
    node_name    TEXT        NOT NULL DEFAULT '',
    target       TEXT        NOT NULL DEFAULT '',
    operation_id TEXT        NOT NULL DEFAULT '',
    outcome      TEXT        NOT NULL,
    detail       TEXT        NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ccv_admin_actions_created_at_idx ON ccv_admin_actions (created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS ccv_admin_actions;
