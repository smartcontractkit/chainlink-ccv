-- +goose Up
-- The message row holds the worker state. Constant defaults add the columns without a table rewrite.
ALTER TABLE indexer.messages
    ADD COLUMN IF NOT EXISTS attempt_count   INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS retry_deadline  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS trace_parent    TEXT;

-- +goose Down
ALTER TABLE indexer.messages
    DROP COLUMN IF EXISTS trace_parent,
    DROP COLUMN IF EXISTS retry_deadline,
    DROP COLUMN IF EXISTS next_attempt_at,
    DROP COLUMN IF EXISTS attempt_count;
