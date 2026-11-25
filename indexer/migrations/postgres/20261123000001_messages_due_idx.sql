-- +goose Up
-- Separate from the column migration, so the ALTER TABLE lock is released before the build.
-- The build blocks writes to indexer.messages and scans the full table.
CREATE INDEX IF NOT EXISTS idx_messages_processing_due
    ON indexer.messages (next_attempt_at NULLS FIRST) WHERE status = 'PROCESSING';

-- +goose Down
DROP INDEX IF EXISTS indexer.idx_messages_processing_due;
