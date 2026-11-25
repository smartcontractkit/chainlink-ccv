-- +goose Up
-- The default covers inserts from older images during a rollout; 24 hours is the deployed window.
ALTER TABLE indexer.messages ALTER COLUMN retry_deadline SET DEFAULT NOW() + INTERVAL '24 hours';

-- Stamp the in-flight rows with the same window. The partial index from the last migration finds them.
UPDATE indexer.messages
SET retry_deadline = (ingestion_timestamp AT TIME ZONE 'UTC') + INTERVAL '24 hours'
WHERE status = 'PROCESSING' AND retry_deadline IS NULL;

-- +goose Down
ALTER TABLE indexer.messages ALTER COLUMN retry_deadline DROP DEFAULT;
