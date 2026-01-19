-- +goose Up
CREATE TABLE IF NOT EXISTS verifier_node_results (
    message_id BYTEA PRIMARY KEY,
    message JSONB NOT NULL,
    ccv_version BYTEA NOT NULL,
    ccv_addresses JSONB NOT NULL,
    executor_address BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    verifier_source_address BYTEA NOT NULL,
    verifier_dest_address BYTEA NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for efficient lookups by message_id (covered by PRIMARY KEY)
-- Index for timestamp-based queries if needed
CREATE INDEX IF NOT EXISTS idx_verifier_node_results_timestamp ON verifier_node_results(timestamp);

-- +goose Down
DROP INDEX IF EXISTS idx_verifier_node_results_timestamp;
DROP TABLE IF EXISTS verifier_node_results;


