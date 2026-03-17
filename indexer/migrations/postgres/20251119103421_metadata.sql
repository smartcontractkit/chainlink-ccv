-- +goose Up
-- +goose StatementBegin
ALTER TABLE indexer.verifier_results ADD COLUMN verifier_name TEXT;
ALTER TABLE indexer.verifier_results RENAME COLUMN timestamp TO attestation_timestamp;
ALTER TABLE indexer.verifier_results RENAME COLUMN created_at TO ingestion_timestamp;

-- We're going to drop the previous index and use ingestion_timestamp instead.
DROP INDEX IF EXISTS idx_verifier_results_timestamp;
CREATE INDEX IF NOT EXISTS idx_verifier_results_timestamp ON indexer.verifier_results(ingestion_timestamp);

-- Similar thing for the query pattern index
DROP INDEX IF EXISTS idx_verifier_results_query_pattern;
CREATE INDEX IF NOT EXISTS idx_verifier_results_query_pattern ON indexer.verifier_results(ingestion_timestamp, source_chain_selector, dest_chain_selector);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE indexer.verifier_results DROP COLUMN verifier_name; 
ALTER TABLE indexer.verifier_results RENAME COLUMN attestation_timestamp TO timestamp;
ALTER TABLE indexer.verifier_results RENAME COLUMN ingestion_timestamp TO created_at;

DROP INDEX IF EXISTS idx_verifier_results_timestamp;
CREATE INDEX IF NOT EXISTS idx_verifier_results_timestamp ON indexer.verifier_results(timestamp);
DROP INDEX IF EXISTS idx_verifier_results_query_pattern;
CREATE INDEX IF NOT EXISTS idx_verifier_results_query_pattern ON indexer.verifier_results(timestamp, source_chain_selector, dest_chain_selector);
-- +goose StatementEnd
