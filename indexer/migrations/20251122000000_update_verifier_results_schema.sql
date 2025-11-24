-- +goose Up
-- +goose StatementBegin

-- Rename verifier address columns to match new naming convention
ALTER TABLE indexer.verifier_results 
    RENAME COLUMN source_verifier_address TO verifier_source_address;

ALTER TABLE indexer.verifier_results 
    RENAME COLUMN dest_verifier_address TO verifier_dest_address;

-- Add new CCV-specific fields
ALTER TABLE indexer.verifier_results 
    ADD COLUMN message_ccv_addresses TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];

ALTER TABLE indexer.verifier_results 
    ADD COLUMN message_executor_address TEXT NOT NULL DEFAULT '';

-- Remove deprecated columns (created_at already renamed to ingestion_timestamp in previous migration)
ALTER TABLE indexer.verifier_results 
    DROP COLUMN nonce,
    DROP COLUMN blob_data,
    DROP COLUMN receipt_blobs,
    DROP COLUMN verifier_name;

-- Create new indexes for attestation_timestamp (ingestion_timestamp index already exists from previous migration)
CREATE INDEX IF NOT EXISTS idx_verifier_results_attestation_timestamp 
    ON indexer.verifier_results(attestation_timestamp);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Remove new index
DROP INDEX IF EXISTS idx_verifier_results_attestation_timestamp;

-- Add back removed columns
ALTER TABLE indexer.verifier_results 
    ADD COLUMN nonce BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN blob_data BYTEA,
    ADD COLUMN receipt_blobs JSONB NOT NULL DEFAULT '[]'::JSONB,
    ADD COLUMN verifier_name TEXT;

-- Remove new columns
ALTER TABLE indexer.verifier_results 
    DROP COLUMN message_executor_address,
    DROP COLUMN message_ccv_addresses;

-- Rename columns back
ALTER TABLE indexer.verifier_results 
    RENAME COLUMN verifier_dest_address TO dest_verifier_address;

ALTER TABLE indexer.verifier_results 
    RENAME COLUMN verifier_source_address TO source_verifier_address;

-- +goose StatementEnd
