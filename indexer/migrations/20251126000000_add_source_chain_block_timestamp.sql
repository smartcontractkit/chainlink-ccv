-- +goose Up
-- +goose StatementBegin

-- Add source_chain_block_timestamp column to indexer.verifier_results
-- This represents the timestamp when the message was included in a source chain block
-- Default to current time in milliseconds for existing rows
ALTER TABLE indexer.verifier_results 
    ADD COLUMN source_chain_block_timestamp TIMESTAMP NOT NULL DEFAULT now();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE indexer.verifier_results 
    DROP COLUMN source_chain_block_timestamp;

-- +goose StatementEnd
