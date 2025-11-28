-- +goose Up
-- +goose StatementBegin

-- Add source_chain_block_timestamp column to commit_verification_records
-- This represents the timestamp when the message was included in a source chain block
-- Default to current time in milliseconds for existing rows
ALTER TABLE commit_verification_records 
    ADD COLUMN source_chain_block_timestamp TIMESTAMP NOT NULL DEFAULT now();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE commit_verification_records 
    DROP COLUMN source_chain_block_timestamp;

-- +goose StatementEnd
