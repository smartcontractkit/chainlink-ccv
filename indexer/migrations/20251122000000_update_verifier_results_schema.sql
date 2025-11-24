-- +goose Up
-- +goose StatementBegin

-- Drop the old table (we don't care about existing data)
DROP TABLE IF EXISTS indexer.verifier_results;

-- Create table with correct schema matching postgres.go expectations
CREATE TABLE indexer.verifier_results (
    -- Primary identifiers
    message_id TEXT NOT NULL,
    verifier_source_address TEXT NOT NULL,
    verifier_dest_address TEXT NOT NULL,
    
    -- Timestamps
    attestation_timestamp TIMESTAMPTZ NOT NULL,
    ingestion_timestamp TIMESTAMPTZ NOT NULL,
    
    -- Chain selector columns for efficient querying
    source_chain_selector DECIMAL(20,0) NOT NULL,
    dest_chain_selector DECIMAL(20,0) NOT NULL,
    
    -- CCV data fields
    ccv_data BYTEA,
    
    -- Message stored as JSONB for flexible querying
    message JSONB NOT NULL,
    
    -- CCV-specific fields stored as TEXT arrays with hex-encoded addresses
    message_ccv_addresses TEXT[] NOT NULL,
    message_executor_address TEXT NOT NULL,
    
    -- Constraints
    PRIMARY KEY (message_id, verifier_source_address, verifier_dest_address)
);

-- Indexes for efficient querying
CREATE INDEX idx_verifier_results_message_id 
    ON indexer.verifier_results(message_id);

CREATE INDEX idx_verifier_results_attestation_timestamp 
    ON indexer.verifier_results(attestation_timestamp);

CREATE INDEX idx_verifier_results_ingestion_timestamp 
    ON indexer.verifier_results(ingestion_timestamp);

-- Indexes on dedicated chain selector columns
CREATE INDEX idx_verifier_results_source_chain_selector 
    ON indexer.verifier_results(source_chain_selector);

CREATE INDEX idx_verifier_results_dest_chain_selector 
    ON indexer.verifier_results(dest_chain_selector);

-- Composite index for common query pattern (timestamp + chain filters)
CREATE INDEX idx_verifier_results_query_pattern 
    ON indexer.verifier_results(ingestion_timestamp, source_chain_selector, dest_chain_selector);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS indexer.verifier_results;
-- +goose StatementEnd
