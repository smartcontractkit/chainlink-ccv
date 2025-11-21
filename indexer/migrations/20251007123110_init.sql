-- +goose Up
-- +goose StatementBegin
CREATE SCHEMA IF NOT EXISTS indexer;

CREATE TABLE IF NOT EXISTS indexer.verifier_results (
    -- Primary identifiers for the verifier result (form the primary key)
    message_id TEXT NOT NULL,
    source_verifier_address TEXT NOT NULL,
    dest_verifier_address TEXT NOT NULL,
    
    -- Query fields (indexed for performance)
    timestamp TIMESTAMPTZ NOT NULL,
    source_chain_selector DECIMAL(20, 0) NOT NULL,
    dest_chain_selector DECIMAL(20, 0) NOT NULL,

    nonce BIGINT NOT NULL,
    
    -- Binary data fields
    ccv_data BYTEA,
    blob_data BYTEA,
    
    -- Message is stored for every verifier result to avoid joins and the additional overhead
    message JSONB NOT NULL,
    receipt_blobs JSONB NOT NULL,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    PRIMARY KEY (message_id, source_verifier_address, dest_verifier_address)
);

CREATE INDEX IF NOT EXISTS idx_verifier_results_message_id 
    ON indexer.verifier_results(message_id);

CREATE INDEX IF NOT EXISTS idx_verifier_results_timestamp 
    ON indexer.verifier_results(timestamp);

CREATE INDEX IF NOT EXISTS idx_verifier_results_source_chain 
    ON indexer.verifier_results(source_chain_selector);

CREATE INDEX IF NOT EXISTS idx_verifier_results_dest_chain 
    ON indexer.verifier_results(dest_chain_selector);

CREATE INDEX IF NOT EXISTS idx_verifier_results_query_pattern 
    ON indexer.verifier_results(timestamp, source_chain_selector, dest_chain_selector);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS indexer.verifier_results;
DROP SCHEMA IF EXISTS indexer CASCADE;
-- +goose StatementEnd
