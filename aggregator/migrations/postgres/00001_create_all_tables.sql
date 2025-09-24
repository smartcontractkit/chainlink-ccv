-- +goose Up
-- Create all tables and indexes for PostgreSQL

-- Create function to automatically update updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create commit_verification_records table
CREATE TABLE IF NOT EXISTS commit_verification_records (
    id BIGSERIAL PRIMARY KEY,
    message_id TEXT NOT NULL,
    committee_id TEXT NOT NULL,
    participant_id TEXT NOT NULL DEFAULT '',
    signer_address TEXT NOT NULL,
    source_chain_selector TEXT NOT NULL,
    dest_chain_selector TEXT NOT NULL,
    onramp_address TEXT NOT NULL,
    offramp_address TEXT NOT NULL,
    signature_r BYTEA NOT NULL DEFAULT '',
    signature_s BYTEA NOT NULL DEFAULT '',
    ccv_node_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT unique_verification UNIQUE (message_id, signer_address, committee_id)
);

-- Create commit_aggregated_reports table
CREATE TABLE IF NOT EXISTS commit_aggregated_reports (
    id BIGSERIAL PRIMARY KEY,
    message_id TEXT NOT NULL,
    committee_id TEXT NOT NULL,
    report_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT unique_aggregated_report UNIQUE (message_id, committee_id)
);

-- Create block_checkpoints table
CREATE TABLE IF NOT EXISTS block_checkpoints (
    id BIGSERIAL PRIMARY KEY,
    client_id TEXT NOT NULL,
    chain_selector TEXT NOT NULL,
    finalized_block_height TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT unique_client_chain UNIQUE (client_id, chain_selector)
);

-- Create indexes for commit_verification_records
CREATE INDEX IF NOT EXISTS idx_commit_verification_records_message_id ON commit_verification_records(message_id);
CREATE INDEX IF NOT EXISTS idx_commit_verification_records_committee_id ON commit_verification_records(committee_id);

-- Create indexes for commit_aggregated_reports
CREATE INDEX IF NOT EXISTS idx_commit_aggregated_reports_committee_id ON commit_aggregated_reports(committee_id);
CREATE INDEX IF NOT EXISTS idx_commit_aggregated_reports_updated_at ON commit_aggregated_reports(updated_at);

-- Create indexes for block_checkpoints
CREATE INDEX IF NOT EXISTS idx_block_checkpoints_client_id ON block_checkpoints(client_id);
CREATE INDEX IF NOT EXISTS idx_block_checkpoints_chain_selector ON block_checkpoints(chain_selector);
CREATE INDEX IF NOT EXISTS idx_block_checkpoints_updated_at ON block_checkpoints(updated_at);

-- Create triggers to automatically update updated_at column
CREATE TRIGGER update_commit_verification_records_updated_at
    BEFORE UPDATE ON commit_verification_records
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_commit_aggregated_reports_updated_at
    BEFORE UPDATE ON commit_aggregated_reports
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_block_checkpoints_updated_at
    BEFORE UPDATE ON block_checkpoints
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- +goose Down
-- Drop triggers first
DROP TRIGGER IF EXISTS update_block_checkpoints_updated_at ON block_checkpoints;
DROP TRIGGER IF EXISTS update_commit_aggregated_reports_updated_at ON commit_aggregated_reports;
DROP TRIGGER IF EXISTS update_commit_verification_records_updated_at ON commit_verification_records;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop indexes
DROP INDEX IF EXISTS idx_block_checkpoints_updated_at;
DROP INDEX IF EXISTS idx_block_checkpoints_chain_selector;
DROP INDEX IF EXISTS idx_block_checkpoints_client_id;
DROP INDEX IF EXISTS idx_commit_aggregated_reports_updated_at;
DROP INDEX IF EXISTS idx_commit_aggregated_reports_committee_id;
DROP INDEX IF EXISTS idx_commit_verification_records_committee_id;
DROP INDEX IF EXISTS idx_commit_verification_records_message_id;

-- Drop tables
DROP TABLE IF EXISTS block_checkpoints;
DROP TABLE IF EXISTS commit_aggregated_reports;
DROP TABLE IF EXISTS commit_verification_records;