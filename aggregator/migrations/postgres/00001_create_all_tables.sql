-- +goose Up
CREATE SEQUENCE IF NOT EXISTS commit_verification_records_seq_num_seq;
CREATE SEQUENCE IF NOT EXISTS commit_aggregated_reports_seq_num_seq;
CREATE TABLE IF NOT EXISTS commit_verification_records (
    id BIGSERIAL PRIMARY KEY,
    seq_num BIGINT NOT NULL DEFAULT nextval('commit_verification_records_seq_num_seq'),
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
    CONSTRAINT unique_verification_sequence UNIQUE (message_id, committee_id, signer_address, seq_num)
);

CREATE TABLE IF NOT EXISTS commit_aggregated_reports (
    id BIGSERIAL PRIMARY KEY,
    seq_num BIGINT NOT NULL DEFAULT nextval('commit_aggregated_reports_seq_num_seq'),
    message_id TEXT NOT NULL,
    committee_id TEXT NOT NULL,
    verification_record_ids BIGINT[] NOT NULL,
    report_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_aggregated_report_sequence UNIQUE (message_id, committee_id, seq_num)
);

CREATE TABLE IF NOT EXISTS block_checkpoints (
    id BIGSERIAL PRIMARY KEY,
    client_id TEXT NOT NULL,
    chain_selector TEXT NOT NULL,
    finalized_block_height TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT unique_client_chain UNIQUE (client_id, chain_selector)
);

-- Used by all "latest record" queries
CREATE INDEX IF NOT EXISTS idx_verification_latest ON commit_verification_records(message_id, committee_id, signer_address, seq_num DESC);
-- Used by batchGetVerificationRecords
CREATE INDEX IF NOT EXISTS idx_verification_by_id ON commit_verification_records(id);
-- Used by GetCCVData and aggregated report queries
CREATE INDEX IF NOT EXISTS idx_aggregated_latest ON commit_aggregated_reports(message_id, committee_id, seq_num DESC);
-- Used by QueryAggregatedReports with time range
CREATE INDEX IF NOT EXISTS idx_aggregated_reports_time_query ON commit_aggregated_reports(committee_id, created_at, message_id, seq_num DESC);
-- Used by ListOrphanedMessageCommitteePairs for efficient LEFT JOIN on (message_id, committee_id)
CREATE INDEX IF NOT EXISTS idx_verification_message_committee ON commit_verification_records(message_id, committee_id);
CREATE INDEX IF NOT EXISTS idx_aggregated_message_committee ON commit_aggregated_reports(message_id, committee_id);

-- Used by Checkpoint APIs
CREATE INDEX IF NOT EXISTS idx_block_checkpoints_client_id ON block_checkpoints(client_id);
CREATE INDEX IF NOT EXISTS idx_block_checkpoints_chain_selector ON block_checkpoints(chain_selector);
CREATE INDEX IF NOT EXISTS idx_block_checkpoints_updated_at ON block_checkpoints(updated_at);



-- +goose Down
DROP INDEX IF EXISTS idx_aggregated_message_committee;
DROP INDEX IF EXISTS idx_verification_message_committee;
DROP INDEX IF EXISTS idx_block_checkpoints_updated_at;
DROP INDEX IF EXISTS idx_block_checkpoints_chain_selector;
DROP INDEX IF EXISTS idx_block_checkpoints_client_id;
DROP INDEX IF EXISTS idx_aggregated_latest;
DROP INDEX IF EXISTS idx_verification_by_id;
DROP INDEX IF EXISTS idx_verification_latest;
DROP INDEX IF EXISTS idx_aggregated_reports_time_query;

DROP TABLE IF EXISTS block_checkpoints;
DROP TABLE IF EXISTS commit_aggregated_reports;
DROP TABLE IF EXISTS commit_verification_records;

DROP SEQUENCE IF EXISTS commit_verification_records_seq_num_seq;
DROP SEQUENCE IF EXISTS commit_aggregated_reports_seq_num_seq;
DROP SEQUENCE IF EXISTS commit_verification_records_seq_num_seq;
DROP SEQUENCE IF EXISTS commit_aggregated_reports_seq_num_seq;