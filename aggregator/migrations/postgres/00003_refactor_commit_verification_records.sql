-- +goose Up
DROP TABLE IF EXISTS commit_aggregated_reports CASCADE;
DROP TABLE IF EXISTS commit_verification_records CASCADE;
DROP SEQUENCE IF EXISTS commit_verification_records_seq_num_seq;
DROP SEQUENCE IF EXISTS commit_aggregated_reports_seq_num_seq;

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
    verification_timestamp TIMESTAMPTZ NOT NULL,
    idempotency_key UUID NOT NULL,
    aggregation_key TEXT NOT NULL,
    
    source_verifier_address BYTEA NOT NULL,
    blob_data BYTEA NOT NULL,
    ccv_data BYTEA NOT NULL,
    
    message_data JSONB NOT NULL,
    receipt_blobs JSONB,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_verification UNIQUE (message_id, committee_id, signer_address, idempotency_key, aggregation_key)
);

CREATE TABLE IF NOT EXISTS commit_aggregated_reports (
    id BIGSERIAL PRIMARY KEY,
    seq_num BIGINT NOT NULL DEFAULT nextval('commit_aggregated_reports_seq_num_seq'),
    message_id TEXT NOT NULL,
    committee_id TEXT NOT NULL,
    verification_record_ids BIGINT[] NOT NULL,
    winning_receipt_blobs JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_aggregated_report_sequence UNIQUE (message_id, committee_id, verification_record_ids)
);

CREATE INDEX IF NOT EXISTS idx_verification_latest ON commit_verification_records(message_id, committee_id, signer_address, seq_num DESC);
CREATE INDEX IF NOT EXISTS idx_verification_by_id ON commit_verification_records(id);
CREATE INDEX IF NOT EXISTS idx_verification_aggregation_key ON commit_verification_records(message_id, aggregation_key, committee_id, seq_num DESC);
CREATE INDEX IF NOT EXISTS idx_aggregated_latest ON commit_aggregated_reports(message_id, committee_id, seq_num DESC);
CREATE INDEX IF NOT EXISTS idx_aggregated_reports_time_query ON commit_aggregated_reports(committee_id, created_at, message_id, seq_num DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_aggregated_reports_time_query;
DROP INDEX IF EXISTS idx_aggregated_latest;
DROP INDEX IF EXISTS idx_verification_aggregation_key;
DROP INDEX IF EXISTS idx_verification_by_id;
DROP INDEX IF EXISTS idx_verification_latest;

DROP TABLE IF EXISTS commit_aggregated_reports;
DROP TABLE IF EXISTS commit_verification_records;

DROP SEQUENCE IF EXISTS commit_verification_records_seq_num_seq;
DROP SEQUENCE IF EXISTS commit_aggregated_reports_seq_num_seq;
