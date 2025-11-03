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
    verification_timestamp BIGINT NOT NULL,
    idempotency_key UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_verification UNIQUE (message_id, committee_id, signer_address, idempotency_key)
);

CREATE TABLE IF NOT EXISTS commit_aggregated_reports (
    id BIGSERIAL PRIMARY KEY,
    seq_num BIGINT NOT NULL DEFAULT nextval('commit_aggregated_reports_seq_num_seq'),
    message_id TEXT NOT NULL,
    committee_id TEXT NOT NULL,
    verification_record_ids BIGINT[] NOT NULL,
    report_data BYTEA NOT NULL,
    winning_receipt_blobs JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_aggregated_report_sequence UNIQUE (message_id, committee_id, verification_record_ids)
);

CREATE TABLE IF NOT EXISTS chain_statuses (
    id BIGSERIAL PRIMARY KEY,
    client_id TEXT NOT NULL,
    chain_selector TEXT NOT NULL,
    finalized_block_height TEXT NOT NULL,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT unique_client_chain UNIQUE (client_id, chain_selector)
);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER set_timestamp_chain_statuses
    BEFORE UPDATE ON chain_statuses
    FOR EACH ROW
    EXECUTE FUNCTION trigger_set_timestamp();

-- Used by all "latest record" queries
CREATE INDEX IF NOT EXISTS idx_verification_latest ON commit_verification_records(message_id, committee_id, signer_address, seq_num DESC);
-- Used by batchGetVerificationRecords
CREATE INDEX IF NOT EXISTS idx_verification_by_id ON commit_verification_records(id);
-- Used by GetCCVData and aggregated report queries
CREATE INDEX IF NOT EXISTS idx_aggregated_latest ON commit_aggregated_reports(message_id, committee_id, seq_num DESC);
-- Used by QueryAggregatedReports with time range
CREATE INDEX IF NOT EXISTS idx_aggregated_reports_time_query ON commit_aggregated_reports(committee_id, created_at, message_id, seq_num DESC);

-- Used by Chain Status APIs
CREATE INDEX IF NOT EXISTS idx_chain_statuses_client_id ON chain_statuses(client_id);
CREATE INDEX IF NOT EXISTS idx_chain_statuses_chain_selector ON chain_statuses(chain_selector);
CREATE INDEX IF NOT EXISTS idx_chain_statuses_updated_at ON chain_statuses(updated_at);



-- +goose Down
DROP INDEX IF EXISTS idx_chain_statuses_updated_at;
DROP INDEX IF EXISTS idx_chain_statuses_chain_selector;
DROP INDEX IF EXISTS idx_chain_statuses_client_id;
DROP INDEX IF EXISTS idx_aggregated_latest;
DROP INDEX IF EXISTS idx_verification_by_id;
DROP INDEX IF EXISTS idx_verification_latest;
DROP INDEX IF EXISTS idx_aggregated_reports_time_query;

DROP TABLE IF EXISTS chain_statuses;
DROP TABLE IF EXISTS commit_aggregated_reports;
DROP TABLE IF EXISTS commit_verification_records;

DROP SEQUENCE IF EXISTS commit_verification_records_seq_num_seq;
DROP SEQUENCE IF EXISTS commit_aggregated_reports_seq_num_seq;
DROP SEQUENCE IF EXISTS commit_verification_records_seq_num_seq;
DROP SEQUENCE IF EXISTS commit_aggregated_reports_seq_num_seq;