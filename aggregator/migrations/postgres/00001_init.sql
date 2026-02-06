-- +goose Up
CREATE SEQUENCE IF NOT EXISTS commit_verification_records_seq_num_seq;
CREATE SEQUENCE IF NOT EXISTS commit_aggregated_reports_seq_num_seq;

CREATE TABLE IF NOT EXISTS commit_verification_records (
    id BIGSERIAL PRIMARY KEY,
    seq_num BIGINT NOT NULL DEFAULT nextval('commit_verification_records_seq_num_seq'),
    message_id TEXT NOT NULL,
    signer_identifier TEXT NOT NULL,
    aggregation_key TEXT NOT NULL,
    message_data JSONB NOT NULL,
    ccv_version BYTEA,
    signature BYTEA,
    message_ccv_addresses TEXT[],
    message_executor_address TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_verification UNIQUE (message_id, signer_identifier, aggregation_key)
);

CREATE TABLE IF NOT EXISTS commit_aggregated_reports (
    id BIGSERIAL PRIMARY KEY,
    seq_num BIGINT NOT NULL DEFAULT nextval('commit_aggregated_reports_seq_num_seq'),
    message_id TEXT NOT NULL,
    verification_record_ids BIGINT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_aggregated_report_sequence UNIQUE (message_id, verification_record_ids)
);

CREATE INDEX IF NOT EXISTS idx_verification_latest ON commit_verification_records(message_id, signer_identifier, seq_num DESC);
CREATE INDEX IF NOT EXISTS idx_verification_aggregation_key ON commit_verification_records(message_id, aggregation_key, seq_num DESC);
CREATE INDEX IF NOT EXISTS idx_verification_orphan_scan ON commit_verification_records(created_at, message_id, aggregation_key);
CREATE INDEX IF NOT EXISTS idx_aggregated_latest ON commit_aggregated_reports(message_id, seq_num DESC);
CREATE INDEX IF NOT EXISTS idx_aggregated_seq_num ON commit_aggregated_reports(seq_num ASC);

-- +goose Down
DROP INDEX IF EXISTS idx_aggregated_seq_num;
DROP INDEX IF EXISTS idx_aggregated_latest;
DROP INDEX IF EXISTS idx_verification_orphan_scan;
DROP INDEX IF EXISTS idx_verification_aggregation_key;
DROP INDEX IF EXISTS idx_verification_latest;

DROP TABLE IF EXISTS commit_aggregated_reports;
DROP TABLE IF EXISTS commit_verification_records;

DROP SEQUENCE IF EXISTS commit_aggregated_reports_seq_num_seq;
DROP SEQUENCE IF EXISTS commit_verification_records_seq_num_seq;
