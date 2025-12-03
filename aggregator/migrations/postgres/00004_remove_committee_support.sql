-- +goose Up
-- +goose StatementBegin

CREATE INDEX IF NOT EXISTS idx_verification_latest_v2 
    ON commit_verification_records(message_id, signer_address, seq_num DESC);

CREATE INDEX IF NOT EXISTS idx_verification_aggregation_key_v2 
    ON commit_verification_records(message_id, aggregation_key, seq_num DESC);

CREATE INDEX IF NOT EXISTS idx_aggregated_latest_v2 
    ON commit_aggregated_reports(message_id, seq_num DESC);

CREATE INDEX IF NOT EXISTS idx_aggregated_reports_time_query_v2 
    ON commit_aggregated_reports(created_at, message_id, seq_num DESC);

ALTER TABLE commit_verification_records 
    DROP CONSTRAINT IF EXISTS unique_verification;

ALTER TABLE commit_verification_records 
    ADD CONSTRAINT unique_verification_v2 
    UNIQUE (message_id, signer_address, idempotency_key, aggregation_key);

ALTER TABLE commit_aggregated_reports 
    DROP CONSTRAINT IF EXISTS unique_aggregated_report_sequence;

ALTER TABLE commit_aggregated_reports 
    ADD CONSTRAINT unique_aggregated_report_sequence_v2 
    UNIQUE (message_id, verification_record_ids);

DROP INDEX IF EXISTS idx_verification_latest;
DROP INDEX IF EXISTS idx_verification_aggregation_key;
DROP INDEX IF EXISTS idx_aggregated_latest;
DROP INDEX IF EXISTS idx_aggregated_reports_time_query;

-- Drop committee_id columns from tables
ALTER TABLE commit_verification_records DROP COLUMN IF EXISTS committee_id;
ALTER TABLE commit_aggregated_reports DROP COLUMN IF EXISTS committee_id;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Restore committee_id columns
ALTER TABLE commit_verification_records ADD COLUMN IF NOT EXISTS committee_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE commit_aggregated_reports ADD COLUMN IF NOT EXISTS committee_id TEXT NOT NULL DEFAULT 'default';

CREATE INDEX IF NOT EXISTS idx_verification_latest 
    ON commit_verification_records(message_id, committee_id, signer_address, seq_num DESC);

CREATE INDEX IF NOT EXISTS idx_verification_aggregation_key 
    ON commit_verification_records(message_id, aggregation_key, committee_id, seq_num DESC);

CREATE INDEX IF NOT EXISTS idx_aggregated_latest 
    ON commit_aggregated_reports(message_id, committee_id, seq_num DESC);

CREATE INDEX IF NOT EXISTS idx_aggregated_reports_time_query 
    ON commit_aggregated_reports(committee_id, created_at, message_id, seq_num DESC);

ALTER TABLE commit_verification_records 
    DROP CONSTRAINT IF EXISTS unique_verification_v2;

ALTER TABLE commit_verification_records 
    ADD CONSTRAINT unique_verification 
    UNIQUE (message_id, committee_id, signer_address, idempotency_key, aggregation_key);

ALTER TABLE commit_aggregated_reports 
    DROP CONSTRAINT IF EXISTS unique_aggregated_report_sequence_v2;

ALTER TABLE commit_aggregated_reports 
    ADD CONSTRAINT unique_aggregated_report_sequence 
    UNIQUE (message_id, committee_id, verification_record_ids);

DROP INDEX IF EXISTS idx_verification_latest_v2;
DROP INDEX IF EXISTS idx_verification_aggregation_key_v2;
DROP INDEX IF EXISTS idx_aggregated_latest_v2;
DROP INDEX IF EXISTS idx_aggregated_reports_time_query_v2;

-- +goose StatementEnd
