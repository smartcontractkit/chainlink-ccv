-- +goose Up
-- +goose StatementBegin

-- Update commit_verification_records table
-- Drop the old UNIQUE constraint that includes idempotency_key and committee_id
ALTER TABLE commit_verification_records 
    DROP CONSTRAINT IF EXISTS unique_verification;

-- Add new columns for CCV version, signature, and message-level CCV info
ALTER TABLE commit_verification_records 
    ADD COLUMN IF NOT EXISTS ccv_version BYTEA,
    ADD COLUMN IF NOT EXISTS signature BYTEA,
    ADD COLUMN IF NOT EXISTS message_ccv_addresses TEXT[],
    ADD COLUMN IF NOT EXISTS message_executor_address TEXT;

-- Drop old columns
ALTER TABLE commit_verification_records 
    DROP COLUMN IF EXISTS source_verifier_address,
    DROP COLUMN IF EXISTS blob_data,
    DROP COLUMN IF EXISTS ccv_data,
    DROP COLUMN IF EXISTS receipt_blobs,
    DROP COLUMN IF EXISTS committee_id,
    DROP COLUMN IF EXISTS idempotency_key,
    DROP COLUMN IF EXISTS verification_timestamp;

-- Add new UNIQUE constraint without committee_id and idempotency_key
ALTER TABLE commit_verification_records 
    ADD CONSTRAINT unique_verification UNIQUE (message_id, signer_address, aggregation_key);

-- Drop the old winning_receipt_blobs column and committee_id
ALTER TABLE commit_aggregated_reports 
    DROP COLUMN IF EXISTS winning_receipt_blobs,
    DROP COLUMN IF EXISTS committee_id;

-- Drop the old unique constraint that includes committee_id
ALTER TABLE commit_aggregated_reports
    DROP CONSTRAINT IF EXISTS unique_aggregated_report_sequence;

-- Add new unique constraint without committee_id
ALTER TABLE commit_aggregated_reports
    ADD CONSTRAINT unique_aggregated_report_sequence UNIQUE (message_id, verification_record_ids);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Restore commit_verification_records old constraint
ALTER TABLE commit_verification_records
    DROP CONSTRAINT IF EXISTS unique_verification;

-- Restore commit_verification_records old columns
ALTER TABLE commit_verification_records 
    ADD COLUMN IF NOT EXISTS source_verifier_address BYTEA,
    ADD COLUMN IF NOT EXISTS blob_data BYTEA,
    ADD COLUMN IF NOT EXISTS ccv_data BYTEA,
    ADD COLUMN IF NOT EXISTS receipt_blobs JSONB,
    ADD COLUMN IF NOT EXISTS committee_id TEXT,
    ADD COLUMN IF NOT EXISTS idempotency_key UUID,
    ADD COLUMN IF NOT EXISTS verification_timestamp TIMESTAMPTZ;

-- For existing records, set verification_timestamp to created_at
UPDATE commit_verification_records
SET verification_timestamp = created_at
WHERE verification_timestamp IS NULL;

-- Make it not null
ALTER TABLE commit_verification_records 
    ALTER COLUMN verification_timestamp SET NOT NULL;

-- Remove commit_verification_records new columns
ALTER TABLE commit_verification_records 
    DROP COLUMN IF EXISTS ccv_version,
    DROP COLUMN IF EXISTS signature,
    DROP COLUMN IF EXISTS message_ccv_addresses,
    DROP COLUMN IF EXISTS message_executor_address;

-- Restore old constraint
ALTER TABLE commit_verification_records
    ADD CONSTRAINT unique_verification UNIQUE (message_id, committee_id, signer_address, idempotency_key, aggregation_key);

-- Restore commit_aggregated_reports old constraint
ALTER TABLE commit_aggregated_reports
    DROP CONSTRAINT IF EXISTS unique_aggregated_report_sequence;

-- Restore commit_aggregated_reports old columns
ALTER TABLE commit_aggregated_reports 
    ADD COLUMN IF NOT EXISTS winning_receipt_blobs JSONB,
    ADD COLUMN IF NOT EXISTS committee_id TEXT;

-- Restore old constraint
ALTER TABLE commit_aggregated_reports
    ADD CONSTRAINT unique_aggregated_report_sequence UNIQUE (message_id, committee_id, verification_record_ids);

-- +goose StatementEnd
