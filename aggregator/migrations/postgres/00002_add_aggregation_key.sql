-- +goose Up
ALTER TABLE commit_verification_records ADD COLUMN aggregation_key TEXT;

-- Backfill existing rows with message_id
UPDATE commit_verification_records SET aggregation_key = message_id WHERE aggregation_key IS NULL;

-- Make the column NOT NULL
ALTER TABLE commit_verification_records ALTER COLUMN aggregation_key SET NOT NULL;

-- Drop the old unique constraint
ALTER TABLE commit_verification_records DROP CONSTRAINT unique_verification;

-- Add the new unique constraint with aggregation_key
ALTER TABLE commit_verification_records ADD CONSTRAINT unique_verification UNIQUE (message_id, committee_id, signer_address, idempotency_key, aggregation_key);

-- Add index for efficient querying by aggregation_key
CREATE INDEX IF NOT EXISTS idx_verification_aggregation_key ON commit_verification_records(message_id, aggregation_key, committee_id, seq_num DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_verification_aggregation_key;

-- Drop the new unique constraint
ALTER TABLE commit_verification_records DROP CONSTRAINT unique_verification;

-- Restore the old unique constraint
ALTER TABLE commit_verification_records ADD CONSTRAINT unique_verification UNIQUE (message_id, committee_id, signer_address, idempotency_key);

ALTER TABLE commit_verification_records DROP COLUMN aggregation_key;