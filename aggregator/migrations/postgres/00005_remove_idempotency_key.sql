-- +goose Up
-- +goose StatementBegin

ALTER TABLE commit_verification_records 
    DROP CONSTRAINT IF EXISTS unique_verification_v2;

ALTER TABLE commit_verification_records 
    DROP COLUMN IF EXISTS idempotency_key;

ALTER TABLE commit_verification_records 
    ADD CONSTRAINT unique_verification_v3 
    UNIQUE (message_id, signer_address, aggregation_key);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE commit_verification_records 
    DROP CONSTRAINT IF EXISTS unique_verification_v3;

ALTER TABLE commit_verification_records 
    ADD COLUMN idempotency_key UUID NOT NULL DEFAULT gen_random_uuid();

ALTER TABLE commit_verification_records 
    ADD CONSTRAINT unique_verification_v2 
    UNIQUE (message_id, signer_address, idempotency_key, aggregation_key);

-- +goose StatementEnd
