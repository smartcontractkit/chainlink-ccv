-- +goose Up
-- +goose StatementBegin

ALTER TABLE commit_verification_records 
    DROP COLUMN IF EXISTS participant_id;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE commit_verification_records 
    ADD COLUMN participant_id TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd
