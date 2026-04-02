-- +goose Up
-- +goose StatementBegin
ALTER TABLE indexer.messages
    ADD COLUMN message_ccv_addresses TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE indexer.messages
    DROP COLUMN message_ccv_addresses;
-- +goose StatementEnd
