-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_messages_status_ingestion_timestamp
    ON indexer.messages(status, ingestion_timestamp);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS indexer.idx_messages_status_ingestion_timestamp;
-- +goose StatementEnd
