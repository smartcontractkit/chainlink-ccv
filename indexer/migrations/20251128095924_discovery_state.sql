-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS indexer.discovery_state(
  discovery_location TEXT PRIMARY KEY,
  last_sequence_number BIGINT NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE TABLE indexer.discovery_state;
-- +goose StatementEnd
