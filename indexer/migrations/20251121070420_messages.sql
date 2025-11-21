-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS indexer.messages (
  -- Primary Key
  message_id TEXT NOT NULL,

  -- Message & Indexing Fields
  message JSONB NOT NULL,
  status TEXT NOT NULL,
  lastErr TEXT,

  -- Query fields
  source_chain_selector DECIMAL(20, 0) NOT NULL,
  dest_chain_selector DECIMAL(20, 0) NOT NULL,

  -- Metadata
  ingestion_timestamp TIMESTAMP NOT NULL,

  -- Constraints
  PRIMARY KEY (message_id)
)
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS indexer.messages;
-- +goose StatementEnd
