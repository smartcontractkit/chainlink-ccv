-- +goose Up
DROP TRIGGER IF EXISTS set_timestamp_chain_statuses ON chain_statuses;
DROP FUNCTION IF EXISTS trigger_set_timestamp();
DROP INDEX IF EXISTS idx_chain_statuses_updated_at;
DROP INDEX IF EXISTS idx_chain_statuses_chain_selector;
DROP INDEX IF EXISTS idx_chain_statuses_client_id;
DROP TABLE IF EXISTS chain_statuses;

-- +goose Down
CREATE TABLE IF NOT EXISTS chain_statuses (
    id BIGSERIAL PRIMARY KEY,
    client_id TEXT NOT NULL,
    chain_selector TEXT NOT NULL,
    finalized_block_height TEXT NOT NULL,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT unique_client_chain UNIQUE (client_id, chain_selector)
);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER set_timestamp_chain_statuses
    BEFORE UPDATE ON chain_statuses
    FOR EACH ROW
    EXECUTE FUNCTION trigger_set_timestamp();

CREATE INDEX IF NOT EXISTS idx_chain_statuses_client_id ON chain_statuses(client_id);
CREATE INDEX IF NOT EXISTS idx_chain_statuses_chain_selector ON chain_statuses(chain_selector);
CREATE INDEX IF NOT EXISTS idx_chain_statuses_updated_at ON chain_statuses(updated_at);

