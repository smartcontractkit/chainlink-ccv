-- +goose Up
CREATE TABLE IF NOT EXISTS chain_statuses (
    chain_selector TEXT PRIMARY KEY,
    finalized_block_height TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- +goose Down
DROP TABLE IF EXISTS chain_statuses;

