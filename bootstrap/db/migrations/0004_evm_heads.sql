-- +goose Up

-- The evm schema holds tables owned by chainlink-evm's production services, which standalone CCV
-- runs directly (see integration/pkg/accessors/evm). chainlink-evm ships no migrations of its own:
-- in a Chainlink node these tables come from chainlink-core's migration set, so CCV owns an adapted
-- copy here and runs it through the bootstrapper's normal migration path.
--
-- A dedicated schema rather than public lets the column and index names match chainlink-evm's
-- hardcoded queries exactly without colliding with CCV's own tables.
CREATE SCHEMA IF NOT EXISTS evm;

-- heads is read and written by chainlink-evm/pkg/heads.DbORM. Its column set is fixed by that ORM's
-- queries, so it is copied rather than designed.
--
-- Two deliberate differences from chainlink-core's version of this table:
--
--  1. No id column. Core still carries one as deprecated_id (its migration 0292) only so it can
--     confirm nothing reads it before a hard drop. A head is uniquely identified by
--     (evm_chain_id, hash), the ORM never selects or inserts an id, and this schema is new, so
--     there is nothing to deprecate.
--  2. No foreign key on evm_chain_id. Core's referenced evm_chains table was removed in its
--     migration 0184, and standalone CCV has no chain registry table at all: the set of chains is
--     the mounted EVM config.
CREATE TABLE IF NOT EXISTS evm.heads (
    hash BYTEA NOT NULL,
    number BIGINT NOT NULL,
    parent_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    "timestamp" TIMESTAMPTZ NOT NULL,
    l1_block_number BIGINT,
    evm_chain_id NUMERIC(78, 0) NOT NULL,
    base_fee_per_gas NUMERIC(78, 0),
    CONSTRAINT chk_hash_size CHECK (octet_length(hash) = 32),
    CONSTRAINT chk_parent_hash_size CHECK (octet_length(parent_hash) = 32)
);

-- IdempotentInsertHead relies on ON CONFLICT DO NOTHING against this unique index, so re-inserting
-- a head the tracker has already seen (on restart, or when a subscription redelivers one) is a
-- no-op rather than a duplicate row.
CREATE UNIQUE INDEX IF NOT EXISTS idx_heads_evm_chain_id_hash ON evm.heads (evm_chain_id, hash);

-- Serves LatestHead, LatestHeads, and TrimOldHeads, which all filter on evm_chain_id and then order
-- or range over number.
CREATE INDEX IF NOT EXISTS idx_heads_evm_chain_id_number ON evm.heads (evm_chain_id, number);

-- +goose Down
DROP TABLE IF EXISTS evm.heads;
DROP SCHEMA IF EXISTS evm;
