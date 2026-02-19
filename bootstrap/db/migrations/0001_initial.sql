-- +goose Up

-- This table is used by the keystore library to store encrypted key material.
-- See: https://github.com/smartcontractkit/chainlink-common/tree/main/keystore
CREATE TABLE IF NOT EXISTS encrypted_keystore (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    encrypted_data BYTEA NOT NULL
);

-- This table stores the active job spec received from the Job Distributor.
-- Only one job should be active at a time; new jobs replace the previous one.
CREATE TABLE IF NOT EXISTS job_store (
    id SERIAL PRIMARY KEY,
    proposal_id TEXT NOT NULL,
    version BIGINT NOT NULL,
    spec TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose Down
DROP TABLE IF EXISTS encrypted_keystore;
DROP TABLE IF EXISTS job_store;
