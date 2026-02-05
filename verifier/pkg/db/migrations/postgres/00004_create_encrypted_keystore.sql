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

-- +goose Down
DROP TABLE IF EXISTS encrypted_keystore;
