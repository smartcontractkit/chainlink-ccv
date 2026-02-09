-- +goose Up
-- This table stores the active job spec received from the Job Distributor.
CREATE TABLE IF NOT EXISTS job_store (
    id SERIAL PRIMARY KEY,
    proposal_id TEXT NOT NULL,
    version BIGINT NOT NULL,
    spec TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose Down
DROP TABLE IF EXISTS job_store;
