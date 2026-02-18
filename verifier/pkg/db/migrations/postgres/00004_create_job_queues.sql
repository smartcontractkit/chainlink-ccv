-- +goose Up
-- Create verification_tasks queue table
-- This table stores tasks that need to be verified by the TaskVerifierProcessor

CREATE TABLE IF NOT EXISTS verification_tasks (
    id BIGSERIAL PRIMARY KEY,
    job_id UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),

    -- Chain and message identification
    chain_selector TEXT NOT NULL,
    message_id TEXT NOT NULL,

    -- Job payload stored as JSONB for flexibility
    -- Contains serialized VerificationTask struct
    task_data JSONB NOT NULL,

    -- Job lifecycle state
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,

    -- Retry handling
    attempt_count INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    last_error TEXT,

    -- Metadata for monitoring and debugging
    block_number BIGINT NOT NULL,
    tx_hash BYTEA NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,

    -- Constraints
    CONSTRAINT verification_tasks_status_check
        CHECK (status IN ('pending', 'processing', 'completed', 'failed'))
);

-- Index for efficient job consumption
-- Using partial index to only index jobs that can be consumed
CREATE INDEX IF NOT EXISTS idx_verification_tasks_consume
    ON verification_tasks (available_at ASC, id ASC)
    WHERE status IN ('pending', 'failed');

-- Index for efficient stats queries
CREATE INDEX IF NOT EXISTS idx_verification_tasks_status
    ON verification_tasks (status);

-- Index for chain-specific queries and monitoring
CREATE INDEX IF NOT EXISTS idx_verification_tasks_chain_status
    ON verification_tasks (chain_selector, status);

-- Index for deduplication and message tracking
CREATE INDEX IF NOT EXISTS idx_verification_tasks_chain_message
    ON verification_tasks (chain_selector, message_id);

-- Index for time-based queries
CREATE INDEX IF NOT EXISTS idx_verification_tasks_created
    ON verification_tasks (created_at DESC);

-- Archive table for completed verification tasks
CREATE TABLE IF NOT EXISTS verification_tasks_archive (
    id BIGINT PRIMARY KEY,
    job_id UUID UNIQUE NOT NULL,
    chain_selector TEXT NOT NULL,
    message_id TEXT NOT NULL,
    task_data JSONB NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    available_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ NOT NULL,
    attempt_count INT NOT NULL,
    max_attempts INT NOT NULL,
    last_error TEXT,
    block_number BIGINT NOT NULL,
    tx_hash BYTEA NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL
);

-- Index for archive cleanup
CREATE INDEX IF NOT EXISTS idx_verification_tasks_archive_completed
    ON verification_tasks_archive (completed_at DESC);

-- Index for archive queries by chain
CREATE INDEX IF NOT EXISTS idx_verification_tasks_archive_chain
    ON verification_tasks_archive (chain_selector, completed_at DESC);

-- Create verification_results queue table
-- This table stores verification results that need to be written to storage

CREATE TABLE IF NOT EXISTS verification_results (
    id BIGSERIAL PRIMARY KEY,
    job_id UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),

    -- Chain and message identification
    chain_selector TEXT NOT NULL,
    message_id TEXT NOT NULL,

    -- Job payload stored as JSONB
    -- Contains serialized VerifierNodeResult struct
    result_data JSONB NOT NULL,

    -- Job lifecycle state
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,

    -- Retry handling
    attempt_count INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    last_error TEXT,

    -- Link to source task for traceability
    task_job_id UUID REFERENCES verification_tasks(job_id),

    -- Constraints
    CONSTRAINT verification_results_status_check
        CHECK (status IN ('pending', 'processing', 'completed', 'failed'))
);

-- Index for efficient job consumption
CREATE INDEX IF NOT EXISTS idx_verification_results_consume
    ON verification_results (available_at ASC, id ASC)
    WHERE status IN ('pending', 'failed');

-- Index for efficient stats queries
CREATE INDEX IF NOT EXISTS idx_verification_results_status
    ON verification_results (status);

-- Index for chain-specific queries
CREATE INDEX IF NOT EXISTS idx_verification_results_chain_status
    ON verification_results (chain_selector, status);

-- Index for message tracking
CREATE INDEX IF NOT EXISTS idx_verification_results_chain_message
    ON verification_results (chain_selector, message_id);

-- Index for time-based queries
CREATE INDEX IF NOT EXISTS idx_verification_results_created
    ON verification_results (created_at DESC);

-- Archive table for completed verification results
CREATE TABLE IF NOT EXISTS verification_results_archive (
    id BIGINT PRIMARY KEY,
    job_id UUID UNIQUE NOT NULL,
    chain_selector TEXT NOT NULL,
    message_id TEXT NOT NULL,
    result_data JSONB NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    available_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ NOT NULL,
    attempt_count INT NOT NULL,
    max_attempts INT NOT NULL,
    last_error TEXT,
    task_job_id UUID
);

-- Index for archive cleanup
CREATE INDEX IF NOT EXISTS idx_verification_results_archive_completed
    ON verification_results_archive (completed_at DESC);

-- Index for archive queries by chain
CREATE INDEX IF NOT EXISTS idx_verification_results_archive_chain
    ON verification_results_archive (chain_selector, completed_at DESC);

-- Create queue stats table for monitoring
CREATE TABLE IF NOT EXISTS job_queue_stats (
    id BIGSERIAL PRIMARY KEY,
    queue_name TEXT NOT NULL,
    chain_selector TEXT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Queue depth metrics
    pending_count BIGINT NOT NULL DEFAULT 0,
    processing_count BIGINT NOT NULL DEFAULT 0,
    failed_count BIGINT NOT NULL DEFAULT 0,
    completed_last_hour BIGINT NOT NULL DEFAULT 0,

    -- Performance metrics
    avg_processing_time_ms BIGINT,
    p95_processing_time_ms BIGINT,
    p99_processing_time_ms BIGINT,

    -- Age metrics
    oldest_pending_age_seconds BIGINT
);

-- Index for time-series queries
CREATE INDEX IF NOT EXISTS idx_job_queue_stats_queue_time
    ON job_queue_stats (queue_name, chain_selector, recorded_at DESC);

-- Index for latest stats lookup
CREATE INDEX IF NOT EXISTS idx_job_queue_stats_latest
    ON job_queue_stats (queue_name, chain_selector, recorded_at DESC);

-- Add comments for documentation
COMMENT ON TABLE verification_tasks IS 'Queue for messages that need to be verified';
COMMENT ON TABLE verification_results IS 'Queue for verification results that need to be written to storage';
COMMENT ON TABLE job_queue_stats IS 'Time-series metrics for queue monitoring';

-- +goose Down

-- Drop archive tables
DROP TABLE IF EXISTS verification_results_archive;
DROP TABLE IF EXISTS verification_tasks_archive;

-- Drop main tables (results first due to foreign key)
DROP TABLE IF EXISTS verification_results;
DROP TABLE IF EXISTS verification_tasks;

-- Drop stats table
DROP TABLE IF EXISTS job_queue_stats;

