-- +goose Up
CREATE TABLE ccv_recovery_readers (
    owner_id TEXT NOT NULL,
    chain_selector NUMERIC(20,0) NOT NULL,
    node_id TEXT NOT NULL,
    history_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    session_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    latest_block NUMERIC(20,0),
    head_observed_at TIMESTAMPTZ,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    active_reset_id UUID,
    audit_failures BIGINT NOT NULL DEFAULT 0,
    last_audit_failure_at TIMESTAMPTZ,
    PRIMARY KEY (owner_id, chain_selector)
);

CREATE TABLE ccv_recovery_events (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    dedup_key TEXT NOT NULL UNIQUE,
    owner_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    chain_selector NUMERIC(20,0) NOT NULL,
    dest_chain_selector NUMERIC(20,0),
    message_id TEXT,
    source_block NUMERIC(20,0),
    kind TEXT NOT NULL CHECK (kind IN ('drop', 'finality_incident', 'reader_reset')),
    stage TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN ('remote_chain_cursed', 'message_disablement_rule', 'finality_violation', 'operator_reset')),
    tx_hash TEXT,
    block_hash TEXT,
    incident_id UUID,
    details JSONB NOT NULL DEFAULT '{}',
    first_observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    observations BIGINT NOT NULL DEFAULT 1,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days'
);
CREATE INDEX idx_ccv_recovery_events_owner ON ccv_recovery_events (owner_id, chain_selector, id DESC);
CREATE INDEX idx_ccv_recovery_events_message ON ccv_recovery_events (message_id, id DESC) WHERE message_id IS NOT NULL;
CREATE INDEX idx_ccv_recovery_events_expiry ON ccv_recovery_events (owner_id, expires_at);

CREATE TABLE ccv_recovery_operations (
    id UUID PRIMARY KEY,
    owner_id TEXT NOT NULL,
    chain_selector NUMERIC(20,0) NOT NULL,
    from_block NUMERIC(20,0) NOT NULL CHECK (from_block >= 0),
    to_block NUMERIC(20,0) NOT NULL CHECK (to_block >= from_block),
    next_block NUMERIC(20,0) NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('replay', 'reset-reader')),
    state TEXT NOT NULL DEFAULT 'accepted' CHECK (state IN ('accepted', 'running', 'completed', 'cancelled', 'failed', 'blocked')),
    reset_applied BOOLEAN NOT NULL DEFAULT FALSE,
    actor TEXT NOT NULL,
    note TEXT NOT NULL,
    admitted BIGINT NOT NULL DEFAULT 0,
    dropped BIGINT NOT NULL DEFAULT 0,
    conflicts BIGINT NOT NULL DEFAULT 0,
    filtered BIGINT NOT NULL DEFAULT 0,
    errors BIGINT NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (owner_id, chain_selector) REFERENCES ccv_recovery_readers(owner_id, chain_selector)
);
CREATE INDEX idx_ccv_recovery_operations_pending ON ccv_recovery_operations (owner_id, chain_selector, created_at, id)
    WHERE state IN ('accepted', 'running');
CREATE INDEX idx_ccv_recovery_operations_expiry ON ccv_recovery_operations (owner_id, updated_at)
    WHERE state IN ('completed', 'cancelled', 'failed');

-- +goose Down
DROP TABLE ccv_recovery_operations;
DROP TABLE ccv_recovery_events;
DROP TABLE ccv_recovery_readers;
