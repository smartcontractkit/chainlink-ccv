-- +goose Up
CREATE TABLE aggregator_chain_statuses (
    chain_selector BIGINT NOT NULL,
    lane_side TEXT NOT NULL CHECK (lane_side IN ('source', 'destination')),
    disabled BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (chain_selector, lane_side)
);

-- +goose Down
DROP TABLE IF EXISTS aggregator_chain_statuses;
