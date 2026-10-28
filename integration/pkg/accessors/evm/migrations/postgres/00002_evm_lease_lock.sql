-- +goose Up
-- One row: the process holding the EVM database lease. The unique index on a constant allows only one.
CREATE TABLE evm.lease_lock (
    client_id uuid NOT NULL,
    expires_at timestamp with time zone NOT NULL
);
CREATE UNIQUE INDEX only_one_lease_lock ON evm.lease_lock ((client_id IS NOT NULL));

-- +goose Down
DROP TABLE evm.lease_lock;
