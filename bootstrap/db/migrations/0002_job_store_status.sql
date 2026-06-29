-- +goose Up
ALTER TABLE job_store
    ADD COLUMN status TEXT NOT NULL DEFAULT 'approved'
        CHECK (status IN ('pending', 'approved'));

-- +goose Down
ALTER TABLE job_store
    DROP COLUMN status;
