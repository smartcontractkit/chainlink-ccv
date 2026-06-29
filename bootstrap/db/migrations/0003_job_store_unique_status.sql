-- +goose Up
ALTER TABLE job_store ADD CONSTRAINT job_store_unique_status UNIQUE (status);

-- +goose Down
ALTER TABLE job_store DROP CONSTRAINT job_store_unique_status;
