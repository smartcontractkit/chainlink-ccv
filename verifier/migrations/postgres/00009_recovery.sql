-- +goose Up
ALTER TABLE ccv_task_verifier_jobs_archive ADD COLUMN failure_category TEXT NOT NULL DEFAULT 'unknown'
    CHECK (failure_category IN ('unknown','policy_rejected','retry_window_expired','validation_error','storage_failure'));
ALTER TABLE ccv_storage_writer_jobs_archive ADD COLUMN failure_category TEXT NOT NULL DEFAULT 'unknown'
    CHECK (failure_category IN ('unknown','policy_rejected','retry_window_expired','validation_error','storage_failure'));

-- Cover archive inventory without reading JSON payloads or unbounded error text.
CREATE INDEX idx_ccv_task_archive_inventory ON ccv_task_verifier_jobs_archive
    (owner_id, chain_selector, failure_category, completed_at) WHERE status = 'failed';
CREATE INDEX idx_ccv_storage_archive_inventory ON ccv_storage_writer_jobs_archive
    (owner_id, chain_selector, failure_category, completed_at) WHERE status = 'failed';
CREATE INDEX idx_ccv_task_archive_message ON ccv_task_verifier_jobs_archive
    (message_id, owner_id, created_at DESC, job_id DESC) WHERE status = 'failed';
CREATE INDEX idx_ccv_storage_archive_message ON ccv_storage_writer_jobs_archive
    (message_id, owner_id, created_at DESC, job_id DESC) WHERE status = 'failed';

-- +goose Down
DROP INDEX idx_ccv_storage_archive_message;
DROP INDEX idx_ccv_task_archive_message;
DROP INDEX idx_ccv_storage_archive_inventory;
DROP INDEX idx_ccv_task_archive_inventory;
ALTER TABLE ccv_storage_writer_jobs_archive DROP COLUMN failure_category;
ALTER TABLE ccv_task_verifier_jobs_archive DROP COLUMN failure_category;
