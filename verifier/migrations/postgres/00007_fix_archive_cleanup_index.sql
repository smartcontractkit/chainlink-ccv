-- +goose Up

-- Flip cleanup indexes from DESC to ASC so that old rows (the target of
-- "WHERE completed_at < $1") sit at the head of the index. With ASC order
-- Postgres can do a forward Index Scan and stop as soon as the predicate
-- is no longer satisfied, giving O(deleted rows) instead of O(table) work
-- at production selectivity (e.g. daily cleanup with 30-day retention).

DROP INDEX IF EXISTS idx_ccv_task_verifier_jobs_archive_completed;
CREATE INDEX idx_ccv_task_verifier_jobs_archive_completed
    ON ccv_task_verifier_jobs_archive (owner_id, completed_at ASC);

DROP INDEX IF EXISTS idx_ccv_storage_writer_jobs_archive_completed;
CREATE INDEX idx_ccv_storage_writer_jobs_archive_completed
    ON ccv_storage_writer_jobs_archive (owner_id, completed_at ASC);

-- +goose Down

DROP INDEX IF EXISTS idx_ccv_task_verifier_jobs_archive_completed;
CREATE INDEX idx_ccv_task_verifier_jobs_archive_completed
    ON ccv_task_verifier_jobs_archive (owner_id, completed_at DESC);

DROP INDEX IF EXISTS idx_ccv_storage_writer_jobs_archive_completed;
CREATE INDEX idx_ccv_storage_writer_jobs_archive_completed
    ON ccv_storage_writer_jobs_archive (owner_id, completed_at DESC);
