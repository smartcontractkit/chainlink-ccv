-- +goose Up
-- Add dedup_key to the job queue tables. The old columns and unique constraint stay, so a
-- verifier that predates this migration still works after it. The trigger fills dedup_key
-- for its inserts; the format must match jobqueue.MessageDedupKey.

-- +goose StatementBegin
CREATE FUNCTION ccv_job_queue_fill_dedup_key() RETURNS trigger AS $$
BEGIN
    IF NEW.dedup_key IS NULL THEN
        NEW.dedup_key := encode(NEW.message_id, 'hex') || ':' || NEW.chain_selector::text;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

ALTER TABLE ccv_task_verifier_jobs ADD COLUMN dedup_key TEXT;
UPDATE ccv_task_verifier_jobs SET dedup_key = encode(message_id, 'hex') || ':' || chain_selector::text;
ALTER TABLE ccv_task_verifier_jobs ALTER COLUMN dedup_key SET NOT NULL;
ALTER TABLE ccv_task_verifier_jobs
    ADD CONSTRAINT ccv_task_verifier_jobs_unique_dedup_key UNIQUE (owner_id, dedup_key);
CREATE TRIGGER ccv_task_verifier_jobs_fill_dedup_key
    BEFORE INSERT ON ccv_task_verifier_jobs
    FOR EACH ROW EXECUTE FUNCTION ccv_job_queue_fill_dedup_key();

ALTER TABLE ccv_storage_writer_jobs ADD COLUMN dedup_key TEXT;
UPDATE ccv_storage_writer_jobs SET dedup_key = encode(message_id, 'hex') || ':' || chain_selector::text;
ALTER TABLE ccv_storage_writer_jobs ALTER COLUMN dedup_key SET NOT NULL;
ALTER TABLE ccv_storage_writer_jobs
    ADD CONSTRAINT ccv_storage_writer_jobs_unique_dedup_key UNIQUE (owner_id, dedup_key);
CREATE TRIGGER ccv_storage_writer_jobs_fill_dedup_key
    BEFORE INSERT ON ccv_storage_writer_jobs
    FOR EACH ROW EXECUTE FUNCTION ccv_job_queue_fill_dedup_key();

-- Archive rows from before this migration keep a NULL dedup_key; no backfill of large tables.
ALTER TABLE ccv_task_verifier_jobs_archive ADD COLUMN dedup_key TEXT;
CREATE TRIGGER ccv_task_verifier_jobs_archive_fill_dedup_key
    BEFORE INSERT ON ccv_task_verifier_jobs_archive
    FOR EACH ROW EXECUTE FUNCTION ccv_job_queue_fill_dedup_key();

ALTER TABLE ccv_storage_writer_jobs_archive ADD COLUMN dedup_key TEXT;
CREATE TRIGGER ccv_storage_writer_jobs_archive_fill_dedup_key
    BEFORE INSERT ON ccv_storage_writer_jobs_archive
    FOR EACH ROW EXECUTE FUNCTION ccv_job_queue_fill_dedup_key();

-- +goose Down
DROP TRIGGER IF EXISTS ccv_storage_writer_jobs_archive_fill_dedup_key ON ccv_storage_writer_jobs_archive;
ALTER TABLE ccv_storage_writer_jobs_archive DROP COLUMN IF EXISTS dedup_key;
DROP TRIGGER IF EXISTS ccv_task_verifier_jobs_archive_fill_dedup_key ON ccv_task_verifier_jobs_archive;
ALTER TABLE ccv_task_verifier_jobs_archive DROP COLUMN IF EXISTS dedup_key;

DROP TRIGGER IF EXISTS ccv_storage_writer_jobs_fill_dedup_key ON ccv_storage_writer_jobs;
ALTER TABLE ccv_storage_writer_jobs DROP COLUMN IF EXISTS dedup_key;
DROP TRIGGER IF EXISTS ccv_task_verifier_jobs_fill_dedup_key ON ccv_task_verifier_jobs;
ALTER TABLE ccv_task_verifier_jobs DROP COLUMN IF EXISTS dedup_key;

DROP FUNCTION IF EXISTS ccv_job_queue_fill_dedup_key();
