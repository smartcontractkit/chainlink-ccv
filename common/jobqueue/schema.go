package jobqueue

import "fmt"

// CreateTablesSQL returns the DDL for a DedupKeyColumn queue table and its archive.
// Services copy its output into their own migrations; tests run it directly.
func CreateTablesSQL(name string) string {
	return fmt.Sprintf(`
CREATE TABLE %[1]s
(
    id             BIGSERIAL   PRIMARY KEY,
    job_id         UUID        UNIQUE NOT NULL,
    owner_id       TEXT        NOT NULL,
    dedup_key      TEXT        NOT NULL,
    task_data      JSONB       NOT NULL,
    status         TEXT        NOT NULL DEFAULT 'pending',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    available_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at     TIMESTAMPTZ,
    attempt_count  INT         NOT NULL DEFAULT 0,
    retry_deadline TIMESTAMPTZ NOT NULL,
    last_error     TEXT,
    CONSTRAINT %[1]s_status_check CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    CONSTRAINT %[1]s_unique_job UNIQUE (owner_id, dedup_key)
);

CREATE INDEX idx_%[1]s_consume
    ON %[1]s (owner_id, available_at ASC, id ASC) WHERE status = 'pending';

CREATE INDEX idx_%[1]s_stale
    ON %[1]s (owner_id, started_at ASC, id ASC) WHERE status = 'processing' AND started_at IS NOT NULL;

CREATE INDEX idx_%[1]s_status
    ON %[1]s (owner_id, status);

CREATE TABLE %[1]s_archive
(
    id             BIGINT      PRIMARY KEY,
    job_id         UUID        UNIQUE NOT NULL,
    owner_id       TEXT        NOT NULL,
    dedup_key      TEXT        NOT NULL,
    task_data      JSONB       NOT NULL,
    status         TEXT        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL,
    available_at   TIMESTAMPTZ NOT NULL,
    started_at     TIMESTAMPTZ,
    attempt_count  INT         NOT NULL,
    retry_deadline TIMESTAMPTZ NOT NULL,
    last_error     TEXT,
    completed_at   TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_%[1]s_archive_completed
    ON %[1]s_archive (owner_id, completed_at DESC);

CREATE INDEX idx_%[1]s_archive_dedup_key
    ON %[1]s_archive (dedup_key);
`, name)
}
