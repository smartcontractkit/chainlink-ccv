-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS indexer.replay_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  force_overwrite BOOLEAN NOT NULL DEFAULT false,

  -- Deterministic hash of the request parameters (type, force, since/message_ids).
  -- Used by FindResumable to match a crashed job to an identical retry request.
  request_hash TEXT NOT NULL DEFAULT '',

  -- Discovery replay params
  since_sequence_number BIGINT,

  -- Message replay params
  message_ids TEXT[],

  -- Progress tracking (resumable cursor)
  progress_cursor BIGINT DEFAULT 0,
  total_items INT DEFAULT 0,
  processed_items INT DEFAULT 0,

  -- Heartbeat for stale-job detection
  last_heartbeat TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  error_message TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_replay_jobs_status ON indexer.replay_jobs (status);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS indexer.replay_jobs;
-- +goose StatementEnd
