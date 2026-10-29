-- Demo data for the verifier database; demo.sh seeds it after the harness has
-- started (the harness applies the verifier migrations at startup). Message IDs
-- are 8x8 repeats: deadbeef = attested, cafebabe = executable target, 0badf00d = expired.

-- Chain 1 is healthy; chain 2 is finality-blocked (drives the replay vs
-- reset-reader split on the source recovery page).
INSERT INTO ccv_chain_statuses (chain_selector, verifier_id, finalized_block_height, disabled, updated_at) VALUES
    (1, 'CCTPVerifier', 1150, FALSE, NOW() - INTERVAL '5 minutes'),
    (2, 'CCTPVerifier', 950, TRUE, NOW() - INTERVAL '5 minutes')
ON CONFLICT DO NOTHING;

-- One reader per chain, registered by the (pretend) running verifier.
INSERT INTO ccv_recovery_readers
    (owner_id, chain_selector, node_id, history_started_at, session_started_at,
     last_seen_at, latest_block, head_observed_at, disabled, active_reset_id,
     audit_failures, last_audit_failure_at)
VALUES
    ('CCTPVerifier', 1, 'verifier-1',
     NOW() - INTERVAL '7 days', NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 minute',
     123400, NOW() - INTERVAL '1 minute', FALSE, NULL, 0, NULL),
    ('CCTPVerifier', 2, 'verifier-1',
     NOW() - INTERVAL '7 days', NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 minute',
     99900, NOW() - INTERVAL '1 minute', TRUE, NULL, 0, NULL)
ON CONFLICT DO NOTHING;

-- Durable drop and incident evidence. The 0xcafebabe message is the demo's main
-- character: dropped pre-admission during a remote-chain curse, then re-admitted
-- and failed again in both queues.
INSERT INTO ccv_recovery_events
    (event_id, dedup_key, owner_id, node_id, chain_selector, dest_chain_selector,
     message_id, source_block, kind, stage, reason, tx_hash, block_hash, incident_id,
     details, first_observed_at, last_observed_at, observations, expires_at)
VALUES
    (gen_random_uuid(), 'demo-drop-cafebabe', 'CCTPVerifier', 'verifier-1', 1, 2,
     '0xcafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe', 1200,
     'drop', 'pre_admission', 'remote_chain_cursed', NULL, NULL, NULL,
     '{"demo": "seeded"}',
     NOW() - INTERVAL '2 hours', NOW() - INTERVAL '10 minutes', 3, NOW() + INTERVAL '30 days'),
    (gen_random_uuid(), 'demo-finality-1', 'CCTPVerifier', 'verifier-1', 1, NULL,
     NULL, NULL, 'finality_incident', 'head_tracker', 'finality_violation', NULL, NULL,
     gen_random_uuid(), '{"duration_blocks": 120}',
     NOW() - INTERVAL '3 hours', NOW() - INTERVAL '3 hours', 1, NOW() + INTERVAL '30 days');

-- Recovery operation history for the operations table.
INSERT INTO ccv_recovery_operations
    (id, owner_id, chain_selector, from_block, to_block, next_block, mode, state,
     reset_applied, actor, note, admitted, dropped, conflicts, filtered, errors,
     last_error, created_at, updated_at)
VALUES
    (gen_random_uuid(), 'CCTPVerifier', 1, 1000, 1100, 1100, 'replay', 'completed',
     FALSE, 'alice@example.com', 'post-incident recheck after the remote chain curse lifted',
     42, 2, 0, 1, 0, '', NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days' + INTERVAL '40 minutes'),
    (gen_random_uuid(), 'CCTPVerifier', 2, 500, 600, 540, 'reset-reader', 'cancelled',
     FALSE, 'bob@example.com', 'abandoned: incident turned out to be RPC flakiness',
     0, 0, 0, 0, 0, '', NOW() - INTERVAL '1 day', NOW() - INTERVAL '20 hours');

-- Failed archive rows the search and reschedule flows read; categories are derived
-- at read time from these values (verifier/pkg/jobqueue/archivecategory): policy
-- or selector errors → policy_rejected / validation_error, storage-writer rows →
-- storage_failure, completed_at past retry_deadline → retry_window_expired.
INSERT INTO ccv_task_verifier_jobs_archive
    (id, job_id, owner_id, chain_selector, message_id, task_data, status, created_at,
     available_at, started_at, attempt_count, retry_deadline, last_error, completed_at)
VALUES
    (1, gen_random_uuid(), 'CCTPVerifier', 1,
     decode('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', 'hex'),
     '{"demo": true}', 'failed',
     NOW() - INTERVAL '3 hours', NOW() - INTERVAL '3 hours', NOW() - INTERVAL '3 hours' + INTERVAL '1 minute',
     3, NOW() + INTERVAL '23 hours', 'policy hook rejected: sanctioned sender',
     NOW() - INTERVAL '1 hour'),
    (2, gen_random_uuid(), 'CCTPVerifier', 1,
     decode('cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe', 'hex'),
     '{"demo": true}', 'failed',
     NOW() - INTERVAL '90 minutes', NOW() - INTERVAL '90 minutes', NOW() - INTERVAL '90 minutes' + INTERVAL '1 minute',
     5, NOW() + INTERVAL '24 hours', 'source chain selector 9999 is not configured for this verifier',
     NOW() - INTERVAL '30 minutes'),
    (4, gen_random_uuid(), 'CCTPVerifier', 1,
     decode('0badf00d0badf00d0badf00d0badf00d0badf00d0badf00d0badf00d0badf00d', 'hex'),
     '{"demo": true}', 'failed',
     NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days' + INTERVAL '1 minute',
     2, NOW() - INTERVAL '2 days', 'transient RPC error, retried out',
     NOW() - INTERVAL '25 hours');

INSERT INTO ccv_storage_writer_jobs_archive
    (id, job_id, owner_id, chain_selector, message_id, task_data, status, created_at,
     available_at, started_at, attempt_count, retry_deadline, last_error, completed_at)
VALUES
    (3, gen_random_uuid(), 'CCTPVerifier', 1,
     decode('cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe', 'hex'),
     '{"demo": true}', 'failed',
     NOW() - INTERVAL '80 minutes', NOW() - INTERVAL '80 minutes', NOW() - INTERVAL '80 minutes' + INTERVAL '1 minute',
     2, NOW() + INTERVAL '24 hours', 'write to storage: context deadline exceeded',
     NOW() - INTERVAL '20 minutes');

-- No action-log rows: the console's audit is in-memory and session-scoped, so the
-- action log page shows only what you do live during the demo.
