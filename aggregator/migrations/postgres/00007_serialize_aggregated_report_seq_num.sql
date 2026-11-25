-- +goose Up
-- A report gets its seq_num only after the previous report commits, so readers see seq_num in order.
SET LOCAL lock_timeout = '5s';

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION next_aggregated_report_seq_num() RETURNS BIGINT
LANGUAGE plpgsql VOLATILE AS $$
BEGIN
    -- Key is crc64 ECMA of "aggregated_report_seq_num". The lock holds until commit or rollback.
    PERFORM pg_advisory_xact_lock(5323499729184835101);
    RETURN nextval('commit_aggregated_reports_seq_num_seq');
END;
$$;
-- +goose StatementEnd

ALTER TABLE commit_aggregated_reports
    ALTER COLUMN seq_num SET DEFAULT next_aggregated_report_seq_num();

-- Must come after ALTER TABLE: the table lock stops inserts before the sequence is locked.
ALTER SEQUENCE commit_aggregated_reports_seq_num_seq CACHE 1;

-- +goose Down
SET LOCAL lock_timeout = '5s';

ALTER TABLE commit_aggregated_reports
    ALTER COLUMN seq_num SET DEFAULT nextval('commit_aggregated_reports_seq_num_seq');

DROP FUNCTION IF EXISTS next_aggregated_report_seq_num();
