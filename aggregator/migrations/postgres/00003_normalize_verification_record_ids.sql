-- +goose Up

-- Junction table with FK enforcement
CREATE TABLE commit_aggregated_report_verifications (
    aggregated_report_id BIGINT NOT NULL
        REFERENCES commit_aggregated_reports(id) ON DELETE CASCADE,
    verification_record_id BIGINT NOT NULL
        REFERENCES commit_verification_records(id) ON DELETE RESTRICT,
    ordinal INT NOT NULL,
    PRIMARY KEY (aggregated_report_id, verification_record_id)
);

CREATE INDEX idx_carv_verification_id
    ON commit_aggregated_report_verifications(verification_record_id);

-- Migrate existing array data into the junction table
INSERT INTO commit_aggregated_report_verifications
    (aggregated_report_id, verification_record_id, ordinal)
SELECT car.id, vid.id, vid.ord
FROM commit_aggregated_reports car,
     LATERAL UNNEST(car.verification_record_ids) WITH ORDINALITY AS vid(id, ord);

-- Add aggregation_key to reports (needed for orphan lookup by key so CCV version change triggers recovery)
ALTER TABLE commit_aggregated_reports ADD COLUMN aggregation_key TEXT;
UPDATE commit_aggregated_reports car
SET aggregation_key = (
    SELECT cvr.aggregation_key
    FROM commit_verification_records cvr
    JOIN commit_aggregated_report_verifications carv ON carv.verification_record_id = cvr.id
    WHERE carv.aggregated_report_id = car.id
    ORDER BY carv.ordinal
    LIMIT 1
);
ALTER TABLE commit_aggregated_reports ALTER COLUMN aggregation_key SET NOT NULL;

-- Enforce NOT NULL on columns that should never be nullable
ALTER TABLE commit_verification_records ALTER COLUMN ccv_version SET NOT NULL;
ALTER TABLE commit_verification_records ALTER COLUMN signature SET NOT NULL;
ALTER TABLE commit_verification_records ALTER COLUMN message_ccv_addresses SET NOT NULL;
ALTER TABLE commit_verification_records ALTER COLUMN message_executor_address SET NOT NULL;

-- Replace old constraint with one that includes aggregation_key
ALTER TABLE commit_aggregated_reports
    DROP CONSTRAINT unique_aggregated_report_sequence;
ALTER TABLE commit_aggregated_reports
    ADD CONSTRAINT unique_report_message_key_verifications
    UNIQUE (message_id, aggregation_key, verification_record_ids);

-- Drop idx_verification_latest (migration 00002 added ccv_version to it, but
-- batchGetVerificationRecordIDs now filters by aggregation_key instead of ccv_version;
-- the unique_verification constraint covers that query)
DROP INDEX IF EXISTS idx_verification_latest;

-- Replace idx_aggregated_latest to include aggregation_key (needed by
-- GetCommitAggregatedReportByAggregationKey and orphan LEFT JOIN)
DROP INDEX IF EXISTS idx_aggregated_latest;
CREATE INDEX idx_aggregated_latest
    ON commit_aggregated_reports(message_id, aggregation_key, seq_num DESC);

-- +goose Down

DROP INDEX IF EXISTS idx_aggregated_latest;
CREATE INDEX idx_aggregated_latest ON commit_aggregated_reports(message_id, seq_num DESC);

CREATE INDEX idx_verification_latest
    ON commit_verification_records(message_id, signer_identifier, ccv_version, seq_num DESC);

ALTER TABLE commit_aggregated_reports
    DROP CONSTRAINT unique_report_message_key_verifications;
ALTER TABLE commit_aggregated_reports
    ADD CONSTRAINT unique_aggregated_report_sequence UNIQUE (message_id, verification_record_ids);

ALTER TABLE commit_aggregated_reports DROP COLUMN aggregation_key;

ALTER TABLE commit_verification_records ALTER COLUMN message_executor_address DROP NOT NULL;
ALTER TABLE commit_verification_records ALTER COLUMN message_ccv_addresses DROP NOT NULL;
ALTER TABLE commit_verification_records ALTER COLUMN signature DROP NOT NULL;
ALTER TABLE commit_verification_records ALTER COLUMN ccv_version DROP NOT NULL;

DROP INDEX IF EXISTS idx_carv_verification_id;
DROP TABLE IF EXISTS commit_aggregated_report_verifications;
