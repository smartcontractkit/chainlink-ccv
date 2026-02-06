-- +goose Up
DROP INDEX IF EXISTS idx_verification_latest;
CREATE INDEX idx_verification_latest ON commit_verification_records(message_id, signer_identifier, ccv_version, seq_num DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_verification_latest;
CREATE INDEX idx_verification_latest ON commit_verification_records(message_id, signer_identifier, seq_num DESC);
