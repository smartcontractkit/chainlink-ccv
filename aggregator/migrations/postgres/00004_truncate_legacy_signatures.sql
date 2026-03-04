-- +goose Up
UPDATE commit_verification_records
SET signature = substring(signature FROM 1 FOR 64)
WHERE length(signature) = 84;

-- +goose Down
-- Irreversible: the 20-byte signer address suffix cannot be reconstructed from the truncated data.
-- The signer address is stored separately in the signer_identifier column.
