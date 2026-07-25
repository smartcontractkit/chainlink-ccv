-- +goose Up
ALTER TABLE verifier_node_results ADD COLUMN traceparent TEXT;

-- +goose Down
ALTER TABLE verifier_node_results DROP COLUMN traceparent TEXT;
