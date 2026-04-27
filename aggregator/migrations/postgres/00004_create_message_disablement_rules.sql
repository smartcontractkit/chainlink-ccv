-- +goose Up
CREATE TABLE message_disablement_rules (
    id UUID PRIMARY KEY,
    type TEXT NOT NULL CHECK (type IN ('Chain', 'Lane', 'Token')),
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (type, data)
);

CREATE INDEX idx_message_disablement_rules_type ON message_disablement_rules (type);

-- +goose Down
DROP INDEX IF EXISTS idx_message_disablement_rules_type;
DROP TABLE IF EXISTS message_disablement_rules;
