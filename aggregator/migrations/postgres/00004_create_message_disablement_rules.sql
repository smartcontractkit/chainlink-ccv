-- +goose Up
CREATE TABLE message_disablement_rules (
    id UUID PRIMARY KEY,
    type TEXT NOT NULL CHECK (type IN ('Chain', 'Lane', 'Token')),
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (type, data)
);

-- +goose Down
DROP TABLE IF EXISTS message_disablement_rules;
