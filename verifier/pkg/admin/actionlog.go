package admin

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

// Action is one console mutation record. OperationID carries the recovery operation ID
// when the action produced one; Detail holds per-target outcomes or error text.
type Action struct {
	ID          int64     `db:"id"`
	Actor       string    `db:"actor"`
	Action      string    `db:"action"`
	NodeName    string    `db:"node_name"`
	Target      string    `db:"target"`
	OperationID string    `db:"operation_id"`
	Outcome     string    `db:"outcome"`
	Detail      string    `db:"detail"`
	CreatedAt   time.Time `db:"created_at"`
}

// ActionLog is the durable record of every console mutation. It lives in the console's
// own database, never in a node database.
type ActionLog struct {
	ds *sqlx.DB
}

func NewActionLog(ds *sqlx.DB) *ActionLog {
	return &ActionLog{ds: ds}
}

func (l *ActionLog) Record(ctx context.Context, a Action) error {
	_, err := l.ds.ExecContext(ctx, `
		INSERT INTO ccv_admin_actions (actor, action, node_name, target, operation_id, outcome, detail)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		a.Actor, a.Action, a.NodeName, a.Target, a.OperationID, a.Outcome, a.Detail)
	if err != nil {
		return fmt.Errorf("failed to record action: %w", err)
	}
	return nil
}

// List returns newest-first actions; beforeID=0 starts at the latest.
func (l *ActionLog) List(ctx context.Context, limit int, beforeID int64) ([]Action, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var actions []Action
	err := l.ds.SelectContext(ctx, &actions, `
		SELECT id, actor, action, node_name, target, operation_id, outcome, detail, created_at
		FROM ccv_admin_actions
		WHERE ($1 = 0 OR id < $1)
		ORDER BY id DESC
		LIMIT $2`, beforeID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list actions: %w", err)
	}
	return actions, nil
}
