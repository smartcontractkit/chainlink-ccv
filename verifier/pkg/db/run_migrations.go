package db

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"

	"github.com/smartcontractkit/chainlink-ccv/verifier/migrations"
)

var migrationGate = make(chan struct{}, 1)

// RunPostgresMigrations applies PostgreSQL database migrations.
//
// Deprecated: use RunPostgresMigrationsContext so a caller's deadline can
// abort a hung migration; this wrapper is unbounded by any caller context.
func RunPostgresMigrations(db *sqlx.DB) error {
	return RunPostgresMigrationsContext(context.Background(), db)
}

// RunPostgresMigrationsContext applies PostgreSQL database migrations, aborting
// when ctx is done. The serialization gate is ctx-aware: a concurrent migration
// holding the gate cannot block this call past its own deadline.
func RunPostgresMigrationsContext(ctx context.Context, db *sqlx.DB) error {
	select {
	case migrationGate <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("aborted waiting for migration gate: %w", ctx.Err())
	}
	defer func() { <-migrationGate }()

	goose.SetBaseFS(migrations.PostgresMigrations)

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set goose dialect: %w", err)
	}

	if err := goose.UpContext(ctx, db.DB, "postgres"); err != nil {
		return fmt.Errorf("failed to run postgres migrations: %w", err)
	}

	return nil
}
