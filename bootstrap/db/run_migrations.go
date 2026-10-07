package db

import (
	"context"
	"embed"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

var migrationGate = make(chan struct{}, 1)

// RunMigrations applies the bootstrap database migrations.
//
// Deprecated: use RunMigrationsContext so a caller's startup deadline can abort
// a hung migration; this wrapper is unbounded by any caller context.
func RunMigrations(db *sqlx.DB) error {
	return RunMigrationsContext(context.Background(), db)
}

// RunMigrationsContext applies the bootstrap database migrations, aborting when
// ctx is done.
func RunMigrationsContext(ctx context.Context, db *sqlx.DB) error {
	select {
	case migrationGate <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("aborted waiting for migration gate: %w", ctx.Err())
	}
	defer func() { <-migrationGate }()

	goose.SetBaseFS(migrations)

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set goose dialect: %w", err)
	}

	if err := goose.UpContext(ctx, db.DB, "migrations"); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}
