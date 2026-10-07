package db

import (
	"context"
	"fmt"
	"sync"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"

	"github.com/smartcontractkit/chainlink-ccv/verifier/migrations"
)

var migrationMutex = sync.Mutex{}

// RunPostgresMigrations applies PostgreSQL database migrations.
//
// Deprecated: use RunPostgresMigrationsContext so a caller's startup deadline
// can abort a hung migration; this wrapper is unbounded by any caller context.
func RunPostgresMigrations(db *sqlx.DB) error {
	return RunPostgresMigrationsContext(context.Background(), db)
}

// RunPostgresMigrationsContext applies PostgreSQL database migrations, aborting
// when ctx is done.
func RunPostgresMigrationsContext(ctx context.Context, db *sqlx.DB) error {
	migrationMutex.Lock()
	defer migrationMutex.Unlock()

	goose.SetBaseFS(migrations.PostgresMigrations)

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set goose dialect: %w", err)
	}

	if err := goose.UpContext(ctx, db.DB, "postgres"); err != nil {
		return fmt.Errorf("failed to run postgres migrations: %w", err)
	}

	return nil
}
