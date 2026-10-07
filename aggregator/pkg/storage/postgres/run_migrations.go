package postgres

import (
	"context"
	"fmt"
	"sync"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/migrations"
)

var migrationMutex = sync.Mutex{}

// RunMigrations applies database-specific SQL migrations.
//
// Deprecated: use RunMigrationsContext so a caller's deadline can abort a hung
// migration; this wrapper is unbounded by any caller context.
func RunMigrations(db *sqlx.DB, dbType string) error {
	return RunMigrationsContext(context.Background(), db, dbType)
}

// RunMigrationsContext applies PostgreSQL database migrations, aborting when
// ctx is done.
func RunMigrationsContext(ctx context.Context, db *sqlx.DB, dbType string) error {
	migrationMutex.Lock()
	defer migrationMutex.Unlock()

	switch dbType {
	case "postgres", "postgresql":
		// supported
	default:
		return fmt.Errorf("unsupported database type: %s", dbType)
	}

	goose.SetBaseFS(migrations.PostgresMigrations)

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set goose dialect: %w", err)
	}

	if err := goose.UpContext(ctx, db.DB, "postgres"); err != nil {
		return fmt.Errorf("failed to run postgres migrations: %w", err)
	}

	return nil
}
