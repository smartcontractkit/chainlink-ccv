package postgres

import (
	"context"
	"fmt"
	"hash/crc64"
	"io/fs"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/migrations"
)

// migrationLockID is the Postgres advisory lock key for the aggregator migrations. It is different
// from the goose default, so that other services on the same database do not wait for this lock.
var migrationLockID = int64(crc64.Checksum([]byte("aggregator_migrations"), crc64.MakeTable(crc64.ECMA)))

var migrationGate = make(chan struct{}, 1)

// RunMigrations applies database-specific SQL migrations.
//
// Deprecated: use RunMigrationsContext so a caller's deadline can abort a hung
// migration; this wrapper is unbounded by any caller context.
func RunMigrations(db *sqlx.DB, dbType string) error {
	return RunMigrationsContext(context.Background(), db, dbType)
}

// RunMigrationsContext applies PostgreSQL database migrations, aborting when ctx is done.
// An advisory lock stops two replicas from applying the same migration at the same time.
func RunMigrationsContext(ctx context.Context, db *sqlx.DB, dbType string) error {
	select {
	case migrationGate <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("aborted waiting for migration gate: %w", ctx.Err())
	}
	defer func() { <-migrationGate }()

	switch dbType {
	case "postgres", "postgresql":
		// supported
	default:
		return fmt.Errorf("unsupported database type: %s", dbType)
	}

	return runLockedMigrations(ctx, db)
}

func runLockedMigrations(ctx context.Context, db *sqlx.DB) error {
	fsys, err := fs.Sub(migrations.PostgresMigrations, "postgres")
	if err != nil {
		return fmt.Errorf("failed to open embedded migrations: %w", err)
	}

	locker, err := lock.NewPostgresSessionLocker(lock.WithLockID(migrationLockID))
	if err != nil {
		return fmt.Errorf("failed to create migration locker: %w", err)
	}

	provider, err := goose.NewProvider(goose.DialectPostgres, db.DB, fsys, goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("failed to create goose provider: %w", err)
	}

	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("failed to run postgres migrations: %w", err)
	}

	return nil
}
