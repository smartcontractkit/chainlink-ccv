// Package db runs the EVM accessor's own migrations, which are independent of the verifier's.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"

	"github.com/pressly/goose/v3"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/migrations"
)

// versionTable keeps the EVM migrations' history apart from the verifier's goose_db_version, which
// shares this database and would otherwise treat version 1 as already applied.
const versionTable = "evm_goose_db_version"

var migrationGate = make(chan struct{}, 1)

// RunPostgresMigrationsContext applies all of the EVM accessor's PostgreSQL migrations, aborting when ctx
// is done. The serialization gate is ctx-aware: a concurrent migration holding the gate cannot
// block this call past its own deadline.
func RunPostgresMigrationsContext(ctx context.Context, db *sql.DB) error {
	select {
	case migrationGate <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("aborted waiting for migration gate: %w", ctx.Err())
	}
	defer func() { <-migrationGate }()

	fsys, err := fs.Sub(migrations.PostgresMigrations, "postgres")
	if err != nil {
		return fmt.Errorf("failed to open embedded migrations: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, fsys, goose.WithTableName(versionTable))
	if err != nil {
		return fmt.Errorf("failed to create goose provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("failed to run evm postgres migrations: %w", err)
	}
	return nil
}
