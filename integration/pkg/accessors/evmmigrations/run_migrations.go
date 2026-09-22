package evmmigrations

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"

	"github.com/pressly/goose/v3"
)

// VersionTable must not be the default `goose_db_version` used by verifier/pkg/db: both
// roots start at version 1, so sharing a table would make each skip the other's migrations.
const VersionTable = "goose_evm_db_version"

const migrationsDir = "postgres"

// RunEVMMigrations creates the `evm` LogPoller schema. Safe to call repeatedly.
//
// Takes a *sql.DB rather than a sqlutil.DataSource because goose.NewProvider needs a
// concrete handle, which DataSource does not expose.
func RunEVMMigrations(ctx context.Context, db *sql.DB) error {
	fsys, err := fs.Sub(PostgresMigrations, migrationsDir)
	if err != nil {
		return fmt.Errorf("failed to get sub filesystem for embedded evm migration dir: %w", err)
	}

	provider, err := goose.NewProvider(goose.DialectPostgres, db, fsys,
		goose.WithTableName(VersionTable))
	if err != nil {
		return fmt.Errorf("failed to create goose provider for evm migrations: %w", err)
	}

	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("failed to run evm migrations: %w", err)
	}

	return nil
}
