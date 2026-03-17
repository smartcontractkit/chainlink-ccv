package postgres

import (
	"fmt"
	"sync"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/migrations"
)

var migrationMutex = sync.Mutex{}

// RunMigrations applies database-specific SQL migrations.
func RunMigrations(db *sqlx.DB, dbType string) error {
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

	if err := goose.Up(db.DB, "postgres"); err != nil {
		return fmt.Errorf("failed to run postgres migrations: %w", err)
	}

	return nil
}
