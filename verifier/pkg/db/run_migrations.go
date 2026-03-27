package db

import (
	"fmt"
	"sync"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"

	"github.com/smartcontractkit/chainlink-ccv/verifier/migrations"
)

var migrationMutex = sync.Mutex{}

// RunPostgresMigrations applies PostgreSQL database migrations.
func RunPostgresMigrations(db *sqlx.DB) error {
	migrationMutex.Lock()
	defer migrationMutex.Unlock()

	goose.SetBaseFS(migrations.PostgresMigrations)

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set goose dialect: %w", err)
	}

	if err := goose.Up(db.DB, "postgres"); err != nil {
		return fmt.Errorf("failed to run postgres migrations: %w", err)
	}

	return nil
}
