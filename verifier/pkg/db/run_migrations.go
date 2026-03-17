package db

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"
)

var migrationMutex = sync.Mutex{}

// RunPostgresMigrations applies PostgreSQL database migrations.
func RunPostgresMigrations(db *sqlx.DB) error {
	migrationMutex.Lock()
	defer migrationMutex.Unlock()

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set goose dialect: %w", err)
	}

	migrationsPath, err := findMigrationsDir()
	if err != nil {
		return err
	}

	if err := goose.Up(db.DB, migrationsPath); err != nil {
		return fmt.Errorf("failed to run postgres migrations: %w", err)
	}

	return nil
}

// findMigrationsDir locates the verifier/migrations/postgres directory by searching
// common relative paths so the function works both from the service root and from
// deeper test paths.
func findMigrationsDir() (string, error) {
	const subdir = "migrations/postgres"

	candidates := []string{
		subdir,                                         // from verifier/ root
		fmt.Sprintf("../%s", subdir),                   // from verifier/pkg
		fmt.Sprintf("../../%s", subdir),                // from verifier/pkg/db (tests)
		fmt.Sprintf("../../../%s", subdir),             // from verifier/pkg/db/sub (tests)
		fmt.Sprintf("../../../../verifier/%s", subdir), // from cmd/verifier
		fmt.Sprintf("verifier/%s", subdir),             // from repo root
	}

	for _, candidate := range candidates {
		if absPath, err := filepath.Abs(candidate); err == nil {
			if info, err := os.Stat(absPath); err == nil && info.IsDir() {
				return absPath, nil
			}
		}
	}

	return "", fmt.Errorf("could not find verifier migrations directory (%s) in any of: %v", subdir, candidates)
}
