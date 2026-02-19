package postgres

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"
)

const postgresDialect = "postgres"

var migrationMutex = sync.Mutex{}

// runMigrations applies database-specific SQL migrations.
func RunMigrations(db *sqlx.DB, dbType string) error {
	migrationMutex.Lock()
	defer migrationMutex.Unlock()

	var dialect, migrationsSubdir string

	switch dbType {
	case postgresDialect, "postgresql":
		dialect = postgresDialect
		migrationsSubdir = postgresDialect
	default:
		return fmt.Errorf("unsupported database type: %s", dbType)
	}

	if err := goose.SetDialect(dialect); err != nil {
		return fmt.Errorf("failed to set goose dialect for %s: %w", dbType, err)
	}

	// Find database-specific migrations directory
	var migrationsPath string
	candidates := []string{
		fmt.Sprintf("../migrations/%s", migrationsSubdir),                     // From aggregator root
		fmt.Sprintf("migrations/%s", migrationsSubdir),                        // From working directory
		fmt.Sprintf("../../migrations/%s", migrationsSubdir),                  // From pkg/<subpackage> (tests)
		fmt.Sprintf("../../../migrations/%s", migrationsSubdir),               // From pkg/storage/postgres (tests)
		fmt.Sprintf("../../../../aggregator/migrations/%s", migrationsSubdir), // From deep test paths
	}

	for _, candidate := range candidates {
		if absPath, err := filepath.Abs(candidate); err == nil {
			if info, err := os.Stat(absPath); err == nil && info.IsDir() {
				migrationsPath = absPath
				break
			}
		}
	}

	if migrationsPath == "" {
		return fmt.Errorf("could not find %s migrations directory in any of: %v", migrationsSubdir, candidates)
	}

	if err := goose.Up(db.DB, migrationsPath); err != nil {
		return fmt.Errorf("failed to run %s migrations: %w", migrationsSubdir, err)
	}

	return nil
}
