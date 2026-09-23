package admin

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin/migrations"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/db"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const gooseTableName = "ccv_admin_goose_db_version"

var migrationMutex sync.Mutex

// openPostgres opens a pooled postgres connection and runs the given migrations. Shared
// by node databases (verifier migrations, matching the CLI) and the console database
// (admin migrations).
func openPostgres(lggr logger.Logger, url string, migrate func(*sqlx.DB) error) (*sqlx.DB, error) {
	dbx, err := sql.Open("postgres", url)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres database: %w", err)
	}
	dbx.SetMaxOpenConns(10)
	dbx.SetMaxIdleConns(5)
	dbx.SetConnMaxLifetime(300 * time.Second)
	dbx.SetConnMaxIdleTime(60 * time.Second)

	sqlxDB := sqlx.NewDb(dbx, "postgres")
	if migrate != nil {
		if err := migrate(sqlxDB); err != nil {
			_ = dbx.Close()
			return nil, err
		}
	}
	return sqlxDB, nil
}

// openNodeDB opens a node's verifier application database, applying verifier migrations
// exactly as the CLI does.
func openNodeDB(lggr logger.Logger, secretsPath string) (*sqlx.DB, error) {
	secrets, err := vsecrets.Load(secretsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load node secrets file: %w", err)
	}
	url := secrets.DatabaseURL()
	if url == "" {
		return nil, fmt.Errorf("node secrets file %q has no [db].url", secretsPath)
	}
	return openPostgres(lggr, url, func(sqlxDB *sqlx.DB) error {
		if err := db.RunPostgresMigrations(sqlxDB); err != nil {
			return fmt.Errorf("failed to run verifier migrations: %w", err)
		}
		return nil
	})
}

// openConsoleDB opens the console's own database for the action log. A missing secrets
// file or an empty [db].url is not an error: the console runs read-only (nil, nil).
func openConsoleDB(lggr logger.Logger, secretsPath string) (*sqlx.DB, error) {
	secrets, err := vsecrets.Load(secretsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load console secrets file: %w", err)
	}
	url := secrets.DatabaseURL()
	if url == "" {
		lggr.Infow("console database not configured; mutations are disabled (read-only mode)", "secretsPath", secretsPath)
		return nil, nil
	}
	return openPostgres(lggr, url, runAdminMigrations)
}

func runAdminMigrations(sqlxDB *sqlx.DB) error {
	migrationMutex.Lock()
	defer migrationMutex.Unlock()

	goose.SetBaseFS(migrations.PostgresMigrations)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set goose dialect: %w", err)
	}
	goose.SetTableName(gooseTableName)
	if err := goose.Up(sqlxDB.DB, "postgres"); err != nil {
		return fmt.Errorf("failed to run admin migrations: %w", err)
	}
	return nil
}
