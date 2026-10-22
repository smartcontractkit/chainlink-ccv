package evm

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq" // registers the "postgres" driver for sql.Open

	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/common/lazy"
	evmdb "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/db"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Database pool settings, the same fixed values the verifier uses for its own database.
const (
	defaultMaxOpenConns    = 20
	defaultMaxIdleConns    = 10
	defaultConnMaxLifetime = 300 * time.Second
	defaultConnMaxIdleTime = 60 * time.Second

	// startupTimeout bounds one connect-and-migrate attempt.
	startupTimeout = 2 * time.Minute
)

// newLazyDB is the EVM accessor's database, shared by everything the factory builds. It connects and
// migrates on first use, so chains that never need it never connect. It is nil when none is configured.
func newLazyDB(lggr logger.Logger, cfg *evmconfig.DBConfig) *lazy.Lazy[*sql.DB] {
	if cfg == nil {
		return nil
	}
	return lazy.New(func(ctx context.Context) (*sql.DB, error) {
		ctx, cancel := context.WithTimeout(ctx, startupTimeout)
		defer cancel()
		return connectAndMigrateDB(ctx, lggr, cfg)
	})
}

// evmDB returns the EVM database, connecting on the first call, or nil, nil when none is configured.
// A failed connect is not cached, so the next call retries.
func (a *accessor) evmDB(ctx context.Context) (*sql.DB, error) {
	if a.db == nil {
		return nil, nil
	}
	return a.db.Value(ctx)
}

// connectAndMigrateDB opens the EVM accessor's database and migrates it, like the verifier's connectVerifierDB.
func connectAndMigrateDB(ctx context.Context, lggr logger.Logger, cfg *evmconfig.DBConfig) (*sql.DB, error) {
	db, err := OpenDB(ctx, lggr, cfg)
	if err != nil {
		return nil, err
	}
	if err := evmdb.RunPostgresMigrationsContext(ctx, db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to run postgres migrations: %w", err)
	}
	return db, nil
}

// OpenDB opens and pings the EVM database.
func OpenDB(ctx context.Context, lggr logger.Logger, cfg *evmconfig.DBConfig) (*sql.DB, error) {
	db, err := sql.Open("postgres", cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres database: %w", err)
	}
	db.SetMaxOpenConns(defaultMaxOpenConns)
	db.SetMaxIdleConns(defaultMaxIdleConns)
	db.SetConnMaxLifetime(defaultConnMaxLifetime)
	db.SetConnMaxIdleTime(defaultConnMaxIdleTime)

	if err := ccvcommon.EnsureDBConnectionContext(ctx, lggr, db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping postgres database: %w", err)
	}
	return db, nil
}
