package storage

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/postgres"
	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	_ "github.com/lib/pq" // PostgreSQL driver
)

const (
	postgresDriver         = "postgres"
	defaultMaxOpenConns    = 25
	defaultMaxIdleConns    = 10
	defaultConnMaxLifetime = 3600 // 1 hour in seconds
	defaultConnMaxIdleTime = 300  // 5 minutes in seconds
)

// CommitVerificationStorage combines all storage interfaces for production use.
type CommitVerificationStorage interface {
	common.CommitVerificationStore
	common.CommitVerificationAggregatedStore
	common.Sink
}

// Factory creates storage instances based on configuration.
type Factory struct {
	logger logger.SugaredLogger
}

// NewStorageFactory creates a new storage factory.
func NewStorageFactory(logger logger.SugaredLogger) *Factory {
	return &Factory{
		logger: logger,
	}
}

// CreateStorage creates a storage instance based on the provided configuration.
func (f *Factory) CreateStorage(config *model.StorageConfig, monitoring common.AggregatorMonitoring) (CommitVerificationStorage, error) {
	if config.StorageType != model.StorageTypePostgreSQL {
		return nil, fmt.Errorf("unsupported storage type: %s (only postgres is supported)", config.StorageType)
	}
	return f.createPostgreSQLStorage(config)
}

// createPostgreSQLStorage creates a PostgreSQL-backed storage instance.
func (f *Factory) createPostgreSQLStorage(config *model.StorageConfig) (CommitVerificationStorage, error) {
	if config.ConnectionURL == "" {
		return nil, fmt.Errorf("PostgreSQL connection URL is required")
	}

	db, err := sql.Open(postgresDriver, config.ConnectionURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open PostgreSQL database: %w", err)
	}

	// Configure connection pool settings
	maxOpenConns := config.MaxOpenConns
	if maxOpenConns <= 0 {
		maxOpenConns = defaultMaxOpenConns
	}
	db.SetMaxOpenConns(maxOpenConns)

	maxIdleConns := config.MaxIdleConns
	if maxIdleConns <= 0 {
		maxIdleConns = defaultMaxIdleConns
	}
	db.SetMaxIdleConns(maxIdleConns)

	connMaxLifetime := config.ConnMaxLifetime
	if connMaxLifetime <= 0 {
		connMaxLifetime = defaultConnMaxLifetime
	}
	db.SetConnMaxLifetime(time.Duration(connMaxLifetime) * time.Second)

	connMaxIdleTime := config.ConnMaxIdleTime
	if connMaxIdleTime <= 0 {
		connMaxIdleTime = defaultConnMaxIdleTime
	}
	db.SetConnMaxIdleTime(time.Duration(connMaxIdleTime) * time.Second)

	f.logger.Infow("Database connection pool configured",
		"maxOpenConns", maxOpenConns,
		"maxIdleConns", maxIdleConns,
		"connMaxLifetime", connMaxLifetime,
		"connMaxIdleTime", connMaxIdleTime,
	)

	if err := ccvcommon.EnsureDBConnection(f.logger, db); err != nil {
		return nil, fmt.Errorf("failed to ping PostgreSQL database: %w", err)
	}

	// Create sqlx wrapper for sqlutil.DataSource compatibility
	sqlxDB := sqlx.NewDb(db, postgresDriver)

	// Run PostgreSQL migrations
	err = postgres.RunMigrations(sqlxDB, postgresDriver)
	if err != nil {
		return nil, fmt.Errorf("failed to run PostgreSQL migrations: %w", err)
	}

	return postgres.NewDatabaseStorage(sqlxDB, config.PageSize, f.logger), nil
}
