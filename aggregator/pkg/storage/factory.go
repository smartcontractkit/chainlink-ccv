package storage

import (
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/memory"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/postgres"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	_ "github.com/lib/pq" // PostgreSQL driver
)

const (
	postgresDriver      = "postgres"
	defaultMaxOpenConns = 25
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
	switch config.StorageType {
	case model.StorageTypeMemory:
		return memory.NewInMemoryStorage(), nil
	case model.StorageTypePostgreSQL:
		return f.createPostgreSQLStorage(config)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", config.StorageType)
	}
}

func (f *Factory) CreateChainStatusStorage(config *model.StorageConfig, monitoring common.AggregatorMonitoring) (common.ChainStatusStorageInterface, error) {
	switch config.StorageType {
	case model.StorageTypeMemory:
		return memory.NewChainStatusStorage(), nil
	case model.StorageTypePostgreSQL:
		if config.ConnectionURL == "" {
			return nil, fmt.Errorf("PostgreSQL connection URL is required")
		}

		db, err := sql.Open(postgresDriver, config.ConnectionURL)
		if err != nil {
			return nil, fmt.Errorf("failed to open PostgreSQL database: %w", err)
		}
		db.SetMaxOpenConns(defaultMaxOpenConns)

		if err := db.Ping(); err != nil {
			return nil, fmt.Errorf("failed to ping PostgreSQL database: %w", err)
		}

		// Create sqlx wrapper for sqlutil.DataSource compatibility
		sqlxDB := sqlx.NewDb(db, postgresDriver)
		// Run PostgreSQL migrations
		err = postgres.RunMigrations(sqlxDB, postgresDriver)
		if err != nil {
			return nil, fmt.Errorf("failed to run PostgreSQL migrations: %w", err)
		}
		return postgres.NewDatabaseChainStatusStorage(sqlxDB), nil
	default:
		return nil, fmt.Errorf("unsupported chain status storage type: %s", config.StorageType)
	}
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
	db.SetMaxOpenConns(defaultMaxOpenConns)

	if err := db.Ping(); err != nil {
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
