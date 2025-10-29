package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/jmoiron/sqlx"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/memory"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/postgres"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	_ "github.com/lib/pq" // PostgreSQL driver

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

const (
	postgresDriver      = "postgres"
	defaultMaxOpenConns = 25
)

var earliestDateForGetMessageSince = time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC)

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
	case model.StorageTypeDynamoDB:
		return f.createDynamoDBStorage(config, monitoring)
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
	case model.StorageTypeDynamoDB:
		return f.createDynamoDBChainStatusStorage(config, monitoring)
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

// createDynamoDBStorage creates a DynamoDB-backed storage instance.
func (f *Factory) createDynamoDBStorage(config *model.StorageConfig, monitoring common.AggregatorMonitoring) (CommitVerificationStorage, error) {
	client, err := createDynamoDBClient(config)
	if err != nil {
		return nil, err
	}

	// Create storage instance with configurable minimum date
	storage := ddb.NewDynamoDBStorage(
		client,
		config.DynamoDB.CommitVerificationRecordTableName,
		config.DynamoDB.FinalizedFeedTableName,
		earliestDateForGetMessageSince,
		f.logger,
		monitoring,
		config.PageSize,
		config.DynamoDB.ShardCount,
	)

	return storage, nil
}

func createDynamoDBClient(config *model.StorageConfig) (*dynamodb.Client, error) {
	// Validate required configuration
	if config.DynamoDB.ChainStatusTableName == "" {
		return nil, fmt.Errorf("DynamoDB ChainStatusTableName is required")
	}

	// Set default region if not specified
	region := config.DynamoDB.Region
	if region == "" {
		region = "us-east-1"
	}

	// Create AWS config
	awsConfig, err := awsconfig.LoadDefaultConfig(context.TODO(),
		awsconfig.WithRegion(region),
		func() awsconfig.LoadOptionsFunc {
			if config.DynamoDB.Endpoint != "" {
				// Use static credentials for custom endpoint (DynamoDB Local testing)
				return awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "test"))
			}
			return func(o *awsconfig.LoadOptions) error { return nil }
		}(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create DynamoDB client
	var client *dynamodb.Client
	if config.DynamoDB.Endpoint != "" {
		client = dynamodb.NewFromConfig(awsConfig, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String(config.DynamoDB.Endpoint)
		})
	} else {
		client = dynamodb.NewFromConfig(awsConfig)
	}
	return client, nil
}

// createDynamoDBChainStatusStorage creates a DynamoDB-backed chain status storage instance.
func (f *Factory) createDynamoDBChainStatusStorage(config *model.StorageConfig, monitoring common.AggregatorMonitoring) (common.ChainStatusStorageInterface, error) {
	client, err := createDynamoDBClient(config)
	if err != nil {
		return nil, err
	}

	// Create chain status storage instance
	chainStatusStorage := ddb.NewChainStatusStorage(
		client,
		config.DynamoDB.ChainStatusTableName,
		monitoring,
	)

	return chainStatusStorage, nil
}
