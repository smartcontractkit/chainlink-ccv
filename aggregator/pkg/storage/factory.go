package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/jmoiron/sqlx"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/memory"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/postgres"

	_ "github.com/lib/pq"  // PostgreSQL driver
	_ "modernc.org/sqlite" // SQLite driver

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
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
type Factory struct{}

// NewStorageFactory creates a new storage factory.
func NewStorageFactory() *Factory {
	return &Factory{}
}

// CreateStorage creates a storage instance based on the provided configuration.
func (f *Factory) CreateStorage(config model.StorageConfig) (CommitVerificationStorage, error) {
	switch config.StorageType {
	case model.StorageTypeMemory:
		return memory.NewInMemoryStorage(), nil
	case model.StorageTypePostgreSQL:
		return f.createPostgreSQLStorage(config)
	case model.StorageTypeDynamoDB:
		return f.createDynamoDBStorage(config)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", config.StorageType)
	}
}

func (f *Factory) CreateCheckpointStorage(config model.StorageConfig) (common.CheckpointStorageInterface, error) {
	switch config.StorageType {
	case model.StorageTypeMemory:
		return memory.NewCheckpointStorage(), nil
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
		return postgres.NewDatabaseCheckpointStorage(sqlxDB), nil
	case model.StorageTypeDynamoDB:
		return f.createDynamoDBCheckpointStorage(config)
	default:
		return nil, fmt.Errorf("unsupported checkpoint storage type: %s", config.StorageType)
	}
}

// createPostgreSQLStorage creates a PostgreSQL-backed storage instance.
func (f *Factory) createPostgreSQLStorage(config model.StorageConfig) (CommitVerificationStorage, error) {
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

	return postgres.NewDatabaseStorage(sqlxDB), nil
}

// createDynamoDBStorage creates a DynamoDB-backed storage instance.
func (f *Factory) createDynamoDBStorage(config model.StorageConfig) (CommitVerificationStorage, error) {
	client, err := createDynamoDBClient(config)
	if err != nil {
		return nil, err
	}

	// Create storage instance
	storage := ddb.NewDynamoDBStorage(
		client,
		config.DynamoDB.CommitVerificationRecordTableName,
		config.DynamoDB.FinalizedFeedTableName,
	)

	return storage, nil
}

func createDynamoDBClient(config model.StorageConfig) (*dynamodb.Client, error) {
	// Validate required configuration
	if config.DynamoDB.CheckpointTableName == "" {
		return nil, fmt.Errorf("DynamoDB CheckpointTableName is required")
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

// createDynamoDBCheckpointStorage creates a DynamoDB-backed checkpoint storage instance.
func (f *Factory) createDynamoDBCheckpointStorage(config model.StorageConfig) (common.CheckpointStorageInterface, error) {
	client, err := createDynamoDBClient(config)
	if err != nil {
		return nil, err
	}

	// Create checkpoint storage instance
	checkpointStorage := ddb.NewCheckpointStorage(
		client,
		config.DynamoDB.CheckpointTableName,
	)

	return checkpointStorage, nil
}
