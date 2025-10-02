package tests

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/dynamodb"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb" //nolint:goimports
	agg "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

const bufSize = 1024 * 1024

type ConfigOption = func(*model.AggregatorConfig) *model.AggregatorConfig

func WithCommitteeConfig(committeeConfig map[string]*model.Committee) ConfigOption {
	return func(cfg *model.AggregatorConfig) *model.AggregatorConfig {
		cfg.Committees = committeeConfig
		return cfg
	}
}

func WithStorageType(storageType string) ConfigOption {
	return func(cfg *model.AggregatorConfig) *model.AggregatorConfig {
		cfg.Storage.StorageType = model.StorageType(storageType)
		return cfg
	}
}

func WithStubMode(stub bool) ConfigOption {
	return func(cfg *model.AggregatorConfig) *model.AggregatorConfig {
		cfg.StubMode = stub
		return cfg
	}
}

// CreateServerAndClient creates a test server and client for functional testing.
// Uses DynamoDB storage by default, but can be overridden with options.
func CreateServerAndClient(t *testing.T, options ...ConfigOption) (pb.AggregatorClient, pb.CCVDataClient, func(), error) {
	buf := bufconn.Listen(bufSize)
	// Setup logging - always debug level for now
	lggr, err := logger.NewWith(func(logConfig *zap.Config) {
		logConfig.Development = true
		logConfig.Encoding = "console"
		logConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	})
	if err != nil {
		panic(err)
	}

	// Use SugaredLogger for better API
	sugaredLggr := logger.Sugared(lggr)

	// Create base config with DynamoDB storage as default
	config := &model.AggregatorConfig{
		Server: model.ServerConfig{
			Address: ":50051",
		},
		Storage: model.StorageConfig{
			StorageType: model.StorageTypeDynamoDB, // Default to DynamoDB
		},
		Monitoring: model.MonitoringConfig{
			Enabled: false,
		},
	}

	// Apply options for committee config, stub mode, storage type, etc.
	for _, option := range options {
		config = option(config)
	}

	// Setup storage based on final configuration
	var cleanupStorage func()

	switch config.Storage.StorageType {
	case model.StorageTypeDynamoDB:
		storageConfig, cleanup, err := setupDynamoDBStorage(t)
		if err != nil {
			return nil, nil, nil, err
		}
		config.Storage = storageConfig
		cleanupStorage = cleanup
	case model.StorageTypeMemory:
		// No setup needed for memory storage
		cleanupStorage = func() {}
	default:
		return nil, nil, nil, fmt.Errorf("unsupported storage type: %s", config.Storage.StorageType)
	}

	s := agg.NewServer(sugaredLggr, config)
	err = s.Start(buf)
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	aggregatorClient, aggregatorConn, err := createAggregatorClient(ctx, buf)
	if err != nil {
		t.Fatalf("failed to create aggregator client: %v", err)
	}

	ccvDataClient, ccvDataConn, err := createCCVDataClient(ctx, buf)
	if err != nil {
		t.Fatalf("failed to create CCV data client: %v", err)
	}

	return aggregatorClient, ccvDataClient, func() {
		if err := aggregatorConn.Close(); err != nil {
			t.Errorf("failed to close connection: %v", err)
		}
		if err := ccvDataConn.Close(); err != nil {
			t.Errorf("failed to close connection: %v", err)
		}
		cleanupStorage()
	}, nil
}

func setupDynamoDBStorage(t *testing.T) (model.StorageConfig, func(), error) {
	// Start DynamoDB Local container
	dynamoContainer, err := dynamodb.Run(t.Context(), "amazon/dynamodb-local:2.2.1", testcontainers.WithWaitStrategy(wait.ForHTTP("/").WithStatusCodeMatcher(func(status int) bool {
		return status == 400
	})))
	if err != nil {
		return model.StorageConfig{}, nil, err
	}
	time.Sleep(5 * time.Second) // Wait for container to be fully ready

	// Get connection string
	connectionString, err := dynamoContainer.ConnectionString(t.Context())
	if err != nil {
		return model.StorageConfig{}, nil, err
	}

	storageConfig := model.StorageConfig{
		StorageType: "dynamodb",
		DynamoDB: model.DynamoDBConfig{
			CommitVerificationRecordTableName: "commit_verification_records_test",
			FinalizedFeedTableName:            "finalized_feed_test",
			CheckpointTableName:               "checkpoint_storage_test",
			Region:                            "us-east-1",
			Endpoint:                          "http://" + connectionString,
		},
	}

	// Create DynamoDB client using the same pattern as the factory
	awsConfig, err := awsconfig.LoadDefaultConfig(context.TODO(),
		awsconfig.WithRegion(storageConfig.DynamoDB.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "test")),
	)
	if err != nil {
		return model.StorageConfig{}, nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	ddbClient := awsdynamodb.NewFromConfig(awsConfig, func(o *awsdynamodb.Options) {
		o.BaseEndpoint = aws.String(storageConfig.DynamoDB.Endpoint)
	})

	ctx := context.Background()

	// Create the commit verification records table
	err = ddb.CreateCommitVerificationRecordsTable(ctx, ddbClient, storageConfig.DynamoDB.CommitVerificationRecordTableName)
	if err != nil {
		return model.StorageConfig{}, nil, fmt.Errorf("failed to create commit verification records table: %w", err)
	}

	// Create the finalized feed table
	err = ddb.CreateFinalizedFeedTable(ctx, ddbClient, storageConfig.DynamoDB.FinalizedFeedTableName)
	if err != nil {
		return model.StorageConfig{}, nil, fmt.Errorf("failed to create finalized feed table: %w", err)
	}

	// Create the checkpoint table
	err = ddb.CreateCheckpointTable(ctx, ddbClient, storageConfig.DynamoDB.CheckpointTableName)
	if err != nil {
		return model.StorageConfig{}, nil, fmt.Errorf("failed to create checkpoint table: %w", err)
	}

	cleanup := func() {
		if err := dynamoContainer.Terminate(context.Background()); err != nil {
			t.Errorf("failed to terminate dynamodb container: %v", err)
		}
	}

	return storageConfig, cleanup, nil
}

func createCCVDataClient(ctx context.Context, ccvDataBuf *bufconn.Listener) (pb.CCVDataClient, *grpc.ClientConn, error) {
	bufDialer := func(context.Context, string) (net.Conn, error) {
		return ccvDataBuf.Dial()
	}

	//nolint:staticcheck // grpc.WithInsecure is deprecated but needed for test setup
	ccvDataConn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		return nil, nil, err
	}

	client := pb.NewCCVDataClient(ccvDataConn)
	return client, ccvDataConn, nil
}

func createAggregatorClient(ctx context.Context, aggregatorBuf *bufconn.Listener) (pb.AggregatorClient, *grpc.ClientConn, error) {
	bufDialer := func(context.Context, string) (net.Conn, error) {
		return aggregatorBuf.Dial()
	}

	//nolint:staticcheck // grpc.WithInsecure is deprecated but needed for test setup
	aggregatorConn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		return nil, nil, err
	}

	client := pb.NewAggregatorClient(aggregatorConn)
	return client, aggregatorConn, nil
}
