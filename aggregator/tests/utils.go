package tests

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/ddb"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

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

func WithPaginationConfig(pageSize int) ConfigOption {
	return func(cfg *model.AggregatorConfig) *model.AggregatorConfig {
		cfg.Storage.PageSize = pageSize
		return cfg
	}
}

func WithShardCount(shardCount int) ConfigOption {
	return func(cfg *model.AggregatorConfig) *model.AggregatorConfig {
		if cfg.Storage.DynamoDB == nil {
			cfg.Storage.DynamoDB = &model.DynamoDBConfig{}
		}
		cfg.Storage.DynamoDB.ShardCount = shardCount
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
		Storage: &model.StorageConfig{
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
		storageConfig, cleanup, err := setupDynamoDBStorage(t, config.Storage)
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

func setupDynamoDBStorage(t *testing.T, existingConfig *model.StorageConfig) (*model.StorageConfig, func(), error) {
	// Start DynamoDB Local container
	_, connectionString, cleanup := ddb.SetupTestDynamoDB(t)

	// Preserve existing storage config and only update DynamoDB-specific fields
	if existingConfig.DynamoDB == nil {
		existingConfig.DynamoDB = &model.DynamoDBConfig{}
	}

	existingConfig.DynamoDB.CommitVerificationRecordTableName = ddb.TestCommitVerificationRecordTableName
	existingConfig.DynamoDB.FinalizedFeedTableName = ddb.TestFinalizedFeedTableName
	existingConfig.DynamoDB.CheckpointTableName = ddb.TestCheckpointTableName
	existingConfig.DynamoDB.Region = "us-east-1"
	existingConfig.DynamoDB.Endpoint = "http://" + connectionString

	return existingConfig, cleanup, nil
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
