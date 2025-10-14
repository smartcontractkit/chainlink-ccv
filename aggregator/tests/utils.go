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
	hmacutil "github.com/smartcontractkit/chainlink-ccv/common/pkg/hmac"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

const bufSize = 1024 * 1024

var (
	defaultAPIKey = "test-api-key"
	defaultSecret = "test-secret-key"
)

// ClientConfig holds configuration for test client behavior.
type ClientConfig struct {
	SkipAuth bool
	APIKey   string
	Secret   string
}

type ConfigOption = func(*model.AggregatorConfig, *ClientConfig) (*model.AggregatorConfig, *ClientConfig)

func WithCommitteeConfig(committeeConfig map[string]*model.Committee) ConfigOption {
	return func(cfg *model.AggregatorConfig, clientCfg *ClientConfig) (*model.AggregatorConfig, *ClientConfig) {
		cfg.Committees = committeeConfig
		return cfg, clientCfg
	}
}

func WithStorageType(storageType string) ConfigOption {
	return func(cfg *model.AggregatorConfig, clientCfg *ClientConfig) (*model.AggregatorConfig, *ClientConfig) {
		cfg.Storage.StorageType = model.StorageType(storageType)
		return cfg, clientCfg
	}
}

func WithStubMode(stub bool) ConfigOption {
	return func(cfg *model.AggregatorConfig, clientCfg *ClientConfig) (*model.AggregatorConfig, *ClientConfig) {
		cfg.StubMode = stub
		return cfg, clientCfg
	}
}

func WithPaginationConfig(pageSize int) ConfigOption {
	return func(cfg *model.AggregatorConfig, clientCfg *ClientConfig) (*model.AggregatorConfig, *ClientConfig) {
		cfg.Storage.PageSize = pageSize
		return cfg, clientCfg
	}
}

func WithShardCount(shardCount int) ConfigOption {
	return func(cfg *model.AggregatorConfig, clientCfg *ClientConfig) (*model.AggregatorConfig, *ClientConfig) {
		if cfg.Storage.DynamoDB == nil {
			cfg.Storage.DynamoDB = &model.DynamoDBConfig{}
		}
		cfg.Storage.DynamoDB.ShardCount = shardCount
		return cfg, clientCfg
	}
}

func WithAPIKeyAuth(apiKey, secret string) ConfigOption {
	return func(cfg *model.AggregatorConfig, clientCfg *ClientConfig) (*model.AggregatorConfig, *ClientConfig) {
		cfg.APIKeys.Clients[apiKey] = &model.APIClient{
			ClientID:    apiKey,
			Description: "Custom test client",
			Enabled:     true,
			Secrets: map[string]string{
				"current": secret,
			},
		}
		return cfg, clientCfg
	}
}

func WithClientAuth(apiKey, secret string) ConfigOption {
	return func(cfg *model.AggregatorConfig, clientCfg *ClientConfig) (*model.AggregatorConfig, *ClientConfig) {
		clientCfg.APIKey = apiKey
		clientCfg.Secret = secret
		clientCfg.SkipAuth = false
		return cfg, clientCfg
	}
}

func WithoutClientAuth() ConfigOption {
	return func(cfg *model.AggregatorConfig, clientCfg *ClientConfig) (*model.AggregatorConfig, *ClientConfig) {
		clientCfg.SkipAuth = true
		return cfg, clientCfg
	}
}

// CreateServerAndClient creates a test server and client for functional testing.
// Uses DynamoDB storage by default, but can be overridden with options.
func CreateServerAndClient(t *testing.T, options ...ConfigOption) (pb.AggregatorClient, pb.CCVDataClient, func(), error) {
	// Create server
	listener, serverCleanup, err := CreateServerOnly(t, options...)
	if err != nil {
		return nil, nil, nil, err
	}

	clientConfig := &ClientConfig{
		SkipAuth: false,
		APIKey:   defaultAPIKey,
		Secret:   defaultSecret,
	}

	dummyConfig := &model.AggregatorConfig{
		Storage: &model.StorageConfig{
			DynamoDB: &model.DynamoDBConfig{},
		},
		APIKeys: model.APIKeyConfig{
			Clients: make(map[string]*model.APIClient),
		},
	}
	for _, option := range options {
		_, clientConfig = option(dummyConfig, clientConfig)
	}

	aggregatorClient, ccvDataClient, clientCleanup := CreateAuthenticatedClient(
		t,
		listener,
		options...,
	)

	cleanup := func() {
		clientCleanup()
		serverCleanup()
	}

	return aggregatorClient, ccvDataClient, cleanup, nil
}

// CreateServerOnly creates and starts a test gRPC server using bufconn for in-memory communication.
func CreateServerOnly(t *testing.T, options ...ConfigOption) (*bufconn.Listener, func(), error) {
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
		APIKeys: model.APIKeyConfig{
			Clients: make(map[string]*model.APIClient),
		},
	}

	config.APIKeys.Clients[defaultAPIKey] = &model.APIClient{
		ClientID:    "test-client",
		Description: "Test client for integration tests",
		Enabled:     true,
		Secrets: map[string]string{
			"current": defaultSecret,
		},
	}

	clientConfig := &ClientConfig{
		SkipAuth: false,
		APIKey:   defaultAPIKey,
		Secret:   defaultSecret,
	}

	for _, option := range options {
		config, clientConfig = option(config, clientConfig)
	}

	// Setup storage based on final configuration
	var cleanupStorage func()

	switch config.Storage.StorageType {
	case model.StorageTypeDynamoDB:
		storageConfig, cleanup, err := setupDynamoDBStorage(t, config.Storage)
		if err != nil {
			return nil, nil, err
		}
		config.Storage = storageConfig
		cleanupStorage = cleanup
	case model.StorageTypeMemory:
		// No setup needed for memory storage
		cleanupStorage = func() {}
	default:
		return nil, nil, fmt.Errorf("unsupported storage type: %s", config.Storage.StorageType)
	}

	s := agg.NewServer(sugaredLggr, config)
	err = s.Start(buf)
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	cleanup := func() {
		cleanupStorage()
	}

	return buf, cleanup, nil
}

// CreateAuthenticatedClient creates a gRPC client with optional HMAC authentication.
func CreateAuthenticatedClient(t *testing.T, listener *bufconn.Listener, options ...ConfigOption) (pb.AggregatorClient, pb.CCVDataClient, func()) {
	clientConfig := &ClientConfig{
		SkipAuth: false,
		APIKey:   defaultAPIKey,
		Secret:   defaultSecret,
	}

	dummyConfig := &model.AggregatorConfig{
		Storage: &model.StorageConfig{
			DynamoDB: &model.DynamoDBConfig{},
		},
		APIKeys: model.APIKeyConfig{
			Clients: make(map[string]*model.APIClient),
		},
	}
	for _, option := range options {
		_, clientConfig = option(dummyConfig, clientConfig)
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	var clientOptions []grpc.DialOption
	if !clientConfig.SkipAuth {
		hmacConfig := &hmacutil.ClientConfig{
			APIKey: clientConfig.APIKey,
			Secret: clientConfig.Secret,
		}
		clientOptions = []grpc.DialOption{
			grpc.WithUnaryInterceptor(createSimpleHMACClientInterceptor(hmacConfig)),
		}
	}

	aggregatorClient, aggregatorConn, err := createAggregatorClient(ctx, listener, clientOptions...)
	if err != nil {
		t.Fatalf("failed to create aggregator client: %v", err)
	}

	ccvDataClient, ccvDataConn, err := createCCVDataClient(ctx, listener, clientOptions...)
	if err != nil {
		t.Fatalf("failed to create CCV data client: %v", err)
	}

	cleanup := func() {
		if err := aggregatorConn.Close(); err != nil {
			t.Errorf("failed to close aggregator connection: %v", err)
		}
		if err := ccvDataConn.Close(); err != nil {
			t.Errorf("failed to close ccv data connection: %v", err)
		}
	}

	return aggregatorClient, ccvDataClient, cleanup
}

func createSimpleHMACClientInterceptor(config *hmacutil.ClientConfig) grpc.UnaryClientInterceptor {
	return hmacutil.NewClientInterceptor(config)
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

func createCCVDataClient(ctx context.Context, ccvDataBuf *bufconn.Listener, opts ...grpc.DialOption) (pb.CCVDataClient, *grpc.ClientConn, error) {
	bufDialer := func(context.Context, string) (net.Conn, error) {
		return ccvDataBuf.Dial()
	}

	//nolint:staticcheck // grpc.WithInsecure is deprecated but needed for test setup
	defaultOpts := []grpc.DialOption{
		grpc.WithContextDialer(bufDialer),
		grpc.WithInsecure(),
	}

	// Append custom options (like interceptors)
	allOpts := append(defaultOpts, opts...)

	//nolint:staticcheck // grpc.DialContext is deprecated but needed for bufconn test setup
	ccvDataConn, err := grpc.DialContext(ctx, "bufnet", allOpts...)
	if err != nil {
		return nil, nil, err
	}

	client := pb.NewCCVDataClient(ccvDataConn)
	return client, ccvDataConn, nil
}

func createAggregatorClient(ctx context.Context, aggregatorBuf *bufconn.Listener, opts ...grpc.DialOption) (pb.AggregatorClient, *grpc.ClientConn, error) {
	bufDialer := func(context.Context, string) (net.Conn, error) {
		return aggregatorBuf.Dial()
	}

	//nolint:staticcheck // grpc.WithInsecure is deprecated but needed for test setup
	defaultOpts := []grpc.DialOption{
		grpc.WithContextDialer(bufDialer),
		grpc.WithInsecure(),
	}

	// Append custom options (like interceptors)
	allOpts := append(defaultOpts, opts...)

	//nolint:staticcheck // grpc.DialContext is deprecated but needed for bufconn test setup
	aggregatorConn, err := grpc.DialContext(ctx, "bufnet", allOpts...)
	if err != nil {
		return nil, nil, err
	}

	client := pb.NewAggregatorClient(aggregatorConn)
	return client, aggregatorConn, nil
}
