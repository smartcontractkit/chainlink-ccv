package tests

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	agg "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg"
	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
	msgdiscoverypb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-discovery/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
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

func WithCommitteeConfig(committeeConfig *model.Committee) ConfigOption {
	return func(cfg *model.AggregatorConfig, clientCfg *ClientConfig) (*model.AggregatorConfig, *ClientConfig) {
		cfg.Committee = committeeConfig
		return cfg, clientCfg
	}
}

func WithStorageType(storageType string) ConfigOption {
	return func(cfg *model.AggregatorConfig, clientCfg *ClientConfig) (*model.AggregatorConfig, *ClientConfig) {
		cfg.Storage.StorageType = model.StorageType(storageType)
		return cfg, clientCfg
	}
}

func WithPaginationConfig(pageSize int) ConfigOption {
	return func(cfg *model.AggregatorConfig, clientCfg *ClientConfig) (*model.AggregatorConfig, *ClientConfig) {
		cfg.Storage.PageSize = pageSize
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
// Uses PostgreSQL storage by default, but can be overridden with options.
func CreateServerAndClient(t *testing.T, options ...ConfigOption) (committeepb.CommitteeVerifierClient, verifierpb.VerifierClient, msgdiscoverypb.MessageDiscoveryClient, func(), error) {
	// Create server
	listener, serverCleanup, err := CreateServerOnly(t, options...)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	clientConfig := &ClientConfig{
		SkipAuth: false,
		APIKey:   defaultAPIKey,
		Secret:   defaultSecret,
	}

	dummyConfig := &model.AggregatorConfig{
		Storage: &model.StorageConfig{},
		APIKeys: model.APIKeyConfig{
			Clients: make(map[string]*model.APIClient),
		},
	}
	for _, option := range options {
		_, clientConfig = option(dummyConfig, clientConfig)
	}

	aggregatorClient, ccvDataClient, messageDiscoveryClient, clientCleanup := CreateAuthenticatedClient(
		t,
		listener,
		options...,
	)

	cleanup := func() {
		clientCleanup()
		serverCleanup()
	}

	return aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup, nil
}

// CreateServerOnly creates and starts a test gRPC server using bufconn for in-memory communication.
func CreateServerOnly(t *testing.T, options ...ConfigOption) (*bufconn.Listener, func(), error) {
	buf := bufconn.Listen(bufSize)
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.DebugLevel))
	require.NoError(t, err)

	// Use SugaredLogger for better API
	sugaredLggr := logger.Sugared(lggr)

	// Create base config with PostgreSQL storage as default
	config := &model.AggregatorConfig{
		Server: model.ServerConfig{
			Address: ":50051",
		},
		Storage: &model.StorageConfig{
			StorageType: model.StorageTypePostgreSQL, // Default to PostgreSQL
		},
		Monitoring: model.MonitoringConfig{
			Enabled: false,
		},
		APIKeys: model.APIKeyConfig{
			Clients: make(map[string]*model.APIClient),
		},
		RateLimiting: model.RateLimitingConfig{
			Enabled: true,
			Storage: model.RateLimiterStoreConfig{
				Type: "memory",
			},
			DefaultLimits: map[string]model.RateLimitConfig{
				// Generous defaults for tests - 10000 requests per minute
				msgdiscoverypb.MessageDiscovery_GetMessagesSince_FullMethodName:                    {LimitPerMinute: 10000},
				verifierpb.Verifier_GetVerifierResultsForMessage_FullMethodName:                    {LimitPerMinute: 10000},
				committeepb.CommitteeVerifier_WriteCommitteeVerifierNodeResult_FullMethodName:      {LimitPerMinute: 10000},
				committeepb.CommitteeVerifier_BatchWriteCommitteeVerifierNodeResult_FullMethodName: {LimitPerMinute: 10000},
				committeepb.CommitteeVerifier_ReadCommitteeVerifierNodeResult_FullMethodName:       {LimitPerMinute: 10000},
				committeepb.CommitteeVerifier_WriteChainStatus_FullMethodName:                      {LimitPerMinute: 10000},
				committeepb.CommitteeVerifier_ReadChainStatus_FullMethodName:                       {LimitPerMinute: 10000},
			},
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
	case model.StorageTypeMemory:
		// No setup needed for memory storage
		cleanupStorage = func() {}
	case model.StorageTypePostgreSQL:
		storageConfig, cleanup, err := setupPostgresStorage(t, config.Storage)
		if err != nil {
			return nil, nil, err
		}
		config.Storage = storageConfig
		cleanupStorage = cleanup
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
func CreateAuthenticatedClient(t *testing.T, listener *bufconn.Listener, options ...ConfigOption) (committeepb.CommitteeVerifierClient, verifierpb.VerifierClient, msgdiscoverypb.MessageDiscoveryClient, func()) {
	clientConfig := &ClientConfig{
		SkipAuth: false,
		APIKey:   defaultAPIKey,
		Secret:   defaultSecret,
	}

	dummyConfig := &model.AggregatorConfig{
		Storage: &model.StorageConfig{},
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

	messageDiscoveryClient, messageDiscoveryConn, err := createMessageDiscoveryClient(ctx, listener, clientOptions...)
	if err != nil {
		_ = aggregatorConn.Close()
		_ = ccvDataConn.Close()
		t.Fatalf("failed to create message discovery client: %v", err)
	}

	cleanup := func() {
		if err := aggregatorConn.Close(); err != nil {
			t.Errorf("failed to close aggregator connection: %v", err)
		}
		if err := ccvDataConn.Close(); err != nil {
			t.Errorf("failed to close ccv data connection: %v", err)
		}
		if err := messageDiscoveryConn.Close(); err != nil {
			t.Errorf("failed to close message discovery connection: %v", err)
		}
	}

	return aggregatorClient, ccvDataClient, messageDiscoveryClient, cleanup
}

func createSimpleHMACClientInterceptor(config *hmacutil.ClientConfig) grpc.UnaryClientInterceptor {
	return hmacutil.NewClientInterceptor(config)
}

func setupPostgresStorage(t *testing.T, existingConfig *model.StorageConfig) (*model.StorageConfig, func(), error) {
	// Start PostgreSQL testcontainer
	postgresContainer, err := postgres.Run(t.Context(),
		"postgres:15-alpine",
		postgres.WithDatabase("test_db"),
		postgres.WithUsername("test_user"),
		postgres.WithPassword("test_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		return nil, nil, err
	}

	// Get connection string from container
	connectionString, err := postgresContainer.ConnectionString(t.Context(), "sslmode=disable")
	if err != nil {
		return nil, nil, err
	}

	storageConfig := &model.StorageConfig{
		StorageType:   "postgres",
		ConnectionURL: connectionString,
		PageSize:      existingConfig.PageSize,
	}

	cleanup := func() {
		if err := postgresContainer.Terminate(context.Background()); err != nil {
			t.Errorf("failed to terminate postgres container: %v", err)
		}
	}

	return storageConfig, cleanup, nil
}

func createCCVDataClient(ctx context.Context, ccvDataBuf *bufconn.Listener, opts ...grpc.DialOption) (verifierpb.VerifierClient, *grpc.ClientConn, error) {
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

	client := verifierpb.NewVerifierClient(ccvDataConn)
	return client, ccvDataConn, nil
}

func createAggregatorClient(ctx context.Context, aggregatorBuf *bufconn.Listener, opts ...grpc.DialOption) (committeepb.CommitteeVerifierClient, *grpc.ClientConn, error) {
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

	client := committeepb.NewCommitteeVerifierClient(aggregatorConn)
	return client, aggregatorConn, nil
}

func createMessageDiscoveryClient(ctx context.Context, messageDiscoveryBuf *bufconn.Listener, opts ...grpc.DialOption) (msgdiscoverypb.MessageDiscoveryClient, *grpc.ClientConn, error) {
	bufDialer := func(context.Context, string) (net.Conn, error) {
		return messageDiscoveryBuf.Dial()
	}

	//nolint:staticcheck // grpc.WithInsecure is deprecated but needed for test setup
	defaultOpts := []grpc.DialOption{
		grpc.WithContextDialer(bufDialer),
		grpc.WithInsecure(),
	}

	// Append custom options (like interceptors)
	allOpts := append(defaultOpts, opts...)

	//nolint:staticcheck // grpc.DialContext is deprecated but needed for bufconn test setup
	messageDiscoveryConn, err := grpc.DialContext(ctx, "bufnet", allOpts...)
	if err != nil {
		return nil, nil, err
	}

	client := msgdiscoverypb.NewMessageDiscoveryClient(messageDiscoveryConn)
	return client, messageDiscoveryConn, nil
}
