package tests

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
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

func WithStubMode(stub bool) ConfigOption {
	return func(cfg *model.AggregatorConfig) *model.AggregatorConfig {
		cfg.StubMode = stub
		return cfg
	}
}

func WithPaginationConfig(pageLimit int, tokenSecret string) ConfigOption {
	return func(cfg *model.AggregatorConfig) *model.AggregatorConfig {
		cfg.Pagination = model.PaginationConfig{
			PageLimit:   pageLimit,
			TokenSecret: tokenSecret,
		}
		return cfg
	}
}

// CreateServerAndClient creates a test server and client for functional testing.
func CreateServerAndClient(t *testing.T, options ...ConfigOption) (pb.AggregatorClient, pb.CCVDataClient, func(), error) {
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
		t.Fatalf("failed to start postgres container: %v", err)
	}

	// Get connection string from container
	connectionString, err := postgresContainer.ConnectionString(t.Context(), "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get connection string: %v", err)
	}

	buf := bufconn.Listen(bufSize)
	// Setup logging - always debug level for now
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	})
	if err != nil {
		panic(err)
	}

	// Use SugaredLogger for better API
	sugaredLggr := logger.Sugared(lggr)
	config := &model.AggregatorConfig{
		Server: model.ServerConfig{
			Address: ":50051",
		},
		Storage: model.StorageConfig{
			StorageType:   "postgres",
			ConnectionURL: connectionString,
		},
		Monitoring: model.MonitoringConfig{
			Enabled: false,
		},
	}

	for _, option := range options {
		config = option(config)
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

		// Terminate the PostgreSQL container
		if err := postgresContainer.Terminate(context.Background()); err != nil {
			t.Errorf("failed to terminate postgres container: %v", err)
		}
	}, nil
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
