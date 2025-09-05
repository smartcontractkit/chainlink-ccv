package functionaltests

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/pb/aggregator"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	agg "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg"
)

const bufSize = 1024 * 1024

// CreateServerAndClient creates a test server and client for functional testing.
func CreateServerAndClient(t *testing.T, committeeConfig map[string]model.Committee) (aggregator.AggregatorClient, aggregator.CCVDataClient, func(), error) {
	aggregatorBuf := bufconn.Listen(bufSize)
	ccvDataBuf := bufconn.Listen(bufSize)
	// Setup logging - always debug level for now
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
	})
	if err != nil {
		panic(err)
	}

	// Use SugaredLogger for better API
	lggr = logger.Sugared(lggr)
	s := agg.NewServer(lggr, model.AggregatorConfig{
		Server: model.ServerConfig{
			CommitAggregatorAddress: ":50051",
			CCVDataAddress:          ":50052",
		},
		Storage: model.StorageConfig{
			StorageType: "memory",
		},
		Committees: committeeConfig,
	})
	go func() {
		_, _ = s.StartCommitAggregator(aggregatorBuf)
	}()

	go func() {
		_, _ = s.StartCCVData(ccvDataBuf)
	}()

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	aggregatorClient, aggregatorConn, err := createAggregatorClient(ctx, aggregatorBuf)
	if err != nil {
		t.Fatalf("failed to create aggregator client: %v", err)
	}

	ccvDataClient, ccvDataConn, err := createCCVDataClient(ctx, ccvDataBuf)
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
	}, nil
}

func createCCVDataClient(ctx context.Context, ccvDataBuf *bufconn.Listener) (aggregator.CCVDataClient, *grpc.ClientConn, error) {
	bufDialer := func(context.Context, string) (net.Conn, error) {
		return ccvDataBuf.Dial()
	}

	//nolint:staticcheck // grpc.WithInsecure is deprecated but needed for test setup
	ccvDataConn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		return nil, nil, err
	}

	client := aggregator.NewCCVDataClient(ccvDataConn)
	return client, ccvDataConn, nil
}

func createAggregatorClient(ctx context.Context, aggregatorBuf *bufconn.Listener) (aggregator.AggregatorClient, *grpc.ClientConn, error) {
	bufDialer := func(context.Context, string) (net.Conn, error) {
		return aggregatorBuf.Dial()
	}

	//nolint:staticcheck // grpc.WithInsecure is deprecated but needed for test setup
	aggregatorConn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		return nil, nil, err
	}

	client := aggregator.NewAggregatorClient(aggregatorConn)
	return client, aggregatorConn, nil
}
