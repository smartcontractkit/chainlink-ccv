package functionaltests

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pb/aggregator"
	agg "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

// CreateServerAndClient creates a test server and client for functional testing.
func CreateServerAndClient(t *testing.T, committeeConfig map[string]model.Committee) (aggregator.AggregatorClient, func(), error) {
	lis := bufconn.Listen(bufSize)
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
			Address: ":50051",
		},
		Storage: model.StorageConfig{
			StorageType: "memory",
		},
		Committees: committeeConfig,
	})
	go func() {
		_, _ = s.Start(lis)
	}()

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	bufDialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	//nolint:staticcheck // grpc.WithInsecure is deprecated but needed for test setup
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("failed to dial bufnet: %v", err)
	}

	client := aggregator.NewAggregatorClient(conn)
	return client, func() {
		if err := conn.Close(); err != nil {
			t.Errorf("failed to close connection: %v", err)
		}
		if err := lis.Close(); err != nil {
			t.Errorf("failed to close listener: %v", err)
		}
	}, nil
}
