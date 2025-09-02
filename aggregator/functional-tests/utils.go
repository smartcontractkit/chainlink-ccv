package functionaltests

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rs/zerolog"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pb/aggregator"
	agg "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

func CreateServerAndClient(t *testing.T) (aggregator.AggregatorClient, func(), error) {
	lis := bufconn.Listen(bufSize)
	l := log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(zerolog.DebugLevel)
	s := agg.NewServer(l, model.AggregatorConfig{
		Storage: model.StorageConfig{
			StorageType: "memory",
		},
		Aggregation: model.AggregationConfig{
			AggregationStrategy: "stub",
		},
	})
	go func() {
		s.Start(lis)
	}()

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	bufDialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("failed to dial bufnet: %v", err)
	}

	client := aggregator.NewAggregatorClient(conn)
	return client, func() {
		conn.Close()
		lis.Close()
	}, nil
}
