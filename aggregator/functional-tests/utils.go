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
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

func CreateServerAndClient(t *testing.T) (aggregator.AggregatorClient, func(), error) {
	lis = bufconn.Listen(bufSize)
	l := log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(zerolog.DebugLevel)
	s := agg.NewServer(l)
	go func() {
		s.Start(lis)
	}()

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

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
