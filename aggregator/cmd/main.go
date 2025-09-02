package main

import (
	"net"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	aggregator "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

func main() {
	lvlStr := os.Getenv("AGGREGATOR_LOG_LEVEL")
	if lvlStr == "" {
		lvlStr = "info"
	}
	lvl, err := zerolog.ParseLevel(lvlStr)
	if err != nil {
		panic(err)
	}
	l := log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(lvl)

	config := model.AggregatorConfig{
		Storage: model.StorageConfig{
			StorageType: "memory",
		},
		Aggregation: model.AggregationConfig{
			AggregationStrategy: "stub",
		},
	}

	server := aggregator.NewServer(l, config)

	port := os.Getenv("AGGREGATOR_PORT")
	if port == "" {
		port = ":50051"
	}
	lis, err := net.Listen("tcp", port)
	if err != nil {
		l.Fatal().Err(err).Msg("failed to listen")
	}
	defer lis.Close()

	stop, err := server.Start(lis)
	if err != nil {
		l.Fatal().Err(err).Msg("failed to start server")
	}
	defer stop()
}
