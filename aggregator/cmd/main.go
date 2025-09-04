// Package main provides the entry point for the aggregator service.
package main

import (
	"context"
	"net"

	aggregator "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"go.uber.org/zap"
)

func main() {
	// Setup logging - always debug level for now
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
	})
	if err != nil {
		panic(err)
	}

	lggr = logger.Sugared(lggr)

	config := model.AggregatorConfig{
		Server: model.ServerConfig{
			Address: ":50051",
		},
		Storage: model.StorageConfig{
			StorageType: "memory",
		},
		DisableValidation: true,
	}

	server := aggregator.NewServer(lggr, config)

	address := config.Server.Address
	lc := &net.ListenConfig{}
	lis, err := lc.Listen(context.Background(), "tcp", address)
	if err != nil {
		lggr.Fatalw("failed to listen", "address", address, "error", err)
	}
	defer func() {
		if err := lis.Close(); err != nil {
			lggr.Errorw("failed to close listener", "error", err)
		}
	}()

	stop, err := server.Start(lis)
	if err != nil {
		lggr.Fatalw("failed to start server", "error", err)
	}
	defer stop()
}
