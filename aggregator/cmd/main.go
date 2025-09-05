// Package main provides the entry point for the aggregator service.
package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	aggregator "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg"
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
	ctx := context.Background()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	lc := &net.ListenConfig{}
	lis, err := lc.Listen(context.Background(), "tcp", config.Server.Address)
	if err != nil {
		lggr.Fatalw("failed to listen for CCV data service", "address", config.Server.Address, "error", err)
	}

	err = server.Start(lis)
	if err != nil {
		lggr.Fatalw("failed to start CCV data service", "error", err)
	}

	<-ctx.Done()
	if err := server.Stop(); err != nil {
		lggr.Errorw("failed to stop CCV data service", "error", err)
	}
	if err := lis.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		lggr.Errorw("failed to close listener", "error", err)
	}
	lggr.Info("Aggregator service shut down gracefully")
}
