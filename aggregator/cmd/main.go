// Package main provides the entry point for the aggregator service.
package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/grafana/pyroscope-go"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/configuration"
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

	sugaredLggr := logger.Sugared(lggr)

	filePath := "aggregator.toml"
	if len(os.Args) > 1 {
		filePath = os.Args[1]
	}
	config, err := configuration.LoadConfig(filePath)
	if err != nil {
		lggr.Errorw("Failed to load configuration", "error", err)
		os.Exit(1)
	}
	if _, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "aggregator",
		ServerAddress:   config.PyroscopeURL,
		Logger:          pyroscope.StandardLogger,
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileGoroutines,
			pyroscope.ProfileBlockDuration,
			pyroscope.ProfileMutexDuration,
		},
	}); err != nil {
		lggr.Errorw("Failed to start pyroscope", "error", err)
	}

	server := aggregator.NewServer(sugaredLggr, config)
	ctx := context.Background()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	lc := &net.ListenConfig{}
	lis, err := lc.Listen(context.Background(), "tcp", config.Server.Address)
	if err != nil {
		sugaredLggr.Fatalw("failed to listen for CCV data service", "address", config.Server.Address, "error", err)
	}

	err = server.Start(lis)
	if err != nil {
		sugaredLggr.Fatalw("failed to start CCV data service", "error", err)
	}

	<-ctx.Done()
	if err := server.Stop(); err != nil {
		sugaredLggr.Errorw("failed to stop CCV data service", "error", err)
	}
	if err := lis.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		sugaredLggr.Errorw("failed to close listener", "error", err)
	}
	sugaredLggr.Info("Aggregator service shut down gracefully")
}
