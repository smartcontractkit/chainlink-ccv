// Package main provides the entry point for the aggregator service.
package main

import (
	"context"
	"net"

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
			CommitAggregatorAddress: ":50051",
			CCVDataAddress:          ":50052",
		},
		Storage: model.StorageConfig{
			StorageType: "memory",
		},
		DisableValidation: true,
	}

	server := aggregator.NewServer(lggr, config)

	// Start both services concurrently
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	commitStop := startCommitAggregator(ctx, lggr, server, config.Server.CommitAggregatorAddress)
	ccvStop := startCCVDataService(ctx, lggr, server, config.Server.CCVDataAddress)

	defer func() {
		if commitStop != nil {
			commitStop()
		}
		if ccvStop != nil {
			ccvStop()
		}
	}()

	lggr.Infow("Services started", "commitAddress", config.Server.CommitAggregatorAddress, "ccvAddress", config.Server.CCVDataAddress)

	<-ctx.Done()
}

func startCommitAggregator(ctx context.Context, lggr logger.Logger, server *aggregator.Server, address string) func() {
	lc := &net.ListenConfig{}
	lis, err := lc.Listen(ctx, "tcp", address)
	if err != nil {
		lggr.Fatalw("failed to listen for commit aggregator", "address", address, "error", err)
	}

	var stop func()
	go func() {
		defer func() {
			if err := lis.Close(); err != nil {
				lggr.Errorw("failed to close commit aggregator listener", "address", address, "error", err)
			}
		}()

		stopFunc, err := server.StartCommitAggregator(lis)
		if err != nil {
			lggr.Fatalw("failed to start commit aggregator", "error", err)
		}
		stop = stopFunc
	}()

	return func() {
		if stop != nil {
			stop()
		}
	}
}

func startCCVDataService(ctx context.Context, lggr logger.Logger, server *aggregator.Server, address string) func() {
	lc := &net.ListenConfig{}
	lis, err := lc.Listen(ctx, "tcp", address)
	if err != nil {
		lggr.Fatalw("failed to listen for CCV data service", "address", address, "error", err)
	}

	var stop func()
	go func() {
		defer func() {
			if err := lis.Close(); err != nil {
				lggr.Errorw("failed to close CCV data service listener", "address", address, "error", err)
			}
		}()

		stopFunc, err := server.StartCCVDataService(lis)
		if err != nil {
			lggr.Fatalw("failed to start CCV data service", "error", err)
		}
		stop = stopFunc
	}()

	return func() {
		if stop != nil {
			stop()
		}
	}
}
