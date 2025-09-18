package main

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/ethereum/go-ethereum/common"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/destinationreader"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	execconfig "github.com/smartcontractkit/chainlink-ccv/executor/pkg/configuration"
	x "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

var configPath = "executor_config.toml"

func main() {
	executorConfig, err := loadConfiguration(configPath)
	if err != nil {
		os.Exit(1)
	}
	if executorConfig.Validate() != nil {
		os.Exit(1)
	}

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

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	contractTransmitters := make(map[protocol.ChainSelector]contracttransmitter.ContractTransmitter)
	destReaders := make(map[protocol.ChainSelector]destinationreader.DestinationReader)
	// create executor components
	for strSel, chain := range executorConfig.BlockchainInfos {
		selector, err := strconv.ParseUint(strSel, 10, 64)
		if err != nil {
			lggr.Errorw("Invalid chain selector in configuration", "error", err, "chainSelector", strSel)
			continue
		}

		dr := destinationreader.NewEvmDestinationReaderFromChainInfo(ctx, lggr, selector, chain)

		ct, err := contracttransmitter.NewEVMContractTransmitterFromRPC(
			ctx,
			lggr,
			selector,
			chain.Nodes[0].InternalHTTPUrl,
			executorConfig.PrivateKey,
			common.HexToAddress(chain.OfframpRouter),
		)
		if err != nil {
			lggr.Errorw("Failed to create contract transmitter", "error", err)
			os.Exit(1)
		}

		destReaders[protocol.ChainSelector(selector)] = dr
		contractTransmitters[protocol.ChainSelector(selector)] = ct
	}

	// create executor
	ex := x.NewChainlinkExecutor(lggr, contractTransmitters, destReaders)

	// create dummy leader elector
	le := leaderelector.RandomDelayLeader{}

	indexerStream := ccvstreamer.NewIndexerStorageStreamer(
		executorConfig.IndexerAddress,
		lggr,
		time.Now().Add(-1*executorConfig.GetLookbackWindow()).Unix(),
		executorConfig.GetPollingInterval(),
		executorConfig.GetBackoffDuration())

	// Create executor coordinator
	coordinator, err := executor.NewCoordinator(
		executor.WithLogger(lggr),
		executor.WithExecutor(ex),
		executor.WithLeaderElector(&le),
		executor.WithCCVResultStreamer(indexerStream),
	)
	if err != nil {
		lggr.Errorw("Failed to create execution coordinator", "error", err)
		os.Exit(1)
	}

	if err := coordinator.Start(ctx); err != nil {
		lggr.Errorw("Failed to start execution coordinator", "error", err)
		os.Exit(1)
	}

	<-sigCh
	lggr.Infow("🛑 Shutdown signal received, stopping verifier...")

	// Graceful shutdown
	_, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop execution coordinator
	if err := coordinator.Stop(); err != nil {
		lggr.Errorw("Execution coordinator stop error", "error", err)
	}

	lggr.Infow("✅ Execution service stopped gracefully")
}

func loadConfiguration(filepath string) (*execconfig.Configuration, error) {
	var config execconfig.Configuration
	if _, err := toml.DecodeFile(filepath, &config); err != nil {
		return nil, err
	}
	return &config, nil
}
