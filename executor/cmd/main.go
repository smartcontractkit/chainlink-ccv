package main

import (
	"context"
	"go.uber.org/zap"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/destinationreader"
	x "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/utils"
	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var (
	chainBRpc                  = "http://blockchain-dst:8555"
	chainBPk                   = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	chainSelB                  = protocol.ChainSelector(12922642891491394802)
	chainBCcvAggregatorAddress = "0xA51c1fc2f0D1a1b8494Ed1FE312d7C3a78Ed91C0"
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

	// Use SugaredLogger for better API
	lggr = logger.Sugared(lggr)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// create executor components
	dr, err := destinationreader.NewEvmDestinationReaderFromRPC(lggr, chainSelB, chainBRpc)
	if err != nil {
		lggr.Errorw("Failed to create destination reader", "error", err)
		os.Exit(1)
	}

	ct, err := contracttransmitter.NewEVMContractTransmitterFromRPC(
		ctx,
		lggr,
		12922642891491394802,
		chainBRpc,
		chainBPk,
		common.HexToAddress(chainBCcvAggregatorAddress))

	// create executor
	ex := x.NewChainlinkExecutor(lggr, map[protocol.ChainSelector]contracttransmitter.ContractTransmitter{
		chainSelB: ct,
	}, map[protocol.ChainSelector]destinationreader.DestinationReader{
		chainSelB: dr,
	})

	// create dummy leader elector
	le := leaderelector.RandomDelayLeader{}

	// create data subscriber
	sdp := utils.NewScheduledDataPusher(lggr)

	// Create executor coordinator
	coordinator, err := executor.NewCoordinator(
		executor.WithLogger(lggr),
		executor.WithExecutor(ex),
		executor.WithLeaderElector(&le),
		executor.WithCCVDataReader(sdp),
	)
	if err != nil {
		lggr.Errorw("Failed to create execution coordinator", "error", err)
		os.Exit(1)
	}

	if err := coordinator.Start(ctx); err != nil {
		lggr.Errorw("Failed to start execution coordinator", "error", err)
		os.Exit(1)
	}

	// start sending message on data pusher
	go sdp.Run(ctx, 30*time.Second)

	<-sigCh
	lggr.Infow("🛑 Shutdown signal received, stopping verifier...")

	// Graceful shutdown
	_, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop executor coordinator
	if err := coordinator.Stop(); err != nil {
		lggr.Errorw("Execution coordinator stop error", "error", err)
	}

	lggr.Infow("✅ Execution service stopped gracefully")
}
