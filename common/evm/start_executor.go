package evm

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/destinationreader"
	x "github.com/smartcontractkit/chainlink-ccv/executor/pkg/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/leaderelector"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/chains/legacyevm"
)

// StartCCVExecutor starts an executor with evm chains.
func StartCCVExecutor(
	ctx context.Context,
	lggr logger.Logger,
	cfg CCVConfig,
	relayers map[protocol.ChainSelector]legacyevm.Chain,
) {
	transmitters := make(map[protocol.ChainSelector]executor.ContractTransmitter)
	destReaders := make(map[protocol.ChainSelector]executor.DestinationReader)

	for sel, chain := range relayers {
		if _, ok := cfg.ChainConfigs[sel]; !ok {
			lggr.Warnw("No config for chain, skipping.", "chainID", sel)
			continue
		}

		transmitters[sel] = contracttransmitter.NewEVMContractTransmitterFromTxm(
			logger.With(lggr, "component", "ContractTransmitter"),
			uint64(sel),
			chain.TxManager())

		destReaders[sel] = destinationreader.NewEvmDestinationReader(
			logger.With(lggr, "component", "DestinationReader"),
			uint64(sel),
			chain.Client(),
			cfg.ChainConfigs[sel].CCVAggregatorAddress)
	}

	ex := x.NewChainlinkExecutor(
		logger.With(lggr, "component", "Executor"),
		transmitters,
		destReaders)

	// TODO: in memory storage reader??
	// TODO: indexer or aggregator reader.
	strm := ccvstreamer.NewOffchainStorageStreamer(
		nil, 1*time.Second, 1*time.Second)

	exec, err := executor.NewCoordinator(
		executor.WithLogger(logger.With(lggr, "component", "Coordinator")),
		executor.WithExecutor(ex),
		executor.WithLeaderElector(&leaderelector.RandomDelayLeader{}),
		executor.WithCCVResultStreamer(strm),
	)
	if err != nil {
		lggr.Errorw("Failed to create execution coordinator.", "error", err)
		return
	}

	err = exec.Start(ctx)
	if err != nil {
		lggr.Errorw("Failed to start execution coordinator.", "error", err)
		return
	}

	for {
		lggr.Info("Executor is running:", exec.HealthReport())
		time.Sleep(10 * time.Second)
	}
}
