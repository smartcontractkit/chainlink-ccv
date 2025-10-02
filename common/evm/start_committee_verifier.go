package evm

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/reader"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/chains/legacyevm"
)

func StartCCVComitteeVerifier(
	ctx context.Context,
	lggr logger.Logger,
	cfg CCVConfig,
	relayers map[protocol.ChainSelector]legacyevm.Chain,
) {
	wait := true
	for wait {
		wait = true
		lggr.Warn("verifier waiting...")
		time.Sleep(1 * time.Second)
	}

	// Initialize chain components.
	sourceReader := map[protocol.ChainSelector]verifier.SourceReader{}
	for sel, chain := range relayers {
		if _, ok := cfg.ChainConfigs[sel]; !ok {
			lggr.Warnw("No config for chain, skipping.", "chainID", sel)
			continue
		}

		// TODO: Add checkpoint manager -- optional?
		sourceReader[sel] = reader.NewEVMSourceReader(
			chain.Client(),
			cfg.ChainConfigs[sel].CCVProxyAddress,
			sel,
			nil,
			logger.With(lggr, "component", "SourceReader", "chainID", sel))
	}

	cv := commit.NewCommitVerifier(
		verifier.CoordinatorConfig{},
		nil,
		logger.With(lggr, "component", "CommitVerifier"),
	)

	verifierCoordinator, err := verifier.NewVerificationCoordinator(
		verifier.WithLogger(logger.With(lggr, "component", "VerifierCoordinator")),
		verifier.WithSourceReaders(sourceReader),
		verifier.WithConfig(verifier.CoordinatorConfig{VerifierID: "rubber-ducky"}),
		verifier.WithVerifier(cv),
		verifier.WithStorage(storageaccess.NewInMemoryOffchainStorage(
			logger.With(lggr, "component", "StorageAccessor"))),
	)
	if err != nil {
		lggr.Errorw("Failed to create verification coordinator.", "error", err)
		return
	}

	lggr.Infow("Starting verifier")
	err = verifierCoordinator.Start(ctx)
	if err != nil {
		lggr.Errorw("Failed to start verification coordinator.", "error", err)
		return
	}

	for {
		lggr.Infow("verifier health", "HealthCheck()", verifierCoordinator.HealthCheck(ctx))
		time.Sleep(10 * time.Second)
	}
}
