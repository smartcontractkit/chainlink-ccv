package clnode

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/chains/legacyevm"

	vcommon "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/common"
)

// StartCCVComitteeVerifier starts the Committee Verifier with evm chains.
func StartCCVComitteeVerifier(
	ctx context.Context,
	lggr logger.Logger,
	cfg CCVConfig,
	relayers map[protocol.ChainSelector]legacyevm.Chain,
) {
	// Initialize chain components.
	sourceReaders := make(map[protocol.ChainSelector]verifier.SourceReader)
	for sel, chain := range relayers {
		if _, ok := cfg.ChainConfigs[sel]; !ok {
			lggr.Warnw("No config for chain, skipping.", "chainID", sel)
			continue
		}

		sourceReader, err := sourcereader.NewEVMSourceReader(
			chain.Client(),
			common.HexToAddress(cfg.ChainConfigs[sel].CCVProxyAddress),
			"TODO: topic-here",
			sel,
			logger.With(lggr, "component", "SourceReader", "chainID", sel))
		if err != nil {
			lggr.Errorw("Failed to create source reader.", "error", err, "chainID", sel)
			return
		}
		sourceReaders[sel] = sourceReader
	}

	cv, err := commit.NewCommitVerifier(
		verifier.CoordinatorConfig{},
		nil,
		logger.With(lggr, "component", "CommitVerifier"),
		nil,
	)
	if err != nil {
		lggr.Errorw("Failed to create commit verifier.", "error", err)
		return
	}

	verifierCoordinator, err := verifier.NewVerificationCoordinator(
		verifier.WithLogger(logger.With(lggr, "component", "VerifierCoordinator")),
		verifier.WithSourceReaders(sourceReaders),
		verifier.WithConfig(verifier.CoordinatorConfig{VerifierID: "rubber-ducky"}),
		verifier.WithVerifier(cv),
		verifier.WithStorage(vcommon.NewInMemoryOffchainStorage(
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
		lggr.Infow("verifier health", "HealthCheck()", verifierCoordinator.HealthReport())
		time.Sleep(10 * time.Second)
	}
}
