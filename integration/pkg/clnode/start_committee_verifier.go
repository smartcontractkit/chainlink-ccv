package clnode

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/chains/legacyevm"
)

// StartCCVComitteeVerifier starts the Committee Verifier with evm chains.
func StartCCVComitteeVerifier(
	ctx context.Context,
	lggr logger.Logger,
	ccvConfig CCVConfig,
	ccvSecrets CCVSecretsConfig,
	relayers map[protocol.ChainSelector]legacyevm.Chain,
) error {
	cfg := ccvConfig.Verifier

	if err := cfg.Validate(); err != nil {
		lggr.Errorw("Invalid CCV verifier configuration.", "error", err)
	}

	/*
		// TODO: BlockchainInfos is only used for creating the chainreader, not needed on CL node.
		blockchainInfo, err := mapInfos(cfg.BlockchainInfos)
		if err != nil {
			lggr.Errorw("Invalid CCV configuration, failed to map blockchain infos.", "error", err)
		}
	*/
	onRampAddrs, err := mapAddresses(cfg.OnRampAddresses)
	if err != nil {
		lggr.Errorw("Invalid CCV configuration, failed to map onramp addresses.", "error", err)
	}
	verifierAddrs, err := mapAddresses(cfg.CommitteeVerifierAddresses)
	if err != nil {
		lggr.Errorw("Invalid CCV configuration, failed to map verifier addresses.", "error", err)
	}

	// Initialize per-chain components.
	sourceReaders := make(map[protocol.ChainSelector]verifier.SourceReader)
	sourceConfigs := make(map[protocol.ChainSelector]verifier.SourceConfig)
	for sel, chain := range relayers {
		if _, ok := onRampAddrs[sel]; !ok {
			lggr.Warnw("No onramp address for chain, skipping.", "chainID", sel)
			continue
		}
		if _, ok := verifierAddrs[sel]; !ok {
			lggr.Warnw("No verifier address for chain, skipping.", "chainID", sel)
			continue
		}

		sourceReader, err := sourcereader.NewEVMSourceReader(
			chain.Client(),
			// TODO: use UnknownAddress instead of ethereum address.
			common.HexToAddress(onRampAddrs[sel].String()),
			onramp.OnRampCCIPMessageSent{}.Topic().Hex(),
			sel,
			logger.With(lggr, "component", "SourceReader", "chainID", sel))
		if err != nil {
			lggr.Errorw("Failed to create source reader.", "error", err, "chainID", sel)
			return fmt.Errorf("failed to create source reader: %w", err)
		}
		sourceReaders[sel] = sourceReader
		sourceConfigs[sel] = verifier.SourceConfig{
			VerifierAddress: verifierAddrs[sel],
			PollInterval:    1 * time.Second,
			ChainSelector:   sel,
		}
	}

	// Initialize other required services and configs.

	// TODO: monitoring

	// Checkpoint manager
	hmacConfig := &hmac.ClientConfig{
		APIKey: cfg.AggregatorAPIKey,
		Secret: cfg.AggregatorSecretKey,
	}

	aggregatorWriter, err := storageaccess.NewAggregatorWriter(cfg.AggregatorAddress, lggr, hmacConfig)
	if err != nil {
		lggr.Errorw("Failed to create aggregator writer", "error", err)
		return fmt.Errorf("failed to create aggregator writer: %w", err)
	}

	aggregatorReader, err := storageaccess.NewAggregatorReader(cfg.AggregatorAddress, lggr, 0, hmacConfig) // since=0 for checkpoint reads
	if err != nil {
		// Clean up writer if reader creation fails
		err := aggregatorWriter.Close()
		if err != nil {
			lggr.Errorw("Failed to close aggregator writer", "error", err)
		}
		lggr.Errorw("Failed to create aggregator reader", "error", err)
		return fmt.Errorf("failed to create aggregator reader: %w", err)
	}

	// Create checkpoint manager (includes both writer and reader)
	checkpointManager := storageaccess.NewAggregatorCheckpointManager(aggregatorWriter, aggregatorReader)

	coordinatorConfig := verifier.CoordinatorConfig{
		VerifierID:          cfg.VerifierID,
		SourceConfigs:       sourceConfigs,
		StorageBatchSize:    50,
		StorageBatchTimeout: 100 * time.Millisecond,
	}

	// Signer
	signer, err := verifier.NewECDSAMessageSignerFromString(ccvSecrets.Verifier.SigningKey)
	if err != nil {
		lggr.Errorw("Failed to create message signer", "error", err)
		return fmt.Errorf("failed to create message signer: %w", err)
	}

	// CommitVerifier
	cv, err := verifier.NewCommitVerifier(
		coordinatorConfig,
		signer,
		logger.With(lggr, "component", "CommitVerifier"),
		nil,
	)
	if err != nil {
		lggr.Errorw("Failed to create commit verifier.", "error", err)
		return fmt.Errorf("failed to create commit verifier: %w", err)
	}

	verifierCoordinator, err := verifier.NewVerificationCoordinator(
		verifier.WithLogger(logger.With(lggr, "component", "VerifierCoordinator")),
		verifier.WithVerifier(cv),
		verifier.WithSourceReaders(sourceReaders),
		verifier.WithCheckpointManager(checkpointManager),
		verifier.WithStorage(aggregatorWriter),
		verifier.WithConfig(coordinatorConfig),
	)
	if err != nil {
		lggr.Errorw("Failed to create verification coordinator.", "error", err)
		return fmt.Errorf("failed to create verification coordinator: %w", err)
	}

	lggr.Infow("Starting verifier")
	err = verifierCoordinator.Start(ctx)
	if err != nil {
		lggr.Errorw("Failed to start verification coordinator.", "error", err)
		return fmt.Errorf("failed to start verification coordinator: %w", err)
	}

	for {
		lggr.Infow("verifier health", "HealthCheck()", verifierCoordinator.HealthReport())
		time.Sleep(10 * time.Second)
	}
}
