package constructors

import (
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/chains/legacyevm"
)

// NewVerificationCoordinator starts the Committee Verifier with evm chains.
func NewVerificationCoordinator(
	lggr logger.Logger,
	cfg verifier.Config,
	secrets VerifierSecrets,
	relayers map[protocol.ChainSelector]legacyevm.Chain,
) (*verifier.Coordinator, error) {
	if err := cfg.Validate(); err != nil {
		lggr.Errorw("Invalid CCV verifier configuration.", "error", err)
	}

	onRampAddrs, err := mapAddresses(cfg.OnRampAddresses)
	if err != nil {
		lggr.Errorw("Invalid CCV configuration, failed to map onramp addresses.", "error", err)
		return nil, fmt.Errorf("invalid ccv configuration: failed to map onramp addresses: %w", err)
	}
	verifierAddrs, err := mapAddresses(cfg.CommitteeVerifierAddresses)
	if err != nil {
		lggr.Errorw("Invalid CCV configuration, failed to map verifier addresses.", "error", err)
		return nil, fmt.Errorf("invalid ccv configuration: failed to map verifier addresses: %w", err)
	}

	// Initialize chain components.
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
			chain.HeadTracker(),
			// TODO: use UnknownAddress instead of ethereum address.
			common.HexToAddress(onRampAddrs[sel].String()),
			// TODO: does this need to be configurable?
			onramp.OnRampCCIPMessageSent{}.Topic().Hex(),
			sel,
			logger.With(lggr, "component", "SourceReader", "chainID", sel))
		if err != nil {
			lggr.Errorw("Failed to create source reader.", "error", err, "chainID", sel)
			return nil, fmt.Errorf("failed to create source reader: %w", err)
		}
		sourceReaders[sel] = sourceReader
		sourceConfigs[sel] = verifier.SourceConfig{
			VerifierAddress: verifierAddrs[sel],
			PollInterval:    1 * time.Second, // TODO: make configurable
			ChainSelector:   sel,
		}
	}

	// Initialize other required services and configs.

	// TODO: monitoring
	var verifierMonitoring verifier.Monitoring

	// Checkpoint manager
	hmacConfig := &hmac.ClientConfig{
		APIKey: cfg.AggregatorAPIKey,
		Secret: cfg.AggregatorSecretKey,
	}

	aggregatorWriter, err := storageaccess.NewAggregatorWriter(cfg.AggregatorAddress, lggr, hmacConfig)
	if err != nil {
		lggr.Errorw("Failed to create aggregator writer", "error", err)
		return nil, fmt.Errorf("failed to create aggregator writer: %w", err)
	}

	aggregatorReader, err := storageaccess.NewAggregatorReader(cfg.AggregatorAddress, lggr, 0, hmacConfig) // since=0 for checkpoint reads
	if err != nil {
		// Clean up writer if reader creation fails
		err := aggregatorWriter.Close()
		if err != nil {
			lggr.Errorw("Failed to close aggregator writer", "error", err)
		}
		lggr.Errorw("Failed to create aggregator reader", "error", err)
		return nil, fmt.Errorf("failed to create aggregator reader: %w", err)
	}

	// Create chain status manager (includes both writer and reader)
	chainStatusManager := storageaccess.NewAggregatorChainStatusManager(aggregatorWriter, aggregatorReader)

	coordinatorConfig := verifier.CoordinatorConfig{
		VerifierID:          cfg.VerifierID,
		SourceConfigs:       sourceConfigs,
		StorageBatchSize:    50,
		StorageBatchTimeout: 100 * time.Millisecond,
	}

	// Create commit verifier (with ECDSA signer)
	signer, addr, err := commit.NewECDSAMessageSignerFromString(secrets.SigningKey)
	if err != nil {
		lggr.Errorw("Failed to create message signer", "error", err)
		return nil, fmt.Errorf("failed to create message signer: %w", err)
	}
	commitVerifier, err := commit.NewCommitVerifier(coordinatorConfig, addr, signer, lggr, verifierMonitoring)
	if err != nil {
		lggr.Errorw("Failed to create commit verifier", "error", err)
		return nil, fmt.Errorf("failed to create commit verifier: %w", err)
	}

	// Create verification coordinator
	verifierCoordinator, err := verifier.NewCoordinator(
		verifier.WithLogger(lggr),
		verifier.WithVerifier(commitVerifier),
		verifier.WithSourceReaders(sourceReaders),
		verifier.WithChainStatusManager(chainStatusManager),
		verifier.WithStorage(aggregatorWriter),
		verifier.WithConfig(coordinatorConfig),
		verifier.WithLogger(lggr),
		verifier.WithMonitoring(verifierMonitoring),
	)
	if err != nil {
		lggr.Errorw("Failed to create verification coordinator", "error", err)
		return nil, fmt.Errorf("failed to create verification coordinator: %w", err)
	}

	return verifierCoordinator, nil
	/*
		for {
			lggr.Infow("verifier health", "HealthCheck()", verifierCoordinator.HealthReport())
			time.Sleep(10 * time.Second)
		}
	*/
}
