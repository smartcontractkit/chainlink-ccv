package constructors

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/chains/legacyevm"
)

// NewVerificationCoordinator starts the Committee Verifier with evm chains.
// Signing is passed in because it's managed differently in the CL node vs standalone modes.
// The DataSource is passed in from CL node, or created by standalone mode.
func NewVerificationCoordinator(
	lggr logger.Logger,
	cfg commit.Config,
	aggregatorSecret *hmac.ClientConfig,
	signingAddress protocol.UnknownAddress,
	signer verifier.MessageSigner,
	relayers map[protocol.ChainSelector]legacyevm.Chain,
	ds sqlutil.DataSource,
) (*verifier.Coordinator, error) {
	if err := cfg.Validate(); err != nil {
		lggr.Errorw("Invalid CCV verifier configuration.", "error", err)
	}

	// TODO: this verification shouldn't be here?
	cfgSignerBytes := common.HexToAddress(cfg.SignerAddress).Bytes()
	if !bytes.Equal(signingAddress.Bytes(), cfgSignerBytes) {
		return nil, fmt.Errorf("signing address does not match configuration: config %x vs provided %x", cfgSignerBytes, signingAddress.Bytes())
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
	rmnRemoteAddrs, err := mapAddresses(cfg.RMNRemoteAddresses)
	if err != nil {
		lggr.Errorw("Invalid CCV configuration, failed to map RMN Remote addresses.", "error", err)
		return nil, fmt.Errorf("invalid ccv configuration: failed to map RMN Remote addresses: %w", err)
	}
	defaultExecutorAddrs, err := mapAddresses(cfg.DefaultExecutorOnRampAddresses)
	if err != nil {
		lggr.Errorw("Invalid CCV configuration, failed to map default executor addresses.", "error", err)
		return nil, fmt.Errorf("invalid ccv configuration: failed to map default executor addresses: %w", err)
	}

	// TODO: monitoring config home
	verifierMonitoring, err := monitoring.InitMonitoring(beholder.Config{
		InsecureConnection:       cfg.Monitoring.Beholder.InsecureConnection,
		CACertFile:               cfg.Monitoring.Beholder.CACertFile,
		OtelExporterHTTPEndpoint: cfg.Monitoring.Beholder.OtelExporterHTTPEndpoint,
		OtelExporterGRPCEndpoint: cfg.Monitoring.Beholder.OtelExporterGRPCEndpoint,
		LogStreamingEnabled:      cfg.Monitoring.Beholder.LogStreamingEnabled,
		MetricReaderInterval:     time.Second * time.Duration(cfg.Monitoring.Beholder.MetricReaderInterval),
		TraceSampleRatio:         cfg.Monitoring.Beholder.TraceSampleRatio,
		TraceBatchTimeout:        time.Second * time.Duration(cfg.Monitoring.Beholder.TraceBatchTimeout),
	})
	if err != nil {
		lggr.Errorw("Failed to initialize verifier monitoring", "error", err)
		return nil, fmt.Errorf("failed to initialize verifier monitoring: %w", err)
	}

	// Initialize chain components.
	sourceReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader)
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
			common.HexToAddress(rmnRemoteAddrs[sel].String()),
			// TODO: does this need to be configurable?
			onramp.OnRampCCIPMessageSent{}.Topic().Hex(),
			sel,
			logger.With(lggr, "component", "SourceReader", "chainID", sel))
		if err != nil {
			lggr.Errorw("Failed to create source reader.", "error", err, "chainID", sel)
			return nil, fmt.Errorf("failed to create source reader: %w", err)
		}

		observedSourceReader := sourcereader.NewObservedSourceReader(
			sourceReader, cfg.VerifierID, sel, verifierMonitoring,
		)

		sourceReaders[sel] = observedSourceReader
		sourceConfigs[sel] = verifier.SourceConfig{
			VerifierAddress:        verifierAddrs[sel],
			DefaultExecutorAddress: defaultExecutorAddrs[sel],
			PollInterval:           2 * time.Second, // TODO: make configurable
			ChainSelector:          sel,
			RMNRemoteAddress:       rmnRemoteAddrs[sel],
		}
	}

	// Initialize other required services and configs.

	// Checkpoint manager
	// TODO: these are secrets, probably shouldn't be in config.
	aggregatorWriter, err := storageaccess.NewAggregatorWriter(cfg.AggregatorAddress, lggr, aggregatorSecret, cfg.InsecureAggregatorConnection)
	if err != nil {
		lggr.Errorw("Failed to create aggregator writer", "error", err)
		return nil, fmt.Errorf("failed to create aggregator writer: %w", err)
	}

	// Create chain status manager using postgres
	chainStatusManager := chainstatus.NewPostgresChainStatusManager(ds, lggr)

	coordinatorConfig := verifier.CoordinatorConfig{
		VerifierID:          cfg.VerifierID,
		SourceConfigs:       sourceConfigs,
		StorageBatchSize:    50,
		StorageBatchTimeout: 100 * time.Millisecond,
		StorageRetryDelay:   5 * time.Second,
	}

	// Create commit verifier (with ECDSA signer)
	ecdsaSigner := commit.NewECDSASignerWithKeystoreSigner(signer)
	commitVerifier, err := commit.NewCommitVerifier(coordinatorConfig, signingAddress, ecdsaSigner, lggr, verifierMonitoring)
	if err != nil {
		lggr.Errorw("Failed to create commit verifier", "error", err)
		return nil, fmt.Errorf("failed to create commit verifier: %w", err)
	}

	messageTracker := monitoring.NewMessageLatencyTracker(
		lggr,
		coordinatorConfig.VerifierID,
		verifierMonitoring,
	)

	// Create verification coordinator
	verifierCoordinator, err := verifier.NewCoordinator(
		context.TODO(),
		lggr,
		commitVerifier,
		sourceReaders,
		aggregatorWriter,
		coordinatorConfig,
		messageTracker,
		verifierMonitoring,
		chainStatusManager,
	)
	if err != nil {
		lggr.Errorw("Failed to create verification coordinator", "error", err)
		return nil, fmt.Errorf("failed to create verification coordinator: %w", err)
	}

	return verifierCoordinator, nil
}
