package constructors

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/common/monitoring/logging"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/messagerules"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/heartbeat"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/policy"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/chains/legacyevm"
)

// NewVerificationCoordinator builds a verifier coordinator. aggregatorSecrets maps each
// aggregator's SecretName (AggregatorConnection.SecretName) to its HMAC credential — a consolidated
// verifier writes to every aggregator, each of which authenticates it with its own credential.
// Keying by SecretName (rather than position) avoids any ordering contract with
// cfg.ResolvedAggregators(); the legacy single-aggregator config has an empty SecretName, so its
// credential is keyed by "".
//
// Optional dependencies are passed as opts rather than as parameters. This constructor is called
// from the Chainlink node repo, so a positional signature that grows breaks that build until a
// change lands there, and the two cannot land at once.
func NewVerificationCoordinator(
	lggr logger.Logger,
	cfg commit.Config,
	aggregatorSecrets map[string]*hmac.ClientConfig,
	signingAddress protocol.UnknownAddress,
	signer verifier.MessageSigner,
	relayers map[protocol.ChainSelector]legacyevm.Chain,
	ds sqlutil.DataSource,
	opts ...VerificationCoordinatorOption,
) (*verifier.Coordinator, error) {
	options := newVerificationCoordinatorOptions(opts)

	lggr = logging.WithService(lggr, "verifier")

	if err := cfg.Validate(); err != nil {
		lggr.Errorw("Invalid CCV verifier configuration.", "error", err)
		return nil, fmt.Errorf("invalid ccv verifier configuration: %w", err)
	}

	if err := commit.ValidateSignerAddress(cfg.SignerAddress, signingAddress); err != nil {
		return nil, err
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
	// Deprecated: derived from each OnRamp's on-chain static config. Still parsed when present
	// so the source reader can warn on a mismatch with the derived address.
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

	protocol.InitChainSelectorCache()

	verifierMonitoring, err := monitoring.InitMonitoring("committee_verifier")
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

		chainMetrics := verifierMonitoring.Metrics().With(
			"chain_selector", fmt.Sprintf("%d", sel),
			"chain_name", sel.ChainName(),
		)
		sourceReader, err := evm.NewEVMSourceReader(
			// This CL entry point has no context parameter (its signature is consumed by the
			// Chainlink node repo and must stay unchanged); the reader bounds the one-shot
			// static-config read with its own timeout.
			context.Background(),
			chain.Client(),
			chain.HeadTracker(),
			// TODO: use UnknownAddress instead of ethereum address.
			common.HexToAddress(onRampAddrs[sel].String()),
			// Deprecated configured RMN Remote, zero when unset: the reader derives the
			// authoritative address on-chain and warns if this disagrees with it.
			common.HexToAddress(rmnRemoteAddrs[sel].String()),
			onramp.OnRampCCIPMessageSent{}.Topic().Hex(),
			sel,
			logger.With(lggr, "component", "SourceReader", "chainID", sel),
			evmconfig.DefaultSourceReaderHeaderFetchBatchSize,
			func(ctx context.Context) {
				chainMetrics.IncrementCriticalSourceInvariantViolations(ctx)
			},
		)
		if err != nil {
			lggr.Errorw("Failed to create source reader.", "error", err, "chainID", sel)
			return nil, fmt.Errorf("failed to create source reader: %w", err)
		}

		observedSourceReader, err := sourcereader.NewObservedSourceReader(
			sourceReader, cfg.VerifierID, sel, verifierMonitoring,
		)
		if err != nil {
			lggr.Errorw("Failed to create observed source reader.", "error", err, "chainID", sel)
			return nil, fmt.Errorf("failed to create observed source reader: %w", err)
		}

		sourceReaders[sel] = observedSourceReader
		sourceConfigs[sel] = verifier.SourceConfig{
			VerifierAddress:        verifierAddrs[sel],
			DefaultExecutorAddress: defaultExecutorAddrs[sel],
			PollInterval:           verifier.SourceReaderPollInterval, // TODO: make configurable
			ChainSelector:          sel,
		}
	}
	if len(sourceReaders) == 0 {
		return nil, fmt.Errorf("no source readers configured: ensure at least one chain has matching onramp and verifier addresses")
	}

	// Initialize other required services and configs.

	// Resolve the aggregators this verifier writes to, heartbeats, and reads disablement rules
	// from. Backwards compatible: a legacy single aggregator_address resolves to a one-element list.
	resolvedAggregators, err := cfg.ResolvedAggregators()
	if err != nil {
		lggr.Errorw("Invalid aggregator configuration", "error", err)
		return nil, fmt.Errorf("invalid aggregator configuration: %w", err)
	}

	// Each aggregator authenticates with its own credential, looked up by SecretName.
	// resolvedSecrets is index-aligned with resolvedAggregators for the wiring below.
	resolvedSecrets := make([]*hmac.ClientConfig, len(resolvedAggregators))
	for i, a := range resolvedAggregators {
		sec, ok := aggregatorSecrets[a.SecretName]
		if !ok {
			return nil, fmt.Errorf("missing aggregator secret for %q (secret_name %q)", a.Label(), a.SecretName)
		}
		resolvedSecrets[i] = sec
	}

	writeTargets := make([]storageaccess.AggregatorTarget, len(resolvedAggregators))
	heartbeatTargets := make([]heartbeatclient.AggregatorTarget, len(resolvedAggregators))
	for i, a := range resolvedAggregators {
		writeTargets[i] = storageaccess.AggregatorTarget{
			Label:               a.Label(),
			Address:             a.Address,
			Insecure:            a.InsecureConnection,
			HMACConfig:          resolvedSecrets[i],
			MaxSendMsgSizeBytes: a.MaxSendMsgSizeBytes,
			MaxRecvMsgSizeBytes: a.MaxRecvMsgSizeBytes,
		}
		heartbeatTargets[i] = heartbeatclient.AggregatorTarget{
			Label:      a.Label(),
			Address:    a.Address,
			Insecure:   a.InsecureConnection,
			HMACConfig: resolvedSecrets[i],
		}
	}

	fanOutWriter, err := storageaccess.NewFanOutAggregatorWriter(
		writeTargets,
		cfg.VerifierID,
		lggr,
		verifierMonitoring,
	)
	if err != nil {
		lggr.Errorw("Failed to create fan-out aggregator writer", "error", err)
		return nil, fmt.Errorf("failed to create fan-out aggregator writer: %w", err)
	}

	observedOffchainWriter := storageaccess.NewObservedOffchainWriter(
		fanOutWriter,
		cfg.VerifierID,
		lggr,
		verifierMonitoring,
	)

	chainStatusStore := chainstatus.NewPostgresChainStatusStore(ds, lggr)
	chainStatusManager := chainstatus.NewPostgresChainStatusManager(chainStatusStore, cfg.VerifierID)

	coordinatorConfig := verifier.CoordinatorConfig{
		VerifierID:          cfg.VerifierID,
		SourceConfigs:       sourceConfigs,
		StorageBatchSize:    50,
		StorageBatchTimeout: 100 * time.Millisecond,
		StorageRetryDelay:   2 * time.Second,
		HeartbeatInterval:   10 * time.Second,
		// How often buffered chain statuses are written. A disabled status is written immediately.
		ChainStatusFlushInterval:  chainstatus.DefaultFlushInterval,
		ChainStatusFlushThreshold: chainstatus.DefaultFlushThreshold,
	}

	// Create commit verifier (with ECDSA signer)
	ecdsaSigner := commit.NewECDSASignerWithKeystoreSigner(signer)
	commitVerifier, err := commit.NewCommitVerifier(coordinatorConfig, signingAddress, ecdsaSigner, lggr, verifierMonitoring)
	if err != nil {
		lggr.Errorw("Failed to create commit verifier", "error", err)
		return nil, fmt.Errorf("failed to create commit verifier: %w", err)
	}

	// Apply the operator's policy hook. With no [policy_hook] section this returns the commit
	// verifier unchanged.
	gatedVerifier, err := policy.WrapVerifier(lggr, cfg.VerifierID, commitVerifier, cfg.PolicyHook, verifierMonitoring, options.policyHookCredential)
	if err != nil {
		lggr.Errorw("Failed to apply policy hook", "error", err)
		return nil, fmt.Errorf("failed to apply policy hook: %w", err)
	}

	heartbeatSender, err := heartbeatclient.NewFanOutHeartbeatSender(
		heartbeatTargets,
		cfg.VerifierID,
		lggr,
		heartbeat.NewHeartbeatMonitoringAdapter(verifierMonitoring),
	)
	if err != nil {
		lggr.Errorw("Failed to create fan-out heartbeat sender", "error", err)
		return nil, fmt.Errorf("failed to create fan-out heartbeat sender: %w", err)
	}

	messageRulesPollInterval, err := cfg.MessageDisablementRulesPollIntervalDuration()
	if err != nil {
		return nil, fmt.Errorf("message disablement rules poll interval: %w", err)
	}
	messageRulesClientTimeout, err := cfg.MessageDisablementRulesClientTimeoutDuration()
	if err != nil {
		return nil, fmt.Errorf("message disablement rules client timeout: %w", err)
	}

	namedPollers := make([]messagerules.NamedPoller, 0, len(resolvedAggregators))
	for i, a := range resolvedAggregators {
		aggLggr := logger.With(lggr, "component", "MessageRulesPoller", "aggregator", a.Label())
		messageRulesClient, rErr := messagerules.NewGRPCClient(
			a.Address,
			aggLggr,
			resolvedSecrets[i],
			a.InsecureConnection,
			a.MaxRecvMsgSizeBytes,
		)
		if rErr != nil {
			lggr.Errorw("Failed to create message rules gRPC client", "error", rErr, "aggregator", a.Label())
			return nil, fmt.Errorf("failed to create message rules client for %q: %w", a.Label(), rErr)
		}

		poller, rErr := messagerules.NewPollerService(
			messageRulesClient,
			messageRulesPollInterval,
			messageRulesClientTimeout,
			aggLggr,
			verifierMonitoring.Metrics().With("aggregator", a.Label()),
		)
		if rErr != nil {
			lggr.Errorw("Failed to create message rules poller", "error", rErr, "aggregator", a.Label())
			return nil, fmt.Errorf("failed to create message rules poller for %q: %w", a.Label(), rErr)
		}
		namedPollers = append(namedPollers, messagerules.NewNamedPoller(a.Label(), poller))
	}

	messageRulesPoller, err := messagerules.NewMultiAggregatorRulesChecker(
		logger.With(lggr, "component", "MultiAggregatorMessageRulesChecker"),
		verifierMonitoring.Metrics(),
		namedPollers...,
	)
	if err != nil {
		lggr.Errorw("Failed to create multi-aggregator message rules checker", "error", err)
		return nil, fmt.Errorf("failed to create multi-aggregator message rules checker: %w", err)
	}

	messageTracker := monitoring.NewMessageLatencyTracker(
		lggr,
		coordinatorConfig.VerifierID,
		verifierMonitoring,
	)

	verifierCoordinator, err := verifier.NewCoordinator(
		lggr,
		gatedVerifier,
		sourceReaders,
		observedOffchainWriter,
		coordinatorConfig,
		messageTracker,
		verifierMonitoring,
		chainStatusManager,
		heartbeatSender,
		messageRulesPoller,
		ds,
	)
	if err != nil {
		lggr.Errorw("Failed to create verification coordinator", "error", err)
		return nil, fmt.Errorf("failed to create verification coordinator: %w", err)
	}

	return verifierCoordinator, nil
}
