package verifier

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/cursechecker"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/messagerules"
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
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// committeeVerifierDeps carries the inputs startCommitteeVerifier needs from its caller.
// db is optional: nil connects from secrets and the stack owns the connection (legacy committee
// binary); non-nil is a shared connection owned by the caller (unified verifier).
type committeeVerifierDeps struct {
	keystore           keystore.Keystore
	sourceReaders      map[protocol.ChainSelector]chainaccess.SourceReader
	db                 sqlutil.DataSource
	secrets            *vsecrets.VerifierSecrets
	verifierMonitoring verifier.Monitoring
}

// committeeStack is a running committee verifier: the coordinator plus the services the owning
// factory must release on Stop. chainStatusDB is nil when the caller supplied deps.db (shared
// ownership); resolvedAggregators feeds the admin console's aggregator freshness checks.
type committeeStack struct {
	coordinator         *verifier.Coordinator
	fanOutWriter        *storageaccess.FanOutWriter
	heartbeatClient     heartbeatclient.HeartbeatSender
	chainStatusDB       sqlutil.DataSource
	resolvedAggregators []commit.AggregatorConnection
}

// close releases the stack's fan-out writer and heartbeat client. The chain status DB is not
// closed here: when the caller supplied a shared connection it owns it, matching the committee
// factory, which never closes its DB.
func (s *committeeStack) close() error {
	var errs error
	if s.fanOutWriter != nil {
		errs = errors.Join(errs, s.fanOutWriter.Close())
	}
	if s.heartbeatClient != nil {
		errs = errors.Join(errs, s.heartbeatClient.Close())
	}
	return errs
}

// startCommitteeVerifier builds and starts the full committee verifier stack for one job config:
// signer, chain status manager, policy-gated commit verifier, fan-out aggregator writer,
// heartbeat sender, message-rules pollers, and the coordinator. It is shared by the committee
// factory and the unified factory; the caller owns source reader construction and HTTP serving.
func startCommitteeVerifier(ctx context.Context, lggr logger.Logger, config commit.Config, deps committeeVerifierDeps) (*committeeStack, error) {
	// Create verifier addresses before source readers setup
	verifierAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.CommitteeVerifierAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			lggr.Errorw("Failed to create verifier address", "error", err)
			return nil, fmt.Errorf("failed to create verifier address: %w", err)
		}
		verifierAddresses[selector] = addr
	}
	defaultExecutorAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.DefaultExecutorOnRampAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			lggr.Errorw("Failed to create default executor address", "error", err)
			return nil, fmt.Errorf("failed to create default executor address: %w", err)
		}
		defaultExecutorAddresses[selector] = addr
	}

	// Resolve the aggregators this job writes to, heartbeats, and reads disablement rules from.
	// Backwards compatible: a legacy single aggregator_address resolves to a one-element list.
	resolvedAggregators, err := config.ResolvedAggregators()
	if err != nil {
		lggr.Errorw("Invalid aggregator configuration", "error", err)
		return nil, fmt.Errorf("invalid aggregator configuration: %w", err)
	}
	lggr.Infow("Resolved aggregators", "count", len(resolvedAggregators))

	// Each aggregator authenticates the verifier with its own HMAC credential, resolved from the
	// verifier secrets file (keyed by secret_name) with fallback to the per-aggregator environment
	// variables (VERIFIER_AGGREGATOR_<NAME>_API_KEY/SECRET_KEY).
	aggregatorSecrets := deps.secrets.AggregatorSecrets()
	aggregatorHMACs := make([]*hmac.ClientConfig, len(resolvedAggregators))
	for i, a := range resolvedAggregators {
		hmacConfig, hErr := a.ResolveHMACConfig(aggregatorSecrets)
		if hErr != nil {
			lggr.Errorw("Failed to resolve aggregator credentials", "error", hErr, "aggregator", a.Label())
			return nil, fmt.Errorf("failed to resolve aggregator credentials: %w", hErr)
		}
		aggregatorHMACs[i] = hmacConfig
	}

	writeTargets := make([]storageaccess.AggregatorTarget, len(resolvedAggregators))
	heartbeatTargets := make([]heartbeatclient.AggregatorTarget, len(resolvedAggregators))
	for i, a := range resolvedAggregators {
		writeTargets[i] = storageaccess.AggregatorTarget{
			Label:               a.Label(),
			Address:             a.Address,
			Insecure:            a.InsecureConnection,
			HMACConfig:          aggregatorHMACs[i],
			MaxSendMsgSizeBytes: a.MaxSendMsgSizeBytes,
			MaxRecvMsgSizeBytes: a.MaxRecvMsgSizeBytes,
		}
		heartbeatTargets[i] = heartbeatclient.AggregatorTarget{
			Label:      a.Label(),
			Address:    a.Address,
			Insecure:   a.InsecureConnection,
			HMACConfig: aggregatorHMACs[i],
		}
	}

	if len(deps.sourceReaders) == 0 {
		return nil, fmt.Errorf("no source readers configured: ensure at least one chain has a working source reader")
	}

	// Create coordinator configuration. Only chains that produced a source reader are configured;
	// the coordinator uses sourceReaders as authoritative, so configs must be aligned with it.
	sourceConfigs := make(map[protocol.ChainSelector]verifier.SourceConfig)
	for selector := range deps.sourceReaders {
		strSelector := strconv.FormatUint(uint64(selector), 10)

		sourceConfigs[selector] = verifier.SourceConfig{
			VerifierAddress:        verifierAddresses[strSelector],
			DefaultExecutorAddress: defaultExecutorAddresses[strSelector],
			PollInterval:           verifier.SourceReaderPollInterval,
			ChainSelector:          selector,
			DisableFinalityChecker: slices.Contains(config.DisableFinalityCheckers, strSelector),
		}

		lggr.Infow("Configured source chain", "chainSelector", selector)
	}

	coordinatorConfig := verifier.CoordinatorConfig{
		VerifierID:          config.VerifierID,
		SourceConfigs:       sourceConfigs,
		StorageBatchSize:    50,
		StorageBatchTimeout: 100 * time.Millisecond,
		StorageRetryDelay:   2 * time.Second,
		CursePollInterval:   cursechecker.DEFAULT_POLL_INTERVAL, // Poll RMN Remotes for curse status
		HeartbeatInterval:   10 * time.Second,                   // Send heartbeat to aggregator every 10s
		// How often buffered chain statuses are written. A disabled status is written immediately.
		ChainStatusFlushInterval:  chainstatus.DefaultFlushInterval,
		ChainStatusFlushThreshold: chainstatus.DefaultFlushThreshold,
	}

	signer, _, signerAddress, err := commit.NewSignerFromKeystore(ctx, deps.keystore, commit.DefaultECDSASigningKeyName)
	if err != nil {
		lggr.Errorw("Failed to create signer", "error", err)
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}
	if err := commit.ValidateSignerAddress(config.SignerAddress, signerAddress); err != nil {
		lggr.Errorw("Verifier signing key does not match job configuration", "error", err)
		return nil, err
	}
	lggr.Infow("Using signer address", "address", signerAddress)

	// Create the chain status manager (PostgreSQL storage) with monitoring decorator. A nil
	// deps.db connects from secrets here (legacy binary owns its connection); a non-nil deps.db
	// is the unified factory's shared connection.
	var chainStatusManager protocol.ChainStatusManager
	var chainStatusDB sqlutil.DataSource
	if deps.db != nil {
		chainStatusStore := chainstatus.NewPostgresChainStatusStore(deps.db, lggr)
		chainStatusManager = chainstatus.NewMonitoredChainStatusManager(
			chainstatus.NewPostgresChainStatusManager(chainStatusStore, config.VerifierID), deps.verifierMonitoring.Metrics())
	} else {
		//nolint:noeagerio // the service's own DB is a hard dependency: connect + migrate fail fast (bounded by the startup ctx) and JD/local restarts retry
		manager, db, err := createChainStatusManager(ctx, lggr, config.VerifierID, deps.verifierMonitoring, deps.secrets)
		if err != nil {
			lggr.Errorw("Failed to create chain status manager", "error", err)
			return nil, fmt.Errorf("failed to create chain status manager: %w", err)
		}
		chainStatusManager, chainStatusDB = manager, db
	}

	// Create commit verifier
	commitVerifier, err := commit.NewCommitVerifier(coordinatorConfig, signerAddress, signer, lggr, deps.verifierMonitoring)
	if err != nil {
		lggr.Errorw("Failed to create commit verifier", "error", err)
		return nil, fmt.Errorf("failed to create commit verifier: %w", err)
	}

	// Resolve the credential the policy endpoint identifies this verifier by: the secrets file
	// when it carries a [policy_hook] table, otherwise the environment. Nil is the supported
	// unauthenticated case, so only a malformed or half-supplied pair fails here.
	policyCredential, err := policy.ResolveCredential(deps.secrets.PolicyHookSecret())
	if err != nil {
		lggr.Errorw("Failed to resolve policy hook credential", "error", err)
		return nil, fmt.Errorf("failed to resolve policy hook credential: %w", err)
	}

	// Apply the operator's policy hook. With no [policy_hook] section the decorator returns the
	// commit verifier unchanged.
	gatedVerifier, err := vtypes.Chain(commitVerifier, policy.Gate(lggr, config.VerifierID, config.PolicyHook, deps.verifierMonitoring, policyCredential))
	if err != nil {
		lggr.Errorw("Failed to apply policy hook", "error", err)
		return nil, fmt.Errorf("failed to apply policy hook: %w", err)
	}

	// Write fan-out: one resilient + observed stack per aggregator, all writes fan out to every
	// aggregator (all-must-ack). The top-level observed writer records the aggregate outcome.
	fanOutWriter, err := storageaccess.NewFanOutAggregatorWriter(
		writeTargets,
		config.VerifierID,
		lggr,
		deps.verifierMonitoring,
	)
	if err != nil {
		lggr.Errorw("Failed to create fan-out aggregator writer", "error", err)
		return nil, fmt.Errorf("failed to create fan-out aggregator writer: %w", err)
	}

	observedOffchainWriter := storageaccess.NewObservedOffchainWriter(
		fanOutWriter,
		config.VerifierID,
		lggr,
		deps.verifierMonitoring,
	)

	// Heartbeat fan-out: send liveness to every aggregator; per-aggregator metrics are recorded
	// inside each wrapped observed client. A failure to one aggregator is non-blocking.
	heartbeatSender, err := heartbeatclient.NewFanOutHeartbeatSender(
		heartbeatTargets,
		config.VerifierID,
		lggr,
		heartbeat.NewHeartbeatMonitoringAdapter(deps.verifierMonitoring),
	)
	if err != nil {
		lggr.Errorw("Failed to create fan-out heartbeat sender", "error", err)
		return nil, fmt.Errorf("failed to create fan-out heartbeat sender: %w", err)
	}

	messageRulesPollInterval, err := config.MessageDisablementRulesPollIntervalDuration()
	if err != nil {
		return nil, fmt.Errorf("message disablement rules poll interval: %w", err)
	}
	messageRulesClientTimeout, err := config.MessageDisablementRulesClientTimeoutDuration()
	if err != nil {
		return nil, fmt.Errorf("message disablement rules client timeout: %w", err)
	}

	// Message-rules union: one poller per aggregator; a message is disabled if any aggregator
	// disables it (fail-safe union), and verification is blocked while any source is unknown.
	namedPollers := make([]messagerules.NamedPoller, 0, len(resolvedAggregators))
	for i, a := range resolvedAggregators {
		aggLggr := logger.With(lggr, "component", "MessageRulesPoller", "aggregator", a.Label())
		messageRulesClient, rErr := messagerules.NewGRPCClient(
			a.Address,
			aggLggr,
			aggregatorHMACs[i],
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
			deps.verifierMonitoring.Metrics().With("aggregator", a.Label()),
		)
		if rErr != nil {
			lggr.Errorw("Failed to create message rules poller", "error", rErr, "aggregator", a.Label())
			return nil, fmt.Errorf("failed to create message rules poller for %q: %w", a.Label(), rErr)
		}
		namedPollers = append(namedPollers, messagerules.NewNamedPoller(a.Label(), poller))
	}

	messageRulesPoller, err := messagerules.NewMultiAggregatorRulesChecker(
		logger.With(lggr, "component", "MultiAggregatorMessageRulesChecker"),
		deps.verifierMonitoring.Metrics(),
		namedPollers...,
	)
	if err != nil {
		lggr.Errorw("Failed to create multi-aggregator message rules checker", "error", err)
		return nil, fmt.Errorf("failed to create multi-aggregator message rules checker: %w", err)
	}

	messageTracker := monitoring.NewMessageLatencyTracker(
		lggr,
		config.VerifierID,
		deps.verifierMonitoring,
	)

	coordinator, err := verifier.NewCoordinator(
		lggr,
		gatedVerifier,
		deps.sourceReaders,
		observedOffchainWriter,
		coordinatorConfig,
		messageTracker,
		deps.verifierMonitoring,
		chainStatusManager,
		heartbeatSender,
		messageRulesPoller,
		chainStatusDBOrShared(deps, chainStatusDB),
		verifier.WithSourceRecovery(),
	)
	if err != nil {
		lggr.Errorw("Failed to create verification coordinator", "error", err)
		return nil, fmt.Errorf("failed to create verification coordinator: %w", err)
	}

	// Start the verification coordinator
	lggr.Infow("Starting Verification Coordinator",
		"verifierID", coordinatorConfig.VerifierID,
		"verifierAddress", verifierAddresses,
	)

	if err := coordinator.Start(ctx); err != nil {
		lggr.Errorw("Failed to start verification coordinator", "error", err)
		return nil, fmt.Errorf("failed to start verification coordinator: %w", err)
	}

	return &committeeStack{
		coordinator:         coordinator,
		fanOutWriter:        fanOutWriter,
		heartbeatClient:     heartbeatSender,
		chainStatusDB:       chainStatusDB,
		resolvedAggregators: resolvedAggregators,
	}, nil
}

// chainStatusDBOrShared returns the DB handle the coordinator should use: the caller's shared
// connection when supplied, otherwise the connection this stack opened itself.
func chainStatusDBOrShared(deps committeeVerifierDeps, own sqlutil.DataSource) sqlutil.DataSource {
	if deps.db != nil {
		return deps.db
	}
	return own
}

func createChainStatusManager(ctx context.Context, lggr logger.Logger, verifierID string, monitoring verifier.Monitoring, secrets *vsecrets.VerifierSecrets) (protocol.ChainStatusManager, sqlutil.DataSource, error) {
	sqlDB, err := ConnectToPostgresDB(ctx, lggr, secrets)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to Postgres DB: %w", err)
	}
	chainStatusStore := chainstatus.NewPostgresChainStatusStore(sqlDB, lggr)
	chainStatusManager := chainstatus.NewPostgresChainStatusManager(chainStatusStore, verifierID)
	// Wrap with monitoring decorator to track query durations. The Coordinator
	// adds the batcher on top of this, so the metrics measure real database calls.
	monitoredManager := chainstatus.NewMonitoredChainStatusManager(chainStatusManager, monitoring.Metrics())
	return monitoredManager, sqlDB, nil
}
