package verifier

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/grafana/pyroscope-go"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
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
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// factory is a ServiceFactory implementation that creates a committee verifier service.
type factory struct {
	lggr             logger.Logger
	server           *http.Server
	coordinator      *verifier.Coordinator
	profiler         *pyroscope.Profiler
	aggregatorWriter *storageaccess.FanOutWriter
	heartbeatClient  heartbeatclient.HeartbeatSender
	chainStatusDB    sqlutil.DataSource
}

// NewCommitteeVerifierServiceFactory creates a new ServiceFactory for the committee verifier service.
func NewCommitteeVerifierServiceFactory() bootstrap.ServiceFactory {
	return &factory{}
}

// Start implements [bootstrap.ServiceFactory].
func (f *factory) Start(ctx context.Context, spec bootstrap.JobSpec, deps bootstrap.ServiceDeps) error {
	lggr := logger.Sugared(logger.Named(deps.Logger, "CommitteeVerifier"))
	f.lggr = lggr

	lggr.Infow("Starting committee verifier service", "spec", spec)

	protocol.InitChainSelectorCache()

	genericConfig, err := spec.GetGenericConfig()
	if err != nil {
		return fmt.Errorf("failed to get generic config: %w", err)
	}

	var config commit.Config
	if err := spec.GetAppConfig(&config); err != nil {
		return fmt.Errorf("failed to get app config: %w", err)
	}
	lggr.Infow("Using blockchain information from config", "info", genericConfig.ChainConfig)

	// TODO: this should be passed in via the config maybe?
	apiKey := os.Getenv("VERIFIER_AGGREGATOR_API_KEY")
	if apiKey == "" {
		lggr.Errorw("VERIFIER_AGGREGATOR_API_KEY environment variable is required")
		return fmt.Errorf("VERIFIER_AGGREGATOR_API_KEY environment variable is required")
	}
	if err := hmac.ValidateAPIKey(apiKey); err != nil {
		lggr.Errorw("Invalid VERIFIER_AGGREGATOR_API_KEY", "error", err)
		return fmt.Errorf("invalid VERIFIER_AGGREGATOR_API_KEY: %w", err)
	}
	lggr.Infow("Loaded VERIFIER_AGGREGATOR_API_KEY from environment")

	// TODO: this should be passed in via the config maybe?
	secretKey := os.Getenv("VERIFIER_AGGREGATOR_SECRET_KEY")
	if secretKey == "" {
		lggr.Errorw("VERIFIER_AGGREGATOR_SECRET_KEY environment variable is required")
		return fmt.Errorf("VERIFIER_AGGREGATOR_SECRET_KEY environment variable is required")
	}
	if err := hmac.ValidateSecret(secretKey); err != nil {
		lggr.Errorw("Invalid VERIFIER_AGGREGATOR_SECRET_KEY", "error", err)
		return fmt.Errorf("invalid VERIFIER_AGGREGATOR_SECRET_KEY: %w", err)
	}
	lggr.Infow("Loaded VERIFIER_AGGREGATOR_SECRET_KEY from environment")

	profiler, err := StartPyroscope(lggr, config.PyroscopeURL, "verifier")
	if err != nil {
		lggr.Errorw("Failed to start pyroscope", "error", err)
		return fmt.Errorf("failed to start pyroscope: %w", err)
	}
	f.profiler = profiler

	chainSelectors := genericConfig.ChainConfig.GetAllChainSelectors()

	// Create verifier addresses before source readers setup
	verifierAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.CommitteeVerifierAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			lggr.Errorw("Failed to create verifier address", "error", err)
			return fmt.Errorf("failed to create verifier address: %w", err)
		}
		verifierAddresses[selector] = addr
	}
	defaultExecutorAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.DefaultExecutorOnRampAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			lggr.Errorw("Failed to create default executor address", "error", err)
			return fmt.Errorf("failed to create default executor address: %w", err)
		}
		defaultExecutorAddresses[selector] = addr
	}

	hmacConfig := &hmac.ClientConfig{
		APIKey: apiKey,
		Secret: secretKey,
	}

	// Resolve the aggregators this job writes to, heartbeats, and reads disablement rules from.
	// Backwards compatible: a legacy single aggregator_address resolves to a one-element list.
	resolvedAggregators, err := config.ResolvedAggregators()
	if err != nil {
		lggr.Errorw("Invalid aggregator configuration", "error", err)
		return fmt.Errorf("invalid aggregator configuration: %w", err)
	}
	lggr.Infow("Resolved aggregators", "count", len(resolvedAggregators))

	writeTargets := make([]storageaccess.AggregatorTarget, len(resolvedAggregators))
	heartbeatTargets := make([]heartbeatclient.AggregatorTarget, len(resolvedAggregators))
	for i, a := range resolvedAggregators {
		writeTargets[i] = storageaccess.AggregatorTarget{
			Label:               a.Name,
			Address:             a.Address,
			Insecure:            a.InsecureConnection,
			MaxSendMsgSizeBytes: a.MaxSendMsgSizeBytes,
			MaxRecvMsgSizeBytes: a.MaxRecvMsgSizeBytes,
		}
		heartbeatTargets[i] = heartbeatclient.AggregatorTarget{
			Label:    a.Name,
			Address:  a.Address,
			Insecure: a.InsecureConnection,
		}
	}

	sourceReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader)
	for _, selector := range chainSelectors {
		accessor, err := deps.Registry.GetAccessor(ctx, selector)
		if err != nil {
			lggr.Errorw("Failed to get accessor", "error", err, "selector", selector)
			return fmt.Errorf("failed to get accessor: %w", err)
		}
		reader, err := accessor.SourceReader()
		if err != nil {
			lggr.Errorw("Failed to get source reader for chain", "selector", selector, "error", err)
			return fmt.Errorf("failed to get source reader for chain %d: %w", selector, err)
		}
		sourceReaders[selector] = reader
	}

	// Create coordinator configuration
	sourceConfigs := make(map[protocol.ChainSelector]verifier.SourceConfig)
	rmnRemoteAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.RMNRemoteAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			lggr.Errorw("Failed to create RMN Remote address", "error", err, "selector", selector)
			return fmt.Errorf("failed to create RMN Remote address: %w", err)
		}
		rmnRemoteAddresses[selector] = addr
	}

	for _, selector := range chainSelectors {
		strSelector := strconv.FormatUint(uint64(selector), 10)

		sourceConfigs[selector] = verifier.SourceConfig{
			VerifierAddress:        verifierAddresses[strSelector],
			DefaultExecutorAddress: defaultExecutorAddresses[strSelector],
			PollInterval:           1 * time.Second,
			ChainSelector:          selector,
			RMNRemoteAddress:       rmnRemoteAddresses[strSelector],
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
		CursePollInterval:   2 * time.Second,  // Poll RMN Remotes for curse status every 2s
		HeartbeatInterval:   10 * time.Second, // Send heartbeat to aggregator every 10s
	}

	signer, _, signerAddress, err := commit.NewSignerFromKeystore(ctx, deps.Keystore, commit.DefaultECDSASigningKeyName)
	if err != nil {
		lggr.Errorw("Failed to create signer", "error", err)
		return fmt.Errorf("failed to create signer: %w", err)
	}
	lggr.Infow("Using signer address", "address", signerAddress)

	verifierMonitoring := SetupMonitoring(lggr, config.Monitoring, "committee_verifier")

	// Create chain status manager (PostgreSQL storage) with monitoring decorator
	chainStatusManager, chainStatusDB, err := createChainStatusManager(lggr, config.VerifierID, verifierMonitoring)
	if err != nil {
		lggr.Errorw("Failed to create chain status manager", "error", err)
		return fmt.Errorf("failed to create chain status manager: %w", err)
	}
	f.chainStatusDB = chainStatusDB

	// Create commit verifier
	commitVerifier, err := commit.NewCommitVerifier(coordinatorConfig, signerAddress, signer, lggr, verifierMonitoring)
	if err != nil {
		lggr.Errorw("Failed to create commit verifier", "error", err)
		return fmt.Errorf("failed to create commit verifier: %w", err)
	}

	// Write fan-out: one resilient + observed stack per aggregator, all writes fan out to every
	// aggregator (all-must-ack). The top-level observed writer records the aggregate outcome.
	fanOutWriter, err := storageaccess.NewFanOutAggregatorWriter(
		writeTargets,
		config.VerifierID,
		lggr,
		hmacConfig,
		verifierMonitoring,
	)
	if err != nil {
		lggr.Errorw("Failed to create fan-out aggregator writer", "error", err)
		return fmt.Errorf("failed to create fan-out aggregator writer: %w", err)
	}
	f.aggregatorWriter = fanOutWriter

	observedStorageWriter := storageaccess.NewObservedStorageWriter(
		fanOutWriter,
		config.VerifierID,
		lggr,
		verifierMonitoring,
	)

	// Heartbeat fan-out: send liveness to every aggregator; per-aggregator metrics are recorded
	// inside each wrapped observed client. A failure to one aggregator is non-blocking.
	heartbeatSender, err := heartbeatclient.NewFanOutHeartbeatSender(
		heartbeatTargets,
		config.VerifierID,
		lggr,
		hmacConfig,
		heartbeat.NewHeartbeatMonitoringAdapter(verifierMonitoring),
	)
	if err != nil {
		lggr.Errorw("Failed to create fan-out heartbeat sender", "error", err)
		return fmt.Errorf("failed to create fan-out heartbeat sender: %w", err)
	}
	f.heartbeatClient = heartbeatSender

	messageRulesPollInterval, err := config.MessageDisablementRulesPollIntervalDuration()
	if err != nil {
		return fmt.Errorf("message disablement rules poll interval: %w", err)
	}
	messageRulesClientTimeout, err := config.MessageDisablementRulesClientTimeoutDuration()
	if err != nil {
		return fmt.Errorf("message disablement rules client timeout: %w", err)
	}

	// Message-rules union: one poller per aggregator; a message is disabled if any aggregator
	// disables it (fail-safe union), and verification is blocked while any source is unknown.
	namedPollers := make([]messagerules.NamedPoller, 0, len(resolvedAggregators))
	for _, a := range resolvedAggregators {
		aggLggr := logger.With(lggr, "component", "MessageRulesPoller", "aggregator", a.Name)
		messageRulesClient, rErr := messagerules.NewGRPCClient(
			a.Address,
			aggLggr,
			hmacConfig,
			a.InsecureConnection,
			a.MaxRecvMsgSizeBytes,
		)
		if rErr != nil {
			lggr.Errorw("Failed to create message rules gRPC client", "error", rErr, "aggregator", a.Name)
			return fmt.Errorf("failed to create message rules client for %q: %w", a.Name, rErr)
		}

		poller, rErr := messagerules.NewPollerService(
			messageRulesClient,
			messageRulesPollInterval,
			messageRulesClientTimeout,
			aggLggr,
			verifierMonitoring.Metrics().With("aggregator", a.Name),
		)
		if rErr != nil {
			lggr.Errorw("Failed to create message rules poller", "error", rErr, "aggregator", a.Name)
			return fmt.Errorf("failed to create message rules poller for %q: %w", a.Name, rErr)
		}
		namedPollers = append(namedPollers, messagerules.NewNamedPoller(a.Name, poller))
	}

	messageRulesPoller, err := messagerules.NewUnionPollerService(
		logger.With(lggr, "component", "UnionMessageRulesPoller"),
		namedPollers...,
	)
	if err != nil {
		lggr.Errorw("Failed to create union message rules poller", "error", err)
		return fmt.Errorf("failed to create union message rules poller: %w", err)
	}

	messageTracker := monitoring.NewMessageLatencyTracker(
		lggr,
		config.VerifierID,
		verifierMonitoring,
	)

	coordinator, err := verifier.NewCoordinator(
		lggr,
		commitVerifier,
		sourceReaders,
		observedStorageWriter,
		coordinatorConfig,
		messageTracker,
		verifierMonitoring,
		chainStatusManager,
		heartbeatSender,
		messageRulesPoller,
		chainStatusDB,
	)
	if err != nil {
		lggr.Errorw("Failed to create verification coordinator", "error", err)
		return fmt.Errorf("failed to create verification coordinator: %w", err)
	}

	// Start the verification coordinator
	lggr.Infow("Starting Verification Coordinator",
		"verifierID", coordinatorConfig.VerifierID,
		"verifierAddress", verifierAddresses,
	)

	if err := coordinator.Start(ctx); err != nil {
		lggr.Errorw("Failed to start verification coordinator", "error", err)
		return fmt.Errorf("failed to start verification coordinator: %w", err)
	}

	verifierMonitoring.RecordServiceStarted(ctx)

	// Dedicated mux per Start(): JD job replacement calls Start again after Stop. Using
	// http.HandleFunc would register on DefaultServeMux, which is never cleared — second
	// Start panics with conflicting pattern "/".
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		lggr.Infow("CCV Verifier is running!\n")
		lggr.Infow("Verifier ID: %s\n", coordinatorConfig.VerifierID)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		for serviceName, err := range coordinator.HealthReport() {
			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				lggr.Infow("Unhealthy service: %s, error: %s\n", serviceName, err.Error())
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		lggr.Infow("Healthy\n")
	})

	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := fanOutWriter.GetStats()
		lggr.Infow("Storage Statistics:\n")
		for key, value := range stats {
			lggr.Infow("%s: %v\n", key, value)
		}
	})

	// Start HTTP server
	// TODO: listen port should be configurable.
	server := &http.Server{
		Addr:         ":8100",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		lggr.Infow("🌐 HTTP server starting", "port", "8100")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			lggr.Errorw("HTTP server error", "error", err)
		}
	}()

	f.server = server
	f.coordinator = coordinator

	lggr.Infow("🎯 Verifier service fully started and ready!")

	return nil
}

// Stop implements [bootstrap.ServiceFactory].
func (f *factory) Stop(ctx context.Context) error {
	var allErrors error
	// Stop HTTP server
	if f.server != nil {
		if err := f.server.Shutdown(ctx); err != nil {
			f.lggr.Errorw("HTTP server shutdown error", "error", err)
			allErrors = errors.Join(allErrors, err)
		}
	}

	// Stop verification coordinator
	if f.coordinator != nil {
		if err := f.coordinator.Close(); err != nil {
			f.lggr.Errorw("Coordinator stop error", "error", err)
			allErrors = errors.Join(allErrors, err)
		}
	}

	// Stop pyroscope
	if f.profiler != nil {
		if err := f.profiler.Stop(); err != nil {
			f.lggr.Errorw("Pyroscope stop error", "error", err)
			allErrors = errors.Join(allErrors, err)
		}
	}

	// Stop aggregator writer
	// TODO: is this stopped by the coordinator?
	if f.aggregatorWriter != nil {
		if err := f.aggregatorWriter.Close(); err != nil {
			f.lggr.Errorw("Aggregator writer stop error", "error", err)
			allErrors = errors.Join(allErrors, err)
		}
	}

	// Stop heartbeat client
	if f.heartbeatClient != nil {
		if err := f.heartbeatClient.Close(); err != nil {
			f.lggr.Errorw("Heartbeat client stop error", "error", err)
			allErrors = errors.Join(allErrors, err)
		}
	}

	f.server = nil
	f.coordinator = nil
	f.profiler = nil
	f.aggregatorWriter = nil
	f.heartbeatClient = nil
	f.lggr = nil
	f.chainStatusDB = nil

	return allErrors
}

func createChainStatusManager(lggr logger.Logger, verifierID string, monitoring verifier.Monitoring) (protocol.ChainStatusManager, sqlutil.DataSource, error) {
	sqlDB, err := ConnectToPostgresDB(lggr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to Postgres DB: %w", err)
	}
	chainStatusStore := chainstatus.NewPostgresChainStatusStore(sqlDB, lggr)
	chainStatusManager := chainstatus.NewPostgresChainStatusManager(chainStatusStore, verifierID)
	// Wrap with monitoring decorator to track query durations
	monitoredManager := chainstatus.NewMonitoredChainStatusManager(chainStatusManager, monitoring.Metrics())
	return monitoredManager, sqlDB, nil
}
