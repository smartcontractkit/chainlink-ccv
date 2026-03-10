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

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// CreateAccessorFactoryFunc is a function that creates an accessor factory for a given chain family.
// The blockchain infos map is keyed by chain selector (as string); the callback may build a
// family-specific helper from it (e.g. blockchain.NewHelper for EVM).
type CreateAccessorFactoryFunc[T any] func(
	ctx context.Context,
	lggr logger.Logger,
	blockchainInfos map[string]*T,
	cfg commit.Config,
) (chainaccess.AccessorFactory, error)

// chainSelectorsFromMap returns chain selectors parsed from the keys of a map keyed by selector string.
func chainSelectorsFromMap[T any](m map[string]*T) []protocol.ChainSelector {
	out := make([]protocol.ChainSelector, 0, len(m))
	for sel := range m {
		u, err := strconv.ParseUint(sel, 10, 64)
		if err != nil {
			continue
		}
		out = append(out, protocol.ChainSelector(u))
	}
	return out
}

// factory is a ServiceFactory implementation that creates a committee verifier service.
// T is the chain config type for this family (e.g. blockchain.Info for EVM).
// NOTE: this factory supports only a single chain family at a time.
// This is by design, since deployed CCIP apps will be built with a single chain family, but potentially
// supporting many chains from that same family.
type factory[T any] struct {
	lggr             logger.Logger
	server           *http.Server
	coordinator      *verifier.Coordinator
	profiler         *pyroscope.Profiler
	aggregatorWriter *storageaccess.AggregatorWriter
	heartbeatClient  *heartbeatclient.HeartbeatClient
	chainStatusDB    sqlutil.DataSource

	createAccessorFactoryFunc CreateAccessorFactoryFunc[T]
	chainFamily               string
}

// NewServiceFactory creates a new ServiceFactory for the committee verifier service.
// T is the chain config type for this family (e.g. blockchain.Info for EVM).
func NewServiceFactory[T any](chainFamily string, createAccessorFactoryFunc CreateAccessorFactoryFunc[T]) bootstrap.ServiceFactory[commit.JobSpec] {
	return &factory[T]{
		createAccessorFactoryFunc: createAccessorFactoryFunc,
		chainFamily:               chainFamily,
	}
}

// Start implements [bootstrap.ServiceFactory].
func (f *factory[T]) Start(ctx context.Context, spec commit.JobSpec, deps bootstrap.ServiceDeps) error {
	lggr := logger.Sugared(logger.Named(deps.Logger, "CommitteeVerifier"))
	f.lggr = lggr

	lggr.Infow("Starting verifier service", "spec", spec)

	config, blockchainInfos, err := commit.LoadConfigWithBlockchainInfos[T](spec)
	if err != nil {
		lggr.Errorw("Failed to load configuration", "error", err)
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	lggr.Infow("Using blockchain information from config", "chainCount", len(blockchainInfos))

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

	chainSelectors := chainSelectorsFromMap(blockchainInfos)

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

	aggregatorWriter, err := storageaccess.NewAggregatorWriter(
		config.AggregatorAddress,
		lggr,
		hmacConfig,
		config.InsecureAggregatorConnection,
		config.AggregatorMaxSendMsgSizeBytes,
		config.AggregatorMaxRecvMsgSizeBytes,
	)
	if err != nil {
		lggr.Errorw("Failed to create aggregator writer", "error", err)
		return fmt.Errorf("failed to create aggregator writer: %w", err)
	}

	f.aggregatorWriter = aggregatorWriter

	accessorFactory, err := f.createAccessorFactoryFunc(ctx, lggr, blockchainInfos, *config)
	if err != nil {
		lggr.Errorw("Failed to create accessor factory", "error", err)
		return fmt.Errorf("failed to create accessor factory: %w", err)
	}

	sourceReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader)
	for _, selector := range chainSelectors {
		family, err := chainsel.GetSelectorFamily(uint64(selector))
		if err != nil {
			lggr.Errorw("Failed to get selector family", "error", err, "selector", selector)
			return fmt.Errorf("failed to get selector family: %w", err)
		}
		if family != f.chainFamily {
			lggr.Warnw("Skipping chain in provided config, doesn't match expected chain family",
				"selector", selector,
				"family", family,
				"expectedFamily", f.chainFamily,
			)
			continue
		}

		accessor, err := accessorFactory.GetAccessor(ctx, selector)
		if err != nil {
			lggr.Errorw("Failed to get accessor", "error", err, "selector", selector)
			return fmt.Errorf("failed to get accessor: %w", err)
		}
		reader := accessor.SourceReader()
		if reader == nil {
			lggr.Errorw("Failed to get source reader for chain", "selector", selector)
			return fmt.Errorf("failed to get source reader for chain: %w", err)
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

	signer, _, signerAddress, err := commit.NewSignerFromKeystore(ctx, deps.Keystore, keys.DefaultECDSASigningKeyName)
	if err != nil {
		lggr.Errorw("Failed to create signer", "error", err)
		return fmt.Errorf("failed to create signer: %w", err)
	}
	lggr.Infow("Using signer address", "address", signerAddress)

	verifierMonitoring := SetupMonitoring(lggr, config.Monitoring)

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

	observedStorageWriter := storageaccess.NewObservedStorageWriter(
		storageaccess.NewDefaultResilientStorageWriter(
			aggregatorWriter,
			lggr,
		),
		config.VerifierID,
		lggr,
		verifierMonitoring,
	)

	heartbeatClient, err := heartbeatclient.NewHeartbeatClient(
		config.AggregatorAddress,
		lggr,
		hmacConfig,
		config.InsecureAggregatorConnection,
	)
	if err != nil {
		lggr.Errorw("Failed to create heartbeat client", "error", err)
		return fmt.Errorf("failed to create heartbeat client: %w", err)
	}

	f.heartbeatClient = heartbeatClient

	observedHeartbeatClient := heartbeatclient.NewObservedHeartbeatClient(
		heartbeatClient,
		config.VerifierID,
		lggr,
		verifier.NewHeartbeatMonitoringAdapter(verifierMonitoring),
	)

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
		observedHeartbeatClient,
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

	// Setup HTTP server for health checks and status
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		lggr.Infow("CCV Verifier is running!\n")
		lggr.Infow("Verifier ID: %s\n", coordinatorConfig.VerifierID)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
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

	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := aggregatorWriter.GetStats()
		lggr.Infow("Storage Statistics:\n")
		for key, value := range stats {
			lggr.Infow("%s: %v\n", key, value)
		}
	})

	// Start HTTP server
	// TODO: listen port should be configurable.
	server := &http.Server{Addr: ":8100", ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
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
func (f *factory[T]) Stop(ctx context.Context) error {
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
	chainStatusManager := chainstatus.NewPostgresChainStatusManager(sqlDB, lggr, verifierID)
	// Wrap with monitoring decorator to track query durations
	monitoredManager := chainstatus.NewMonitoredChainStatusManager(chainStatusManager, monitoring.Metrics())
	return monitoredManager, sqlDB, nil
}
