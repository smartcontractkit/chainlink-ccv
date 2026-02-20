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

	"github.com/BurntSushi/toml"
	"github.com/grafana/pyroscope-go"
	"github.com/jmoiron/sqlx"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
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
type CreateAccessorFactoryFunc func(
	ctx context.Context,
	lggr logger.Logger,
	helper *blockchain.Helper,
	cfg commit.Config,
) (chainaccess.AccessorFactory, error)

// factory is a ServiceFactory implementation that creates a committee verifier service.
// NOTE: this factory supports only a single chain family at a time.
// This is by design, since deployed CCIP apps will be built with a single chain family, but potentially
// supporting many chains from that same family.
type factory struct {
	lggr              logger.Logger
	server            *http.Server
	coordinator       *verifier.Coordinator
	profiler          *pyroscope.Profiler
	aggregatorWriter  *storageaccess.AggregatorWriter
	heartbeatClient   *heartbeatclient.HeartbeatClient
	chainStatusDB     *sqlx.DB
	coordinatorCancel context.CancelFunc

	createAccessorFactoryFunc CreateAccessorFactoryFunc
}

// NewServiceFactory creates a new ServiceFactory for the committee verifier service.
func NewServiceFactory(createAccessorFactoryFunc CreateAccessorFactoryFunc) bootstrap.ServiceFactory {
	return &factory{
		createAccessorFactoryFunc: createAccessorFactoryFunc,
	}
}

// Start implements [bootstrap.ServiceFactory].
func (f *factory) Start(ctx context.Context, spec string, deps bootstrap.ServiceDeps) error {
	lggr := logger.Sugared(logger.Named(deps.Logger, "CommitteeVerifier"))
	f.lggr = lggr

	lggr.Infow("Starting verifier service", "spec", spec)

	config, blockchainInfos, err := loadConfiguration(spec)
	if err != nil {
		lggr.Errorw("Failed to load configuration", "error", err)
		return fmt.Errorf("failed to load configuration: %w", err)
	}

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

	blockchainHelper := LoadBlockchainInfo(ctx, lggr, blockchainInfos)

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

	aggregatorWriter, err := storageaccess.NewAggregatorWriter(config.AggregatorAddress, lggr, hmacConfig, config.InsecureAggregatorConnection)
	if err != nil {
		lggr.Errorw("Failed to create aggregator writer", "error", err)
		return fmt.Errorf("failed to create aggregator writer: %w", err)
	}

	f.aggregatorWriter = aggregatorWriter

	accessorFactory, err := f.createAccessorFactoryFunc(ctx, lggr, blockchainHelper, *config)
	if err != nil {
		lggr.Errorw("Failed to create accessor factory", "error", err)
		return fmt.Errorf("failed to create accessor factory: %w", err)
	}

	sourceReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader)
	for _, selector := range blockchainHelper.GetAllChainSelectors() {
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

	for _, selector := range blockchainHelper.GetAllChainSelectors() {
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

	signer, _, signerAddress, err := commit.NewSignerFromKeystore(ctx, deps.Keystore, bootstrap.DefaultECDSASigningKeyName)
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

	// Create verification coordinator
	// TODO: we shouldn't have to create a long-lived context here, the context below
	// is being used in downstream components and ends up getting canceled due to only
	// being for startup rather than long-lived.
	coordinatorCtx, coordinatorCancel := context.WithCancel(context.Background())
	coordinator, err := verifier.NewCoordinator(
		coordinatorCtx,
		lggr,
		commitVerifier,
		sourceReaders,
		observedStorageWriter,
		coordinatorConfig,
		messageTracker,
		verifierMonitoring,
		chainStatusManager,
		observedHeartbeatClient,
	)
	if err != nil {
		coordinatorCancel()
		lggr.Errorw("Failed to create verification coordinator", "error", err)
		return fmt.Errorf("failed to create verification coordinator: %w", err)
	}
	f.coordinatorCancel = coordinatorCancel

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

	// Cancel the coordinator context
	if f.coordinatorCancel != nil {
		f.coordinatorCancel()
	}

	// Close the db
	if f.chainStatusDB != nil {
		if err := f.chainStatusDB.Close(); err != nil {
			f.lggr.Errorw("Chain status DB close error", "error", err)
			allErrors = errors.Join(allErrors, err)
		}
	}

	// Reset the state
	f.server = nil
	f.coordinator = nil
	f.coordinatorCancel = nil
	f.profiler = nil
	f.aggregatorWriter = nil
	f.heartbeatClient = nil
	f.lggr = nil
	f.chainStatusDB = nil

	return allErrors
}

func loadConfiguration(spec string) (*commit.Config, map[string]*blockchain.Info, error) {
	// Decode the outer job spec first.
	var outerSpec commit.JobSpec
	if _, err := toml.Decode(spec, &outerSpec); err != nil {
		return nil, nil, fmt.Errorf("failed to parse job spec: %w", err)
	}

	// Decode the inner config next.
	var config commit.ConfigWithBlockchainInfos
	if md, err := toml.Decode(outerSpec.CommitteeVerifierConfig, &config); err != nil {
		return nil, nil, fmt.Errorf("failed to decode committee verifier config: %w", err)
	} else if len(md.Undecoded()) > 0 {
		return nil, nil, fmt.Errorf("unknown fields in committee verifier config: %v", md.Undecoded())
	}

	return &config.Config, config.BlockchainInfos, nil
}

func createChainStatusManager(lggr logger.Logger, verifierID string, monitoring verifier.Monitoring) (protocol.ChainStatusManager, *sqlx.DB, error) {
	sqlDB, err := ConnectToPostgresDB(lggr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to Postgres DB: %w", err)
	}
	chainStatusManager := chainstatus.NewPostgresChainStatusManager(sqlDB, lggr, verifierID)
	// Wrap with monitoring decorator to track query durations
	monitoredManager := chainstatus.NewMonitoredChainStatusManager(chainStatusManager, monitoring.Metrics())
	return monitoredManager, sqlDB, nil
}
