package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"go.uber.org/zap/zapcore"

	cmd "github.com/smartcontractkit/chainlink-ccv/cmd/verifier"
	"github.com/smartcontractkit/chainlink-ccv/common/jdclient"
	"github.com/smartcontractkit/chainlink-ccv/common/jdlifecycle"
	"github.com/smartcontractkit/chainlink-ccv/common/jobstore"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/infoserver"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/keys"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	// Keystore configuration env vars.
	KeystorePasswordEnvVar    = "KEYSTORE_PASSWORD"
	KeystoreStorageNameEnvVar = "KEYSTORE_STORAGE_NAME"

	// Job Distributor configuration env vars.
	JDWSRPCURLEnvVar     = "JD_WSRPC_URL"
	JDCSAPublicKeyEnvVar = "JD_CSA_PUBLIC_KEY"

	// HTTP server configuration.
	InfoServerAddrEnvVar  = "INFO_SERVER_ADDR"
	defaultInfoServerAddr = ":8080"
)

// JobSpec is the structure of the committee verifier job spec.
type JobSpec struct {
	ExternalJobID           string `toml:"externalJobID"`
	SchemaVersion           int    `toml:"schemaVersion"`
	Type                    string `toml:"type"`
	CommitteeVerifierConfig string `toml:"committeeVerifierConfig"`
}

func main() {
	// Debug level currently spams a lot of logs from the RPC callers.
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.InfoLevel))
	if err != nil {
		panic(fmt.Sprintf("Failed to create logger: %v", err))
	}
	lggr = logger.Named(lggr, "verifier")

	// Use SugaredLogger for better API
	lggr = logger.Sugared(lggr)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	if err := run(ctx, lggr, sigCh); err != nil {
		lggr.Fatalw("Failed to run verifier", "error", err)
	}
}

// run executes the verifier lifecycle using the JobLifecycleManager:
// 1. INIT: Generates/loads keys from keystore, starts info server
// 2. READY: Creates JD client and lifecycle manager
// 3. ACTIVE: Lifecycle manager handles job lifecycle (proposals, deletions, etc.)
func run(ctx context.Context, lggr logger.Logger, sigCh chan os.Signal) error {
	lggr.Infow("Starting verifier")

	// ========== PHASE 1: INIT ==========
	lggr.Infow("Phase 1: Initializing keys...")

	keystorePassword := os.Getenv(KeystorePasswordEnvVar)
	if keystorePassword == "" {
		return fmt.Errorf("KEYSTORE_PASSWORD environment variable is required")
	}

	// Connect to database and run migrations
	chainStatusDB, err := cmd.ConnectToPostgresDB(lggr)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	if chainStatusDB == nil {
		return fmt.Errorf("database connection is required")
	}
	defer chainStatusDB.Close() //nolint:errcheck // not critical for shutdown

	// Load keystore (using wrapper that handles missing keystore gracefully)
	storageName := os.Getenv(KeystoreStorageNameEnvVar)
	if storageName == "" {
		storageName = "verifier-keystore"
	}
	keystoreStorage := keys.NewPGStorage(chainStatusDB, storageName)
	ks, err := keystore.LoadKeystore(ctx, keystoreStorage, keystorePassword)
	if err != nil {
		return fmt.Errorf("failed to load keystore: %w", err)
	}

	// Get or create both keys
	keyPair, err := keys.GetOrCreateKeys(ctx, ks)
	if err != nil {
		return fmt.Errorf("failed to initialize keys: %w", err)
	}

	lggr.Infow("Keys initialized",
		"signingAddress", keyPair.SigningAddress,
		"csaPublicKey", hex.EncodeToString(keyPair.CSAPublicKey),
	)

	// ========== PHASE 2: READY ==========
	lggr.Infow("Phase 2: Starting servers...")

	// 2a. Start HTTP info server (non-blocking)
	infoAddr := os.Getenv(InfoServerAddrEnvVar)
	if infoAddr == "" {
		infoAddr = defaultInfoServerAddr
	}
	infoServer := infoserver.New(infoAddr, keyPair.SigningAddress, keyPair.CSAPublicKey, lggr)
	go func() {
		if err := infoServer.Start(); err != nil && err != http.ErrServerClosed {
			lggr.Errorw("Info server error", "error", err)
		}
	}()
	lggr.Infow("HTTP info server started", "addr", infoAddr)

	// 2b. Parse JD public key
	jdCSAPublicKeyHex := os.Getenv(JDCSAPublicKeyEnvVar)
	if jdCSAPublicKeyHex == "" {
		return fmt.Errorf("JD_CSA_PUBLIC_KEY environment variable is required")
	}
	jdCSAPublicKey, err := hex.DecodeString(jdCSAPublicKeyHex)
	if err != nil {
		return fmt.Errorf("invalid JD_CSA_PUBLIC_KEY: %w", err)
	}

	// 2c. Create JD client
	jdWSRPCURL := os.Getenv(JDWSRPCURLEnvVar)
	if jdWSRPCURL == "" {
		return fmt.Errorf("JD_WSRPC_URL environment variable is required")
	}
	jdClient := jdclient.NewClient(keyPair.CSASigner, jdCSAPublicKey, jdWSRPCURL, lggr)

	// 2d. Create job store for persistence
	jobStore := jobstore.NewStore(chainStatusDB)

	// 2e. Create the job runner
	runner := &committeeRunner{
		lggr:          lggr,
		ks:            ks,
		chainStatusDB: chainStatusDB,
		infoServer:    infoServer,
	}

	// 2f. Create lifecycle manager
	manager := jdlifecycle.NewManager(jdlifecycle.Config{
		JDClient: jdClient,
		JobStore: jobStore,
		Runner:   runner,
		Logger:   lggr,
	})

	// ========== PHASE 3: ACTIVE ==========
	lggr.Infow("Phase 3: Starting lifecycle manager...")

	// Handle shutdown signal in a separate goroutine
	go func() {
		select {
		case sig := <-sigCh:
			lggr.Infow("Received shutdown signal", "signal", sig)
			manager.Shutdown()
		case <-ctx.Done():
			// Context cancelled, manager will handle this
		}
	}()

	// Run the lifecycle manager (blocks until shutdown)
	if err := manager.Run(ctx); err != nil {
		lggr.Errorw("Lifecycle manager error", "error", err)
	}

	// Shutdown info server
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := infoServer.Shutdown(shutdownCtx); err != nil {
		lggr.Warnw("Error shutting down info server", "error", err)
	}

	lggr.Infow("Verifier shutdown complete")
	return nil
}

func unmarshalJobSpec(jobSpec string) (commit.ConfigWithBlockchainInfos, error) {
	// Unmarshal outer spec
	var spec JobSpec
	if err := toml.Unmarshal([]byte(jobSpec), &spec); err != nil {
		return commit.ConfigWithBlockchainInfos{}, fmt.Errorf("failed to unmarshal job spec: %w", err)
	}

	// Unmarshal inner spec
	var cfg commit.ConfigWithBlockchainInfos
	if err := toml.Unmarshal([]byte(spec.CommitteeVerifierConfig), &cfg); err != nil {
		return commit.ConfigWithBlockchainInfos{}, fmt.Errorf("failed to unmarshal committee verifier config: %w", err)
	}

	return cfg, nil
}

// startCoordinator creates and starts the verification coordinator.
func startCoordinator(
	ctx context.Context,
	lggr logger.Logger,
	config *commit.Config,
	blockchainInfos map[string]*blockchain.Info,
	ks keystore.Keystore,
	chainStatusDB *sqlx.DB,
) (*verifier.Coordinator, *heartbeatclient.HeartbeatClient, error) {
	apiKey := os.Getenv("VERIFIER_AGGREGATOR_API_KEY")
	if apiKey == "" {
		return nil, nil, fmt.Errorf("VERIFIER_AGGREGATOR_API_KEY environment variable is required")
	}
	if err := hmac.ValidateAPIKey(apiKey); err != nil {
		return nil, nil, fmt.Errorf("invalid VERIFIER_AGGREGATOR_API_KEY: %w", err)
	}

	secretKey := os.Getenv("VERIFIER_AGGREGATOR_SECRET_KEY")
	if secretKey == "" {
		return nil, nil, fmt.Errorf("VERIFIER_AGGREGATOR_SECRET_KEY environment variable is required")
	}
	if err := hmac.ValidateSecret(secretKey); err != nil {
		return nil, nil, fmt.Errorf("invalid VERIFIER_AGGREGATOR_SECRET_KEY: %w", err)
	}

	cmd.StartPyroscope(lggr, config.PyroscopeURL, "verifier")
	blockchainHelper := cmd.LoadBlockchainInfo(ctx, lggr, blockchainInfos)

	// Create verifier addresses
	verifierAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.CommitteeVerifierAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create verifier address: %w", err)
		}
		verifierAddresses[selector] = addr
	}
	defaultExecutorAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.DefaultExecutorOnRampAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create default executor address: %w", err)
		}
		defaultExecutorAddresses[selector] = addr
	}

	hmacConfig := &hmac.ClientConfig{
		APIKey: apiKey,
		Secret: secretKey,
	}

	aggregatorWriter, err := storageaccess.NewAggregatorWriter(config.AggregatorAddress, lggr, hmacConfig, config.InsecureAggregatorConnection)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create aggregator writer: %w", err)
	}

	chainStatusManager := chainstatus.NewPostgresChainStatusManager(chainStatusDB, lggr, config.VerifierID)

	registry := accessors.NewRegistry(blockchainHelper)
	cmd.RegisterEVM(ctx, registry, lggr, blockchainHelper, config.OnRampAddresses, config.RMNRemoteAddresses)
	cmd.RegisterCanton(ctx, registry, lggr, blockchainHelper, config.CantonConfigs)

	sourceReaders, err := cmd.CreateSourceReaders(ctx, lggr, registry, blockchainHelper, *config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create source readers: %w", err)
	}

	// Create coordinator configuration
	sourceConfigs := make(map[protocol.ChainSelector]verifier.SourceConfig)
	rmnRemoteAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.RMNRemoteAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create RMN Remote address: %w", err)
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
		CursePollInterval:   2 * time.Second,
		HeartbeatInterval:   10 * time.Second,
	}

	// Get signer from keystore using the default signing key name
	signer, publicKey, err := commit.NewSignerFromKeystore(ctx, ks, keys.SigningKeyName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create signer from keystore: %w", err)
	}
	lggr.Infow("Using signer from keystore", "keyName", keys.SigningKeyName, "address", publicKey)

	verifierMonitoring := cmd.SetupMonitoring(lggr, config.Monitoring)

	// Create commit verifier
	commitVerifier, err := commit.NewCommitVerifier(coordinatorConfig, publicKey, signer, lggr, verifierMonitoring)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create commit verifier: %w", err)
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
		return nil, nil, fmt.Errorf("failed to create heartbeat client: %w", err)
	}

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
	coordinator, err := verifier.NewCoordinator(
		ctx,
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
		return nil, nil, fmt.Errorf("failed to create verification coordinator: %w", err)
	}

	// Start the verification coordinator
	lggr.Infow("Starting Verification Coordinator",
		"verifierID", coordinatorConfig.VerifierID,
		"verifierAddress", verifierAddresses,
	)

	if err := coordinator.Start(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to start verification coordinator: %w", err)
	}

	return coordinator, heartbeatClient, nil
}

// committeeRunner implements jdlifecycle.JobRunner for the committee verifier.
// It manages the lifecycle of the verifier coordinator based on job specs from JD.
type committeeRunner struct {
	lggr          logger.Logger
	ks            keystore.Keystore
	chainStatusDB *sqlx.DB
	infoServer    *infoserver.Server

	mu              sync.Mutex
	coordinator     *verifier.Coordinator
	heartbeatClient *heartbeatclient.HeartbeatClient
}

// Ensure committeeRunner implements JobRunner.
var _ jdlifecycle.JobRunner = (*committeeRunner)(nil)

// StartJob implements jdlifecycle.JobRunner.
// It parses the job spec and starts the verification coordinator.
func (r *committeeRunner) StartJob(ctx context.Context, spec string) error {
	r.lggr.Infow("Starting job from spec")

	// Parse the job spec
	cfgWithInfos, err := unmarshalJobSpec(spec)
	if err != nil {
		return fmt.Errorf("failed to unmarshal job spec: %w", err)
	}

	// Start the coordinator
	coordinator, heartbeatClient, err := startCoordinator(
		ctx, r.lggr, &cfgWithInfos.Config, cfgWithInfos.BlockchainInfos, r.ks, r.chainStatusDB,
	)
	if err != nil {
		return fmt.Errorf("failed to start coordinator: %w", err)
	}

	r.mu.Lock()
	r.coordinator = coordinator
	r.heartbeatClient = heartbeatClient
	r.mu.Unlock()

	// Update info server phase
	r.infoServer.SetPhase(infoserver.PhaseActive)

	r.lggr.Infow("Job started successfully")
	return nil
}

// StopJob implements jdlifecycle.JobRunner.
// It stops the currently running coordinator.
func (r *committeeRunner) StopJob(ctx context.Context) error {
	r.mu.Lock()
	coordinator := r.coordinator
	heartbeatClient := r.heartbeatClient
	r.coordinator = nil
	r.heartbeatClient = nil
	r.mu.Unlock()

	if coordinator == nil {
		r.lggr.Infow("No coordinator running, nothing to stop")
		return nil
	}

	r.lggr.Infow("Stopping coordinator")

	var errs error

	// Stop coordinator
	if err := coordinator.Close(); err != nil {
		r.lggr.Warnw("Error stopping coordinator", "error", err)
		errs = errors.Join(errs, err)
	}

	// Close heartbeat client
	if heartbeatClient != nil {
		if err := heartbeatClient.Close(); err != nil {
			r.lggr.Warnw("Error closing heartbeat client", "error", err)
			errs = errors.Join(errs, err)
		}
	}

	// Update info server phase back to ready
	r.infoServer.SetPhase(infoserver.PhaseReady)

	r.lggr.Infow("Coordinator stopped")
	return errs
}
