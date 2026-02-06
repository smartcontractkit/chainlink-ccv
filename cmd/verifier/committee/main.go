package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"go.uber.org/zap/zapcore"

	cmd "github.com/smartcontractkit/chainlink-ccv/cmd/verifier"
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
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jdclient"
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

	run(ctx, lggr, sigCh)
}

// run executes the verifier lifecycle:
// 1. INIT: Generates/loads keys from keystore
// 2. READY: Starts HTTP info server, connects to JD, waits for job proposal
// 3. ACTIVE: Starts coordinator with received config
func run(ctx context.Context, lggr logger.Logger, sigCh chan os.Signal) {
	lggr.Infow("Starting verifier")

	// ========== PHASE 1: INIT ==========
	lggr.Infow("Phase 1: Initializing keys...")

	keystorePassword := os.Getenv(KeystorePasswordEnvVar)
	if keystorePassword == "" {
		lggr.Fatalw("KEYSTORE_PASSWORD environment variable is required")
	}

	// Connect to database and run migrations
	chainStatusDB, err := cmd.ConnectToPostgresDB(lggr)
	if err != nil {
		lggr.Fatalw("Failed to connect to database", "error", err)
	}
	if chainStatusDB == nil {
		lggr.Fatalw("Database connection is required")
	}
	defer chainStatusDB.Close()

	// Load keystore (using wrapper that handles missing keystore gracefully)
	storageName := os.Getenv(KeystoreStorageNameEnvVar)
	if storageName == "" {
		storageName = "verifier-keystore"
	}
	keystoreStorage := keys.NewPGStorage(chainStatusDB, storageName)
	ks, err := keystore.LoadKeystore(ctx, keystoreStorage, keystorePassword)
	if err != nil {
		lggr.Fatalw("Failed to load keystore", "error", err)
	}

	// Get or create both keys
	keyPair, err := keys.GetOrCreateKeys(ctx, ks)
	if err != nil {
		lggr.Fatalw("Failed to initialize keys", "error", err)
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
		lggr.Fatalw("JD_CSA_PUBLIC_KEY environment variable is required")
	}
	jdCSAPublicKey, err := hex.DecodeString(jdCSAPublicKeyHex)
	if err != nil {
		lggr.Fatalw("Invalid JD_CSA_PUBLIC_KEY", "error", err)
	}

	// 2c. Connect to JD
	jdWSRPCURL := os.Getenv(JDWSRPCURLEnvVar)
	if jdWSRPCURL == "" {
		lggr.Fatalw("JD_WSRPC_URL environment variable is required")
	}
	jdClient := jdclient.NewClient(keyPair.CSASigner, jdCSAPublicKey, jdWSRPCURL, lggr)
	if err := jdClient.Connect(ctx); err != nil {
		lggr.Fatalw("Failed to connect to JD", "error", err)
	}
	lggr.Infow("Connected to Job Distributor, waiting for job proposal...")

	// 2d. Wait for job proposal OR shutdown signal
	var config *commit.Config
	var blockchainInfos map[string]*blockchain.Info
	select {
	case proposal := <-jdClient.JobProposalCh():
		lggr.Infow("Received job proposal", "id", proposal.ID)

		// Parse TOML config
		var cfgWithInfos commit.ConfigWithBlockchainInfos
		if _, err := toml.Decode(proposal.Spec, &cfgWithInfos); err != nil {
			lggr.Fatalw("Failed to parse job spec", "error", err)
		}
		config = &cfgWithInfos.Config
		blockchainInfos = cfgWithInfos.BlockchainInfos

		// Auto-approve
		if err := jdClient.ApproveJob(ctx, proposal.ID, proposal.Version); err != nil {
			lggr.Warnw("Failed to approve job", "error", err)
		}

	case sig := <-sigCh:
		lggr.Infow("Received shutdown signal before job proposal", "signal", sig)
		shutdownGracefully(ctx, lggr, infoServer, jdClient, nil, nil)
		return
	}

	// Update phase
	infoServer.SetPhase(infoserver.PhaseActive)

	// ========== PHASE 3: ACTIVE ==========
	lggr.Infow("Phase 3: Starting coordinator...")

	// Start the coordinator with the received config
	coordinator, heartbeatClient := startCoordinator(ctx, lggr, config, blockchainInfos, ks, chainStatusDB)

	lggr.Infow("Verifier service fully started and ready!")

	// Wait for shutdown signal
	sig := <-sigCh
	lggr.Infow("Received shutdown signal", "signal", sig)

	shutdownGracefully(ctx, lggr, infoServer, jdClient, coordinator, heartbeatClient)
}

// startCoordinator creates and starts the verification coordinator.
func startCoordinator(
	ctx context.Context,
	lggr logger.Logger,
	config *commit.Config,
	blockchainInfos map[string]*blockchain.Info,
	ks keystore.Keystore,
	chainStatusDB *sqlx.DB,
) (*verifier.Coordinator, *heartbeatclient.HeartbeatClient) {
	apiKey := os.Getenv("VERIFIER_AGGREGATOR_API_KEY")
	if apiKey == "" {
		lggr.Fatalw("VERIFIER_AGGREGATOR_API_KEY environment variable is required")
	}
	if err := hmac.ValidateAPIKey(apiKey); err != nil {
		lggr.Fatalw("Invalid VERIFIER_AGGREGATOR_API_KEY", "error", err)
	}

	secretKey := os.Getenv("VERIFIER_AGGREGATOR_SECRET_KEY")
	if secretKey == "" {
		lggr.Fatalw("VERIFIER_AGGREGATOR_SECRET_KEY environment variable is required")
	}
	if err := hmac.ValidateSecret(secretKey); err != nil {
		lggr.Fatalw("Invalid VERIFIER_AGGREGATOR_SECRET_KEY", "error", err)
	}

	cmd.StartPyroscope(lggr, config.PyroscopeURL, "verifier")
	blockchainHelper := cmd.LoadBlockchainInfo(ctx, lggr, blockchainInfos)

	// Create verifier addresses
	verifierAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.CommitteeVerifierAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			lggr.Fatalw("Failed to create verifier address", "error", err)
		}
		verifierAddresses[selector] = addr
	}
	defaultExecutorAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.DefaultExecutorOnRampAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			lggr.Fatalw("Failed to create default executor address", "error", err)
		}
		defaultExecutorAddresses[selector] = addr
	}

	hmacConfig := &hmac.ClientConfig{
		APIKey: apiKey,
		Secret: secretKey,
	}

	aggregatorWriter, err := storageaccess.NewAggregatorWriter(config.AggregatorAddress, lggr, hmacConfig, config.InsecureAggregatorConnection)
	if err != nil {
		lggr.Fatalw("Failed to create aggregator writer", "error", err)
	}

	chainStatusManager := chainstatus.NewPostgresChainStatusManager(chainStatusDB, lggr, config.VerifierID)

	registry := accessors.NewRegistry(blockchainHelper)
	cmd.RegisterEVM(ctx, registry, lggr, blockchainHelper, config.OnRampAddresses, config.RMNRemoteAddresses)
	cmd.RegisterCanton(ctx, registry, lggr, blockchainHelper, config.CantonConfigs)

	sourceReaders, err := cmd.CreateSourceReaders(ctx, lggr, registry, blockchainHelper, *config)
	if err != nil {
		lggr.Fatalw("Failed to create source readers", "error", err)
	}

	// Create coordinator configuration
	sourceConfigs := make(map[protocol.ChainSelector]verifier.SourceConfig)
	rmnRemoteAddresses := make(map[string]protocol.UnknownAddress)
	for selector, address := range config.RMNRemoteAddresses {
		addr, err := protocol.NewUnknownAddressFromHex(address)
		if err != nil {
			lggr.Fatalw("Failed to create RMN Remote address", "error", err, "selector", selector)
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
		lggr.Fatalw("Failed to create signer from keystore", "error", err)
	}
	lggr.Infow("Using signer from keystore", "keyName", keys.SigningKeyName, "address", publicKey)

	verifierMonitoring := cmd.SetupMonitoring(lggr, config.Monitoring)

	// Create commit verifier
	commitVerifier, err := commit.NewCommitVerifier(coordinatorConfig, publicKey, signer, lggr, verifierMonitoring)
	if err != nil {
		lggr.Fatalw("Failed to create commit verifier", "error", err)
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
		lggr.Fatalw("Failed to create heartbeat client", "error", err)
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
		lggr.Fatalw("Failed to create verification coordinator", "error", err)
	}

	// Start the verification coordinator
	lggr.Infow("Starting Verification Coordinator",
		"verifierID", coordinatorConfig.VerifierID,
		"verifierAddress", verifierAddresses,
	)

	if err := coordinator.Start(ctx); err != nil {
		lggr.Fatalw("Failed to start verification coordinator", "error", err)
	}

	return coordinator, heartbeatClient
}

// shutdownGracefully performs graceful shutdown of all components.
func shutdownGracefully(
	ctx context.Context,
	lggr logger.Logger,
	infoServer *infoserver.Server,
	jdClient *jdclient.Client,
	coordinator *verifier.Coordinator,
	heartbeatClient *heartbeatclient.HeartbeatClient,
) {
	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Stop coordinator first (if running)
	if coordinator != nil {
		lggr.Infow("Stopping coordinator...")
		if err := coordinator.Close(); err != nil {
			lggr.Warnw("Error stopping coordinator", "error", err)
		}
	}

	// Close heartbeat client
	if heartbeatClient != nil {
		lggr.Infow("Closing heartbeat client...")
		if err := heartbeatClient.Close(); err != nil {
			lggr.Warnw("Error closing heartbeat client", "error", err)
		}
	}

	// Close JD connection
	if jdClient != nil {
		lggr.Infow("Closing JD connection...")
		if err := jdClient.Close(); err != nil {
			lggr.Warnw("Error closing JD connection", "error", err)
		}
	}

	// Shutdown info server (last, so /info remains available longest)
	if infoServer != nil {
		lggr.Infow("Shutting down info server...")
		if err := infoServer.Shutdown(shutdownCtx); err != nil {
			lggr.Warnw("Error shutting down info server", "error", err)
		}
	}

	lggr.Infow("Graceful shutdown complete")
}
