package verifier

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/grafana/pyroscope-go"
	"github.com/jmoiron/sqlx"

	chainsel "github.com/smartcontractkit/chain-selectors"
	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader/canton"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/db"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
)

const (
	// Database environment variables.
	DatabaseURLEnvVar             = "CL_DATABASE_URL"
	DatabaseMaxOpenConnsEnvVar    = "CL_DATABASE_MAX_OPEN_CONNS"
	DatabaseMaxIdleConnsEnvVar    = "CL_DATABASE_MAX_IDLE_CONNS"
	DatabaseConnMaxLifetimeEnvVar = "CL_DATABASE_CONN_MAX_LIFETIME"
	DatabaseConnMaxIdleTimeEnvVar = "CL_DATABASE_CONN_MAX_IDLE_TIME"

	// Database defaults.
	defaultMaxOpenConns    = 20
	defaultMaxIdleConns    = 10
	defaultConnMaxLifetime = 300 // seconds
	defaultConnMaxIdleTime = 60  // seconds
)

func SetupMonitoring(lggr logger.Logger, config verifier.MonitoringConfig) verifier.Monitoring {
	beholderConfig := beholder.Config{
		InsecureConnection:       config.Beholder.InsecureConnection,
		CACertFile:               config.Beholder.CACertFile,
		OtelExporterHTTPEndpoint: config.Beholder.OtelExporterHTTPEndpoint,
		OtelExporterGRPCEndpoint: config.Beholder.OtelExporterGRPCEndpoint,
		LogStreamingEnabled:      config.Beholder.LogStreamingEnabled,
		MetricReaderInterval:     time.Second * time.Duration(config.Beholder.MetricReaderInterval),
		TraceSampleRatio:         config.Beholder.TraceSampleRatio,
		TraceBatchTimeout:        time.Second * time.Duration(config.Beholder.TraceBatchTimeout),
		// Note: due to OTEL spec, all histogram buckets must be defined when the beholder client is created.
		MetricViews: monitoring.MetricViews(),
	}

	// Create the beholder client
	beholderClient, err := beholder.NewClient(beholderConfig)
	if err != nil {
		lggr.Fatalf("failed to create beholder client: %w", err)
	}

	// Set the beholder client and global otel providers
	beholder.SetClient(beholderClient)
	beholder.SetGlobalOtelProviders()
	verifierMonitoring, err := monitoring.InitMonitoring()
	if err != nil {
		lggr.Fatalf("Failed to initialize verifier monitoring: %w", err)
	}
	return verifierMonitoring
}

func LoadBlockchainReadersForToken(
	ctx context.Context,
	lggr logger.Logger,
	registry *sourcereader.Registry,
	blockchainHelper *blockchain.Helper,
	config token.Config,
) map[protocol.ChainSelector]chainaccess.SourceReader {
	sourceReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader)

	for _, selector := range blockchainHelper.GetAllChainSelectors() {
		info, err := blockchainHelper.GetBlockchainByChainSelector(selector)
		if err != nil {
			lggr.Errorw("Failed to get blockchain info", "chainSelector", selector, "error", err)
			continue
		}
		if info.Family != chainsel.FamilyEVM {
			lggr.Errorw("Skipping chain, only EVM is supported", "chainSelector", selector, "family", info.Family)
			continue
		}

		lggr.Infow("⏳ Creating source reader for chain", "chainSelector", selector, "strSelector", uint64(selector))

		reader, err := registry.GetSourceReader(ctx, selector)
		if err != nil {
			lggr.Errorw("❌ Failed to create source reader for chain", "chainSelector", selector, "error", err)
			continue
		}

		sourceReaders[selector] = reader
		lggr.Infow("🚀 Created source reader for chain", "chainSelector", selector)
	}

	return sourceReaders
}

func RegisterEVM(ctx context.Context, registry *sourcereader.Registry, lggr logger.Logger, helper *blockchain.Helper, onRampAddresses, rmnRemoteAddresses map[string]string) {
	// Create the chain clients then the head trackers
	chainClients := make(map[protocol.ChainSelector]client.Client)
	for _, selector := range helper.GetAllChainSelectors() {
		chainClient := pkg.CreateHealthyMultiNodeClient(ctx, helper, lggr, selector)
		chainClients[selector] = chainClient
	}
	headTrackers := make(map[protocol.ChainSelector]heads.Tracker)
	for _, selector := range helper.GetAllChainSelectors() {
		headTracker := sourcereader.NewSimpleHeadTrackerWrapper(chainClients[selector], lggr)
		headTrackers[selector] = headTracker
	}

	registry.Register(chainsel.FamilyEVM, sourcereader.NewEVMFactory(lggr, helper, onRampAddresses, rmnRemoteAddresses, headTrackers, chainClients))
}

func RegisterCanton(ctx context.Context, registry *sourcereader.Registry, lggr logger.Logger, helper *blockchain.Helper, cantonConfigs map[string]commit.CantonConfig) {
	registry.Register(chainsel.FamilyCanton, canton.NewFactory(lggr, helper, cantonConfigs))
}

func CreateSourceReaders(
	ctx context.Context,
	lggr logger.Logger,
	registry *sourcereader.Registry,
	helper *blockchain.Helper,
	config commit.Config,
) (map[protocol.ChainSelector]chainaccess.SourceReader, error) {
	readers := make(map[protocol.ChainSelector]chainaccess.SourceReader)
	for _, selector := range helper.GetAllChainSelectors() {
		reader, err := registry.GetSourceReader(ctx, selector)
		if err != nil {
			lggr.Errorw("❌ Failed to create source reader", "chainSelector", selector, "error", err)
			continue
		}
		readers[selector] = reader
		lggr.Infow("🚀 Created source reader for chain", "chainSelector", selector)
	}
	return readers, nil
}

func ConnectToPostgresDB(lggr logger.Logger) (*sqlx.DB, error) {
	dbURL := os.Getenv(DatabaseURLEnvVar)
	if dbURL == "" {
		return nil, nil
	}

	maxOpenConns := getEnvInt(DatabaseMaxOpenConnsEnvVar, defaultMaxOpenConns)
	maxIdleConns := getEnvInt(DatabaseMaxIdleConnsEnvVar, defaultMaxIdleConns)
	connMaxLifetime := getEnvInt(DatabaseConnMaxLifetimeEnvVar, defaultConnMaxLifetime)
	connMaxIdleTime := getEnvInt(DatabaseConnMaxIdleTimeEnvVar, defaultConnMaxIdleTime)

	dbx, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, nil
	}

	dbx.SetMaxOpenConns(maxOpenConns)
	dbx.SetMaxIdleConns(maxIdleConns)
	dbx.SetConnMaxLifetime(time.Duration(connMaxLifetime) * time.Second)
	dbx.SetConnMaxIdleTime(time.Duration(connMaxIdleTime) * time.Second)

	if err := ccvcommon.EnsureDBConnection(lggr, dbx); err != nil {
		_ = dbx.Close()
		return nil, fmt.Errorf("failed to ping postgres database: %w", err)
	}

	sqlxDB := sqlx.NewDb(dbx, "postgres")

	if err := db.RunPostgresMigrations(sqlxDB); err != nil {
		_ = dbx.Close()
		return nil, fmt.Errorf("failed to run postgres migrations: %w", err)
	}

	lggr.Infow("Using PostgreSQL chain status storage",
		"maxOpenConns", maxOpenConns,
		"maxIdleConns", maxIdleConns,
		"connMaxLifetime", connMaxLifetime,
		"connMaxIdleTime", connMaxIdleTime,
	)

	return sqlxDB, nil
}

func LoadBlockchainInfo(
	ctx context.Context,
	lggr logger.Logger,
	config map[string]*blockchain.Info,
) *blockchain.Helper {
	// Use actual blockchain information from configuration
	if len(config) == 0 {
		lggr.Warnw("No blockchain information in config")
		return nil
	}
	blockchainHelper := blockchain.NewHelper(config)
	lggr.Infow("Using real blockchain information from environment",
		"chainCount", len(config))
	logBlockchainInfo(blockchainHelper, lggr)
	return blockchainHelper
}

func StartPyroscope(lggr logger.Logger, pyroscopeAddress, serviceName string) {
	if _, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: serviceName,
		ServerAddress:   pyroscopeAddress,
		Logger:          nil, // Disable pyroscope logging - so noisy
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileGoroutines,
			pyroscope.ProfileBlockDuration,
			pyroscope.ProfileMutexDuration,
		},
	}); err != nil {
		lggr.Errorw("Failed to start pyroscope", "error", err)
	}
}

func logBlockchainInfo(blockchainHelper *blockchain.Helper, lggr logger.Logger) {
	for _, chainID := range blockchainHelper.GetAllChainSelectors() {
		logChainInfo(blockchainHelper, chainID, lggr)
	}
}

func logChainInfo(blockchainHelper *blockchain.Helper, chainSelector protocol.ChainSelector, lggr logger.Logger) {
	if info, err := blockchainHelper.GetBlockchainInfo(chainSelector); err == nil {
		lggr.Infow("🔗 Blockchain available", "chainSelector", chainSelector, "info", info)
	}

	if rpcURL, err := blockchainHelper.GetRPCEndpoint(chainSelector); err == nil {
		lggr.Infow("🌐 RPC endpoint", "chainSelector", chainSelector, "url", rpcURL)
	}

	if wsURL, err := blockchainHelper.GetWebSocketEndpoint(chainSelector); err == nil {
		lggr.Infow("🔌 WebSocket endpoint", "chainSelector", chainSelector, "url", wsURL)
	}

	if internalURL, err := blockchainHelper.GetInternalRPCEndpoint(chainSelector); err == nil {
		lggr.Infow("🔒 Internal RPC endpoint", "chainSelector", chainSelector, "url", internalURL)
	}

	if nodes, err := blockchainHelper.GetAllNodes(chainSelector); err == nil {
		lggr.Infow("📡 All nodes", "chainSelector", chainSelector, "nodeCount", len(nodes))
	}
}

func getEnvInt(key string, defaultValue int) int {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue
	}
	intVal, err := strconv.Atoi(val)
	if err != nil {
		return defaultValue
	}
	return intVal
}
