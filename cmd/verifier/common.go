package verifier

import (
	"context"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/grafana/pyroscope-go"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
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
	lggr logger.Logger,
	blockchainHelper *protocol.BlockchainHelper,
	chainClients map[protocol.ChainSelector]client.Client,
	config token.Config,
) map[protocol.ChainSelector]chainaccess.SourceReader {
	sourceReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader)

	for _, selector := range blockchainHelper.GetAllChainSelectors() {
		lggr.Infow("Creating source reader", "chainSelector", selector, "strSelector", uint64(selector))
		strSelector := strconv.FormatUint(uint64(selector), 10)

		if config.OnRampAddresses[strSelector] == "" {
			lggr.Errorw("On ramp address is not set", "chainSelector", selector)
			continue
		}
		if config.RMNRemoteAddresses[strSelector] == "" {
			lggr.Errorw("RMN Remote address is not set", "chainSelector", selector)
			continue
		}

		evmSourceReader, err := createEvmChainReader(
			lggr,
			chainClients,
			selector,
			config.OnRampAddresses[strSelector],
			config.RMNRemoteAddresses[strSelector],
		)
		if err != nil {
			lggr.Errorw("Failed to create EVM source reader", "selector", selector, "error", err)
			continue
		}

		// EVMSourceReader implements both SourceReader and HeadTracker interfaces
		sourceReaders[selector] = evmSourceReader

		lggr.Infow("Created blockchain source reader", "chain", selector)
	}

	return sourceReaders
}

func LoadBlockchainReadersForCommit(
	lggr logger.Logger,
	blockchainHelper *protocol.BlockchainHelper,
	chainClients map[protocol.ChainSelector]client.Client,
	config commit.Config,
) map[protocol.ChainSelector]chainaccess.SourceReader {
	sourceReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader)

	for _, selector := range blockchainHelper.GetAllChainSelectors() {
		lggr.Infow("Creating source reader", "chainSelector", selector, "strSelector", uint64(selector))
		strSelector := strconv.FormatUint(uint64(selector), 10)

		if config.CommitteeVerifierAddresses[strSelector] == "" {
			lggr.Errorw("Committee verifier address is not set", "chainSelector", selector)
			continue
		}
		if config.OnRampAddresses[strSelector] == "" {
			lggr.Errorw("On ramp address is not set", "chainSelector", selector)
			continue
		}
		if config.RMNRemoteAddresses[strSelector] == "" {
			lggr.Errorw("RMN Remote address is not set", "chainSelector", selector)
			continue
		}

		evmSourceReader, err := createEvmChainReader(
			lggr,
			chainClients,
			selector,
			config.OnRampAddresses[strSelector],
			config.RMNRemoteAddresses[strSelector],
		)
		if err != nil {
			lggr.Errorw("Failed to create EVM source reader", "selector", selector, "error", err)
			continue
		}

		// EVMSourceReader implements both SourceReader and HeadTracker interfaces
		sourceReaders[selector] = evmSourceReader

		lggr.Infow("Created blockchain source reader", "chain", selector)
	}

	return sourceReaders
}

func createEvmChainReader(
	lggr logger.Logger,
	chainClients map[protocol.ChainSelector]client.Client,
	selector protocol.ChainSelector,
	onRampAddress string,
	rmnRemoteAddress string,
) (chainaccess.SourceReader, error) {
	// Create head tracker wrapper (uses hardcoded confirmation depth of 10 internally)
	// This is only for standalone mode and for testing purposes.
	// In CL node it'll be using HeadTracker which already abstracts away this per chain.
	headTracker := NewSimpleHeadTrackerWrapper(chainClients[selector], lggr)

	evmSourceReader, err := sourcereader.NewEVMSourceReader(
		chainClients[selector],
		headTracker,
		common.HexToAddress(onRampAddress),
		common.HexToAddress(rmnRemoteAddress),
		onramp.OnRampCCIPMessageSent{}.Topic().Hex(),
		selector,
		lggr,
	)
	return evmSourceReader, err
}

func LoadBlockchainInfo(
	ctx context.Context,
	lggr logger.Logger,
	config map[string]*protocol.BlockchainInfo,
) (*protocol.BlockchainHelper, map[protocol.ChainSelector]client.Client) {
	// Use actual blockchain information from configuration
	var blockchainHelper *protocol.BlockchainHelper
	chainClients := make(map[protocol.ChainSelector]client.Client)
	if len(config) == 0 {
		lggr.Warnw("No blockchain information in config")
	} else {
		blockchainHelper = protocol.NewBlockchainHelper(config)
		lggr.Infow("Using real blockchain information from environment",
			"chainCount", len(config))
		logBlockchainInfo(blockchainHelper, lggr)
		for _, selector := range blockchainHelper.GetAllChainSelectors() {
			lggr.Infow("Creating chain client", "chainSelector", selector)
			chainClients[selector] = pkg.CreateHealthyMultiNodeClient(ctx, blockchainHelper, lggr, selector)
		}
	}
	return blockchainHelper, chainClients
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

func logBlockchainInfo(blockchainHelper *protocol.BlockchainHelper, lggr logger.Logger) {
	for _, chainID := range blockchainHelper.GetAllChainSelectors() {
		logChainInfo(blockchainHelper, chainID, lggr)
	}
}

func logChainInfo(blockchainHelper *protocol.BlockchainHelper, chainSelector protocol.ChainSelector, lggr logger.Logger) {
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
