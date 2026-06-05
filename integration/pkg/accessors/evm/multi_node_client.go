package evm

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/config/chaintype"
)

func ptr[T any](t T) *T { return new(t) }

func CreateHealthyMultiNodeClient(ctx context.Context, infos chainaccess.Infos[Info], lggr logger.Logger, chainSelector protocol.ChainSelector) (client.Client, error) {
	info, err := infos.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		lggr.Errorw("Failed to get blockchain info", "error", err, "chainSelector", chainSelector)
		return nil, fmt.Errorf("failed to get blockchain info for chain selector %v: %w", chainSelector, err)
	}
	return CreateMultiNodeClientFromInfo(ctx, info, lggr)
}

// CreateMultiNodeClientFromInfo creates EVM client and tests the connection.
func CreateMultiNodeClientFromInfo(ctx context.Context, blockchainInfo Info, lggr logger.Logger) (client.Client, error) {
	noNewHeadsThreshold := 3 * time.Minute
	selectionMode := new("HighestHead")
	leaseDuration := 0 * time.Second
	pollFailureThreshold := new(uint32(5))
	pollSuccessThreshold := new(uint32(0))
	pollInterval := 2 * time.Second
	syncThreshold := new(uint32(5))
	nodeIsSyncingEnabled := new(false)
	chainTypeStr := blockchainInfo.Type
	finalizedBlockOffset := ptr[uint32](16)
	enforceRepeatableRead := new(true)
	deathDeclarationDelay := time.Second * 3
	noNewFinalizedBlocksThreshold := 15 * time.Minute // High value - allows slow chains and manual mining
	finalizedBlockPollInterval := time.Second * 10
	newHeadsPollInterval := time.Second * 1
	confirmationTimeout := time.Second * 60
	// TODO: there could be multiple nodes configured, why aren't we registering all of them?
	n, err := blockchainInfo.GetFirstNode()
	if err != nil {
		lggr.Errorw("Failed to get first node", "error", err, "chainID", blockchainInfo.ChainID)
		return nil, fmt.Errorf("failed to get first node: %w", err)
	}
	wsURL := n.InternalWSUrl
	httpURL := n.InternalHTTPUrl
	nodeConfigs := []client.NodeConfig{
		{
			Name:    new(blockchainInfo.UniqueChainName),
			WSURL:   new(wsURL),
			HTTPURL: new(httpURL),
		},
	}
	finalityDepth := new(uint32(10))
	safeDepth := new(uint32(6))
	finalityTagEnabled := new(true)
	safeTagSupported := new(true)
	lggr.Infow("Testing multinode chain client", "chainSelector", blockchainInfo.ChainID, "wsURL", wsURL, "httpURL", httpURL)
	chainCfg, nodePool, nodes, err := client.NewClientConfigs(selectionMode, leaseDuration, chainTypeStr, nodeConfigs,
		pollFailureThreshold, pollSuccessThreshold, pollInterval, syncThreshold, nodeIsSyncingEnabled, noNewHeadsThreshold, finalityDepth,
		finalityTagEnabled, safeTagSupported, finalizedBlockOffset, enforceRepeatableRead, deathDeclarationDelay, noNewFinalizedBlocksThreshold,
		finalizedBlockPollInterval, newHeadsPollInterval, confirmationTimeout, safeDepth)
	if err != nil {
		lggr.Errorw("Failed to create client configs", "error", err)
		return nil, fmt.Errorf("failed to create client configs: %w", err)
	}

	idBigInt, success := new(big.Int).SetString(blockchainInfo.ChainID, 10)
	if !success {
		lggr.Errorw("Failed to parse chain ID to big.Int", "chainID", blockchainInfo.ChainID)
		return nil, fmt.Errorf("failed to parse chain ID to big.Int for chainID (%s)", blockchainInfo.ChainID)
	}

	chainClient, err := client.NewEvmClient(nodePool, chainCfg, nil, lggr, idBigInt, nodes, chaintype.ChainType(chainTypeStr))
	if err != nil {
		lggr.Errorw("Failed to create EVM client", "error", err)
		return nil, fmt.Errorf("failed to create evm client: %w", err)
	}

	lggr.Infow("Multinode chain client created successfully",
		"chainID", blockchainInfo.ChainID,
		"nodeStates", chainClient.NodeStates())

	err = chainClient.Dial(ctx)
	if err != nil {
		lggr.Errorw("Failed to dial multinode chain client", "error", err)
		chainClient.Close()
		return nil, fmt.Errorf("failed to dial evm client: %w", err)
	}

	// Test 1: Get latest block using multinode's SelectRPC
	latestBlock, err := chainClient.LatestBlockHeight(ctx)
	if err != nil {
		lggr.Errorw("Failed to get block height", "error", err)
		chainClient.Close()
		return nil, fmt.Errorf("failed to get block height: %w", err)
	}
	lggr.Infow("Latest block (via multinode)", "blockNumber", latestBlock)

	// Test 2: Get chain ID
	chainID := chainClient.ConfiguredChainID()
	lggr.Infow("Chain ID", "chainID", chainID)

	// Test 3: Get a specific block header
	header, err := chainClient.HeadByNumber(ctx, latestBlock)
	if err != nil {
		lggr.Errorw("Failed to get block head", "error", err)
		chainClient.Close()
		return nil, fmt.Errorf("failed to get block head: %w", err)
	}
	lggr.Infow("Block header",
		"number", header.Number,
		"hash", header.Hash.Hex(),
		"timestamp", header.Timestamp)

	lggr.Infow("Multinode chain client tests completed successfully!", "chainID", blockchainInfo.ChainID)
	return chainClient, nil
}
