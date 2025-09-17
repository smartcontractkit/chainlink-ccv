package pkg

import (
	"context"
	"math/big"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/config/chaintype"

	types2 "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

func ptr[T any](t T) *T { return &t }

func CreateHealthyMultiNodeClient(ctx context.Context, blockchainHelper *types.BlockchainHelper, lggr logger.Logger, chainSelector types2.ChainSelector) client.Client {
	blockchainInfo, err := blockchainHelper.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		lggr.Errorw("Failed to get blockchain info", "error", err, "chainSelector", chainSelector)
	}

	return CreateMultiNodeClientFromInfo(ctx, blockchainInfo, lggr)
}

// CreateMultiNodeClientFromInfo tests the multinode chain client connection and returns the client if it's healthy.
func CreateMultiNodeClientFromInfo(ctx context.Context, blockchainInfo *types.BlockchainInfo, lggr logger.Logger) client.Client {
	noNewHeadsThreshold := 3 * time.Minute
	selectionMode := ptr("HighestHead")
	leaseDuration := 0 * time.Second
	pollFailureThreshold := ptr(uint32(5))
	pollInterval := 10 * time.Second
	syncThreshold := ptr(uint32(5))
	nodeIsSyncingEnabled := ptr(false)
	chainTypeStr := blockchainInfo.Type
	finalizedBlockOffset := ptr[uint32](16)
	enforceRepeatableRead := ptr(true)
	deathDeclarationDelay := time.Second * 3
	noNewFinalizedBlocksThreshold := time.Second * 5
	finalizedBlockPollInterval := time.Second * 4
	newHeadsPollInterval := time.Second * 4
	confirmationTimeout := time.Second * 60
	wsURL, _ := blockchainInfo.GetInternalWebsocketEndpoint()
	httpURL, _ := blockchainInfo.GetInternalRPCEndpoint()
	nodeConfigs := []client.NodeConfig{
		{
			Name:    ptr(blockchainInfo.ContainerName),
			WSURL:   ptr(wsURL),
			HTTPURL: ptr(httpURL),
		},
	}
	finalityDepth := ptr(uint32(10))
	safeDepth := ptr(uint32(6))
	finalityTagEnabled := ptr(true)
	lggr.Infow("🔍 Testing multinode chain client", "chainSelector", blockchainInfo.ChainID, "wsURL", wsURL, "httpURL", httpURL)
	chainCfg, nodePool, nodes, _ := client.NewClientConfigs(selectionMode, leaseDuration, chainTypeStr, nodeConfigs,
		pollFailureThreshold, pollInterval, syncThreshold, nodeIsSyncingEnabled, noNewHeadsThreshold, finalityDepth,
		finalityTagEnabled, finalizedBlockOffset, enforceRepeatableRead, deathDeclarationDelay, noNewFinalizedBlocksThreshold,
		finalizedBlockPollInterval, newHeadsPollInterval, confirmationTimeout, safeDepth)

	idBigInt, _ := new(big.Int).SetString(blockchainInfo.ChainID, 10)

	chainClient, err := client.NewEvmClient(nodePool, chainCfg, nil, lggr, idBigInt, nodes, chaintype.ChainType(chainTypeStr))
	if err != nil {
		lggr.Errorw("Failed to create multinode chain client", "error", err)
		return nil
	}
	// defer chainClient.Close()

	lggr.Infow("✅ Multinode chain client created successfully",
		"chainID", blockchainInfo.ChainID,
		"nodeStates", chainClient.NodeStates())

	err = chainClient.Dial(ctx)
	if err != nil {
		lggr.Errorw("Failed to dial multinode chain client", "error", err)
		return nil
	}

	// Test 1: Get latest block using multinode's SelectRPC
	latestBlock, err := chainClient.LatestBlockHeight(ctx)
	if err != nil {
		lggr.Errorw("Failed to get latest block", "error", err)
		return nil
	}
	lggr.Infow("📦 Latest block (via multinode)", "blockNumber", latestBlock)

	// Test 2: Get chain ID
	chainID := chainClient.ConfiguredChainID()
	lggr.Infow("🔗 Chain ID", "chainID", chainID)

	// Test 3: Get a specific block header
	header, err := chainClient.HeadByNumber(ctx, latestBlock)
	if err != nil {
		lggr.Errorw("Failed to get block header", "error", err)
		return nil
	}
	lggr.Infow("📋 Block header",
		"number", header.Number,
		"hash", header.Hash.Hex(),
		"timestamp", header.Timestamp)

	lggr.Infow("✅ Multinode chain client tests completed successfully!", "chainID", blockchainInfo.ChainID)
	return chainClient
}
