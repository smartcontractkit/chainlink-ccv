package evm

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	evmconfig "github.com/smartcontractkit/chainlink-evm/pkg/config"
)

// CreateHealthyMultiNodeClient resolves the requested chain and starts its client.
//
// Deprecated: use CreateMultiNodeClientFromInfo after resolving the chain info.
// This wrapper performs no health checks beyond those performed by client.Dial.
func CreateHealthyMultiNodeClient(
	ctx context.Context,
	infos chainaccess.Infos[Info],
	lggr logger.Logger,
	chainSelector protocol.ChainSelector,
) (client.Client, error) {
	info, err := infos.GetBlockchainByChainSelector(chainSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to get blockchain info for chain selector %v: %w", chainSelector, err)
	}
	return CreateMultiNodeClientFromInfo(ctx, info, lggr)
}

// CreateMultiNodeClientFromInfo creates and starts chainlink-evm's production
// multi-node client. Every configured node is registered with the pool, allowing
// the pool to move reads and writes away from unhealthy RPCs.
func CreateMultiNodeClientFromInfo(ctx context.Context, info Info, lggr logger.Logger) (client.Client, error) {
	chainClient, _, err := newMultiNodeClientFromInfo(info, lggr)
	if err != nil {
		return nil, err
	}
	if err := chainClient.Dial(ctx); err != nil {
		chainClient.Close()
		return nil, fmt.Errorf("failed to dial EVM client for chain %s: %w", info.ChainID, err)
	}
	return chainClient, nil
}

func newMultiNodeClientFromInfo(info Info, lggr logger.Logger) (client.Client, *evmconfig.ChainScoped, error) {
	chainConfig, err := newChainlinkEVMConfig(info)
	if err != nil {
		return nil, nil, err
	}

	chainClient, err := client.NewEvmClient(
		chainConfig.EVM().NodePool(),
		chainConfig.EVM(),
		chainConfig.EVM().NodePool().Errors(),
		lggr,
		chainConfig.EVM().ChainID(),
		chainConfig.Nodes(),
		chainConfig.EVM().ChainType(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create EVM client for chain %s: %w", info.ChainID, err)
	}

	lggr.Infow("Created production multi-node EVM client",
		"chainID", info.ChainID,
		"nodeCount", len(chainConfig.Nodes()),
		"selectionMode", chainConfig.EVM().NodePool().SelectionMode(),
	)
	return chainClient, chainConfig, nil
}
