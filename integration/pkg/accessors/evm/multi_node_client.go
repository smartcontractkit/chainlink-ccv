package evm

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	clevmconfig "github.com/smartcontractkit/chainlink-evm/pkg/config"
)

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

func newMultiNodeClientFromInfo(info Info, lggr logger.Logger) (client.Client, *clevmconfig.ChainScoped, error) {
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
