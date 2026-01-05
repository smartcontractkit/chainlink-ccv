package pricer

import (
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	evmconfig "github.com/smartcontractkit/chainlink-evm/pkg/config"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
)

// TODO: Move this to chainlink-evm/pkg/client.
func NewEvmClientFromConfig(cfg evmtoml.EVMConfig, lggr logger.Logger) (client.Client, error) {
	chainID := cfg.ChainID.ToInt()
	chainCfg := &evmconfig.EVMConfig{C: &cfg}
	nodePoolCfg := &evmconfig.NodePoolConfig{C: cfg.Chain.NodePool}

	return client.NewEvmClient(
		nodePoolCfg,
		chainCfg,
		nil, // clientErrors
		lggr,
		chainID,
		cfg.Nodes,
		cfg.Chain.ChainType.ChainType(),
	)
}
