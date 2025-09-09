package config

import (
	"github.com/smartcontractkit/chainlink-ccv/common/pkg/types"
)

type Configuration struct {
	AggregatorAddress string                           `toml:"aggregator_address"`
	BlockchainInfos   map[string]*types.BlockchainInfo `toml:"blockchain_infos"`
}
