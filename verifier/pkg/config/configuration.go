package config

import (
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal"
)

type Configuration struct {
	AggregatorAddress string                              `toml:"aggregator_address"`
	BlockchainInfos   map[string]*internal.BlockchainInfo `toml:"blockchain_infos"`
}
