package verifier_config

import (
	"github.com/smartcontractkit/chainlink-ccv/common/pkg/types"
)

type Configuration struct {
	AggregatorAddress          string                           `toml:"aggregator_address"`
	PrivateKey                 string                           `toml:"private_key"`
	BlockchainInfos            map[string]*types.BlockchainInfo `toml:"blockchain_infos"`
	CCVProxy1337               string                           `toml:"ccv_proxy_1337"`
	CCVProxy2337               string                           `toml:"ccv_proxy_2337"`
	ChainlinkOnrampAddress1337 string                           `toml:"chainlink_onramp_address_1337"`
	ChainlinkOnrampAddress2337 string                           `toml:"chainlink_onramp_address_2337"`
}
