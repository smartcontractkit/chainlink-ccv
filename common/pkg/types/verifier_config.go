package types

import (
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type VerifierConfig struct {
	AggregatorAddress  string                              `toml:"aggregator_address"`
	AggregatorAPIKey   string                              `toml:"aggregator_api_key"`
	PrivateKey         string                              `toml:"private_key"`
	BlockchainInfos    map[string]*protocol.BlockchainInfo `toml:"blockchain_infos"`
	VerifierOnRamp1337 string                              `toml:"verifier_on_ramp_1337"`
	VerifierOnRamp2337 string                              `toml:"verifier_on_ramp_2337"`
	CCVProxy1337       string                              `toml:"ccv_proxy_1337"`
	CCVProxy2337       string                              `toml:"ccv_proxy_2337"`
	PyroscopeURL       string                              `toml:"pyroscope_url"`
}
