package types

import (
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type VerifierConfig struct {
	AggregatorAddress          string                              `toml:"aggregator_address"`
	PrivateKey                 string                              `toml:"private_key"`
	BlockchainInfos            map[string]*protocol.BlockchainInfo `toml:"blockchain_infos"`
	PyroscopeURL               string                              `toml:"pyroscope_url"`
	CommitteeVerifierAddresses map[string]string                   `toml:"committee_verifier_addresses"`
	CcvProxyAddresses          map[string]string                   `toml:"ccv_proxy_addresses"`
}
