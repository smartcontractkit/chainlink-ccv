package types

import (
	"github.com/smartcontractkit/chainlink-ccv/common/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type VerifierConfig struct {
	VerifierID                 string                              `toml:"verifier_id"`
	AggregatorAddress          string                              `toml:"aggregator_address"`
	AggregatorAPIKey           string                              `toml:"aggregator_api_key"`
	BlockchainInfos            map[string]*protocol.BlockchainInfo `toml:"blockchain_infos"`
	PyroscopeURL               string                              `toml:"pyroscope_url"`
	CommitteeVerifierAddresses map[string]string                   `toml:"committee_verifier_addresses"`
	CcvProxyAddresses          map[string]string                   `toml:"ccv_proxy_addresses"`
	Monitoring                 monitoring.Config                   `toml:"monitoring"`
}
