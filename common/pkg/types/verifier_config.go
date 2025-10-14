package types

import (
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/config"
)

type VerifierConfig struct {
	VerifierID                 string                              `toml:"verifier_id"`
	AggregatorAddress          string                              `toml:"aggregator_address"`
	AggregatorAPIKey           string                              `toml:"aggregator_api_key"`
	AggregatorSecretKey        string                              `toml:"aggregator_secret_key"`
	BlockchainInfos            map[string]*protocol.BlockchainInfo `toml:"blockchain_infos"`
	PyroscopeURL               string                              `toml:"pyroscope_url"`
	CommitteeVerifierAddresses map[string]string                   `toml:"committee_verifier_addresses"`
	CcvProxyAddresses          map[string]string                   `toml:"ccv_proxy_addresses"`
	Monitoring                 config.MonitoringConfig             `toml:"monitoring"`
}
