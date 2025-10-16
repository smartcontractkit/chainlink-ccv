package clnode

import "github.com/smartcontractkit/chainlink-ccv/protocol"

// CCVConfig holds the configuration needed to configure the CCV services.
type CCVConfig struct {
	IndexerAddress string

	CommitteeAggregatorAddress string

	ChainConfigs map[protocol.ChainSelector]ChainConfig
}

// ChainConfig holds chain specific configurations.
type ChainConfig struct {
	CCVAggregatorAddress string
	CCVProxyAddress      string
	CCVCommitteeAddress  string
}
