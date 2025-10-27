package clnode

import (
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

// CCVConfig holds the configuration needed to configure the CCV services.
type CCVConfig struct {
	Verifier verifier.Config
	Executor executor.Configuration

	ChainConfigs map[protocol.ChainSelector]ChainConfig
}

// ChainConfig holds chain-specific configurations.
type ChainConfig struct {
	CCVAggregatorAddress string
	CCVProxyAddress      string
	CCVCommitteeAddress  string
}

type VerifierSecrets struct {
	SigningKey string
}
type CCVSecretsConfig struct {
	Verifier VerifierSecrets
}
