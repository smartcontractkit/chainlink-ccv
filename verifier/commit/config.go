package commit

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

type ConfigWithBlockchainInfos struct {
	Config
	BlockchainInfos map[string]*blockchain.Info `toml:"blockchain_infos"`
}

type StellarReaderConfig struct {
	// NetworkPassphrase is the Stellar network passphrase.
	NetworkPassphrase string `toml:"network_passphrase"`
	// FriendbotURL is the Stellar friendbot URL.
	FriendbotURL string `toml:"friendbot_url"`
	// SorobanRPCURL is the Stellar Soroban RPC URL.
	SorobanRPCURL string `toml:"soroban_rpc_url"`
	// OnRampContractID is the contract ID of the Stellar OnRamp contract.
	OnRampContractID string `toml:"onramp_contract_id"`
}

// StellarConfig is the configuration required for verifiers that read from Stellar.
type StellarConfig struct {
	// TODO: need a better way to do this, this overloads the StellarNetworkInfo struct.
	ReaderConfig StellarReaderConfig `toml:"reader_config"`
}

type Config struct {
	VerifierID        string `toml:"verifier_id"`
	AggregatorAddress string `toml:"aggregator_address"`
	// InsecureAggregatorConnection disables TLS for the aggregator gRPC connection.
	// Only use this for testing when custom certificates cannot be injected.
	InsecureAggregatorConnection bool `toml:"insecure_aggregator_connection"`

	SignerAddress string `toml:"signer_address"`

	PyroscopeURL string `toml:"pyroscope_url"`
	// CommitteeVerifierAddresses is a map the addresses of the committee verifiers for each chain selector.
	CommitteeVerifierAddresses map[string]string `toml:"committee_verifier_addresses"`
	// OnRampAddresses is a map the addresses of the on ramps for each chain selector.
	OnRampAddresses map[string]string `toml:"on_ramp_addresses"`
	// DefaultExecutorOnRampAddresses is a map the addresses of the default executor on ramps for each chain selector.
	// The committee verifier will verify messages that specify the default executor even if they don't
	// specify the committee verifier.
	DefaultExecutorOnRampAddresses map[string]string `toml:"default_executor_on_ramp_addresses"`
	// RMNRemoteAddresses is a map of RMN Remote contract addresses for each chain selector.
	// Required for curse detection.
	RMNRemoteAddresses map[string]string `toml:"rmn_remote_addresses"`
	// DisableFinalityCheckers is a list of chain selectors for which the finality violation checker should be disabled.
	// The chain selectors are formatted as strings of the chain selector.
	DisableFinalityCheckers []string                  `toml:"disable_finality_checkers"`
	Monitoring              verifier.MonitoringConfig `toml:"monitoring"`
}

func (c *Config) Validate() error {
	// Compare map lengths first
	if len(c.OnRampAddresses) != len(c.CommitteeVerifierAddresses) ||
		len(c.OnRampAddresses) != len(c.RMNRemoteAddresses) {
		return fmt.Errorf(
			"invalid verifier configuration, mismatched lengths for onramp (%d), committee verifier (%d), and RMN Remote addresses (%d)",
			len(c.OnRampAddresses),
			len(c.CommitteeVerifierAddresses),
			len(c.RMNRemoteAddresses),
		)
	}

	// Compare map keys (they should all be equal)
	// Since lengths are equal, checking if all keys from one map exist in the others is sufficient.
	for k := range c.OnRampAddresses {
		if _, ok := c.CommitteeVerifierAddresses[k]; !ok {
			return fmt.Errorf("invalid verifier configuration, chain selector in onramp (%s) not in committee verifier addresses", k)
		}
		if _, ok := c.RMNRemoteAddresses[k]; !ok {
			return fmt.Errorf("invalid verifier configuration, chain selector in onramp (%s) not in RMN Remote addresses", k)
		}
	}

	return nil
}
