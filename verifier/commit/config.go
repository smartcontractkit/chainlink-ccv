package commit

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

type ConfigWithBlockchainInfos struct {
	Config
	BlockchainInfos map[string]*protocol.BlockchainInfo `toml:"blockchain_infos"`
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
	RMNRemoteAddresses map[string]string         `toml:"rmn_remote_addresses"`
	Monitoring         verifier.MonitoringConfig `toml:"monitoring"`
}

func (c *Config) Validate() error {
	// Collect chain selectors as sets (map[string]struct{})
	onRampSet := make(map[string]struct{})
	for k := range c.OnRampAddresses {
		onRampSet[k] = struct{}{}
	}
	committeeVerifierSet := make(map[string]struct{})
	for k := range c.CommitteeVerifierAddresses {
		committeeVerifierSet[k] = struct{}{}
	}
	rmnRemoteSet := make(map[string]struct{})
	for k := range c.RMNRemoteAddresses {
		rmnRemoteSet[k] = struct{}{}
	}

	// Compare set lengths first
	if len(onRampSet) != len(committeeVerifierSet) ||
		len(onRampSet) != len(rmnRemoteSet) {
		return fmt.Errorf("invalid verifier configuration, mismatched chain selectors for onramp, committee verifier, and RMN Remote addresses")
	}

	// Compare set values (they should all be equal)
	for k := range onRampSet {
		if _, ok := committeeVerifierSet[k]; !ok {
			return fmt.Errorf("invalid verifier configuration, chain selector in onramp (%s) not in committee verifier addresses", k)
		}
		if _, ok := rmnRemoteSet[k]; !ok {
			return fmt.Errorf("invalid verifier configuration, chain selector in onramp (%s) not in RMN Remote addresses", k)
		}
	}
	for k := range committeeVerifierSet {
		if _, ok := onRampSet[k]; !ok {
			return fmt.Errorf("invalid verifier configuration, chain selector in committee verifier (%s) not in onramp addresses", k)
		}
		if _, ok := rmnRemoteSet[k]; !ok {
			return fmt.Errorf("invalid verifier configuration, chain selector in committee verifier (%s) not in RMN Remote addresses", k)
		}
	}
	for k := range rmnRemoteSet {
		if _, ok := onRampSet[k]; !ok {
			return fmt.Errorf("invalid verifier configuration, chain selector in RMN Remote (%s) not in onramp addresses", k)
		}
		if _, ok := committeeVerifierSet[k]; !ok {
			return fmt.Errorf("invalid verifier configuration, chain selector in RMN Remote (%s) not in committee verifier addresses", k)
		}
	}

	return nil
}
