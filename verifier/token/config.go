package token

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/cctp"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/lombard"
)

type ConfigWithBlockchainInfos struct {
	Config
	BlockchainInfos map[string]*blockchain.Info `toml:"blockchain_infos"`
}

type Config struct {
	PyroscopeURL string `toml:"pyroscope_url"`
	// OnRampAddresses is a map the addresses of the on ramps for each chain selector.
	OnRampAddresses map[string]string `toml:"on_ramp_addresses"`
	// RMNRemoteAddresses is a map of RMN Remote contract addresses for each chain selector.
	// Required for curse detection.
	RMNRemoteAddresses map[string]string `toml:"rmn_remote_addresses"`
	// TokenVerifiers is a list of token verifier configurations. Each entry defines a token verifier instance with its own type, version and configuration.
	TokenVerifiers []VerifierConfig `toml:"token_verifiers"`
	// Monitoring contains the monitoring configuration for the token verifier, including Beholder settings.
	Monitoring verifier.MonitoringConfig `toml:"monitoring"`
}

// VerifierConfig is the base struct for token verifiers. Every token data verifier
// has to define its type and version. The type and version is used to determine which verifier's
// implementation to use. Whenever you want to add a new token verifier type, you need to add a new struct and embed that
// in the VerifierConfig similarly to how cctp.Config is embedded in the VerifierConfig.
type VerifierConfig struct {
	// VerifierID is the unique identifier for this token verifier instance.
	// This allows multiple token verifiers to run on the same node with isolated state.
	VerifierID string `toml:"verifier_id"`
	// Type is the type of the token verifier. You can think of different token verifiers as different
	// strategies for processing token data. For example, you can have a token verifiers for USDC tokens using CCTP
	// and different one for processing LINK token.
	Type string `toml:"type"`
	// Version is the version of the token.VerifierConfig and the matching verifier.Verifier implementation for that config.
	// This is used to determine which version of the verifier to use. Right now, we only have one version
	// of the verifier, but in the future, we might have multiple versions.
	// This is a precautionary measure to ensure that we can upgrade the verifier without breaking the existing ones.
	// Example would be CCTPv1 using AttestationAPI and CCTPv2 using a different API or completely
	// different strategy which requires different configuration and implementation during Verification phase.
	//
	// Example JSON representation (but any format would work, as long proper marshall/unmarshall is implemented):
	// [
	//  {
	//    "type": "cctp",
	//    "version": "2.0",
	//    "attestationAPI": "http://circle.com/attestation",
	//    "attestationAPITimeout": "1s",
	//    "attestationAPIIntervalMilliseconds": "500ms"
	//  },
	//  {
	//    "type": "lombard",
	//    "version": "1.0",
	//    "attestationAPI": "http://lombard.com/gohere",
	//    "attestationAPITimeout": "1s",
	//    "attestationAPIIntervalMilliseconds": "500ms"
	//  }
	// ]
	// Having version in that JSON isn't expensive, but it could reduce the risk of breaking the observers in the future.
	Version string `toml:"version"`

	*cctp.CCTPConfig
	*lombard.LombardConfig
}

func (o *VerifierConfig) IsLombard() bool {
	return o.LombardConfig != nil
}

func (o *VerifierConfig) IsCCTP() bool {
	return o.CCTPConfig != nil
}

func (o *VerifierConfig) UnmarshalTOML(data any) error {
	castedData, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("expected map[string]any, got %T", castedData)
	}

	o.VerifierID, ok = castedData["verifier_id"].(string)
	if !ok {
		return fmt.Errorf("verifier_id field is required for VerifierConfig")
	}

	o.Type, ok = castedData["type"].(string)
	if !ok {
		return fmt.Errorf("type field is required for VerifierConfig")
	}

	o.Version, ok = castedData["version"].(string)
	if !ok {
		return fmt.Errorf("version field is required for VerifierConfig")
	}

	var err error
	o.CCTPConfig, err = cctp.TryParsing(o.Type, o.Version, castedData)
	if err == nil {
		return nil
	}

	o.LombardConfig, err = lombard.TryParsing(o.Type, o.Version, castedData)
	if err == nil {
		return nil
	}

	return fmt.Errorf("unsupported verifier type %s and version %s", o.Type, o.Version)
}
