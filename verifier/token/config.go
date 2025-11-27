package token

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/cctp"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/lbtc"
)

type Config struct {
	VerifierID    string `toml:"verifier_id"`
	SignerAddress string `toml:"signer_address"`

	// TODO: remove from verifier config, readers need to be initialized separately.
	BlockchainInfos map[string]*protocol.BlockchainInfo `toml:"blockchain_infos"`
	PyroscopeURL    string                              `toml:"pyroscope_url"`
	// OnRampAddresses is a map the addresses of the on ramps for each chain selector.
	OnRampAddresses map[string]string `toml:"on_ramp_addresses"`
	// RMNRemoteAddresses is a map of RMN Remote contract addresses for each chain selector.
	// Required for curse detection.
	RMNRemoteAddresses map[string]string         `toml:"rmn_remote_addresses"`
	TokenVerifiers     []VerifierConfig          `toml:"token_verifiers"`
	Monitoring         verifier.MonitoringConfig `toml:"monitoring"`
}

const (
	CCTPHandlerType = "cctp"
	LBTCHandlerType = "lbtc"
)

// VerifierConfig is the base struct for token data observers. Every token data observer
// has to define its type and version. The type and version is used to determine which observer's
// implementation to use. Whenever you want to add a new observer type, you need to add a new struct and embed that
// in the VerifierConfig similarly to how CCTPConfig is embedded in the VerifierConfig.
// There are two additional checks for the VerifierConfig to enforce that it's semantically (Validate)
// and syntactically correct (WellFormed).
type VerifierConfig struct {
	// Type is the type of the token data observer. You can think of different token data observers as different
	// strategies for processing token data. For example, you can have a token data observer for USDC tokens using CCTP
	// and different one for processing LINK token.
	Type string `toml:"type"`
	// Version is the version of the TokenObserverConfig and the matching Observer implementation for that config.
	// This is used to determine which version of the observer to use. Right now, we only have one version
	// of the observer, but in the future, we might have multiple versions.
	// This is a precautionary measure to ensure that we can upgrade the observer without breaking the existing ones.
	// Example would be CCTPv1 using AttestationAPI and CCTPv2 using a different API or completely
	// different strategy which requires different configuration and implementation during Observation phase.
	// [
	//  {
	//    "type": "cctp-cctp",
	//    "version": "1.0",
	//    "attestationAPI": "http://circle.com/attestation",
	//    "attestationAPITimeout": "1s",
	//    "attestationAPIIntervalMilliseconds": "500ms"
	//  },
	//  {
	//    "type": "cctp-cctp",
	//    "version": "2.0",
	//    "customCirlceAPI": "http://cirle.com/gohere",
	//    "yetAnotherAPI": "http://cirle.com/anotherone",
	//    "customCircleAPITimeout": "1s",
	//    "yetAnotherAPITimeout": "500ms"
	//  }
	//]
	// Having version in that JSON isn't expensive, but it could reduce the risk of breaking the observers in the future.
	Version string `toml:"version"`

	cctp *cctp.Config
	lbtc *lbtc.Config
}

func (o *VerifierConfig) UnmarshalTOML(data any) error {
	castedData, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("expected map[string]any, got %T", castedData)
	}

	if v, ok := castedData["type"].(string); ok {
		o.Type = v
	} else {
		return fmt.Errorf("type field is required for VerifierConfig")
	}

	if v, ok := castedData["version"].(string); ok {
		o.Version = v
	} else {
		return fmt.Errorf("version field is required for VerifierConfig")
	}

	if cctpConfig, err := cctp.TryParsing(o.Type, o.Version, castedData); err == nil {
		o.cctp = cctpConfig
		return nil
	}

	if lbtcConfig, err := lbtc.TryParsing(o.Type, o.Version, castedData); err == nil {
		o.lbtc = lbtcConfig
		return nil
	}

	return fmt.Errorf("unsupported verifier type %s and version %s", o.Type, o.Version)
}
