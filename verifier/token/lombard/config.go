package lombard

import (
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

//nolint:revive // type has to be prefixed to avoid name clash in VerifierConfig
type LombardConfig struct {
	AttestationAPI string `json:"attestation_api" toml:"attestation_api"`
	// AttestationAPITimeout defines the timeout for the attestation API.
	AttestationAPITimeout time.Duration `json:"attestation_api_timeout" toml:"attestation_api_timeout"`
	// AttestationAPIInterval defines the rate in requests per second that the attestation API can be called.
	// Default set according to the APIs documentated 10 requests per second rate limit.
	AttestationAPIInterval  time.Duration `json:"attestation_api_interval"   toml:"attestation_api_interval"`
	AttestationAPIBatchSize int           `json:"attestation_api_batch_size" toml:"attestation_api_batch_size"`
	// VerifierVersion is the hex-encoded version of the Lombard verifier contract (must start with 0x prefix).
	// Defaults to DefaultVerifierVersionHex if not specified.
	VerifierVersion string `json:"verifier_version" toml:"verifier_version"`
	// VerifierResolvers is a map of chain selectors to verifier resolver addresses. It's only used for TOML marshall/unmarshall and then
	// final values, properly cast to domain values are stored in ParsedVerifierResolvers
	VerifierResolvers       map[string]any                                     `json:"verifier_resolver_addresses" toml:"verifier_resolver_addresses"`
	ParsedVerifierResolvers map[protocol.ChainSelector]protocol.UnknownAddress `json:"-"                           toml:"-"`
}

func TryParsing(t, v string, data map[string]any) (*LombardConfig, error) {
	if t != "lombard" || v != "1.0" {
		return nil, fmt.Errorf("unsupported verifier type %s and version %s", t, v)
	}

	var ok bool
	var err error
	c := &LombardConfig{}

	c.AttestationAPI, ok = data[("attestation_api")].(string)
	if !ok {
		return nil, fmt.Errorf("attestation_api field is required for lombard verifier")
	}

	c.AttestationAPITimeout, err = common.ParseDurationOrDefault(data[("attestation_api_timeout")], 1*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation_api_timeout: %w", err)
	}

	c.AttestationAPIInterval, err = common.ParseDurationOrDefault(data[("attestation_api_interval")], 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation_api_interval: %w", err)
	}

	c.AttestationAPIBatchSize, err = common.ParseIntOrDefault(data[("attestation_api_batch_size")], 20)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation_api_batch_size: %w", err)
	}

	c.ParsedVerifierResolvers, c.VerifierResolvers, err = common.ParseAddressesMap(data[("verifier_resolver_addresses")])
	if err != nil {
		return nil, fmt.Errorf("invalid verifier_resolver_addresses: %w", err)
	}

	// Parse verifier version hex, default to DefaultVerifierVersionHex if not specified
	if verifierVersionHex, ok := data["verifier_version"].(string); ok {
		c.VerifierVersion = verifierVersionHex
	} else {
		c.VerifierVersion = DefaultVerifierVersionHex
	}

	return c, nil
}

// ParsedVerifierVersion converts the hex-encoded verifier version to ByteSlice.
func (c *LombardConfig) ParsedVerifierVersion() (protocol.ByteSlice, error) {
	return protocol.NewByteSliceFromHex(c.VerifierVersion)
}
