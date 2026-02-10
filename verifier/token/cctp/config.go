package cctp

import (
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

//nolint:revive // type has to be prefixed to avoid name clash in VerifierConfig
type CCTPConfig struct {
	AttestationAPI string `json:"attestation_api" toml:"attestation_api"`
	// AttestationAPITimeout defines the timeout for the attestation API.
	AttestationAPITimeout time.Duration `json:"attestation_api_timeout" toml:"attestation_api_timeout"`
	// AttestationAPIInterval defines the rate in requests per second that the attestation API can be called.
	// Default set according to the APIs documentated 10 requests per second rate limit.
	AttestationAPIInterval time.Duration `json:"attestation_api_interval" toml:"attestation_api_interval"`
	// AttestationAPICooldown defines in what time it is allowed to make next call to API.
	// Activates when plugin hits API's rate limits
	AttestationAPICooldown time.Duration `json:"attestation_api_cooldown" toml:"attestation_api_cooldown"`
	// Verifiers is a map of chain selectors to verifier addresses. It's only used for TOML marshall/unmarshall and then
	// final values, properly cast to domain values are stored in ParsedVerifiers
	// That configuration field is required to match against messageSender from the CCTPMessage returned from AttestationAPI
	Verifiers       map[string]any                                     `json:"verifier_addresses" toml:"verifier_addresses"`
	ParsedVerifiers map[protocol.ChainSelector]protocol.UnknownAddress `json:"-"                  toml:"-"`
	// VerifierResolvers is a map of chain selectors to verifier resolver addresses. It's only used for TOML marshall/unmarshall and then
	// final values, properly cast to domain values are stored in ParsedVerifierResolvers
	VerifierResolvers       map[string]any                                     `json:"verifier_resolver_addresses" toml:"verifier_resolver_addresses"`
	ParsedVerifierResolvers map[protocol.ChainSelector]protocol.UnknownAddress `json:"-"                           toml:"-"`
}

func TryParsing(t, v string, data map[string]any) (*CCTPConfig, error) {
	if t != "cctp" || v != "2.0" {
		return nil, fmt.Errorf("unsupported verifier type %s and version %s", t, v)
	}

	var ok bool
	var err error
	c := &CCTPConfig{}

	c.AttestationAPI, ok = data["attestation_api"].(string)
	if !ok {
		return nil, fmt.Errorf("attestation_api field is required for cctp verifier")
	}

	c.AttestationAPITimeout, err = common.ParseDurationOrDefault(data["attestation_api_timeout"], 1*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation_api_timeout: %w", err)
	}

	c.AttestationAPIInterval, err = common.ParseDurationOrDefault(data["attestation_api_interval"], 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation_api_interval: %w", err)
	}

	c.AttestationAPICooldown, err = common.ParseDurationOrDefault(data["attestation_api_cooldown"], 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation_api_cooldown: %w", err)
	}

	c.ParsedVerifierResolvers, c.VerifierResolvers, err = common.ParseAddressesMap(data["verifier_resolver_addresses"])
	if err != nil {
		return nil, fmt.Errorf("invalid verifier_resolver_addresses: %w", err)
	}

	c.ParsedVerifiers, c.Verifiers, err = common.ParseAddressesMap(data["verifier_addresses"])
	if err != nil {
		return nil, fmt.Errorf("invalid verifier_addresses: %w", err)
	}

	return c, nil
}
