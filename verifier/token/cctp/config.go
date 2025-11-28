package cctp

import (
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type Config struct {
	AttestationAPI string
	// AttestationAPITimeout defines the timeout for the attestation API.
	AttestationAPITimeout time.Duration
	// AttestationAPIInterval defines the rate in requests per second that the attestation API can be called.
	// Default set according to the APIs documentated 10 requests per second rate limit.
	AttestationAPIInterval time.Duration
	// AttestationAPICooldown defines in what time it is allowed to make next call to API.
	// Activates when plugin hits API's rate limits
	AttestationAPICooldown time.Duration

	Verifiers map[protocol.ChainSelector]protocol.UnknownAddress
}

func TryParsing(t, v string, data map[string]any) (*Config, error) {
	if t != "cctp" || v != "2.0" {
		return nil, fmt.Errorf("unsupported verifier type %s and version %s", t, v)
	}

	var ok bool
	var err error
	c := &Config{}

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

	c.Verifiers, err = common.ParseAddressesMap(data["addresses"])
	if err != nil {
		return nil, fmt.Errorf("invalid addresses: %w", err)
	}

	return c, nil
}
