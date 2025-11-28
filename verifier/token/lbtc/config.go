package lbtc

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
	AttestationAPIInterval  time.Duration
	AttestationAPIBatchSize int
	Verifiers               map[protocol.ChainSelector]protocol.UnknownAddress
}

func TryParsing(t, v string, data map[string]any) (*Config, error) {
	if t != "lbtc" || v != "1.0" {
		return nil, fmt.Errorf("unsupported verifier type %s and version %s", t, v)
	}

	var ok bool
	var err error
	c := &Config{}

	c.AttestationAPI, ok = data["attestation_api"].(string)
	if !ok {
		return nil, fmt.Errorf("attestation_api field is required for lbtc verifier")
	}

	c.AttestationAPITimeout, err = common.ParseDurationOrDefault(data["attestation_api_timeout"], 1*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation_api_timeout: %w", err)
	}

	c.AttestationAPIInterval, err = common.ParseDurationOrDefault(data["attestation_api_interval"], 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation_api_interval: %w", err)
	}

	c.AttestationAPIBatchSize, err = common.ParseIntOrDefault(data["attestation_api_batch_size"], 20)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation_api_batch_size: %w", err)
	}

	c.Verifiers, err = common.ParseAddressesMap(data["addresses"])
	if err != nil {
		return nil, fmt.Errorf("invalid addresses: %w", err)
	}

	return c, nil
}
