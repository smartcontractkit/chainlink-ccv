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

	c := &Config{}
	if v, ok := data["attestation_api"].(string); ok {
		c.AttestationAPI = v
	} else {
		return nil, fmt.Errorf("attestation_api field is required for lbtc verifier")
	}

	if v, err := common.ParseDurationOrDefault(data["attestation_api_timeout"], 5*time.Second); err == nil {
		c.AttestationAPITimeout = v
	} else {
		return nil, fmt.Errorf("invalid attestation_api_timeout: %w", err)
	}

	if v, err := common.ParseDurationOrDefault(data["attestation_api_interval"], 100*time.Millisecond); err == nil {
		c.AttestationAPIInterval = v
	} else {
		return nil, fmt.Errorf("invalid attestation_api_interval: %w", err)
	}

	if v, err := common.ParseIntOrDefault(data["attestation_api_batch_size"], 20); err == nil {
		c.AttestationAPIBatchSize = v
	} else {
		return nil, fmt.Errorf("invalid attestation_api_batch_size: %w", err)
	}

	if result, err := common.ParseAddressesMap(data["addresses"]); err == nil {
		c.Verifiers = result
	} else {
		return nil, fmt.Errorf("invalid addresses: %w", err)
	}

	return c, nil
}
