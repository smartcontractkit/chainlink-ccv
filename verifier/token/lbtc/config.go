package lbtc

import (
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

//nolint:revive // type has to be prefixed to avoid name clash in VerifierConfig
type LBTCConfig struct {
	AttestationAPI string `toml:"attestation_api"`
	// AttestationAPITimeout defines the timeout for the attestation API.
	AttestationAPITimeout time.Duration `toml:"attestation_api_timeout"`
	// AttestationAPIInterval defines the rate in requests per second that the attestation API can be called.
	// Default set according to the APIs documentated 10 requests per second rate limit.
	AttestationAPIInterval  time.Duration `toml:"attestation_api_interval"`
	AttestationAPIBatchSize int           `toml:"attestation_api_batch_size"`
	// Verifiers is a map of chain selectors to verifier addresses. It's only used for TOML marshall/unmarshall and then
	// final values, properly cast to domain values are stored in ParsedVerifiers
	Verifiers       map[string]any                                     `toml:"addresses"`
	ParsedVerifiers map[protocol.ChainSelector]protocol.UnknownAddress `toml:"-"`
}

func TryParsing(t, v string, data map[string]any) (*LBTCConfig, error) {
	if t != "lbtc" || v != "1.0" {
		return nil, fmt.Errorf("unsupported verifier type %s and version %s", t, v)
	}

	var ok bool
	var err error
	c := &LBTCConfig{}

	c.AttestationAPI, ok = data[("attestation_api")].(string)
	if !ok {
		return nil, fmt.Errorf("attestation_api field is required for lbtc verifier")
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

	c.ParsedVerifiers, c.Verifiers, err = common.ParseAddressesMap(data[("addresses")])
	if err != nil {
		return nil, fmt.Errorf("invalid addresses: %w", err)
	}

	return c, nil
}
