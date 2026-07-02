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
	// Retry wait time for when attestation is not in a ready state.
	AttestationNotReadyRetry time.Duration `json:"attestation_not_ready_retry" toml:"attestation_not_ready_retry"`
	// Retry wait time for generic errors (all errors not due to attestation not being ready)
	AttestationGenericErrorRetry time.Duration `json:"attestation_generic_error_retry" toml:"attestation_generic_error_retry"`
	// Number of concurrent workers to be used to fetch and verify attestations.
	AttestationConcurrentFetchers int `json:"attestation_concurrent_fetchers" toml:"attestation_concurrent_fetchers,omitzero"`
	// VerifierVersion is the parsed verifier version of the CCTP verifier contract.
	// Defaults to DefaultVerifierVersion if not specified.
	VerifierVersion protocol.ByteSlice `json:"verifier_version" toml:"verifier_version"`
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

	c.AttestationNotReadyRetry, err = common.ParseDurationOrDefault(data["attestation_not_ready_retry"], 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation_not_ready_retry: %w", err)
	}

	c.AttestationGenericErrorRetry, err = common.ParseDurationOrDefault(data["attestation_generic_error_retry"], 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation_generic_error_retry: %w", err)
	}

	c.AttestationConcurrentFetchers, err = common.ParseIntOrDefault(data["attestation_concurrent_fetchers"], 10)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation_concurrent_fetchers: %w", err)
	}
	// Stops 0 fetchers being set which would block attestation fetching and verification.
	if c.AttestationConcurrentFetchers <= 0 {
		return nil, fmt.Errorf("attestation_concurrent_fetchers must be greater than 0, got %d", c.AttestationConcurrentFetchers)
	}

	c.ParsedVerifierResolvers, c.VerifierResolvers, err = common.ParseAddressesMap(data["verifier_resolver_addresses"])
	if err != nil {
		return nil, fmt.Errorf("invalid verifier_resolver_addresses: %w", err)
	}

	c.ParsedVerifiers, c.Verifiers, err = common.ParseAddressesMap(data["verifier_addresses"])
	if err != nil {
		return nil, fmt.Errorf("invalid verifier_addresses: %w", err)
	}

	// Parse verifier version hex, default to DefaultVerifierVersion if not specified
	if verifierVersionHex, ok := data["verifier_version"].(string); ok {
		c.VerifierVersion, err = protocol.NewByteSliceFromHex(verifierVersionHex)
		if err != nil {
			return nil, fmt.Errorf("invalid verifier_version: %w", err)
		}
	} else {
		c.VerifierVersion = DefaultVerifierVersion
	}

	return c, nil
}
