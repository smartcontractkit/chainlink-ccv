package lombard

import (
	"errors"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// ErrUnsupported marks a type/version pair this package does not handle, so a
// caller probing multiple verifier types can fall through without masking a real
// config error as "unsupported type".
var ErrUnsupported = errors.New("unsupported verifier type")

//nolint:revive // type has to be prefixed to avoid name clash in VerifierConfig
type LombardConfig struct {
	AttestationAPI string `json:"attestation_api" toml:"attestation_api"`
	// AttestationAPITimeout defines the timeout for the attestation API.
	AttestationAPITimeout time.Duration `json:"attestation_api_timeout" toml:"attestation_api_timeout"`
	// AttestationAPIInterval defines the rate in requests per second that the attestation API can be called.
	// Default set according to the APIs documented 10 requests per second rate limit.
	AttestationAPIInterval  time.Duration `json:"attestation_api_interval"   toml:"attestation_api_interval"`
	AttestationAPIBatchSize int           `json:"attestation_api_batch_size" toml:"attestation_api_batch_size"`
	// VerifierVersion is the parsed verifier version of the Lombard verifier contract.
	// Defaults to DefaultVerifierVersion if not specified.
	VerifierVersion protocol.ByteSlice `json:"verifier_version" toml:"verifier_version"`
	// VerifierResolvers is a map of chain selectors to verifier resolver addresses. It's only used for TOML marshall/unmarshall and then
	// final values, properly cast to domain values are stored in ParsedVerifierResolvers
	VerifierResolvers       map[string]any                                     `json:"verifier_resolver_addresses" toml:"verifier_resolver_addresses"`
	ParsedVerifierResolvers map[protocol.ChainSelector]protocol.UnknownAddress `json:"-"                           toml:"-"`
}

// ConfigKeys are the keys TryParsing reads from a [[token_verifiers]] entry for
// this verifier type. Entries are decoded through VerifierConfig.UnmarshalTOML,
// which consumes the whole table, so the TOML decoder reports no undecoded keys
// inside an entry — TryParsing rejects anything outside this list instead of
// letting it silently do nothing.
//
// verifier_id, type and version are read by UnmarshalTOML rather than TryParsing;
// they are listed so they are not reported as unknown.
var ConfigKeys = []string{
	"verifier_id",
	"type",
	"version",
	"verifier_version",
	"attestation_api",
	"attestation_api_timeout",
	"attestation_api_interval",
	"attestation_api_batch_size",
	"verifier_resolver_addresses",
}

func TryParsing(t, v string, data map[string]any) (*LombardConfig, error) {
	if t != "lombard" || v != "1.0" {
		return nil, fmt.Errorf("%w %s and version %s", ErrUnsupported, t, v)
	}

	if unknown := common.UnknownKeys(data, ConfigKeys); len(unknown) > 0 {
		return nil, fmt.Errorf("unknown keys for lombard verifier: %v", unknown)
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
