package zk

import (
	"fmt"
	"strconv"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

//nolint:revive // type has to be prefixed to avoid name clash in VerifierConfig
type ZKConfig struct {
	// NotProvenRetry is the retry wait time while the light client holds no block at or above the message block.
	NotProvenRetry time.Duration `json:"not_proven_retry" toml:"not_proven_retry"`
	// VerifierVersion is the parsed verifier version of the SuccinctZKVerifier contract.
	// Defaults to DefaultVerifierVersion if not specified.
	VerifierVersion protocol.ByteSlice `json:"verifier_version" toml:"verifier_version"`
	// VerifierResolvers is a map of chain selectors to verifier resolver addresses. It's only used for TOML marshall/unmarshall and then
	// final values, properly cast to domain values are stored in ParsedVerifierResolvers
	VerifierResolvers       map[string]any                                     `json:"verifier_resolver_addresses" toml:"verifier_resolver_addresses"`
	ParsedVerifierResolvers map[protocol.ChainSelector]protocol.UnknownAddress `json:"-"                           toml:"-"`
	// Lanes lists the source and destination chain pairs the verifier serves. It's only used for TOML marshall/unmarshall and then
	// final values, properly cast to domain values are stored in ParsedLanes
	Lanes       []LaneConfig `json:"lanes" toml:"lanes"`
	ParsedLanes []Lane       `json:"-"     toml:"-"`
}

// LaneConfig is the TOML shape of one lane. Chain selectors are strings because they exceed the TOML integer range.
type LaneConfig struct {
	SourceChainSelector string `json:"source_chain_selector" toml:"source_chain_selector"`
	DestChainSelector   string `json:"dest_chain_selector"   toml:"dest_chain_selector"`
	// LightClient is the address of the light client contract on the destination chain that proves source chain blocks.
	LightClient string `json:"light_client" toml:"light_client"`
}

// Lane is one parsed source and destination chain pair.
type Lane struct {
	SourceChainSelector protocol.ChainSelector
	DestChainSelector   protocol.ChainSelector
	LightClient         protocol.UnknownAddress
}

func TryParsing(t, v string, data map[string]any) (*ZKConfig, error) {
	if t != "zk" || v != "1.0" {
		return nil, fmt.Errorf("unsupported verifier type %s and version %s", t, v)
	}

	var err error
	c := &ZKConfig{}

	c.NotProvenRetry, err = common.ParseDurationOrDefault(data["not_proven_retry"], 60*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid not_proven_retry: %w", err)
	}

	c.ParsedVerifierResolvers, c.VerifierResolvers, err = common.ParseAddressesMap(data["verifier_resolver_addresses"])
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
	// The contract reads a fixed size version tag in front of the witness.
	if len(c.VerifierVersion) != verifierVersionBytes {
		return nil, fmt.Errorf("verifier_version must be %d bytes, got %d", verifierVersionBytes, len(c.VerifierVersion))
	}

	c.Lanes, c.ParsedLanes, err = parseLanes(data["lanes"])
	if err != nil {
		return nil, fmt.Errorf("invalid lanes: %w", err)
	}

	// The storage writer stamps the resolver address of both chains on every result. A lane without them stores
	// results the indexer and executor cannot match.
	for _, lane := range c.ParsedLanes {
		for _, selector := range []protocol.ChainSelector{lane.SourceChainSelector, lane.DestChainSelector} {
			if _, ok := c.ParsedVerifierResolvers[selector]; !ok {
				return nil, fmt.Errorf("verifier_resolver_addresses has no entry for lane chain %d", selector)
			}
		}
	}

	return c, nil
}

func parseLanes(val any) ([]LaneConfig, []Lane, error) {
	raw, ok := val.([]map[string]any)
	if !ok || len(raw) == 0 {
		return nil, nil, fmt.Errorf("at least one lane is required for zk verifier")
	}

	configs := make([]LaneConfig, 0, len(raw))
	lanes := make([]Lane, 0, len(raw))
	seen := make(map[LaneKey]struct{}, len(raw))
	for i, entry := range raw {
		config, lane, err := parseLane(entry)
		if err != nil {
			return nil, nil, fmt.Errorf("lane %d: %w", i, err)
		}
		key := LaneKey{SourceChainSelector: lane.SourceChainSelector, DestChainSelector: lane.DestChainSelector}
		if _, exists := seen[key]; exists {
			return nil, nil, fmt.Errorf("lane %d: duplicate lane from chain %d to chain %d", i, lane.SourceChainSelector, lane.DestChainSelector)
		}
		seen[key] = struct{}{}
		configs = append(configs, config)
		lanes = append(lanes, lane)
	}
	return configs, lanes, nil
}

func parseLane(entry map[string]any) (LaneConfig, Lane, error) {
	var config LaneConfig
	var lane Lane
	var err error

	config.SourceChainSelector, lane.SourceChainSelector, err = parseSelector(entry["source_chain_selector"])
	if err != nil {
		return LaneConfig{}, Lane{}, fmt.Errorf("invalid source_chain_selector: %w", err)
	}

	config.DestChainSelector, lane.DestChainSelector, err = parseSelector(entry["dest_chain_selector"])
	if err != nil {
		return LaneConfig{}, Lane{}, fmt.Errorf("invalid dest_chain_selector: %w", err)
	}

	var ok bool
	config.LightClient, ok = entry["light_client"].(string)
	if !ok {
		return LaneConfig{}, Lane{}, fmt.Errorf("light_client field is required")
	}
	lane.LightClient, err = protocol.NewUnknownAddressFromHex(config.LightClient)
	if err != nil {
		return LaneConfig{}, Lane{}, fmt.Errorf("invalid light_client: %w", err)
	}

	return config, lane, nil
}

func parseSelector(val any) (string, protocol.ChainSelector, error) {
	raw, ok := val.(string)
	if !ok {
		return "", 0, fmt.Errorf("expected a chain selector string, got %T", val)
	}
	selector, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return "", 0, err
	}
	return raw, protocol.ChainSelector(selector), nil
}
