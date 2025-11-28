package common

import (
	"fmt"
	"strconv"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func ParseIntOrDefault(val any, defaultVal int) (int, error) {
	if v, ok := val.(int64); ok {
		return int(v), nil
	}
	return defaultVal, nil
}

func ParseDurationOrDefault(val any, defaultVal time.Duration) (time.Duration, error) {
	if v, ok := val.(string); ok {
		duration, err := time.ParseDuration(v)
		if err != nil {
			return 0, fmt.Errorf("invalid duration format: %w", err)
		}
		return duration, nil
	}
	return defaultVal, nil
}

func ParseAddressesMap(val any) (map[protocol.ChainSelector]protocol.UnknownAddress, error) {
	result := make(map[protocol.ChainSelector]protocol.UnknownAddress)
	if v, ok := val.(map[string]any); ok {
		for key, value := range v {
			chainSelector, err := strconv.ParseInt(key, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid chain selector %s: %w", key, err)
			}
			address, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("invalid verifier address for chain selector %s: expected string, got %T", key, value)
			}
			//nolint:gosec // disable G115
			result[protocol.ChainSelector(chainSelector)] = protocol.UnknownAddress(address)
		}
		return result, nil
	}
	return nil, fmt.Errorf("expected map for addresses, got %T", val)
}
