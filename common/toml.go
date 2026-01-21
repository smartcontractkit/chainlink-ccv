package common

import (
	"fmt"
	"strconv"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func ParseIntOrDefault(val any, defaultVal int) (int, error) {
	switch v := val.(type) {
	case int:
		return v, nil
	case int32:
		return int(v), nil
	case int64:
		return int(v), nil
	case uint32:
		return int(v), nil
	case uint64:
		// #nosec G115
		return int(v), nil
	case string:
		intVal, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("invalid integer format: %w", err)
		}
		return intVal, nil
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

func ParseAddressesMap(val any) (map[protocol.ChainSelector]protocol.UnknownAddress, map[string]any, error) {
	result := make(map[protocol.ChainSelector]protocol.UnknownAddress)

	if val == nil {
		return result, nil, nil
	}

	if v, ok := val.(map[string]any); ok {
		for key, value := range v {
			chainSelector, err := strconv.ParseUint(key, 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid chain selector %s: %w", key, err)
			}
			address, ok := value.(string)
			if !ok {
				return nil, nil, fmt.Errorf("invalid verifier address for chain selector %s: expected string, got %T", key, value)
			}

			addr, err := protocol.NewUnknownAddressFromHex(address)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid verifier address for chain selector %s: %w", key, err)
			}

			result[protocol.ChainSelector(chainSelector)] = addr
		}
		return result, v, nil
	}
	return nil, nil, fmt.Errorf("expected map for addresses, got %T", val)
}

func AddressesMapToKeyValueMap(addresses map[protocol.ChainSelector]protocol.UnknownAddress) map[string]string {
	result := make(map[string]string)
	for chainSelector, address := range addresses {
		result[strconv.FormatUint(uint64(chainSelector), 10)] = string(address)
	}
	return result
}
