package common

import (
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// Duration is a TOML-aware time.Duration that rejects bare integer values.
// In TOML config files, durations must be quoted strings (e.g. "30m", "5s").
// This prevents silent misinterpretation: a bare TOML integer would be treated
// as nanoseconds by the standard time.Duration unmarshaler.
type Duration time.Duration

func (d *Duration) UnmarshalTOML(val any) error {
	s, ok := val.(string)
	if !ok {
		return fmt.Errorf("duration must be a quoted string (e.g. \"30m\", \"5s\"), got %T, %v", val, val)
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(dur)
	return nil
}

// MarshalTOML implements toml.Marshaler so round-trip marshal/unmarshal
// produces a quoted string (e.g. "1h0m0s") rather than a bare int64.
func (d Duration) MarshalTOML() ([]byte, error) {
	return []byte(strconv.Quote(time.Duration(d).String())), nil
}

// String implements fmt.Stringer.
func (d Duration) String() string {
	return time.Duration(d).String()
}

// ParseIntOrDefault parses a TOML integer value, falling back to defaultVal only
// when the value is absent. A value of an unsupported type is an error rather
// than a silent fallback, so a mistyped field (e.g. `batch_size = true`) cannot
// quietly take the default and look configured.
func ParseIntOrDefault(val any, defaultVal int) (int, error) {
	switch v := val.(type) {
	case nil:
		return defaultVal, nil
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
	default:
		return 0, fmt.Errorf("integer field must be a TOML integer or a quoted integer (e.g. \"42\"), got %T, %v", val, val)
	}
}

// ParseDurationOrDefault parses a TOML duration value, falling back to defaultVal
// only when the value is absent.
//
// Durations must be quoted strings (e.g. "30m", "5s"), the same contract as
// [Duration.UnmarshalTOML]. A bare TOML integer is rejected rather than read as
// nanoseconds: `timeout = 3000000000` used to mean "3s" to the author but the
// default to the app, so the config silently disagreed with the binary. Any other
// non-string type is an error too, so a mistyped field never falls back to a
// default unnoticed.
func ParseDurationOrDefault(val any, defaultVal time.Duration) (time.Duration, error) {
	if val == nil {
		return defaultVal, nil
	}
	v, ok := val.(string)
	if !ok {
		return 0, fmt.Errorf("duration must be a quoted string (e.g. \"30m\", \"5s\"), got %T, %v", val, val)
	}
	duration, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("invalid duration format: %w", err)
	}
	return duration, nil
}

// UnknownKeys returns the sorted names of keys in data that are not in allowed.
//
// A config decoded through a custom UnmarshalTOML consumes its whole TOML table,
// so the decoder reports no undecoded keys for it and otherwise-dropped keys
// would go unnoticed. Callers use this to reject keys that silently do nothing.
func UnknownKeys(data map[string]any, allowed []string) []string {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}

	var unknown []string
	for key := range data {
		if _, ok := allowedSet[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	slices.Sort(unknown)

	return unknown
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
