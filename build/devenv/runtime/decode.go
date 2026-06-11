package devenvruntime

import (
	"fmt"

	"github.com/pelletier/go-toml/v2"
)

// tomlWrapper is the generic envelope used by DecodeConfig to round-trip
// a raw TOML value through the encoder/decoder as a typed Go value.
// Using a fixed key avoids per-component anonymous struct literals.
type tomlWrapper[T any] struct {
	V T `toml:"v"`
}

// DecodeConfig round-trips raw (a decoded TOML value as supplied by the phased
// runtime) into T by re-encoding it through go-toml/v2. It handles both table
// configs (map[string]any → struct) and array configs ([]any → slice) without
// any special casing: raw is always wrapped under the sentinel key "v" so that
// the encoder always produces a valid TOML document regardless of whether raw
// represents a table or an array-of-tables.
//
// componentName appears in error messages only.
// If raw is nil (the config section is absent from the environment file),
// the zero value of T is returned without error.
func DecodeConfig[T any](raw any, componentName string) (T, error) {
	var zero T
	if raw == nil {
		return zero, nil
	}
	b, err := toml.Marshal(tomlWrapper[any]{V: raw})
	if err != nil {
		return zero, fmt.Errorf("re-encoding %s config: %w", componentName, err)
	}
	var out tomlWrapper[T]
	if err := toml.Unmarshal(b, &out); err != nil {
		return zero, fmt.Errorf("decoding %s config: %w", componentName, err)
	}
	return out.V, nil
}
