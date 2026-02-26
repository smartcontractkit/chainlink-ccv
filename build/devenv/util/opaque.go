package util

import (
	"bytes"
	"fmt"

	"github.com/BurntSushi/toml"
)

// OpaqueConfig holds a raw TOML subtree so that devenv does not depend on
// chain-specific config types. Code that needs the concrete config (e.g. in
// chain-family repos) can Marshal Value to TOML and Decode into the real type.
// Use OpaqueToConcreteStrict to decode the opaque config into a concrete config.
type OpaqueConfig struct {
	Value any `toml:"-"`
}

func (c *OpaqueConfig) UnmarshalTOML(v any) error {
	c.Value = v
	return nil
}

// OpaqueToConcreteStrict decodes the opaque config into a concrete config.
// It returns an error if there are any undecoded keys in the opaque config.
func OpaqueToConcreteStrict[T any](opaque OpaqueConfig) (*T, error) {
	// First encode the opaque config to TOML bytes.
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(opaque.Value); err != nil {
		return nil, fmt.Errorf("failed to encode opaque config: %w", err)
	}

	// Then decode the TOML bytes to a concrete config.
	var concrete T
	if md, err := toml.Decode(buf.String(), &concrete); err != nil {
		return nil, fmt.Errorf("failed to unmarshal opaque config: %w", err)
	} else if len(md.Undecoded()) > 0 {
		return nil, fmt.Errorf("undecoded keys in opaque config: %v", md.Undecoded())
	}

	return &concrete, nil
}
