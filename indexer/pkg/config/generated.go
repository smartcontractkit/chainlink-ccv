package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// LoadGeneratedConfig loads the generated configuration from the path specified in the main config.
// Returns nil if GeneratedConfigPath is not set.
// Returns an error if the file exists but cannot be read or parsed.
func LoadGeneratedConfig(configPath string, cfg *Config) (*GeneratedConfig, error) {
	if cfg.GeneratedConfigPath == "" {
		return nil, nil
	}

	generatedPath := cfg.GeneratedConfigPath
	if !filepath.IsAbs(generatedPath) {
		generatedPath = filepath.Join(filepath.Dir(configPath), generatedPath)
	}

	data, err := os.ReadFile(generatedPath) //nolint:gosec // path is from config
	if err != nil {
		return nil, fmt.Errorf("failed to read generated config file %s: %w", generatedPath, err)
	}

	return LoadGeneratedConfigFromBytes(data)
}

// LoadGeneratedConfigFromBytes loads the generated configuration from TOML bytes.
func LoadGeneratedConfigFromBytes(data []byte) (*GeneratedConfig, error) {
	var generated GeneratedConfig
	if err := toml.Unmarshal(data, &generated); err != nil {
		return nil, fmt.Errorf("failed to parse TOML generated config: %w", err)
	}
	return &generated, nil
}

// MergeGeneratedConfig merges the generated configuration into the main configuration.
// It merges IssuerAddresses from the generated config into verifier configs by index.
// Addresses from the generated config are appended to existing addresses (with deduplication).
func MergeGeneratedConfig(cfg *Config, generated *GeneratedConfig) error {
	if generated == nil {
		return nil
	}

	for indexStr, verifierGenerated := range generated.Verifier {
		index, err := strconv.Atoi(indexStr)
		if err != nil {
			return fmt.Errorf("invalid verifier index in generated config: %s (must be numeric)", indexStr)
		}

		if index < 0 || index >= len(cfg.Verifiers) {
			return fmt.Errorf("verifier index %d in generated config is out of range (config has %d verifiers)", index, len(cfg.Verifiers))
		}

		if len(verifierGenerated.IssuerAddresses) > 0 {
			cfg.Verifiers[index].IssuerAddresses = mergeAddresses(
				cfg.Verifiers[index].IssuerAddresses,
				verifierGenerated.IssuerAddresses,
			)
		}
	}

	return nil
}

// mergeAddresses merges two slices of addresses, deduplicating by lowercase comparison.
func mergeAddresses(existing, additional []string) []string {
	seen := make(map[string]struct{}, len(existing))
	result := make([]string, 0, len(existing)+len(additional))

	for _, addr := range existing {
		lower := strings.ToLower(addr)
		if _, ok := seen[lower]; !ok {
			seen[lower] = struct{}{}
			result = append(result, addr)
		}
	}

	for _, addr := range additional {
		lower := strings.ToLower(addr)
		if _, ok := seen[lower]; !ok {
			seen[lower] = struct{}{}
			result = append(result, addr)
		}
	}

	return result
}
