package config

import (
	"fmt"
	"os"
	"path/filepath"
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
// It merges IssuerAddresses from the generated config into verifier configs by Name.
// Each verifier's Name field is matched against the Name field in the generated config entries.
// Addresses from the generated config are appended to existing addresses (with deduplication).
// Returns a list of verifier names from the generated config that had no matching verifier in the main config.
func MergeGeneratedConfig(cfg *Config, generated *GeneratedConfig) []string {
	if generated == nil {
		return nil
	}

	generatedByName := make(map[string]GeneratedVerifierConfig, len(generated.Verifier))
	for _, v := range generated.Verifier {
		generatedByName[v.Name] = v
	}

	matchedNames := make(map[string]bool)

	for i := range cfg.Verifiers {
		name := cfg.Verifiers[i].Name
		if name == "" {
			continue
		}

		verifierGenerated, ok := generatedByName[name]
		if !ok {
			continue
		}

		matchedNames[name] = true

		if len(verifierGenerated.IssuerAddresses) > 0 {
			cfg.Verifiers[i].IssuerAddresses = mergeAddresses(
				cfg.Verifiers[i].IssuerAddresses,
				verifierGenerated.IssuerAddresses,
			)
		}
	}

	var unmatchedNames []string
	for _, v := range generated.Verifier {
		if !matchedNames[v.Name] {
			unmatchedNames = append(unmatchedNames, v.Name)
		}
	}

	return unmatchedNames
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
