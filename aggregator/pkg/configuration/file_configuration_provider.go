// Package configuration provides configuration management for the aggregator service.
package configuration

import (
	"fmt"
	"path/filepath"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

// LoadConfig loads the aggregator configuration from a file.
// If the config specifies a GeneratedConfigPath, it also loads and merges the generated config.
func LoadConfig(filePath string) (*model.AggregatorConfig, error) {
	var config model.AggregatorConfig
	if _, err := toml.DecodeFile(filePath, &config); err != nil {
		return nil, fmt.Errorf("failed to load config from %s: %w", filePath, err)
	}

	if config.GeneratedConfigPath != "" {
		generatedPath := config.GeneratedConfigPath
		if !filepath.IsAbs(generatedPath) {
			generatedPath = filepath.Join(filepath.Dir(filePath), generatedPath)
		}

		generated, err := LoadGeneratedConfig(generatedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load generated config from %s: %w", generatedPath, err)
		}
		config.MergeGeneratedConfig(generated)
	}

	return &config, nil
}

// LoadConfigString loads the aggregator configuration from a string.
// Note: This does not support loading generated config from a path since the base directory is unknown.
func LoadConfigString(configStr string) (*model.AggregatorConfig, error) {
	var config model.AggregatorConfig
	if _, err := toml.Decode(configStr, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	return &config, nil
}

// LoadGeneratedConfig loads the generated configuration from a file.
func LoadGeneratedConfig(filePath string) (*model.GeneratedConfig, error) {
	var generated model.GeneratedConfig
	if _, err := toml.DecodeFile(filePath, &generated); err != nil {
		return nil, fmt.Errorf("failed to load generated config from %s: %w", filePath, err)
	}
	return &generated, nil
}

// LoadGeneratedConfigString loads the generated configuration from a string.
func LoadGeneratedConfigString(configStr string) (*model.GeneratedConfig, error) {
	var generated model.GeneratedConfig
	if _, err := toml.Decode(configStr, &generated); err != nil {
		return nil, fmt.Errorf("failed to parse generated config: %w", err)
	}
	return &generated, nil
}
