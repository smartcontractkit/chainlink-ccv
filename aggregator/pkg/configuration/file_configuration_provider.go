// Package configuration provides configuration management for the aggregator service.
package configuration

import (
	"fmt"
	"path/filepath"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/configvalidate"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// LoadConfig loads the aggregator configuration from a file.
// If the config specifies a GeneratedConfigPath, it also loads and merges the generated config.
func LoadConfig(filePath string, lggr logger.SugaredLogger) (*model.AggregatorConfig, error) {
	var config model.AggregatorConfig
	if _, err := toml.DecodeFile(filePath, &config); err != nil {
		return nil, fmt.Errorf("failed to load config from %s: %w", filePath, err)
	}

	if config.GeneratedConfigPath != "" {
		generatedPath := config.GeneratedConfigPath
		if !filepath.IsAbs(generatedPath) {
			generatedPath = filepath.Join(filepath.Dir(filePath), generatedPath)
		}
		lggr.Infow("Loading generated config from path", "path", generatedPath)
		generated, err := LoadGeneratedConfig(generatedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load generated config from %s: %w", generatedPath, err)
		}
		config.MergeGeneratedConfig(generated)
		lggr.Infow("Merged generated config", "path", generatedPath)
	}

	return &config, nil
}

// ValidateConfigFile strictly decodes the aggregator config at filePath the same
// way the service loads it at startup — decoding the main config and, when
// GeneratedConfigPath is set, the generated config resolved relative to filePath
// — and fails if either document fails to decode (e.g. a type mismatch) or
// contains keys not present in the config struct (drift). Unlike LoadConfig it
// reads no secrets or environment, so it is safe to run in CI against a rendered
// config to catch drift before deploy.
func ValidateConfigFile(filePath string) error {
	var config model.AggregatorConfig
	undecoded, decodeErr := configvalidate.DecodeFileStrict(filePath, &config)
	results := []configvalidate.Result{{
		Name:      filepath.Base(filePath),
		Undecoded: undecoded,
		Err:       decodeErr,
	}}

	// Validate the generated config exactly as LoadConfig merges it, but only when
	// the main config decoded far enough to give us a path.
	if decodeErr == nil && config.GeneratedConfigPath != "" {
		generatedPath := config.GeneratedConfigPath
		if !filepath.IsAbs(generatedPath) {
			generatedPath = filepath.Join(filepath.Dir(filePath), generatedPath)
		}
		var generated model.GeneratedConfig
		genUndecoded, genErr := configvalidate.DecodeFileStrict(generatedPath, &generated)
		results = append(results, configvalidate.Result{
			Name:      filepath.Base(generatedPath),
			Undecoded: genUndecoded,
			Err:       genErr,
		})
	}

	return configvalidate.Report(results...)
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
