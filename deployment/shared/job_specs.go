package shared

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/executor"
)

// Job spec types CCV changesets publish.
const (
	VerifierJobType = "ccvcommitteeverifier"
	ExecutorJobType = "ccvexecutor"
)

// JobSpecType returns the type field of a CCV job spec.
func JobSpecType(spec string) (string, error) {
	var envelope struct {
		Type string `toml:"type"`
	}
	if _, err := toml.Decode(spec, &envelope); err != nil {
		return "", fmt.Errorf("failed to parse job spec: %w", err)
	}
	return envelope.Type, nil
}

// ParseExecutorJobSpec extracts the executor.Configuration embedded in a ccvexecutor job spec.
// Standalone specs carry it in appConfig, CL specs in executorConfig.
func ParseExecutorJobSpec(spec string) (executor.Configuration, error) {
	inner, err := executorInnerConfigFromSpec(spec)
	if err != nil {
		return executor.Configuration{}, err
	}

	var cfg executor.Configuration
	if _, err := toml.Decode(inner, &cfg); err != nil {
		return executor.Configuration{}, fmt.Errorf("failed to parse executor config: %w", err)
	}
	return cfg, nil
}

func executorInnerConfigFromSpec(spec string) (string, error) {
	var wrapper struct {
		Type           string `toml:"type"`
		AppConfig      string `toml:"appConfig"`
		ExecutorConfig string `toml:"executorConfig"`
	}
	if _, err := toml.Decode(spec, &wrapper); err != nil {
		return "", fmt.Errorf("failed to parse job spec wrapper: %w", err)
	}
	if wrapper.Type != ExecutorJobType {
		return "", fmt.Errorf("unexpected job spec type %q (want %q)", wrapper.Type, ExecutorJobType)
	}
	if wrapper.AppConfig != "" && wrapper.ExecutorConfig != "" {
		return "", fmt.Errorf("job spec must set exactly one of appConfig and executorConfig")
	}
	if wrapper.AppConfig != "" {
		return wrapper.AppConfig, nil
	}
	if wrapper.ExecutorConfig != "" {
		return wrapper.ExecutorConfig, nil
	}
	return "", fmt.Errorf("job spec missing appConfig and executorConfig")
}
