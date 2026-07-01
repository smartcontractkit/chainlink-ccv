package jobspec

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
)

// ParseExecutorBootstrapJobSpec decodes a ccvexecutor JD job spec into bootstrap.JobSpec.
// Standalone specs use appConfig; CL specs use executorConfig.
func ParseExecutorBootstrapJobSpec(spec string) (bootstrap.JobSpec, error) {
	var bootSpec bootstrap.JobSpec
	if _, err := toml.Decode(spec, &bootSpec); err != nil {
		return bootstrap.JobSpec{}, fmt.Errorf("decode executor job spec: %w", err)
	}
	if bootSpec.AppConfig != "" {
		// job spec from standalone mode, appConfig is already set
		return bootSpec, nil
	}

	var clEnvelope struct {
		ExecutorConfig string `toml:"executorConfig"`
	}
	if _, err := toml.Decode(spec, &clEnvelope); err != nil {
		return bootstrap.JobSpec{}, fmt.Errorf("decode executorConfig: %w", err)
	}
	if clEnvelope.ExecutorConfig == "" {
		return bootstrap.JobSpec{}, fmt.Errorf("executor job spec missing appConfig and executorConfig")
	}

	bootSpec.AppConfig = clEnvelope.ExecutorConfig
	return bootSpec, nil
}
