package jobspec

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
)

// ParseExecutorBootstrapJobSpec decodes a ccvexecutor JD job spec into bootstrap.JobSpec.
func ParseExecutorBootstrapJobSpec(spec string) (bootstrap.JobSpec, error) {
	var wrapper struct {
		bootstrap.JobSpec
		ExecutorConfig string `toml:"executorConfig"`
	}
	if _, err := toml.Decode(spec, &wrapper); err != nil {
		return bootstrap.JobSpec{}, fmt.Errorf("decode executor job spec: %w", err)
	}
	inner, err := bootstrap.InnerConfig(wrapper.AppConfig, wrapper.ExecutorConfig, "executorConfig")
	if err != nil {
		return bootstrap.JobSpec{}, err
	}
	wrapper.JobSpec.AppConfig = inner
	return wrapper.JobSpec, nil
}
