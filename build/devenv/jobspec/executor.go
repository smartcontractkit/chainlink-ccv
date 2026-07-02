package jobspec

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
)

// ParseExecutorBootstrapJobSpec decodes an executor JD job spec into bootstrap.JobSpec.
func ParseExecutorBootstrapJobSpec(spec string) (bootstrap.JobSpec, error) {
	var wrapper struct {
		bootstrap.JobSpec
		ExecutorConfig string `toml:"executorConfig"`
	}
	md, err := toml.Decode(spec, &wrapper)
	if err != nil {
		return bootstrap.JobSpec{}, fmt.Errorf("decode executor job spec: %w", err)
	}
	if len(md.Undecoded()) > 0 {
		return bootstrap.JobSpec{}, fmt.Errorf("unknown fields in executor job spec: %v", md.Undecoded())
	}

	inner, err := bootstrap.InnerConfig(wrapper.AppConfig, wrapper.ExecutorConfig, "executorConfig")
	if err != nil {
		return bootstrap.JobSpec{}, err
	}
	wrapper.AppConfig = inner
	return wrapper.JobSpec, nil
}
