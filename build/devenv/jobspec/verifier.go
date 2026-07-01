package jobspec

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
)

// ParseVerifierBootstrapJobSpec decodes a ccvcommitteeverifier JD job spec into bootstrap.JobSpec.
func ParseVerifierBootstrapJobSpec(spec string) (bootstrap.JobSpec, error) {
	var wrapper struct {
		bootstrap.JobSpec
		CommitteeVerifierConfig string `toml:"committeeVerifierConfig"`
	}
	if _, err := toml.Decode(spec, &wrapper); err != nil {
		return bootstrap.JobSpec{}, fmt.Errorf("decode verifier job spec: %w", err)
	}
	inner, err := bootstrap.InnerConfig(wrapper.AppConfig, wrapper.CommitteeVerifierConfig, "committeeVerifierConfig")
	if err != nil {
		return bootstrap.JobSpec{}, err
	}
	wrapper.JobSpec.AppConfig = inner
	return wrapper.JobSpec, nil
}
