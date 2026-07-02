package jobspec

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
)

// ParseVerifierBootstrapJobSpec decodes a committee verifier JD job spec into bootstrap.JobSpec.
func ParseVerifierBootstrapJobSpec(spec string) (bootstrap.JobSpec, error) {
	var wrapper struct {
		bootstrap.JobSpec
		CommitteeVerifierConfig string `toml:"committeeVerifierConfig"`
	}
	md, err := toml.Decode(spec, &wrapper)
	if err != nil {
		return bootstrap.JobSpec{}, fmt.Errorf("decode verifier job spec: %w", err)
	}
	if len(md.Undecoded()) > 0 {
		return bootstrap.JobSpec{}, fmt.Errorf("unknown fields in verifier job spec: %v", md.Undecoded())
	}

	inner, err := bootstrap.InnerConfig(wrapper.AppConfig, wrapper.CommitteeVerifierConfig, "committeeVerifierConfig")
	if err != nil {
		return bootstrap.JobSpec{}, err
	}
	wrapper.AppConfig = inner
	return wrapper.JobSpec, nil
}
