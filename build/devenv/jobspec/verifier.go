// Package jobspec parses JD job spec TOML into bootstrap.JobSpec for devenv.
package jobspec

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
)

// ParseVerifierBootstrapJobSpec decodes a ccvcommitteeverifier JD job spec into
// bootstrap.JobSpec. Standalone specs use appConfig; CL specs use committeeVerifierConfig.
func ParseVerifierBootstrapJobSpec(spec string) (bootstrap.JobSpec, error) {
	var bootSpec bootstrap.JobSpec
	if _, err := toml.Decode(spec, &bootSpec); err != nil {
		return bootstrap.JobSpec{}, fmt.Errorf("decode verifier job spec: %w", err)
	}
	if bootSpec.AppConfig != "" {
		return bootSpec, nil
	}

	var clEnvelope struct {
		CommitteeVerifierConfig string `toml:"committeeVerifierConfig"`
	}
	if _, err := toml.Decode(spec, &clEnvelope); err != nil {
		return bootstrap.JobSpec{}, fmt.Errorf("decode committeeVerifierConfig: %w", err)
	}
	if clEnvelope.CommitteeVerifierConfig == "" {
		return bootstrap.JobSpec{}, fmt.Errorf("verifier job spec missing appConfig and committeeVerifierConfig")
	}

	bootSpec.AppConfig = clEnvelope.CommitteeVerifierConfig
	return bootSpec, nil
}
