package jd

import (
	"context"
	"fmt"

	"github.com/pelletier/go-toml/v2"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	ctf_jd "github.com/smartcontractkit/chainlink-testing-framework/framework/components/jd"
)

const configKey = "jd"

// Version is the jd component config schema version. Exactly this version is
// supported; configs declaring any other version are rejected.
const Version = 1

func init() {
	if err := devenvruntime.Register(configKey, factory); err != nil {
		panic(fmt.Sprintf("jd component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

func (c *component) ValidateConfig(componentConfig any) error {
	_, err := decode(componentConfig)
	return err
}

// RunPhase1 starts the JD container and creates the JD client. Node
// registration and chain-config wiring happen later in Phase 2 in the legacy
// component after CL nodes are running.
func (c *component) RunPhase1(
	ctx context.Context,
	_ map[string]any,
	componentConfig any,
) (map[string]any, []devenvruntime.Effect, error) {
	input, err := decode(componentConfig)
	if err != nil {
		return nil, nil, err
	}

	infra, err := jobs.StartJDInfrastructure(ctx, jobs.JDInfrastructureConfig{
		JDInput: input,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("starting JD infrastructure: %w", err)
	}

	return map[string]any{configKey: infra}, nil, nil
}

// decode round-trips the raw TOML map[string]any into *ctf_jd.Input.
// jdConfig embeds the third-party ctf_jd.Input (which we cannot add fields to)
// and adds the component config version. The embedded Input is inlined by
// go-toml, so the [jd] table's fields decode normally alongside its version.
type jdConfig struct {
	Version int `toml:"version"`
	ctf_jd.Input
}

func decode(raw any) (*ctf_jd.Input, error) {
	b, err := toml.Marshal(struct {
		V any `toml:"jd"`
	}{V: raw})
	if err != nil {
		return nil, fmt.Errorf("re-encoding jd config: %w", err)
	}
	var wrapper struct {
		V jdConfig `toml:"jd"`
	}
	if err := toml.Unmarshal(b, &wrapper); err != nil {
		return nil, fmt.Errorf("decoding jd config: %w", err)
	}
	if err := devenvruntime.CheckConfigVersion(wrapper.V.Version, Version); err != nil {
		return nil, err
	}
	return &wrapper.V.Input, nil
}
