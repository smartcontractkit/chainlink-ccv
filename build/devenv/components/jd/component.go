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

// RunPhase2 starts the JD container and creates the JD client. Node
// registration and chain-config wiring happen later in Phase 3 after CL nodes
// are running (still inside the legacy monolith until CommitteeCCV is
// extracted).
func (c *component) RunPhase2(
	ctx context.Context,
	_ map[string]any,
	componentConfig any,
	_ map[string]any,
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
func decode(raw any) (*ctf_jd.Input, error) {
	b, err := toml.Marshal(struct {
		V any `toml:"jd"`
	}{V: raw})
	if err != nil {
		return nil, fmt.Errorf("re-encoding jd config: %w", err)
	}
	var wrapper struct {
		V *ctf_jd.Input `toml:"jd"`
	}
	if err := toml.Unmarshal(b, &wrapper); err != nil {
		return nil, fmt.Errorf("decoding jd config: %w", err)
	}
	return wrapper.V, nil
}
