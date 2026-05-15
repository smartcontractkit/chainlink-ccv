package fake

import (
	"context"
	"fmt"

	"github.com/pelletier/go-toml/v2"

	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
)

const configKey = "fake"

func init() {
	if err := devenvruntime.Register(configKey, factory); err != nil {
		panic(fmt.Sprintf("fake component: %v", err))
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

// RunPhase1 starts the fake data-provider container. It has no dependencies on
// other components and runs in Phase 1 alongside blockchains.
func (c *component) RunPhase1(
	_ context.Context,
	_ map[string]any,
	componentConfig any,
) (map[string]any, []devenvruntime.Effect, error) {
	input, err := decode(componentConfig)
	if err != nil {
		return nil, nil, err
	}

	out, err := services.NewFake(input)
	if err != nil {
		return nil, nil, fmt.Errorf("starting fake data provider: %w", err)
	}
	if input != nil {
		input.Out = out
	}

	return map[string]any{configKey: input}, nil, nil
}

// decode round-trips the raw TOML map[string]any into *services.FakeInput.
func decode(raw any) (*services.FakeInput, error) {
	b, err := toml.Marshal(struct {
		V any `toml:"fake"`
	}{V: raw})
	if err != nil {
		return nil, fmt.Errorf("re-encoding fake config: %w", err)
	}
	var wrapper struct {
		V *services.FakeInput `toml:"fake"`
	}
	if err := toml.Unmarshal(b, &wrapper); err != nil {
		return nil, fmt.Errorf("decoding fake config: %w", err)
	}
	return wrapper.V, nil
}
