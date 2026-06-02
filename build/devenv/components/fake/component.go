package fake

import (
	"context"
	"fmt"

	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
)

const configKey = "fake"

// Version is the fake component config schema version. Exactly this version is
// supported; configs declaring any other version are rejected.
const Version = 1

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

func decode(raw any) (*services.FakeInput, error) {
	input, err := devenvruntime.DecodeConfig[*services.FakeInput](raw, "fake")
	if err != nil {
		return nil, err
	}
	if input != nil {
		if err := devenvruntime.CheckConfigVersion(input.Version, Version); err != nil {
			return nil, err
		}
	}
	return input, nil
}
