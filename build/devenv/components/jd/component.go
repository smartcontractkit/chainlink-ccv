package jd

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	ctf_jd "github.com/smartcontractkit/chainlink-testing-framework/framework/components/jd"
)

const Key = "jd"

// Version is the jd component config schema version. Exactly this version is
// supported; configs declaring any other version are rejected.
const Version = 1

func init() {
	if err := devenvruntime.Register(Key, factory); err != nil {
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
		JDInput:            &input.Input,
		NodeConnectTimeout: input.NodeConnectTimeout,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("starting JD infrastructure: %w", err)
	}

	return map[string]any{Key: infra}, nil, nil
}

// decode round-trips the raw TOML map[string]any into *jdConfig.
// jdConfig embeds the third-party ctf_jd.Input (which we cannot add fields to)
// and adds the version plus devenv-only fields, inlined by go-toml.
type jdConfig struct {
	Version int `toml:"version"`
	ctf_jd.Input
	// NodeConnectTimeout is the raw [jd] node_connect_timeout value carried
	// onto the JD infrastructure; empty uses the default.
	NodeConnectTimeout string `toml:"node_connect_timeout,omitempty"`
}

func decode(raw any) (*jdConfig, error) {
	cfg, err := devenvruntime.DecodeConfig[jdConfig](raw, Key)
	if err != nil {
		return nil, err
	}
	if err := devenvruntime.CheckConfigVersion(cfg.Version, Version); err != nil {
		return nil, err
	}
	return &cfg, nil
}
