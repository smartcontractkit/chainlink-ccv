package blockchains

import (
	"context"
	"fmt"

	"github.com/pelletier/go-toml/v2"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const configKey = "blockchains"

func init() {
	if err := devenvruntime.Register(configKey, factory); err != nil {
		panic(fmt.Sprintf("blockchains component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

func (c *component) ValidateConfig(_ any) error { return nil }

// RunPhase1 deploys all blockchain networks defined in [[blockchains]] config.
// Each blockchain.Input.Out is populated in-place by NewBlockchainNetwork so
// downstream phases can access RPC URLs via the returned slice.
func (c *component) RunPhase1(_ context.Context, _ map[string]any, componentConfig any) (map[string]any, error) {
	bcs, err := decode(componentConfig)
	if err != nil {
		return nil, err
	}

	for i, bc := range bcs {
		if _, err := blockchain.NewBlockchainNetwork(bc); err != nil {
			return nil, fmt.Errorf("blockchain[%d] %q: %w", i, bc.ContainerName, err)
		}
	}

	return map[string]any{configKey: bcs}, nil
}

// decode converts the raw map[string]any slice from loadRaw into []*blockchain.Input
// by round-tripping through TOML bytes.
func decode(raw any) ([]*blockchain.Input, error) {
	b, err := toml.Marshal(struct {
		V any `toml:"blockchains"`
	}{V: raw})
	if err != nil {
		return nil, fmt.Errorf("re-encoding blockchains config: %w", err)
	}
	var wrapper struct {
		V []*blockchain.Input `toml:"blockchains"`
	}
	if err := toml.Unmarshal(b, &wrapper); err != nil {
		return nil, fmt.Errorf("decoding blockchains config: %w", err)
	}
	return wrapper.V, nil
}
