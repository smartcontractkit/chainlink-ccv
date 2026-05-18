package blockchains

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/pelletier/go-toml/v2"

	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const (
	configKey        = "blockchains"
	outputsKey       = "blockchainOutputs"
	privateKeyEnvVar = "PRIVATE_KEY"
)

// simChainIDs are the well-known simulated chain IDs used by Anvil/Geth in devenv.
var simChainIDs = []string{"1337", "2337", "3337"}

func init() {
	if err := devenvruntime.Register(configKey, factory); err != nil {
		panic(fmt.Sprintf("blockchains component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

// ValidateConfig decodes a single [[blockchains]] entry and validates that its
// Type resolves to a known family and that the active PRIVATE_KEY is
// compatible (Anvil key for sim chain IDs, real key otherwise).
func (c *component) ValidateConfig(componentConfig any) error {
	bc, err := decode(componentConfig)
	if err != nil {
		return err
	}
	if bc == nil {
		return errors.New("nil [[blockchains]] entry")
	}
	return checkBlockchainKeys(bc)
}

// RunPhase1 brings up the declared blockchain network via
// blockchain.NewBlockchainNetwork and emits two outputs:
//   - "blockchains" — []*blockchain.Input with Out populated
//   - "blockchainOutputs" — []*blockchain.Output
//
// Each [[blockchains]] entry creates a separate component instance. The
// runtime accumulates length-1 slices across instances into the final slices.
func (c *component) RunPhase1(_ context.Context, _ map[string]any, componentConfig any) (map[string]any, []devenvruntime.Effect, error) {
	bc, err := decode(componentConfig)
	if err != nil {
		return nil, nil, err
	}

	if err := framework.DefaultNetwork(nil); err != nil {
		return nil, nil, fmt.Errorf("setting up default docker network: %w", err)
	}

	out, err := blockchain.NewBlockchainNetwork(bc)
	if err != nil {
		return nil, nil, fmt.Errorf("blockchain %q: %w", bc.ContainerName, err)
	}
	if out == nil {
		return nil, nil, fmt.Errorf("blockchain %q: NewBlockchainNetwork returned nil output", bc.ContainerName)
	}
	bc.Out = out

	return map[string]any{
		configKey:  []*blockchain.Input{bc},
		outputsKey: []*blockchain.Output{out},
	}, nil, nil
}

// checkBlockchainKeys validates that the active private key is compatible with
// the declared blockchain type.
func checkBlockchainKeys(bc *blockchain.Input) error {
	pk := networkPrivateKey()
	family, err := blockchain.TypeToFamily(bc.Type)
	if err != nil {
		return fmt.Errorf("resolving blockchain family for type %q: %w", bc.Type, err)
	}
	if string(family) != blockchain.FamilyEVM {
		return nil
	}
	if pk != devenvcommon.DefaultAnvilKey && slices.Contains(simChainIDs, bc.ChainID) {
		return errors.New("simulated chain configured with a non-Anvil private key; run 'unset PRIVATE_KEY'")
	}
	if pk == devenvcommon.DefaultAnvilKey && !slices.Contains(simChainIDs, bc.ChainID) {
		return errors.New("real chain configured without a private key; export PRIVATE_KEY before running")
	}
	return nil
}

func networkPrivateKey() string {
	if pk := os.Getenv(privateKeyEnvVar); pk != "" {
		return pk
	}
	return devenvcommon.DefaultAnvilKey
}

// decode round-trips a single raw TOML map[string]any into *blockchain.Input
// by re-encoding through go-toml.
func decode(raw any) (*blockchain.Input, error) {
	b, err := toml.Marshal(struct {
		V any `toml:"blockchain"`
	}{V: raw})
	if err != nil {
		return nil, fmt.Errorf("re-encoding blockchain config: %w", err)
	}
	var wrapper struct {
		V *blockchain.Input `toml:"blockchain"`
	}
	if err := toml.Unmarshal(b, &wrapper); err != nil {
		return nil, fmt.Errorf("decoding blockchain config: %w", err)
	}
	return wrapper.V, nil
}
