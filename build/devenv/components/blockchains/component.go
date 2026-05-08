package blockchains

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/pelletier/go-toml/v2"

	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const (
	configKey        = "blockchains"
	outputsKey       = "blockchainOutputs"
	defaultAnvilKey  = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
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

func (c *component) ValidateConfig(_ any) error { return nil }

// RunPhase1 deploys all blockchain networks declared under [[blockchains]] in
// the TOML config. It validates that the active private key is compatible with
// the declared chains, brings up each network via blockchain.NewBlockchainNetwork
// (which populates each Input's Out field), and emits two outputs:
//   - "blockchains" — []*blockchain.Input with Out populated, for downstream
//     components that need both the input parameters and deploy result.
//   - "blockchainOutputs" — []*blockchain.Output, for downstream components
//     that only need the deploy result.
func (c *component) RunPhase1(_ context.Context, _ map[string]any, componentConfig any) (map[string]any, error) {
	bcs, err := decode(componentConfig)
	if err != nil {
		return nil, err
	}
	if len(bcs) == 0 {
		return nil, errors.New("no [[blockchains]] entries declared in config")
	}
	if err := checkBlockchainKeys(bcs); err != nil {
		return nil, err
	}

	if err := framework.DefaultNetwork(nil); err != nil {
		return nil, fmt.Errorf("setting up default docker network: %w", err)
	}

	blockchainOutputs := make([]*blockchain.Output, len(bcs))
	for i, bc := range bcs {
		if _, err := blockchain.NewBlockchainNetwork(bc); err != nil {
			return nil, fmt.Errorf("blockchain[%d] %q: %w", i, bc.ContainerName, err)
		}
		blockchainOutputs[i] = bc.Out
	}

	return map[string]any{
		configKey:  bcs,
		outputsKey: blockchainOutputs,
	}, nil
}

// checkBlockchainKeys validates that the active private key is compatible with
// the declared blockchain types: simulated EVM chains require the default Anvil
// key, real EVM chains require a user-supplied PRIVATE_KEY.
func checkBlockchainKeys(bcs []*blockchain.Input) error {
	pk := networkPrivateKey()
	for _, bc := range bcs {
		family, err := blockchain.TypeToFamily(bc.Type)
		if err != nil {
			return fmt.Errorf("resolving blockchain family for type %q: %w", bc.Type, err)
		}
		if string(family) != blockchain.FamilyEVM {
			continue
		}
		if pk != defaultAnvilKey && slices.Contains(simChainIDs, bc.ChainID) {
			return errors.New("simulated chain configured with a non-Anvil private key; run 'unset PRIVATE_KEY'")
		}
		if pk == defaultAnvilKey && !slices.Contains(simChainIDs, bc.ChainID) {
			return errors.New("real chain configured without a private key; export PRIVATE_KEY before running")
		}
	}
	return nil
}

func networkPrivateKey() string {
	if pk := os.Getenv(privateKeyEnvVar); pk != "" {
		return pk
	}
	return defaultAnvilKey
}

// decode round-trips the raw TOML map[string]any into []*blockchain.Input by
// re-encoding through go-toml. The runtime hands components their config as the
// untyped value parsed by loadRaw, so we re-encode and decode into the typed
// struct that the framework expects.
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
