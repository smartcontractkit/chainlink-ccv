package ccv

import (
	"context"
	"fmt"
	"sync"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

var (
	mu               sync.Mutex
	launcherRegistry = make(map[string]Launcher)
)

// RegisterLauncher registers a launcher for a given chain family.
// If the family is already registered, the call is a no-op.
func RegisterLauncher(chainFamily string, launcher Launcher) {
	mu.Lock()
	defer mu.Unlock()

	if _, ok := launcherRegistry[chainFamily]; ok {
		return
	}
	launcherRegistry[chainFamily] = launcher
}

// GenericServiceDefinition represents a generic service(s) definition that is launched for a specific chain selector.
// Its input and output are deliberately opaque so that it can take on any form and will be
// decoded into concrete types registered by users at runtime.
//
// Note that if many services need to be launched for the same chain selector,
// it is recommended to use a single GenericServiceDefinition with an Input/Output
// that holds the config for all the services that need to be launched.
type GenericServiceDefinition struct {
	// ChainSelector is the chain selector for the service.
	ChainSelector uint64 `toml:"chain_selector"`

	// Input is the input configuration for the service.
	Input util.OpaqueConfig `toml:"input"`

	// Output is the output of the service launch.
	Output util.OpaqueConfig `toml:"output"`
}

// Launcher is the interface for launching a generic service.
// It is expected to be implemented on a per-chain-family basis.
type Launcher interface {
	// Launch launches a generic service for a specific chain selector.
	// It returns the output of the service launch.
	Launch(
		ctx context.Context,
		env *deployment.Environment,
		chains []*blockchain.Output,
		definition *GenericServiceDefinition,
	) (output util.OpaqueConfig, err error)
}

func launchGenericServices(ctx context.Context, in *Cfg, e *deployment.Environment, chains []*blockchain.Output) error {
	for _, definition := range in.GenericServices {
		chainFamily, err := chainsel.GetSelectorFamily(definition.ChainSelector)
		if err != nil {
			return fmt.Errorf("failed to get chain family for chain selector %d: %w", definition.ChainSelector, err)
		}
		launcher, ok := launcherRegistry[chainFamily]
		if !ok {
			return fmt.Errorf("launcher for chain family %s not found", chainFamily)
		}
		output, err := launcher.Launch(ctx, e, chains, definition)
		if err != nil {
			return fmt.Errorf("failed to launch generic service for chain selector %d: %w", definition.ChainSelector, err)
		}
		definition.Output = output
	}
	return nil
}
