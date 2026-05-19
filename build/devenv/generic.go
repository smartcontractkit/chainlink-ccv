package ccv

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// GenericServiceDefinition is an alias for chainreg.GenericServiceDefinition.
type GenericServiceDefinition = chainreg.GenericServiceDefinition

func launchGenericServices(ctx context.Context, in *Cfg, e *deployment.Environment, chains []*blockchain.Output) error {
	l := zerolog.Ctx(ctx)
	for _, definition := range in.GenericServices {
		l.Info().Uint64("ChainSelector", definition.ChainSelector).Msg("Launching generic service")
		chainFamily, err := chainsel.GetSelectorFamily(definition.ChainSelector)
		if err != nil {
			return fmt.Errorf("failed to get chain family for chain selector %d: %w", definition.ChainSelector, err)
		}
		reg, err := chainreg.GetRegistry().Get(chainFamily)
		if err != nil {
			return fmt.Errorf("chain registration for family %s not found: %w", chainFamily, err)
		}
		if reg.Launcher == nil {
			return fmt.Errorf("launcher for chain family %s not found", chainFamily)
		}
		output, err := reg.Launcher.Launch(ctx, e, chains, definition)
		if err != nil {
			return fmt.Errorf("failed to launch generic service for chain selector %d: %w", definition.ChainSelector, err)
		}
		definition.Output = output
	}
	return nil
}
