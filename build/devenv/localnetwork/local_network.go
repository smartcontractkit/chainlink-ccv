// Package localnetwork holds the chain-family-agnostic local network extensions
// devenv can apply to blockchains it has already launched.
//
// The only extension today is RPC failover: a pair of independently
// controllable reverse proxies in front of a chain's RPC endpoint, so a chaos
// test can take one endpoint away and watch a multi-node client move to the
// other. Nothing in this package is family-specific. A family opts in by
// registering Configurator(family) as its chainreg.LocalNetworkConfigurator and
// enabling rpc_failover under [local_networks.<family>.input] in the devenv
// config, whether it lives in this repo or in a product repo that imports it.
package localnetwork

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// Input is the local network input schema. Every family shares it; devenv
// stores it opaquely under [local_networks.<family>.input] and hands it back to
// the family's configurator.
type Input struct {
	RPCFailover *FailoverInput `toml:"rpc_failover,omitempty"`
}

// Output is the local network output schema. Devenv writes it to
// [local_networks.<family>.output]; tests decode it to find the proxies.
type Output struct {
	RPCFailover *FailoverOutput `toml:"rpc_failover,omitempty"`
}

// Configurator returns the chainreg.LocalNetworkConfigurator for family. It is
// the whole of what a family needs to register to get RPC failover:
//
//	chainreg.Register(chainsel.FamilySolana, chainreg.Registration{
//	    LocalNetworkConfigurator: localnetwork.Configurator(chainsel.FamilySolana),
//	})
func Configurator(family string) chainreg.LocalNetworkConfigurator {
	return func(
		ctx context.Context,
		input util.OpaqueConfig,
		outputs []*blockchain.Output,
	) (util.OpaqueConfig, chainreg.LocalNetworkFinalizer, error) {
		return Configure(ctx, family, input, outputs)
	}
}

// Configure decodes the family's opaque local network input and applies every
// enabled extension to outputs. It returns the opaque output to persist and a
// finalizer that undoes the temporary mutations once all consumers have
// captured their network configuration.
func Configure(
	ctx context.Context,
	family string,
	input util.OpaqueConfig,
	outputs []*blockchain.Output,
) (util.OpaqueConfig, chainreg.LocalNetworkFinalizer, error) {
	cfg, err := util.OpaqueToConcreteStrict[Input](input)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding %s local network config: %w", family, err)
	}
	if cfg.RPCFailover == nil || !cfg.RPCFailover.Enabled {
		return nil, nil, nil
	}

	failoverOutput, finalize, err := configureRPCFailover(ctx, family, cfg.RPCFailover, outputs, launchRPCProxy)
	if err != nil {
		return nil, nil, err
	}
	opaqueOutput, err := util.ConcreteToOpaque(Output{RPCFailover: failoverOutput})
	if err != nil {
		finalize()
		return nil, nil, fmt.Errorf("encoding %s local network output: %w", family, err)
	}
	return opaqueOutput, finalize, nil
}
