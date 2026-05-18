// Package chainreg provides a unified registry for per-chain-family devenv extensions.
package chainreg

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// ImplFactory creates CCIP17 implementations for a chain family.
type ImplFactory interface {
	NewEmpty() cciptestinterfaces.CCIP17Configuration
	New(
		ctx context.Context,
		lggr zerolog.Logger,
		env *deployment.Environment,
		chainSelector uint64,
	) (cciptestinterfaces.CCIP17, error)
	DefaultSignerKey(keys services.BootstrapKeys) string
	DefaultFeeAggregator(env *deployment.Environment, chainSelector uint64) string
	SupportsFunding() bool
}

// CLDFProviderFactory creates an initialized CLDF BlockChain provider from CTF blockchain input.
type CLDFProviderFactory func(ctx context.Context, b *ctfblockchain.Input) (cldf_chain.BlockChain, uint64, error)

// ChainConfigLoader loads chain-specific blockchain info for executor/verifier job specs.
type ChainConfigLoader func(outputs []*ctfblockchain.Output) (map[string]any, error)

// GenericServiceDefinition is launched for a specific chain selector via a family Launcher.
type GenericServiceDefinition struct {
	ChainSelector uint64            `toml:"chain_selector"`
	Input         util.OpaqueConfig `toml:"input"`
	Output        util.OpaqueConfig `toml:"output"`
}

// Launcher launches opaque generic services for a chain family.
type Launcher interface {
	Launch(
		ctx context.Context,
		env *deployment.Environment,
		chains []*ctfblockchain.Output,
		definition *GenericServiceDefinition,
	) (output util.OpaqueConfig, err error)
}

// VerifierModifier adjusts committee verifier testcontainer requests for a chain family.
type VerifierModifier = committeeverifier.ReqModifier

// ExecutorModifier adjusts executor testcontainer requests for a chain family.
type ExecutorModifier = executor.ReqModifier

// Registration groups every devenv extension for one chain family.
// Fields are optional; callers should set what the family supports.
type Registration struct {
	ImplFactory            ImplFactory
	CLDFProvider           CLDFProviderFactory
	ChainConfigLoader      ChainConfigLoader
	Launcher               Launcher
	VerifierModifier       VerifierModifier
	ExecutorModifier       ExecutorModifier
	ExtraArgsSerializers   map[uint8]cciptestinterfaces.ExtraArgsSerializer
}
