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
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// ImplFactory is a factory for creating CCIP17 implementations.
// Product repos (chainlink-canton, chainlink-stellar, chainlink-ccip-solana)
// implement this interface and register it via Registration.ImplFactory in their init().
type ImplFactory interface {
	// NewEmpty creates an empty cciptestinterfaces.CCIP17Configuration object, this is
	// primarily used to spin up new environments.
	NewEmpty() cciptestinterfaces.CCIP17Configuration

	// New creates a new cciptestinterfaces.CCIP17 object, this is primarily used in
	// tests.
	New(
		ctx context.Context,
		lggr zerolog.Logger,
		env *deployment.Environment,
		chainSelector uint64,
	) (cciptestinterfaces.CCIP17, error)

	// DefaultSignerKey returns the default signer key for this chain family
	// given the bootstrap keys from a verifier node. Each family selects the
	// appropriate key type (e.g. EVM uses ECDSAAddress, Stellar uses EdDSA).
	// Return "" if no default signer is available.
	DefaultSignerKey(keys services.BootstrapKeys) string

	// DefaultFeeAggregator returns a fee aggregator address to use as a
	// fallback when topology omits one for the given chain. Each family
	// extracts the deployer address in its native format from the environment.
	// Return "" if no fallback is available for the given selector.
	DefaultFeeAggregator(env *deployment.Environment, chainSelector uint64) string

	// SupportsFunding reports whether this chain family supports native token
	// funding of executor addresses. Families that lack on-chain transfer
	// primitives in devenv (e.g. Canton) return false.
	SupportsFunding() bool

	// ExecutorTransmitterKeyName returns the keystore key name that the executor
	// for this chain family declares (via bootstrap.WithKey) and that devenv must
	// fetch from the bootstrap server to learn the on-chain transmitter address.
	// Return "" if the family has no bootstrap-managed transmitter key.
	ExecutorTransmitterKeyName() string

	// ExecutorTransmitterAddress returns the executor's on-chain transmitter
	// address (hex-encoded) for this chain family, extracted from the bootstrap
	// keys. Each family selects the appropriate field (e.g. EVM uses
	// EVMTransmitterAddress, Solana uses SolanaTransmitterAddress).
	// Return "" if no transmitter address is available.
	ExecutorTransmitterAddress(keys services.BootstrapKeys) string
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

// ExtraArgsSerializer serializes message extra args for a destination chain family.
type ExtraArgsSerializer = cciptestinterfaces.ExtraArgsSerializer

// AddressResolver is used by the test framework to resolve addresses of certain
// on-chain contracts. It is expected that it is implemented per-family.
type AddressResolver interface {
	// GetContractReceiver returns the receiver contract address for the given chain selector and qualifier.
	// This typically returns the mock receiver contract, extensively used in tests.
	GetContractReceiver(ds datastore.DataStore, chainSelector uint64, qualifier string) (protocol.UnknownAddress, error)

	// GetExecutor returns the executor contract address for the given chain selector and qualifier.
	GetExecutor(ds datastore.DataStore, chainSelector uint64, qualifier string) (protocol.UnknownAddress, error)

	// GetCommitteeCCV returns the committee CCV address for the given chain selector and qualifier.
	// This address must be usable as a CCV contract address onchain.
	// For EVM, this is typically the committee verifier resolver proxy address.
	GetCommitteeCCV(ds datastore.DataStore, chainSelector uint64, qualifier string) (protocol.UnknownAddress, error)

	// GetToken returns the token address associated with the given token pool ref.
	// poolRef identifies the pool (type, version, qualifier); the resolver maps it
	// to the correct token contract ref for that family.
	GetToken(ds datastore.DataStore, chainSelector uint64, poolRef datastore.AddressRef) (protocol.UnknownAddress, error)
}

// Registration groups every devenv extension for one chain family.
// Fields are optional; callers should set what the family supports.
type Registration struct {
	ImplFactory          ImplFactory
	CLDFProvider         CLDFProviderFactory
	ChainConfigLoader    ChainConfigLoader
	Launcher             Launcher
	VerifierModifier     VerifierModifier
	ExecutorModifier     ExecutorModifier
	ExtraArgsSerializers map[uint8]ExtraArgsSerializer
	AddressResolver      AddressResolver
}
