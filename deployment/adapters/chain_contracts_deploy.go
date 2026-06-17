package adapters

import (
	"github.com/Masterminds/semver/v3"

	mcmstypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

// ExecutorDeployParams describes a single executor to deploy on a chain.
type ExecutorDeployParams struct {
	Qualifier string
	Version   *semver.Version
}

// ProtocolContractsDeployInput is the per-chain input for deploying CCIP
// protocol contracts (RMNRemote, OnRamp, OffRamp, FeeQuoter, Router, Executors).
// Committee verifiers are deployed separately via CommitteeVerifierDeployAdapter.
type ProtocolContractsDeployInput struct {
	// ChainSelector is the chain to deploy on.
	ChainSelector uint64
	// DeployerContract is the deployer/factory address (e.g. CREATE2Factory on EVM).
	DeployerContract string
	// DeployTestRouter deploys a TestRouter alongside the production Router.
	DeployTestRouter bool
	// ExistingAddresses are already-deployed addresses on this chain. The adapter
	// uses these for idempotency — contracts that already exist are not redeployed.
	ExistingAddresses []datastore.AddressRef
	// Executors lists executor instances to deploy.
	Executors []ExecutorDeployParams
	// DeployerKeyOwned when true means deployed contracts remain owned by the
	// deployer key. When false, ownership is transferred to the RBAC timelock.
	DeployerKeyOwned bool
	// FamilyExtras carries chain-family-specific deploy parameters (e.g. RMN
	// params, gas limits) that the adapter interprets.
	FamilyExtras map[string]any
}

// ProtocolContractsDeployOutput is the output of a protocol contracts deployment.
type ProtocolContractsDeployOutput struct {
	// Addresses are newly deployed contract addresses.
	Addresses []datastore.AddressRef
	// BatchOps are MCMS batch operations (e.g. ownership transfer).
	BatchOps []mcmstypes.BatchOperation
	// RefsToTransferOwnership are addresses whose ownership should be
	// transferred to the RBAC timelock in a follow-up step.
	RefsToTransferOwnership []datastore.AddressRef
}

// ProtocolContractsDeployAdapter deploys CCIP protocol contracts on a single
// chain. Implementations are chain-family-specific and registered via the
// singleton FamilyRegistry.
//
// The adapter's sequence is expected to be idempotent: re-running on a chain
// where contracts already exist reconciles any drifted config rather than
// redeploying.
type ProtocolContractsDeployAdapter interface {
	// DeployProtocolContracts returns the per-family sequence that deploys the
	// core CCIP protocol contracts on one chain.
	DeployProtocolContracts() *operations.Sequence[ProtocolContractsDeployInput, ProtocolContractsDeployOutput, chain.BlockChains]
}
