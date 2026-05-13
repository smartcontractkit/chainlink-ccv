package adapters

import (
	"github.com/Masterminds/semver/v3"
	mcms_types "github.com/smartcontractkit/mcms/types"

	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf_ops "github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

// CommitteeVerifierDeployParams describes the per-committee deployment
// parameters consumed by the chain-agnostic CommitteeVerifier deploy. The
// shape mirrors chainlink-ccip's full-chain DeployContractParams entry for a
// committee verifier so callers can move directly from one to the other.
type CommitteeVerifierDeployParams struct {
	Version          *semver.Version
	FeeAggregator    string
	AllowlistAdmin   string
	StorageLocations []string
	// Qualifier distinguishes between multiple committee verifier deployments
	// on the same chain. Required.
	Qualifier string
}

// DeployCommitteeVerifierInput is the chain-agnostic input passed to a
// CommitteeVerifierDeployAdapter sequence. Per-family adapters are
// responsible for interpreting DeployerContract (e.g. a CREATE2Factory hex
// address on EVM) and for looking up family-specific dependencies (such as
// the RMNProxy) from ExistingAddresses.
type DeployCommitteeVerifierInput struct {
	ChainSelector     uint64
	DeployerContract  string
	ExistingAddresses []datastore.AddressRef
	Params            CommitteeVerifierDeployParams
	// DeployerKeyOwned, when true, leaves the deployed contracts owned by the
	// deployer key. When false, the adapter is expected to surface the
	// contracts that need ownership transfer in RefsToTransferOwnership so
	// the caller can wire up MCMS-based transfer. The current chain-agnostic
	// changeset only supports DeployerKeyOwned=true.
	DeployerKeyOwned bool
}

// DeployCommitteeVerifierOutput is the chain-agnostic output of a
// CommitteeVerifier deploy. Adapters return any newly deployed addresses,
// MCMS batch operations produced by post-deploy configuration writes, and
// the subset of contracts that still need ownership transfer when not
// running in deployer-key-owned mode.
type DeployCommitteeVerifierOutput struct {
	Addresses               []datastore.AddressRef
	BatchOps                []mcms_types.BatchOperation
	RefsToTransferOwnership []datastore.AddressRef
}

// CommitteeVerifierDeployAdapter is the chain-family-specific entry point
// for deploying and (idempotently) configuring a CommitteeVerifier and its
// associated resolver on one chain. Implementations live in the
// chain-family packages (e.g. chainlink-ccip/chains/evm) and register
// themselves into the singleton Registry at process startup.
//
// The adapter returns a cldf_ops.Sequence rather than executing directly so
// that the chain-agnostic changeset can drive the OperationsBundle and
// collect ExecutionReports uniformly across families.
type CommitteeVerifierDeployAdapter interface {
	DeployCommitteeVerifier() *cldf_ops.Sequence[DeployCommitteeVerifierInput, DeployCommitteeVerifierOutput, cldf_chain.BlockChains]
}
