package adapters

import (
	"github.com/Masterminds/semver/v3"

	mcmstypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
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
//
// Deployed contracts remain owned by the deployer key. Transferring
// ownership to a timelock/MCMS is composed by a separate changeset on top
// (see CCIP-11432).
type DeployCommitteeVerifierInput struct {
	ChainSelector     uint64
	DeployerContract  string
	ExistingAddresses []datastore.AddressRef
	Params            CommitteeVerifierDeployParams
}

// DeployCommitteeVerifierOutput is the chain-agnostic output of a
// CommitteeVerifier deploy. Adapters return any newly deployed addresses
// and MCMS batch operations produced by post-deploy configuration writes.
type DeployCommitteeVerifierOutput struct {
	Addresses []datastore.AddressRef
	BatchOps  []mcmstypes.BatchOperation
}

// CommitteeVerifierDeployAdapter is the chain-family-specific entry point
// for deploying and (idempotently) configuring a CommitteeVerifier and its
// associated resolver on one chain. Implementations live in the
// chain-family packages (e.g. chainlink-ccip/chains/evm) and register
// themselves into the singleton Registry at process startup.
//
// The adapter returns an operations.Sequence rather than executing directly
// so that the chain-agnostic changeset can drive the OperationsBundle and
// collect ExecutionReports uniformly across families.
type CommitteeVerifierDeployAdapter interface {
	// DeployCommitteeVerifier returns the per-family sequence that the
	// chain-agnostic changeset executes against BlockChains. The sequence
	// is expected to be idempotent: re-running on a chain where the
	// verifier already exists reconciles any drifted dynamic config rather
	// than redeploying.
	DeployCommitteeVerifier() *operations.Sequence[DeployCommitteeVerifierInput, DeployCommitteeVerifierOutput, chain.BlockChains]
}
