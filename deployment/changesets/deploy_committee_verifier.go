package changesets

import (
	"errors"
	"fmt"
	"slices"

	ccipchangesets "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	ccipmcms "github.com/smartcontractkit/chainlink-ccip/deployment/utils/mcms"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// DeployCommitteeVerifierPerChainCfg carries the per-chain inputs for one
// invocation of the chain-agnostic CommitteeVerifier deploy. DeployerContract
// is interpreted by the chain-family adapter (e.g. CREATE2Factory hex on EVM).
// Committee-specific parameters come from DeployCommitteeVerifierInput.Committees.
type DeployCommitteeVerifierPerChainCfg struct {
	DeployerContract string
	// DeployerKeyOwned when true keeps the verifiers with the deployer key.
	// When false (the default), the changeset transfers them to the RBAC
	// timelock and DeployCommitteeVerifierInput.MCMS is required.
	DeployerKeyOwned bool
}

// DeployCommitteeVerifierInput is the imperative input for the chain-agnostic
// DeployCommitteeVerifier changeset. Callers describe the committees they
// want deployed plus the chains those committees should be deployed onto;
// the per-chain adapter resolves any chain-family-specific dependencies
// (RMN, factories, etc.) out of the environment DataStore.
//
// One CommitteeVerifier instance is deployed per (chain, committee) pair —
// i.e. len(ChainSelectors) × len(Committees) deploys in total.
type DeployCommitteeVerifierInput struct {
	// ChainSelectors are the destination chains to deploy each committee onto.
	ChainSelectors []uint64
	// Committees lists the committee deploy parameters. Each entry's
	// Qualifier must be unique within the slice. Every committee is deployed
	// to every chain in ChainSelectors.
	Committees []adapters.CommitteeVerifierDeployParams
	// DefaultCfg supplies fallback per-chain values (notably DeployerContract).
	// It is used when a chain has no entry in ChainCfgs.
	DefaultCfg DeployCommitteeVerifierPerChainCfg
	// ChainCfgs overrides DefaultCfg for specific chains.
	ChainCfgs map[uint64]DeployCommitteeVerifierPerChainCfg
	// MCMS configures the timelock proposal for the ownership handover and the
	// writes the adapter deferred to MCMS.
	MCMS *ccipmcms.Input
}

func (c DeployCommitteeVerifierInput) mcmsInput() ccipmcms.Input {
	if c.MCMS == nil {
		return ccipmcms.Input{}
	}
	return *c.MCMS
}

func (c DeployCommitteeVerifierInput) resolveChainCfg(sel uint64) DeployCommitteeVerifierPerChainCfg {
	if override, ok := c.ChainCfgs[sel]; ok {
		return override
	}
	return c.DefaultCfg
}

// DeployCommitteeVerifier is the chain-agnostic changeset for deploying and
// idempotently configuring CommitteeVerifier contracts (and their resolvers)
// across many chains.
//
// Per-chain work is dispatched through the CommitteeVerifierDeployAdapter.
// Adapters are expected to be idempotent: re-running on a chain where the
// verifier already exists is a no-op (or reconciles any drifted dynamic config).
//
// For a chain with DeployerKeyOwned false, the timelock for MCMS.Qualifier must
// be in the datastore. The output is the deployed address refs and one timelock
// proposal with the ownership acceptance and the writes the adapter deferred to
// MCMS. Once that proposal executes, a re-run proposes nothing. Rollback:
// deploy.TransferOwnershipChangeset executed by the timelock.
func DeployCommitteeVerifier() deployment.ChangeSetV2[DeployCommitteeVerifierInput] {
	validate := func(e deployment.Environment, cfg DeployCommitteeVerifierInput) error {
		return validateCommitteeVerifierDeploy(e, cfg)
	}

	apply := func(e deployment.Environment, cfg DeployCommitteeVerifierInput) (deployment.ChangesetOutput, error) {
		ds := datastore.NewMemoryDataStore()
		res, err := deployCommitteeVerifiersOnChains(e, cfg, ds)
		if err == nil {
			err = requireMCMSForBatchOps(res.BatchOps, cfg.MCMS)
		}
		if err != nil {
			return deployment.ChangesetOutput{Reports: res.Reports, DataStore: ds}, err
		}
		return ccipchangesets.NewOutputBuilder(e, mcmsReaders()).
			WithReports(res.Reports).
			WithBatchOps(res.BatchOps).
			WithDataStore(ds).
			Build(cfg.mcmsInput())
	}

	return deployment.CreateChangeSet(apply, validate)
}

// validateCommitteeVerifierDeploy validates the input for committee verifier deployment.
func validateCommitteeVerifierDeploy(e deployment.Environment, cfg DeployCommitteeVerifierInput) error {
	if len(cfg.ChainSelectors) == 0 {
		return errors.New("at least one chain selector is required")
	}
	if len(cfg.Committees) == 0 {
		return errors.New("at least one committee is required")
	}

	envSelectors := e.BlockChains.ListChainSelectors()
	seen := make(map[uint64]bool, len(cfg.ChainSelectors))
	for _, sel := range cfg.ChainSelectors {
		if seen[sel] {
			return fmt.Errorf("duplicate chain selector %d in ChainSelectors", sel)
		}
		seen[sel] = true
		if !slices.Contains(envSelectors, sel) {
			return fmt.Errorf("chain selector %d is not available in environment", sel)
		}
		chainCfg := cfg.resolveChainCfg(sel)
		if chainCfg.DeployerContract == "" {
			return fmt.Errorf("DeployerContract is required for chain %d", sel)
		}
		if !chainCfg.DeployerKeyOwned {
			if err := validateTimelockHandover(e, sel, cfg.MCMS); err != nil {
				return err
			}
		}
		if _, err := adapters.GetCommitteeVerifierDeployRegistry().Get(sel); err != nil {
			return fmt.Errorf("chain %d: %w", sel, err)
		}
	}
	for sel := range cfg.ChainCfgs {
		if !slices.Contains(cfg.ChainSelectors, sel) {
			return fmt.Errorf("ChainCfgs contains selector %d which is not in ChainSelectors", sel)
		}
	}

	seenQualifier := make(map[string]bool, len(cfg.Committees))
	for _, committee := range cfg.Committees {
		if committee.Qualifier == "" {
			return errors.New("committee qualifier is required")
		}
		if seenQualifier[committee.Qualifier] {
			return fmt.Errorf("duplicate committee qualifier %q in Committees", committee.Qualifier)
		}
		seenQualifier[committee.Qualifier] = true
		if committee.Version == nil {
			return fmt.Errorf("committee %q: Version is required", committee.Qualifier)
		}
		if committee.FeeAggregator == "" {
			return fmt.Errorf("committee %q: FeeAggregator is required", committee.Qualifier)
		}
	}

	return nil
}
