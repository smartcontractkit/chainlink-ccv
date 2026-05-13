package changesets

import (
	"errors"
	"fmt"
	"slices"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// DeployCommitteeVerifierPerChainCfg carries the per-chain inputs for one
// invocation of the chain-agnostic CommitteeVerifier deploy. DeployerContract
// is interpreted by the chain-family adapter (e.g. CREATE2Factory hex on EVM).
type DeployCommitteeVerifierPerChainCfg struct {
	DeployerContract string
	Params           adapters.CommitteeVerifierDeployParams
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
}

func (c DeployCommitteeVerifierInput) resolveChainCfg(sel uint64) DeployCommitteeVerifierPerChainCfg {
	if override, ok := c.ChainCfgs[sel]; ok {
		return override
	}
	return c.DefaultCfg
}

// DeployCommitteeVerifier is the chain-agnostic changeset for deploying and
// idempotently configuring CommitteeVerifier contracts (and their resolvers)
// across many chains. It is the granular, CCV-modular alternative to the
// full-stack DeployChainContracts in chainlink-ccip: a CCV can be deployed
// and configured separately from the rest of the protocol.
//
// Per-chain work is dispatched through registry.ChainAdapters.CommitteeVerifierDeploy,
// which proxies to the chain-family-specific deploy (e.g. on EVM, the existing
// sequences.DeployCommitteeVerifier). Adapters are expected to be idempotent:
// re-running on a chain where the verifier already exists is a no-op (or
// reconciles any drifted dynamic config).
//
// Ownership transfer is intentionally out of scope for this first iteration.
// Callers must run in deployer-key-owned mode (Params.DeployerKeyOwned-equivalent
// is implicit here — the adapter is invoked with DeployerKeyOwned=true).
// Wiring up MCMS-based ownership transfer is tracked as a follow-up so the
// changeset can graduate to managing it alongside the deploy.
func DeployCommitteeVerifier(registry *adapters.Registry) deployment.ChangeSetV2[DeployCommitteeVerifierInput] {
	validate := func(e deployment.Environment, cfg DeployCommitteeVerifierInput) error {
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

			perChain := cfg.resolveChainCfg(sel)
			if perChain.DeployerContract == "" {
				return fmt.Errorf("DeployerContract is required for chain %d", sel)
			}

			a, err := registry.GetByChain(sel)
			if err != nil {
				return fmt.Errorf("chain %d: %w", sel, err)
			}
			if a.CommitteeVerifierDeploy == nil {
				return fmt.Errorf("chain %d: no CommitteeVerifierDeploy adapter registered", sel)
			}
		}
		for sel := range cfg.ChainCfgs {
			if !slices.Contains(cfg.ChainSelectors, sel) {
				return fmt.Errorf("ChainCfgs contains selector %d which is not in ChainSelectors", sel)
			}
		}

		seenQualifier := make(map[string]bool, len(cfg.Committees))
		for _, c := range cfg.Committees {
			if c.Qualifier == "" {
				return errors.New("committee qualifier is required")
			}
			if seenQualifier[c.Qualifier] {
				return fmt.Errorf("duplicate committee qualifier %q in Committees", c.Qualifier)
			}
			seenQualifier[c.Qualifier] = true
			if c.Version == nil {
				return fmt.Errorf("committee %q: Version is required", c.Qualifier)
			}
			if c.FeeAggregator == "" {
				return fmt.Errorf("committee %q: FeeAggregator is required", c.Qualifier)
			}
		}

		return nil
	}

	apply := func(e deployment.Environment, cfg DeployCommitteeVerifierInput) (deployment.ChangesetOutput, error) {
		ds := datastore.NewMemoryDataStore()
		var allReports []operations.Report[any, any]

		for _, sel := range cfg.ChainSelectors {
			a, err := registry.GetByChain(sel)
			if err != nil {
				return deployment.ChangesetOutput{Reports: allReports},
					fmt.Errorf("chain %d: %w", sel, err)
			}

			perChain := cfg.resolveChainCfg(sel)

			existingAddresses := e.DataStore.Addresses().Filter(
				datastore.AddressRefByChainSelector(sel),
			)

			for _, committee := range cfg.Committees {
				input := adapters.DeployCommitteeVerifierInput{
					ChainSelector:     sel,
					DeployerContract:  perChain.DeployerContract,
					ExistingAddresses: existingAddresses,
					Params:            committee,
					DeployerKeyOwned:  true,
				}

				e.Logger.Infow(
					"Deploying CommitteeVerifier",
					"chain", sel,
					"committee", committee.Qualifier,
				)

				report, err := operations.ExecuteSequence(
					e.OperationsBundle,
					a.CommitteeVerifierDeploy.DeployCommitteeVerifier(),
					e.BlockChains,
					input,
				)
				if err != nil {
					return deployment.ChangesetOutput{Reports: allReports},
						fmt.Errorf("chain %d committee %q: deploy failed: %w", sel, committee.Qualifier, err)
				}

				for _, ref := range report.Output.Addresses {
					if addErr := ds.Addresses().Add(ref); addErr != nil &&
						!errors.Is(addErr, datastore.ErrAddressRefExists) {
						return deployment.ChangesetOutput{Reports: allReports},
							fmt.Errorf("chain %d committee %q: failed to add %s %s at %s to datastore: %w",
								sel, committee.Qualifier, ref.Type, ref.Version, ref.Address, addErr)
					}
					// Mirror into existingAddresses for subsequent committee deploys on
					// the same chain so addresses just-deployed by this loop are visible.
					existingAddresses = append(existingAddresses, ref)
				}

				allReports = append(allReports, report.ExecutionReports...)
			}
		}

		return deployment.ChangesetOutput{
			Reports:   allReports,
			DataStore: ds,
		}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}
