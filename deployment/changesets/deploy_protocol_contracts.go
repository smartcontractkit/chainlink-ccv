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

// DeployProtocolContractsPerChainCfg carries the per-chain configuration for
// deploying CCIP protocol contracts (RMN, OnRamp, OffRamp, FeeQuoter, Router,
// Executors). Committee verifiers are deployed separately.
type DeployProtocolContractsPerChainCfg struct {
	// DeployerContract is the deployer/factory address (e.g. CREATE2Factory on EVM).
	DeployerContract string
	// DeployTestRouter deploys a TestRouter alongside the production Router.
	DeployTestRouter bool
	// Executors lists executor instances to deploy.
	Executors []adapters.ExecutorDeployParams
	// DeployerKeyOwned when true means deployed contracts remain owned by the
	// deployer key. When false, ownership is transferred to the RBAC timelock.
	DeployerKeyOwned bool
	// FamilyExtras carries chain-family-specific deploy parameters.
	FamilyExtras map[string]any
}

// DeployProtocolContractsInput is the imperative input for the
// DeployProtocolContracts changeset.
type DeployProtocolContractsInput struct {
	// ChainSelectors are the chains to deploy on.
	ChainSelectors []uint64
	// DefaultCfg supplies fallback per-chain values. Used when a chain has no
	// entry in ChainCfgs.
	DefaultCfg DeployProtocolContractsPerChainCfg
	// ChainCfgs overrides DefaultCfg for specific chains.
	ChainCfgs map[uint64]DeployProtocolContractsPerChainCfg
}

func (c DeployProtocolContractsInput) resolveChainCfg(sel uint64) DeployProtocolContractsPerChainCfg {
	if override, ok := c.ChainCfgs[sel]; ok {
		return override
	}
	return c.DefaultCfg
}

// DeployProtocolContracts is a single-entry, onchain-only changeset that
// deploys the core CCIP protocol contracts (RMN, OnRamp, OffRamp, FeeQuoter,
// Router, Executors) on the specified chains.
//
// Committee verifiers are NOT deployed by this changeset — use
// DeployCommitteeVerifier for that, or OnboardChain for both in one pass.
func DeployProtocolContracts() deployment.ChangeSetV2[DeployProtocolContractsInput] {
	validate := func(e deployment.Environment, cfg DeployProtocolContractsInput) error {
		return validateProtocolContractsDeploy(e, cfg)
	}

	apply := func(e deployment.Environment, cfg DeployProtocolContractsInput) (deployment.ChangesetOutput, error) {
		ds := datastore.NewMemoryDataStore()
		reports, err := deployProtocolContractsOnChains(e, cfg, ds)
		return deployment.ChangesetOutput{Reports: reports, DataStore: ds}, err
	}

	return deployment.CreateChangeSet(apply, validate)
}

// validateProtocolContractsDeploy validates the input for protocol contract deployment.
func validateProtocolContractsDeploy(e deployment.Environment, cfg DeployProtocolContractsInput) error {
	if len(cfg.ChainSelectors) == 0 {
		return errors.New("at least one chain selector is required")
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
		if cfg.resolveChainCfg(sel).DeployerContract == "" {
			return fmt.Errorf("DeployerContract is required for chain %d", sel)
		}
		if _, err := adapters.GetProtocolContractsDeployRegistry().Get(sel); err != nil {
			return fmt.Errorf("chain %d: %w", sel, err)
		}
	}

	for sel := range cfg.ChainCfgs {
		if !slices.Contains(cfg.ChainSelectors, sel) {
			return fmt.Errorf("ChainCfgs contains selector %d which is not in ChainSelectors", sel)
		}
	}

	return nil
}

// deployProtocolContractsOnChains deploys protocol contracts on every chain in
// cfg and writes deployed addresses to ds. This is the shared core used by
// both DeployProtocolContracts and OnboardChain.
func deployProtocolContractsOnChains(
	e deployment.Environment,
	cfg DeployProtocolContractsInput,
	ds datastore.MutableDataStore,
) ([]operations.Report[any, any], error) {
	var allReports []operations.Report[any, any]

	for _, sel := range cfg.ChainSelectors {
		chainCfg := cfg.resolveChainCfg(sel)

		deployer, err := adapters.GetProtocolContractsDeployRegistry().Get(sel)
		if err != nil {
			return allReports, fmt.Errorf("chain %d: %w", sel, err)
		}

		existingAddresses := e.DataStore.Addresses().Filter(
			datastore.AddressRefByChainSelector(sel),
		)

		input := adapters.ProtocolContractsDeployInput{
			ChainSelector:     sel,
			DeployerContract:  chainCfg.DeployerContract,
			DeployTestRouter:  chainCfg.DeployTestRouter,
			ExistingAddresses: existingAddresses,
			Executors:         chainCfg.Executors,
			DeployerKeyOwned:  chainCfg.DeployerKeyOwned,
			FamilyExtras:      chainCfg.FamilyExtras,
		}

		e.Logger.Infow("Deploying protocol contracts",
			"chain", sel,
			"deployTestRouter", chainCfg.DeployTestRouter,
			"executorCount", len(chainCfg.Executors),
		)

		report, err := operations.ExecuteSequence(
			e.OperationsBundle,
			deployer.DeployProtocolContracts(),
			e.BlockChains,
			input,
		)
		allReports = append(allReports, report.ExecutionReports...)
		if err != nil {
			return allReports, fmt.Errorf("chain %d: deploy failed: %w", sel, err)
		}

		for _, ref := range report.Output.Addresses {
			if addErr := ds.Addresses().Add(ref); addErr != nil &&
				!errors.Is(addErr, datastore.ErrAddressRefExists) {
				return allReports, fmt.Errorf("chain %d: failed to add %s %s at %s to datastore: %w",
					sel, ref.Type, ref.Version, ref.Address, addErr)
			}
		}
	}

	return allReports, nil
}

// deployCommitteeVerifiersOnChains deploys committee verifiers on every chain
// in cfg and writes deployed addresses to ds. This is the shared core used by
// both DeployCommitteeVerifier and OnboardChain.
func deployCommitteeVerifiersOnChains(
	e deployment.Environment,
	cfg DeployCommitteeVerifierInput,
	ds datastore.MutableDataStore,
) ([]operations.Report[any, any], error) {
	var allReports []operations.Report[any, any]

	for _, sel := range cfg.ChainSelectors {
		deployer, err := adapters.GetCommitteeVerifierDeployRegistry().Get(sel)
		if err != nil {
			return allReports, fmt.Errorf("chain %d: %w", sel, err)
		}

		existingAddresses := e.DataStore.Addresses().Filter(
			datastore.AddressRefByChainSelector(sel),
		)

		for _, committee := range cfg.Committees {
			input := adapters.DeployCommitteeVerifierInput{
				ChainSelector:     sel,
				DeployerContract:  cfg.resolveChainCfg(sel).DeployerContract,
				ExistingAddresses: existingAddresses,
				Params:            committee,
			}

			e.Logger.Infow("Deploying CommitteeVerifier",
				"chain", sel,
				"committee", committee.Qualifier,
			)

			report, err := operations.ExecuteSequence(
				e.OperationsBundle,
				deployer.DeployCommitteeVerifier(),
				e.BlockChains,
				input,
			)
			allReports = append(allReports, report.ExecutionReports...)
			if err != nil {
				return allReports, fmt.Errorf("chain %d committee %q: deploy failed: %w", sel, committee.Qualifier, err)
			}

			for _, ref := range report.Output.Addresses {
				if addErr := ds.Addresses().Add(ref); addErr != nil &&
					!errors.Is(addErr, datastore.ErrAddressRefExists) {
					return allReports, fmt.Errorf("chain %d committee %q: failed to add %s %s at %s to datastore: %w",
						sel, committee.Qualifier, ref.Type, ref.Version, ref.Address, addErr)
				}
				existingAddresses = append(existingAddresses, ref)
			}
		}
	}

	return allReports, nil
}
