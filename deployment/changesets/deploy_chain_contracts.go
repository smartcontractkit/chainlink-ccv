package changesets

// DeployChainContracts changeset overview
//
// DeployChainContracts is a single-entry, onchain-only product for deploying
// the core CCIP protocol contracts on one or more chains (§5.1).
//
// It deploys: RMNRemote, OnRamp, OffRamp, FeeQuoter, Router (optionally
// TestRouter), and Executors. Committee verifiers are deployed separately via
// DeployCommitteeVerifier.
//
// The changeset is one step in the chain-addition multi-changeset workflow:
//   DeployChainContracts → DeployCommitteeVerifier → LaneExpansion →
//   ApplyVerifierConfig → ApplyExecutorConfig
//
// Deployed contracts remain owned by the deployer key when DeployerKeyOwned
// is true. Otherwise, the adapter produces BatchOps for ownership transfer
// to the RBAC timelock.

import (
	"errors"
	"fmt"
	"slices"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// DeployChainContractsPerChainCfg carries the per-chain configuration for
// deploying CCIP protocol contracts.
type DeployChainContractsPerChainCfg struct {
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

// DeployChainContractsInput is the imperative input for the
// DeployChainContracts changeset.
type DeployChainContractsInput struct {
	// ChainSelectors are the chains to deploy on.
	ChainSelectors []uint64
	// DefaultCfg supplies fallback per-chain values. Used when a chain has no
	// entry in ChainCfgs.
	DefaultCfg DeployChainContractsPerChainCfg
	// ChainCfgs overrides DefaultCfg for specific chains.
	ChainCfgs map[uint64]DeployChainContractsPerChainCfg
}

func (c DeployChainContractsInput) resolveChainCfg(sel uint64) DeployChainContractsPerChainCfg {
	if override, ok := c.ChainCfgs[sel]; ok {
		return override
	}
	return c.DefaultCfg
}

// DeployChainContracts is a single-entry, onchain-only changeset that deploys
// the core CCIP protocol contracts on the specified chains (§5.1).
//
// Per-chain work is dispatched through the ChainContractsDeployAdapter
// registered for each chain's family. The adapter handles contract deployment
// and is expected to be idempotent: re-running on a chain where contracts
// already exist is a no-op or reconciles drifted config.
func DeployChainContracts() deployment.ChangeSetV2[DeployChainContractsInput] {
	validate := func(e deployment.Environment, cfg DeployChainContractsInput) error {
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

			if _, err := adapters.GetChainContractsDeployRegistry().Get(sel); err != nil {
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

	apply := func(e deployment.Environment, cfg DeployChainContractsInput) (deployment.ChangesetOutput, error) {
		outputDS := datastore.NewMemoryDataStore()
		var allReports []operations.Report[any, any]

		for _, sel := range cfg.ChainSelectors {
			chainCfg := cfg.resolveChainCfg(sel)

			deployer, err := adapters.GetChainContractsDeployRegistry().Get(sel)
			if err != nil {
				return deployment.ChangesetOutput{Reports: allReports, DataStore: outputDS},
					fmt.Errorf("chain %d: %w", sel, err)
			}

			existingAddresses := e.DataStore.Addresses().Filter(
				datastore.AddressRefByChainSelector(sel),
			)

			input := adapters.ChainContractsDeployInput{
				ChainSelector:     sel,
				DeployerContract:  chainCfg.DeployerContract,
				DeployTestRouter:  chainCfg.DeployTestRouter,
				ExistingAddresses: existingAddresses,
				Executors:         chainCfg.Executors,
				DeployerKeyOwned:  chainCfg.DeployerKeyOwned,
				FamilyExtras:      chainCfg.FamilyExtras,
			}

			e.Logger.Infow("Deploying chain contracts",
				"chain", sel,
				"deployTestRouter", chainCfg.DeployTestRouter,
				"executorCount", len(chainCfg.Executors),
			)

			report, err := operations.ExecuteSequence(
				e.OperationsBundle,
				deployer.DeployChainContracts(),
				e.BlockChains,
				input,
			)
			allReports = append(allReports, report.ExecutionReports...)
			if err != nil {
				return deployment.ChangesetOutput{Reports: allReports, DataStore: outputDS},
					fmt.Errorf("chain %d: deploy failed: %w", sel, err)
			}

			for _, ref := range report.Output.Addresses {
				if addErr := outputDS.Addresses().Add(ref); addErr != nil &&
					!errors.Is(addErr, datastore.ErrAddressRefExists) {
					return deployment.ChangesetOutput{Reports: allReports, DataStore: outputDS},
						fmt.Errorf("chain %d: failed to add %s %s at %s to datastore: %w",
							sel, ref.Type, ref.Version, ref.Address, addErr)
				}
			}
		}

		return deployment.ChangesetOutput{
			Reports:   allReports,
			DataStore: outputDS,
		}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}
