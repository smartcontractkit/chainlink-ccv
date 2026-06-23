package changesets

// OnboardChain changeset overview
//
// OnboardChain is a single-entry, onchain-only product that deploys everything
// a new chain needs to participate in CCIP 2.0: protocol contracts (RMN,
// OnRamp, OffRamp, FeeQuoter, Router, Executors) AND committee verifiers.
//
// It composes the same deploy helpers used by DeployProtocolContracts and
// DeployCommitteeVerifier, so re-running is idempotent and the result is
// identical to running the two changesets sequentially.
//
// After OnboardChain, the chain is deployed but not yet connected to any lanes.
// Use LaneExpansion to wire lanes, then ApplyVerifierConfig / ApplyExecutorConfig
// for offchain setup.

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

// OnboardChainInput is the imperative input for the OnboardChain changeset.
type OnboardChainInput struct {
	// ProtocolContracts configures the protocol contract deployment
	// (RMN, OnRamp, OffRamp, FeeQuoter, Router, Executors).
	ProtocolContracts DeployProtocolContractsInput
	// CommitteeVerifiers configures the committee verifier deployment.
	// ChainSelectors must match ProtocolContracts.ChainSelectors.
	CommitteeVerifiers DeployCommitteeVerifierInput
}

// OnboardChain deploys both protocol contracts and committee verifiers on the
// specified chains in a single changeset. It is the composite entry point for
// the chain addition workflow (§5.1).
//
// Protocol contracts are deployed first, then committee verifiers (which may
// reference protocol contract addresses via the adapter's ExistingAddresses).
// Both use the same shared helpers as their standalone counterparts, so
// idempotency guarantees are identical.
func OnboardChain() deployment.ChangeSetV2[OnboardChainInput] {
	validate := func(e deployment.Environment, cfg OnboardChainInput) error {
		if err := validateProtocolContractsDeploy(e, cfg.ProtocolContracts); err != nil {
			return fmt.Errorf("protocol contracts: %w", err)
		}
		if err := validateCommitteeVerifierDeploy(e, cfg.CommitteeVerifiers); err != nil {
			return fmt.Errorf("committee verifiers: %w", err)
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg OnboardChainInput) (deployment.ChangesetOutput, error) {
		ds := datastore.NewMemoryDataStore()
		var allReports []operations.Report[any, any]

		// Phase 1: deploy protocol contracts.
		reports, err := deployProtocolContractsOnChains(e, cfg.ProtocolContracts, ds)
		allReports = append(allReports, reports...)
		if err != nil {
			return deployment.ChangesetOutput{Reports: allReports, DataStore: ds},
				fmt.Errorf("protocol contracts: %w", err)
		}

		// Phase 2: deploy committee verifiers. Use a merged DataStore so the
		// CCV adapter can see the protocol addresses just deployed.
		ccvEnv := e
		merged := datastore.NewMemoryDataStore()
		if err := merged.Merge(e.DataStore); err != nil {
			return deployment.ChangesetOutput{Reports: allReports, DataStore: ds},
				fmt.Errorf("failed to merge base datastore: %w", err)
		}
		if err := merged.Merge(ds.Seal()); err != nil {
			return deployment.ChangesetOutput{Reports: allReports, DataStore: ds},
				fmt.Errorf("failed to merge protocol contracts datastore: %w", err)
		}
		ccvEnv.DataStore = merged.Seal()

		reports, err = deployCommitteeVerifiersOnChains(ccvEnv, cfg.CommitteeVerifiers, ds)
		allReports = append(allReports, reports...)
		if err != nil {
			return deployment.ChangesetOutput{Reports: allReports, DataStore: ds},
				fmt.Errorf("committee verifiers: %w", err)
		}

		return deployment.ChangesetOutput{Reports: allReports, DataStore: ds}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}
