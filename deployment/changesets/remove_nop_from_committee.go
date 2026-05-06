package changesets

import (
	"context"
	"fmt"
	"strings"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/operations/revoke_jobs"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// RemoveNOPFromCommitteeInput is the input for step-1 of the RemoveNOP two-entry product.
type RemoveNOPFromCommitteeInput struct {
	// CommitteeQualifier identifies the committee the NOP is leaving.
	CommitteeQualifier string
	// SourceChainSelectors are the source chains for which the NOP's signer should be removed.
	// The changeset automatically updates every destination chain that has this committee
	// verifier deployed — callers do not enumerate dest chains.
	SourceChainSelectors []uint64
	// NOPAlias is the node alias used to look up the NOP's signing address in JD.
	NOPAlias string
	// NewThreshold is the desired threshold after the NOP is removed. Zero keeps the current threshold.
	// Must not exceed the remaining signer count.
	NewThreshold uint8
}

// RemoveNOPOffchainInput is the input for step-2 of the RemoveNOP two-entry product.
type RemoveNOPOffchainInput struct {
	// CommitteeQualifier identifies the committee.
	CommitteeQualifier string
	// SourceChainSelectors are the source chains updated in step-1. Must match step-1.
	SourceChainSelectors []uint64
	// RemovedSignerAddress is the signer address removed in step-1. If non-empty, validate
	// asserts this address is absent onchain on every dest chain for every source chain
	// before writing the new aggregator config — guarding against hook misfires or
	// out-of-order manual invocations where step-1 has not yet landed.
	RemovedSignerAddress string
	// ServiceIdentifiers lists every aggregator service that consumes this committee's config.
	// All are updated atomically in a single changeset run.
	ServiceIdentifiers []string
	// NOPAlias is the alias of the NOP whose verifier jobs should be revoked. All in-scope
	// verifier jobs for this NOP are revoked from JD and removed from the DataStore.
	NOPAlias shared.NOPAlias
}

// RemoveNOPFromCommittee is step-1 of a coupled onchain-first two-entry product.
//
// It fetches the NOP's signing address from JD, then for every destination chain that has
// this committee verifier deployed (discovered automatically from the registry) it reads the
// current onchain committee state and submits an applySignatureConfigs call that removes the
// signer from each of the specified source chain configs. The aggregator config regen is
// deferred to RemoveNOPOffchain (step-2), which runs after the timelock executes via the CLD
// post-proposal hook.
//
// Onchain-first ordering is required because removing a signer from the contract immediately
// stops that signer's votes from being counted, while the aggregator still collects from
// them harmlessly until step-2 updates the offchain config.
func RemoveNOPFromCommittee(registry *adapters.Registry) deployment.ChangeSetV2[RemoveNOPFromCommitteeInput] {
	validate := func(e deployment.Environment, cfg RemoveNOPFromCommitteeInput) error {
		return validateStep1NOP(e, cfg.CommitteeQualifier, cfg.NOPAlias, cfg.SourceChainSelectors, registry)
	}

	apply := func(e deployment.Environment, cfg RemoveNOPFromCommitteeInput) (deployment.ChangesetOutput, error) {
		signerFamily, err := getSignerFamilyFromRegistry(registry, cfg.SourceChainSelectors)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}
		if err := applySignerChangesOnchain(e, registry, cfg.CommitteeQualifier, cfg.NOPAlias, signerFamily,
			cfg.SourceChainSelectors, cfg.NewThreshold, buildRemoveSignerChange); err != nil {
			return deployment.ChangesetOutput{}, err
		}
		return deployment.ChangesetOutput{}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

// RemoveNOPOffchain is step-2 of the RemoveNOP two-entry product.
//
// Validate asserts that the removed signer is absent onchain on every dest chain for every
// source chain listed in SourceChainSelectors (when RemovedSignerAddress is set). This guards
// against hook misfires or manual out-of-order invocations where step-1 has not yet landed.
//
// Apply regenerates the aggregator config from the updated onchain state and writes it to
// the DataStore for each listed service identifier. Dest chains are discovered automatically
// from the registry — the same set used by step-1.
//
// When NOPAlias is set, all verifier jobs scoped to this committee for that NOP are revoked
// from JD and removed from the DataStore in the same run.
func RemoveNOPOffchain(registry *adapters.Registry) deployment.ChangeSetV2[RemoveNOPOffchainInput] {
	validate := func(e deployment.Environment, cfg RemoveNOPOffchainInput) error {
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}
		if len(cfg.SourceChainSelectors) == 0 {
			return fmt.Errorf("at least one source chain selector is required")
		}
		if len(cfg.ServiceIdentifiers) == 0 {
			return fmt.Errorf("at least one service identifier is required")
		}
		if cfg.NOPAlias == "" {
			return fmt.Errorf("NOP alias is required for job revocation")
		}

		committeeChains := registry.AllDeployedCommitteeVerifierChains(e.DataStore, cfg.CommitteeQualifier)
		if len(committeeChains) == 0 {
			return fmt.Errorf("no dest chains found for committee %q — step-1 may not have been applied or adapters are not registered", cfg.CommitteeQualifier)
		}
		for _, sel := range committeeChains {
			a, err := registry.GetByChain(sel)
			if err != nil {
				return fmt.Errorf("dest chain %d: %w", sel, err)
			}
			if a.CommitteeVerifierOnchain == nil {
				return fmt.Errorf("dest chain %d: no CommitteeVerifierOnchain adapter registered", sel)
			}
			if a.Aggregator == nil {
				return fmt.Errorf("dest chain %d: no Aggregator adapter registered", sel)
			}
		}

		// Safety backstop: assert the removed signer is absent onchain on every dest chain for
		// every source chain. Catches hook misfires and out-of-order manual invocations.
		if cfg.RemovedSignerAddress != "" {
			ctx := context.Background()
			committeeStates, err := scanCommitteeStatesForChains(ctx, e, registry, cfg.CommitteeQualifier, committeeChains)
			if err != nil {
				return err
			}
			sourceSet := make(map[uint64]bool, len(cfg.SourceChainSelectors))
			for _, sel := range cfg.SourceChainSelectors {
				sourceSet[sel] = true
			}
			for destSel, state := range committeeStates {
				for _, sc := range state.SignatureConfigs {
					if !sourceSet[sc.SourceChainSelector] {
						continue
					}
					for _, s := range sc.Signers {
						if strings.EqualFold(s, cfg.RemovedSignerAddress) {
							return fmt.Errorf(
								"dest chain %d source chain %d: signer %q still present onchain — step-1 (RemoveNOPFromCommittee) may not have been applied",
								destSel, sc.SourceChainSelector, cfg.RemovedSignerAddress,
							)
						}
					}
				}
			}
		}

		return nil
	}

	apply := func(e deployment.Environment, cfg RemoveNOPOffchainInput) (deployment.ChangesetOutput, error) {
		committeeChains := registry.AllDeployedCommitteeVerifierChains(e.DataStore, cfg.CommitteeQualifier)
		if len(committeeChains) == 0 {
			return deployment.ChangesetOutput{}, fmt.Errorf("no dest chains found for committee %q", cfg.CommitteeQualifier)
		}

		committee, err := buildAggregatorCommittee(e, registry, cfg.CommitteeQualifier, committeeChains, nil)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to build aggregator config: %w", err)
		}

		outputDS := datastore.NewMemoryDataStore()
		if e.DataStore != nil {
			if err := outputDS.Merge(e.DataStore); err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("failed to merge datastore: %w", err)
			}
		}
		for _, svcID := range cfg.ServiceIdentifiers {
			if err := ccvdeployment.SaveAggregatorConfig(outputDS, svcID, committee); err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("failed to save aggregator config for %q: %w", svcID, err)
			}
		}

		if err := revokeVerifierJobsForNOP(e, cfg.NOPAlias, cfg.CommitteeQualifier, outputDS); err != nil {
			return deployment.ChangesetOutput{}, err
		}

		return deployment.ChangesetOutput{DataStore: outputDS}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

// revokeVerifierJobsForNOP collects all verifier jobs scoped to committeeQualifier for
// nopAlias, revokes CL-mode ones via JD, and removes all of them from the DataStore.
func revokeVerifierJobsForNOP(
	e deployment.Environment,
	nopAlias shared.NOPAlias,
	committeeQualifier string,
	ds datastore.MutableDataStore,
) error {
	scope := shared.VerifierJobScope{CommitteeQualifier: committeeQualifier}

	// nil expectedJobsByNOP → every in-scope job for this NOP is treated as orphaned.
	orphanedJobs, err := ccvdeployment.CollectOrphanedJobs(
		ds.Seal(),
		scope,
		nil,
		map[shared.NOPAlias]bool{nopAlias: true},
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to collect orphaned jobs for NOP %q: %w", nopAlias, err)
	}

	if len(orphanedJobs) == 0 {
		e.Logger.Infow("No verifier jobs to revoke for NOP", "nopAlias", nopAlias, "committee", committeeQualifier)
		return nil
	}

	// Revoke CL-mode jobs that haven't already been revoked.
	clJobsToRevoke := make([]shared.JobInfo, 0, len(orphanedJobs))
	for _, j := range orphanedJobs {
		if j.Mode == shared.NOPModeCL && j.LatestStatus() != shared.JobProposalStatusRevoked {
			clJobsToRevoke = append(clJobsToRevoke, j)
		}
	}

	if len(clJobsToRevoke) > 0 {
		if e.Offchain == nil {
			return fmt.Errorf("offchain client required to revoke CL-mode jobs for NOP %q but e.Offchain is nil", nopAlias)
		}
		revokeReport, err := operations.ExecuteOperation(
			e.OperationsBundle,
			revoke_jobs.RevokeJobs,
			revoke_jobs.RevokeJobsDeps{
				JDClient: e.Offchain,
				Logger:   e.Logger,
				NodeIDs:  e.NodeIDs,
			},
			revoke_jobs.RevokeJobsInput{
				Jobs: clJobsToRevoke,
			},
		)
		if err != nil {
			return fmt.Errorf("failed to revoke jobs for NOP %q: %w", nopAlias, err)
		}
		e.Logger.Infow("Verifier jobs revoked for NOP",
			"nopAlias", nopAlias,
			"count", len(revokeReport.Output.RevokedJobs),
			"committee", committeeQualifier,
		)
	}

	if err := ccvdeployment.CleanupOrphanedJobs(ds, orphanedJobs); err != nil {
		return fmt.Errorf("failed to clean up jobs for NOP %q: %w", nopAlias, err)
	}

	return nil
}

// buildRemoveSignerChange constructs a SignatureConfigChange that removes signerToRemove from
// every source chain config whose SourceChainSelector is in sourceChainSelectors. Configs for
// other source chains are left untouched (not included in NewConfigs).
//
// If newThreshold is non-zero it replaces the current threshold; otherwise the existing
// threshold is preserved, subject to not exceeding the remaining signer count.
func buildRemoveSignerChange(state *adapters.CommitteeState, signerToRemove string, newThreshold uint8, sourceChainSelectors []uint64) (adapters.SignatureConfigChange, error) {
	sourceSet := make(map[uint64]bool, len(sourceChainSelectors))
	for _, sel := range sourceChainSelectors {
		sourceSet[sel] = true
	}

	newConfigs := make([]adapters.SignatureConfig, 0, len(sourceChainSelectors))
	for _, sc := range state.SignatureConfigs {
		if !sourceSet[sc.SourceChainSelector] {
			continue
		}
		remaining := make([]string, 0, len(sc.Signers))
		found := false
		for _, s := range sc.Signers {
			if strings.EqualFold(s, signerToRemove) {
				found = true
				continue
			}
			remaining = append(remaining, s)
		}
		if !found {
			return adapters.SignatureConfigChange{}, fmt.Errorf(
				"source chain %d: signer %q not found in committee",
				sc.SourceChainSelector, signerToRemove,
			)
		}
		if len(remaining) == 0 {
			return adapters.SignatureConfigChange{}, fmt.Errorf(
				"source chain %d: cannot remove the last signer from a committee",
				sc.SourceChainSelector,
			)
		}
		threshold := sc.Threshold
		if newThreshold != 0 {
			threshold = newThreshold
		}
		if int(threshold) > len(remaining) {
			return adapters.SignatureConfigChange{}, fmt.Errorf(
				"source chain %d: threshold %d exceeds remaining signer count %d after removal",
				sc.SourceChainSelector, threshold, len(remaining),
			)
		}
		newConfigs = append(newConfigs, adapters.SignatureConfig{
			SourceChainSelector: sc.SourceChainSelector,
			Signers:             remaining,
			Threshold:           threshold,
		})
	}
	return adapters.SignatureConfigChange{NewConfigs: newConfigs}, nil
}
