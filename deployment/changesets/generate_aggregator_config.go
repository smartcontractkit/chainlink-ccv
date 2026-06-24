package changesets

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// GenerateAggregatorConfigInput is the imperative input for the aggregator-config
// regen changeset. Callers pass the chain selectors directly — there is no
// topology lookup. ThresholdOverride (when non-nil) replaces the threshold read
// from onchain state, supporting offchain-first coupled products such as
// IncreaseThresholdOffchain (§5.5).
type GenerateAggregatorConfigInput struct {
	// ServiceIdentifier is the aggregator service whose DataStore-backed config
	// is being written.
	ServiceIdentifier string
	// CommitteeQualifier identifies the committee whose state is being scanned.
	CommitteeQualifier string
	// ChainSelectors are the destination chains hosting the committee verifier
	// to scan. The aggregator config is built from the union of source-chain
	// signature configs found across these chains.
	ChainSelectors []uint64
	// ThresholdOverride, when non-nil, replaces the threshold read from onchain
	// state. Used by offchain-first coupled products to publish the post-change
	// threshold ahead of the onchain mutation.
	ThresholdOverride *uint8
	// ReplaceExisting controls how the result is written to env metadata. By
	// default (false) the changeset is modular: the chains scanned in this run are
	// upserted into the aggregator config already persisted for ServiceIdentifier,
	// so quorum configs and destination verifiers for chains not in ChainSelectors
	// are preserved and per-chain runs accumulate into one committee. Set true to
	// replace the stored config from a full scan of ChainSelectors instead, which
	// also removes stale chains.
	ReplaceExisting bool
}

// GenerateAggregatorConfig is the offchain-only single-entry product that
// regenerates an aggregator's quorum config from onchain committee state and
// writes it to the DataStore for the named service identifier.
//
// The input is imperative — callers pass the chain selectors directly, with no
// *EnvironmentTopology. For coupled-committee products that need to publish the
// post-change threshold ahead of the onchain mutation, set ThresholdOverride.
func GenerateAggregatorConfig() deployment.ChangeSetV2[GenerateAggregatorConfigInput] {
	validate := func(e deployment.Environment, cfg GenerateAggregatorConfigInput) error {
		if cfg.ServiceIdentifier == "" {
			return fmt.Errorf("service identifier is required")
		}
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}
		if len(cfg.ChainSelectors) == 0 {
			return fmt.Errorf("at least one chain selector is required")
		}
		seenSelectors := make(map[uint64]bool, len(cfg.ChainSelectors))
		for _, sel := range cfg.ChainSelectors {
			if seenSelectors[sel] {
				return fmt.Errorf("duplicate chain selector %d in ChainSelectors", sel)
			}
			seenSelectors[sel] = true
		}
		envSelectors := e.BlockChains.ListChainSelectors()
		for _, sel := range cfg.ChainSelectors {
			if !slices.Contains(envSelectors, sel) {
				return fmt.Errorf("chain selector %d is not available in environment", sel)
			}
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg GenerateAggregatorConfigInput) (deployment.ChangesetOutput, error) {
		committee, err := buildAggregatorCommittee(e, cfg.CommitteeQualifier, cfg.ChainSelectors, cfg.ThresholdOverride)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to build aggregator config: %w", err)
		}

		outputDS := datastore.NewMemoryDataStore()
		if e.DataStore != nil {
			if err := outputDS.Merge(e.DataStore); err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("failed to merge existing datastore: %w", err)
			}
		}

		// Modular by default: upsert this run's chains into the stored committee.
		// ReplaceExisting forces a full replace (removing chains no longer scanned).
		save := ccvdeployment.MergeAggregatorConfig
		if cfg.ReplaceExisting {
			save = ccvdeployment.SaveAggregatorConfig
		}
		if err := save(outputDS, cfg.ServiceIdentifier, committee); err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to save aggregator config: %w", err)
		}

		return deployment.ChangesetOutput{DataStore: outputDS}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

func buildAggregatorCommittee(
	e deployment.Environment,
	committeeQualifier string,
	chainSelectors []uint64,
	thresholdOverride *uint8,
) (*model.Committee, error) {
	ctx := context.Background()

	type chainQualifier struct {
		chainSelector uint64
		qualifier     string
	}
	seen := make(map[chainQualifier]bool)
	allCommittees := make(map[string][]*adapters.CommitteeState)
	for _, sel := range chainSelectors {
		if _, err := adapters.GetAggregatorRegistry().Get(sel); err != nil {
			return nil, fmt.Errorf("no aggregator config adapter registered for chain %d: %w", sel, err)
		}
		onchain, err := adapters.GetCommitteeVerifierOnchainRegistry().Get(sel)
		if err != nil {
			return nil, fmt.Errorf("no CommitteeVerifierOnchain adapter registered for chain %d: %w", sel, err)
		}

		states, err := onchain.ScanCommitteeStates(ctx, e, sel)
		if err != nil {
			return nil, fmt.Errorf("failed to scan committee states on chain %d: %w", sel, err)
		}
		for _, state := range states {
			key := chainQualifier{chainSelector: sel, qualifier: state.Qualifier}
			if seen[key] {
				return nil, fmt.Errorf(
					"chain %d has multiple committee verifiers with qualifier %q",
					sel, state.Qualifier,
				)
			}
			seen[key] = true
			allCommittees[state.Qualifier] = append(allCommittees[state.Qualifier], state)
		}
	}

	committeeStates, ok := allCommittees[committeeQualifier]
	if !ok || len(committeeStates) == 0 {
		return nil, fmt.Errorf("committee %q not found in deployed verifier state", committeeQualifier)
	}

	quorumConfigs, err := buildQuorumConfigs(e.DataStore, committeeStates, committeeQualifier, chainSelectors, thresholdOverride)
	if err != nil {
		return nil, fmt.Errorf("failed to build quorum configs: %w", err)
	}

	destVerifiers, err := buildDestinationVerifiers(e.DataStore, committeeQualifier, chainSelectors)
	if err != nil {
		return nil, fmt.Errorf("failed to build destination verifiers: %w", err)
	}

	return &model.Committee{
		QuorumConfigs:        quorumConfigs,
		DestinationVerifiers: destVerifiers,
	}, nil
}

func buildQuorumConfigs(
	ds datastore.DataStore,
	committeeStates []*adapters.CommitteeState,
	committeeQualifier string,
	chainSelectors []uint64,
	thresholdOverride *uint8,
) (map[string]*model.QuorumConfig, error) {
	supportedChains := make(map[uint64]bool, len(chainSelectors))
	for _, sel := range chainSelectors {
		supportedChains[sel] = true
	}

	quorumConfigs := make(map[string]*model.QuorumConfig)

	for _, state := range committeeStates {
		for _, sigConfig := range state.SignatureConfigs {
			if !supportedChains[sigConfig.SourceChainSelector] {
				continue
			}

			chainSelectorStr := strconv.FormatUint(sigConfig.SourceChainSelector, 10)
			if existing, exists := quorumConfigs[chainSelectorStr]; exists {
				effectiveSig := sigConfig
				if thresholdOverride != nil {
					effectiveSig.Threshold = *thresholdOverride
				}
				if err := validateSignatureConfigConsistency(existing, effectiveSig, chainSelectorStr, committeeQualifier); err != nil {
					return nil, err
				}
				continue
			}

			agg, err := adapters.GetAggregatorRegistry().Get(sigConfig.SourceChainSelector)
			if err != nil {
				return nil, fmt.Errorf("no aggregator config adapter registered for chain %d: %w", sigConfig.SourceChainSelector, err)
			}

			sourceVerifierAddr, err := agg.ResolveSourceVerifierAddress(ds, sigConfig.SourceChainSelector, committeeQualifier)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve source verifier for chain %d: %w", sigConfig.SourceChainSelector, err)
			}

			signers := make([]model.Signer, 0, len(sigConfig.Signers))
			for _, addr := range sigConfig.Signers {
				signers = append(signers, model.Signer{Address: addr})
			}

			threshold := sigConfig.Threshold
			if thresholdOverride != nil {
				threshold = *thresholdOverride
			}

			quorumConfigs[chainSelectorStr] = &model.QuorumConfig{
				SourceVerifierAddress: sourceVerifierAddr,
				Signers:               signers,
				Threshold:             threshold,
			}
		}
	}

	return quorumConfigs, nil
}

func validateSignatureConfigConsistency(
	existing *model.QuorumConfig,
	newSig adapters.SignatureConfig,
	chainSelectorStr string,
	committeeQualifier string,
) error {
	if existing.Threshold != newSig.Threshold {
		return fmt.Errorf(
			"committee %q chain %s: conflicting signature config threshold %d vs %d",
			committeeQualifier, chainSelectorStr, existing.Threshold, newSig.Threshold,
		)
	}

	existingAddrs := make([]string, len(existing.Signers))
	for i, s := range existing.Signers {
		existingAddrs[i] = s.Address
	}
	slices.Sort(existingAddrs)

	newAddrs := slices.Clone(newSig.Signers)
	slices.Sort(newAddrs)

	if !slices.Equal(existingAddrs, newAddrs) {
		return fmt.Errorf(
			"committee %q chain %s: conflicting signers (count %d vs %d)",
			committeeQualifier, chainSelectorStr, len(existingAddrs), len(newAddrs),
		)
	}

	return nil
}

func buildDestinationVerifiers(
	ds datastore.DataStore,
	committeeQualifier string,
	destChainSelectors []uint64,
) (map[string]string, error) {
	destVerifiers := make(map[string]string, len(destChainSelectors))

	for _, chainSelector := range destChainSelectors {
		agg, err := adapters.GetAggregatorRegistry().Get(chainSelector)
		if err != nil {
			return nil, fmt.Errorf("no aggregator config adapter registered for chain %d: %w", chainSelector, err)
		}

		addr, err := agg.ResolveDestinationVerifierAddress(ds, chainSelector, committeeQualifier)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve destination verifier for chain %d: %w", chainSelector, err)
		}
		destVerifiers[strconv.FormatUint(chainSelector, 10)] = addr
	}

	return destVerifiers, nil
}
