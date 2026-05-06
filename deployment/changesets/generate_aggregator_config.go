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

type GenerateAggregatorConfigInput struct {
	ServiceIdentifier  string
	CommitteeQualifier string
	Topology           *ccvdeployment.EnvironmentTopology
}

// GenerateAggregatorConfigImperativeInput is the topology-free counterpart to
// GenerateAggregatorConfigInput. ChainSelectors replaces the topology-based chain
// resolution, and ThresholdOverride (when non-nil) replaces the threshold read from
// onchain state — needed for offchain-first coupled products where the onchain change
// has not yet landed.
type GenerateAggregatorConfigImperativeInput struct {
	ServiceIdentifier  string
	CommitteeQualifier string
	ChainSelectors     []uint64
	ThresholdOverride  *uint8
}

func GenerateAggregatorConfig(registry *adapters.Registry) deployment.ChangeSetV2[GenerateAggregatorConfigInput] {
	validate := func(e deployment.Environment, cfg GenerateAggregatorConfigInput) error {
		if cfg.ServiceIdentifier == "" {
			return fmt.Errorf("service identifier is required")
		}
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}
		_, err := resolveAggregatorChainSelectors(e, cfg)
		return err
	}

	apply := func(e deployment.Environment, cfg GenerateAggregatorConfigInput) (deployment.ChangesetOutput, error) {
		chainSelectors, err := resolveAggregatorChainSelectors(e, cfg)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		committee, err := buildAggregatorCommittee(e, registry, cfg.CommitteeQualifier, chainSelectors, nil)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to build aggregator config: %w", err)
		}

		outputDS := datastore.NewMemoryDataStore()
		if e.DataStore != nil {
			if err := outputDS.Merge(e.DataStore); err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("failed to merge existing datastore: %w", err)
			}
		}

		if err := ccvdeployment.SaveAggregatorConfig(outputDS, cfg.ServiceIdentifier, committee); err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to save aggregator config: %w", err)
		}

		return deployment.ChangesetOutput{
			DataStore: outputDS,
		}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

// GenerateAggregatorConfigImperative is the topology-free companion to GenerateAggregatorConfig.
// It accepts chain selectors directly and an optional threshold override, making it suitable
// for use inside coupled-committee changesets where topology is not available.
func GenerateAggregatorConfigImperative(registry *adapters.Registry) deployment.ChangeSetV2[GenerateAggregatorConfigImperativeInput] {
	validate := func(e deployment.Environment, cfg GenerateAggregatorConfigImperativeInput) error {
		if cfg.ServiceIdentifier == "" {
			return fmt.Errorf("service identifier is required")
		}
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}
		if len(cfg.ChainSelectors) == 0 {
			return fmt.Errorf("at least one chain selector is required")
		}
		envSelectors := e.BlockChains.ListChainSelectors()
		for _, sel := range cfg.ChainSelectors {
			if !slices.Contains(envSelectors, sel) {
				return fmt.Errorf("chain selector %d is not available in environment", sel)
			}
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg GenerateAggregatorConfigImperativeInput) (deployment.ChangesetOutput, error) {
		committee, err := buildAggregatorCommittee(e, registry, cfg.CommitteeQualifier, cfg.ChainSelectors, cfg.ThresholdOverride)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to build aggregator config: %w", err)
		}

		outputDS := datastore.NewMemoryDataStore()
		if e.DataStore != nil {
			if err := outputDS.Merge(e.DataStore); err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("failed to merge existing datastore: %w", err)
			}
		}

		if err := ccvdeployment.SaveAggregatorConfig(outputDS, cfg.ServiceIdentifier, committee); err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to save aggregator config: %w", err)
		}

		return deployment.ChangesetOutput{DataStore: outputDS}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

func resolveAggregatorChainSelectors(e deployment.Environment, cfg GenerateAggregatorConfigInput) ([]uint64, error) {
	if cfg.Topology == nil {
		return nil, fmt.Errorf("topology is required")
	}
	if cfg.Topology.NOPTopology == nil {
		return nil, fmt.Errorf("NOP topology is required")
	}

	committee, ok := cfg.Topology.NOPTopology.Committees[cfg.CommitteeQualifier]
	if !ok {
		return nil, fmt.Errorf("committee %q not found in topology", cfg.CommitteeQualifier)
	}

	chainSelectors, err := getCommitteeChainSelectors(committee)
	if err != nil {
		return nil, err
	}

	envSelectors := e.BlockChains.ListChainSelectors()
	for _, s := range chainSelectors {
		if !slices.Contains(envSelectors, s) {
			return nil, fmt.Errorf("committee %q references chain selector %d which is not available in environment", cfg.CommitteeQualifier, s)
		}
	}

	return chainSelectors, nil
}

func buildAggregatorCommittee(
	e deployment.Environment,
	registry *adapters.Registry,
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
		a, err := registry.GetByChain(sel)
		if err != nil {
			return nil, err
		}
		if a.Aggregator == nil {
			return nil, fmt.Errorf("no aggregator config adapter registered for chain %d", sel)
		}
		if a.CommitteeVerifierOnchain == nil {
			return nil, fmt.Errorf("no CommitteeVerifierOnchain adapter registered for chain %d", sel)
		}

		states, err := a.CommitteeVerifierOnchain.ScanCommitteeStates(ctx, e, sel)
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

	quorumConfigs, err := buildQuorumConfigs(e.DataStore, registry, committeeStates, committeeQualifier, chainSelectors, thresholdOverride)
	if err != nil {
		return nil, fmt.Errorf("failed to build quorum configs: %w", err)
	}

	destVerifiers, err := buildDestinationVerifiers(e.DataStore, registry, committeeQualifier, chainSelectors)
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
	registry *adapters.Registry,
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

			a, err := registry.GetByChain(sigConfig.SourceChainSelector)
			if err != nil {
				return nil, err
			}
			if a.Aggregator == nil {
				return nil, fmt.Errorf("no aggregator config adapter registered for chain %d", sigConfig.SourceChainSelector)
			}

			sourceVerifierAddr, err := a.Aggregator.ResolveSourceVerifierAddress(ds, sigConfig.SourceChainSelector, committeeQualifier)
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
	registry *adapters.Registry,
	committeeQualifier string,
	destChainSelectors []uint64,
) (map[string]string, error) {
	destVerifiers := make(map[string]string, len(destChainSelectors))

	for _, chainSelector := range destChainSelectors {
		a, err := registry.GetByChain(chainSelector)
		if err != nil {
			return nil, err
		}
		if a.Aggregator == nil {
			return nil, fmt.Errorf("no aggregator config adapter registered for chain %d", chainSelector)
		}

		addr, err := a.Aggregator.ResolveDestinationVerifierAddress(ds, chainSelector, committeeQualifier)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve destination verifier for chain %d: %w", chainSelector, err)
		}
		destVerifiers[strconv.FormatUint(chainSelector, 10)] = addr
	}

	return destVerifiers, nil
}
