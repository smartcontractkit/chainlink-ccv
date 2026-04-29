package changesets

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/operations/fetch_signing_keys"
)

// AddNOPToCommitteeInput is the input for step-1 of the AddNOP two-entry product.
type AddNOPToCommitteeInput struct {
	// CommitteeQualifier identifies the committee the NOP is joining.
	CommitteeQualifier string
	// ChainSelectors are the destination chains on which the committee verifier is deployed.
	ChainSelectors []uint64
	// NOPAlias is the node alias used to look up the NOP's signing address in JD.
	NOPAlias string
	// NewThreshold is the desired threshold after the NOP is added. Zero keeps the current threshold.
	NewThreshold uint8
}

// AddNOPOffchainInput is the input for step-2 of the AddNOP two-entry product.
type AddNOPOffchainInput struct {
	// CommitteeQualifier identifies the committee.
	CommitteeQualifier string
	// ChainSelectors are the destination chains on which the committee verifier is deployed.
	ChainSelectors []uint64
	// ServiceIdentifiers lists every aggregator service that consumes this committee's config.
	// All are updated atomically in a single changeset run.
	ServiceIdentifiers []string
}

// AddNOPToCommittee is step-1 of a coupled onchain-first two-entry product.
//
// It fetches the NOP's signing address from JD, reads the current onchain committee state,
// and submits an applySignatureConfigs call that appends the new signer. The aggregator
// config regen is deferred to AddNOPOffchain (step-2), which runs after the timelock
// executes via the CLD post-proposal hook.
//
// Onchain-first ordering is safe because adding a new signer does not raise the quorum
// requirement — the existing signers already satisfy the current threshold.
func AddNOPToCommittee(registry *adapters.Registry) deployment.ChangeSetV2[AddNOPToCommitteeInput] {
	validate := func(e deployment.Environment, cfg AddNOPToCommitteeInput) error {
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}
		if len(cfg.ChainSelectors) == 0 {
			return fmt.Errorf("at least one chain selector is required")
		}
		if cfg.NOPAlias == "" {
			return fmt.Errorf("NOP alias is required")
		}
		for _, sel := range cfg.ChainSelectors {
			a, err := registry.GetByChain(sel)
			if err != nil {
				return fmt.Errorf("chain %d: %w", sel, err)
			}
			if a.CommitteeVerifierOnchain == nil {
				return fmt.Errorf("chain %d: no CommitteeVerifierOnchain adapter registered", sel)
			}
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg AddNOPToCommitteeInput) (deployment.ChangesetOutput, error) {
		ctx := context.Background()

		signerFamily, err := getSignerFamilyFromRegistry(registry, cfg.ChainSelectors)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		signerAddress, err := fetchSignerAddress(e, cfg.NOPAlias, signerFamily)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		committeeStates, err := scanCommitteeStatesForChains(ctx, e, registry, cfg.CommitteeQualifier, cfg.ChainSelectors)
		if err != nil {
			return deployment.ChangesetOutput{}, err
		}

		for _, sel := range cfg.ChainSelectors {
			change, err := buildAddSignerChange(committeeStates[sel], signerAddress, cfg.NewThreshold)
			if err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("chain %d: %w", sel, err)
			}
			a, _ := registry.GetByChain(sel)
			if err := a.CommitteeVerifierOnchain.ApplySignatureConfigs(ctx, e, sel, cfg.CommitteeQualifier, change); err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("chain %d: ApplySignatureConfigs failed: %w", sel, err)
			}
		}

		// No DataStore output — aggregator config regen is deferred to step-2.
		return deployment.ChangesetOutput{}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

// AddNOPOffchain is step-2 of the AddNOP two-entry product.
//
// It regenerates the aggregator config from the updated onchain state (which now includes
// the new signer) and writes it to the DataStore for each listed service identifier.
// Triggered by the CLD post-proposal hook after timelock execution.
func AddNOPOffchain(registry *adapters.Registry) deployment.ChangeSetV2[AddNOPOffchainInput] {
	validate := func(e deployment.Environment, cfg AddNOPOffchainInput) error {
		if cfg.CommitteeQualifier == "" {
			return fmt.Errorf("committee qualifier is required")
		}
		if len(cfg.ChainSelectors) == 0 {
			return fmt.Errorf("at least one chain selector is required")
		}
		if len(cfg.ServiceIdentifiers) == 0 {
			return fmt.Errorf("at least one service identifier is required")
		}
		for _, sel := range cfg.ChainSelectors {
			a, err := registry.GetByChain(sel)
			if err != nil {
				return fmt.Errorf("chain %d: %w", sel, err)
			}
			if a.CommitteeVerifierOnchain == nil {
				return fmt.Errorf("chain %d: no CommitteeVerifierOnchain adapter registered", sel)
			}
			if a.Aggregator == nil {
				return fmt.Errorf("chain %d: no Aggregator adapter registered", sel)
			}
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg AddNOPOffchainInput) (deployment.ChangesetOutput, error) {
		committee, err := buildAggregatorCommittee(e, registry, cfg.CommitteeQualifier, cfg.ChainSelectors, nil)
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

		return deployment.ChangesetOutput{DataStore: outputDS}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

// fetchSignerAddress fetches the onchain signing address for a single NOP alias from JD.
func fetchSignerAddress(e deployment.Environment, nopAlias string, signerFamily string) (string, error) {
	if e.Offchain == nil {
		return "", fmt.Errorf("offchain client not available — cannot fetch signer address for NOP %q", nopAlias)
	}

	report, err := operations.ExecuteOperation(
		e.OperationsBundle,
		fetch_signing_keys.FetchNOPSigningKeys,
		fetch_signing_keys.FetchSigningKeysDeps{
			JDClient: e.Offchain,
			Logger:   e.Logger,
			NodeIDs:  e.NodeIDs,
		},
		fetch_signing_keys.FetchSigningKeysInput{
			NOPAliases: []string{nopAlias},
		},
	)
	if err != nil {
		return "", fmt.Errorf("failed to fetch signing keys for NOP %q: %w", nopAlias, err)
	}

	addr := report.Output.SigningKeysByNOP[nopAlias][signerFamily]
	if addr == "" {
		return "", fmt.Errorf("no signer address found in JD for NOP %q family %s", nopAlias, signerFamily)
	}
	return addr, nil
}

// buildAddSignerChange constructs a SignatureConfigChange that appends newSigner to every
// source chain config. If newThreshold is non-zero it replaces the current threshold;
// otherwise the existing threshold is preserved.
func buildAddSignerChange(state *adapters.CommitteeState, newSigner string, newThreshold uint8) (adapters.SignatureConfigChange, error) {
	newConfigs := make([]adapters.SignatureConfig, 0, len(state.SignatureConfigs))
	for _, sc := range state.SignatureConfigs {
		for _, s := range sc.Signers {
			if strings.EqualFold(s, newSigner) {
				return adapters.SignatureConfigChange{}, fmt.Errorf(
					"source chain %d: signer %q is already a committee member",
					sc.SourceChainSelector, newSigner,
				)
			}
		}
		threshold := sc.Threshold
		if newThreshold != 0 {
			threshold = newThreshold
		}
		newConfigs = append(newConfigs, adapters.SignatureConfig{
			SourceChainSelector: sc.SourceChainSelector,
			Signers:             append(slices.Clone(sc.Signers), newSigner),
			Threshold:           threshold,
		})
	}
	return adapters.SignatureConfigChange{NewConfigs: newConfigs}, nil
}
